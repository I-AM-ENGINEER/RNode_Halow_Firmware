#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW_PKG_HANDLER
#include "basic_include.h"
#include <time.h>
#include "lib/logc/log.h"
#include "halow_ack.h"
#include "halow.h"
#include "utils.h"
#include "statistics.h"
#include "configdb.h"
#include "chip/txw4002ack803/sysctrl.h"

#define ACK_CFG_PREFIX  CONFIGDB_ADD_MODULE("hack")
#define ACK_CFG(k)      ACK_CFG_PREFIX "." k
#define ACK_CFG_VER     2

#define ACK_MAX_PEERS   4u
#define ACK_FRAME_MAX   4000u
#define ACK_DEDUP_WIN   HALOW_ACK_ACK_FIDS_MAX
#define ACK_TICK_MS     10u

#define ACK_TX_VACANCY_LOW    8000u
#define ACK_SLOT_LIFE_MAX_MS  6000u
#define ACK_AGG_MAX_HOLD_MS   1000u

#define ACK_RETIRE_Q          2u
#define ACK_SLOTS_RETIRE_MS   2000u

#define ACK_PEND_N            2u
#define ACK_PEND_MAX_TRIES    1500u

#define ACK_L0_STRIKES        12u
#define ACK_BACKOFF_SHIFT_MAX 3u

#define RA_MAX_MCS    7u
#define RA_EWMA_W     8u
#define RA_GRACE_MS   2000u
#define RA_Q8(pct)    ((uint16_t)((uint32_t)(pct) * 256u / 100u))

#define DFLT_MCS_TTL_MS  5000u
#define RADIO_QUIET_MS   1000u
#define RADIO_BUSY_MS    10000u

enum halow_l1_compat {
    HALOW_COMPAT_PLAIN    = 0,
    HALOW_COMPAT_LEGACY   = 1,
    HALOW_COMPAT_ENVELOPE = 2,
};

typedef struct {
    uint8_t  in_use;
    uint8_t  retries_used;
    uint64_t tx_jiff;
    uint64_t born_jiff;
    uint16_t frame_len;
    uint16_t fid;
    uint16_t seq;
    uint8_t  dest_mac[6];
    uint8_t  frame[ACK_FRAME_MAX + 4u];
} ack_slot_t;

typedef struct {
    uint8_t  in_use;
    uint8_t  mac[6];
    uint8_t  cur_retries;
    uint8_t  tx_mcs;            /* HALOW_MCS_DEFAULT = global config MCS */
    int8_t   evm_ewma;
    int8_t   evm_ewma_slow;
    uint16_t loss_ewma_q8;      /* /256 == 0..1 */
    uint32_t tx;
    uint32_t acked;
    uint32_t dropped;
    uint32_t tx_bytes;
    uint32_t retransmitted;
    int32_t  last_tx_s;
    uint64_t last_ack_jiff;
    uint64_t cooldown_until;
    uint16_t acks_since_step;
    uint64_t next_step_allowed;
    uint64_t last_seen;
    uint32_t dedup[ACK_DEDUP_WIN];
    uint8_t  dedup_idx;
    uint16_t rx_since_ack;
    bool     ack_due;
    uint64_t ack_due_jiff;
    int8_t   last_rx_evm;
    uint16_t agg_len;
    uint8_t  agg_nsub;
    uint64_t agg_first_jiff;
    uint8_t  compat;
    uint16_t tx_seq;
    uint16_t rx_seq_last;
    uint64_t rx_seq_win;        /* bit i == seq (rx_seq_last - i) received */
    bool     rx_seq_seen;
    uint32_t l0_strikes;
    uint32_t samp_acked, samp_dropped;
    uint32_t pend_res, pend_fail;
    uint32_t loss_ev_n;
    uint16_t loss_iir_pct;
    uint8_t  ack_probe_cnt;
    uint32_t l0_falls;
    uint64_t created_jiff;
    uint8_t *agg_buf;           /* os_malloc'd on first coalesce */
} ack_peer_t;

static halow_ack_config_t g_ack_cfg;
static halow_ack_stats_t  g_ack_stats;
static struct os_mutex    g_ack_mutex;
static struct os_semaphore g_ack_slot_sem;
static uint32_t           g_ack_sem_debt;

static ack_slot_t *g_slots;
static uint32_t    g_slot_count;
static ack_peer_t  g_peers[ACK_MAX_PEERS];

static uint64_t g_last_data_tx_jiff;

static ack_slot_t *g_retire_q[ACK_RETIRE_Q];
static uint64_t    g_retire_jiff[ACK_RETIRE_Q];
static uint32_t    g_retire_n;

static uint8_t  g_pend_buf[ACK_PEND_N][ACK_FRAME_MAX];
static uint16_t g_pend_len[ACK_PEND_N];
static uint8_t  g_pend_mac[ACK_PEND_N][6];
static uint32_t g_pend_head, g_pend_count;
static uint16_t g_pend_tries[ACK_PEND_N];
static bool     g_pend_draining;

static uint8_t  g_dflt_mcs_cache = 0xFFu;
static uint64_t g_dflt_mcs_jiff;

static void ack_lock(void)   { (void)os_mutex_lock(&g_ack_mutex, -1); }
static void ack_unlock(void) { os_mutex_unlock(&g_ack_mutex); }

/* ================= frame classifiers ================= */

static uint32_t fnv1a( const uint8_t *p, uint16_t len ){
    uint32_t h = 2166136261u;
    while( len-- ){
        h ^= (uint32_t)(*p++);
        h *= 16777619u;
    }
    return h;
}

static bool is_ack_frame( const uint8_t *data, uint16_t len ){
    return (data != NULL &&
            len >= HALOW_ACK_ACK_LEN_MIN &&
            len <= HALOW_ACK_ACK_LEN_MAX &&
            (((uint32_t)len - 3u) & 1u) == 0u &&
            data[0] == HALOW_ACK_MAGIC0 &&
            data[1] == HALOW_ACK_MAGIC1 &&
            data[2] >= 0x80u);
}

static bool is_env_frame( const uint8_t *data, uint16_t len ){
    return (data != NULL &&
            len >= 3u &&
            data[0] == HALOW_ENV_MAGIC0 &&
            data[1] == HALOW_ENV_MAGIC1 &&
            data[2] < 0x80u);
}

bool halow_ack_is_internal_frame( const uint8_t *data, uint16_t len ){
    if( is_ack_frame(data, len) ) return true;
    return (is_env_frame(data, len) &&
            halow_env_type(data) == HALOW_ENV_TYPE_ACK);
}

void halow_ack_env_malformed( void ){
    g_ack_stats.rx_env_unk++;
}

/* ================= slot pool ================= */

static void token_return( void ){
    if( g_ack_sem_debt > 0u ){
        g_ack_sem_debt--;
    }else{
        os_sema_up(&g_ack_slot_sem);
    }
}

static ack_slot_t *slot_alloc( void ){
    for( uint32_t i = 0; i < g_slot_count; i++ )
        if( !g_slots[i].in_use ) return &g_slots[i];
    return NULL;
}

static ack_slot_t *slot_claim_locked( void ){
    if( os_sema_down(&g_ack_slot_sem, 0) != 0 ) return NULL;
    ack_slot_t *s = slot_alloc();
    if( s == NULL ){
        token_return();
        return NULL;
    }
    s->in_use    = 1;
    s->born_jiff = os_jiffies();
    s->seq       = 0xFFFFu;
    return s;
}

static void slot_free_locked( ack_slot_t *s ){
    s->in_use = 0;
    token_return();
}

static ack_slot_t *slot_match( const uint8_t mac[6], uint16_t fid ){
    for( uint32_t i = 0; i < g_slot_count; i++ )
        if( g_slots[i].in_use &&
            g_slots[i].fid == fid &&
            memcmp(g_slots[i].dest_mac, mac, 6) == 0 )
            return &g_slots[i];
    return NULL;
}

static ack_slot_t *slot_for_peer( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < g_slot_count; i++ )
        if( g_slots[i].in_use && memcmp(g_slots[i].dest_mac, mac, 6) == 0 )
            return &g_slots[i];
    return NULL;
}

static void slots_retire( ack_slot_t *old ){
    if( old == NULL ) return;
    if( g_retire_n == ACK_RETIRE_Q ){
        uint32_t victim = 0u;
        for( uint32_t i = 1u; i < ACK_RETIRE_Q; i++ ){
            if( (os_jiffies() - g_retire_jiff[i]) >
                (os_jiffies() - g_retire_jiff[victim]) ) victim = i;
        }
        os_free(g_retire_q[victim]);
        g_retire_q[victim]    = g_retire_q[g_retire_n - 1u];
        g_retire_jiff[victim] = g_retire_jiff[g_retire_n - 1u];
        g_retire_n--;
    }
    g_retire_q[g_retire_n]    = old;
    g_retire_jiff[g_retire_n] = os_jiffies();
    g_retire_n++;
}

static bool slots_resize_locked( uint8_t window ){
    if( window == 0u ) window = HALOW_ACK_DEFAULT_WINDOW;
    if( window > HALOW_ACK_SLOTS_MAX ) window = HALOW_ACK_SLOTS_MAX;
    if( window == g_slot_count && g_slots != NULL ) return true;

    ack_slot_t *nw = (ack_slot_t *)os_malloc((uint32_t)window * sizeof(ack_slot_t));
    if( nw == NULL ){
        log_warn("ack: slot malloc failed window=%u (keep %lu)",
                 (unsigned)window, (unsigned long)g_slot_count);
        return false;
    }
    memset(nw, 0, (uint32_t)window * sizeof(ack_slot_t));

    uint32_t dropped_inuse = 0u;
    for( uint32_t i = 0; i < g_slot_count; i++ )
        if( g_slots != NULL && g_slots[i].in_use ) dropped_inuse++;
    g_ack_stats.dropped += dropped_inuse;

    bool had_old  = ( g_slots != NULL );
    uint8_t old_count = (uint8_t)g_slot_count;
    if( had_old ) slots_retire(g_slots);
    g_slots      = nw;
    g_slot_count = window;

    if( !had_old ){
        os_sema_init(&g_ack_slot_sem, (int32)g_slot_count);
        return true;
    }
    while( dropped_inuse-- > 0u ) os_sema_up(&g_ack_slot_sem);
    int32 delta = (int32)window - (int32)old_count;
    while( delta > 0 ){ os_sema_up(&g_ack_slot_sem); delta--; }
    while( delta < 0 ){
        if( os_sema_down(&g_ack_slot_sem, 0) == 0 ){
            delta++;
        }else{
            g_ack_sem_debt++;
            delta++;
        }
    }
    return true;
}

/* ================= peers ================= */

static ack_peer_t *peer_find( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ )
        if( g_peers[i].in_use && memcmp(g_peers[i].mac, mac, 6) == 0 )
            return &g_peers[i];
    return NULL;
}

static uint8_t ra_ceiling( const ack_peer_t *p );

static uint8_t peer_init_mcs( const ack_peer_t *p ){
    uint8_t mcs;
    if( !g_ack_cfg.rate_adapt ) return HALOW_MCS_DEFAULT;
    mcs = ( p != NULL ) ? ra_ceiling(p) : 4u;
    if( mcs > RA_MAX_MCS ) mcs = RA_MAX_MCS;
    return mcs;
}

static bool peer_is_stale( const ack_peer_t *p ){
    return ( p->last_ack_jiff != 0u &&
             (os_jiffies() - p->last_ack_jiff) > os_msecs_to_jiffies(HALOW_ACK_RA_STALE_MS) );
}

static ack_peer_t *peer_evict_pick( void ){
    ack_peer_t *victim = NULL;
    uint64_t oldest = (uint64_t)-1;
    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        ack_peer_t *c = &g_peers[i];
        if( !c->in_use ){ victim = c; break; }
        if( slot_for_peer(c->mac) != NULL ) continue;
        if( c->agg_nsub > 0u ) continue;
        if( c->last_seen < oldest ){ oldest = c->last_seen; victim = c; }
    }
    return victim;
}

static ack_peer_t *peer_create( const uint8_t mac[6], uint8_t init_mcs ){
    ack_peer_t *p = peer_evict_pick();
    if( p == NULL ) return NULL;
    if( p->agg_buf != NULL ) os_free(p->agg_buf);
    memset(p, 0, sizeof(*p));
    p->in_use       = 1;
    memcpy(p->mac, mac, 6);
    p->cur_retries  = g_ack_cfg.max_retries;
    p->tx_mcs       = init_mcs;
    p->created_jiff = os_jiffies();
    p->compat       = HALOW_COMPAT_LEGACY;
    p->last_seen    = os_jiffies();
    return p;
}

static ack_peer_t *peer_get( const uint8_t mac[6] ){
    ack_peer_t *p = peer_find(mac);
    uint8_t init_mcs = peer_init_mcs(p);

    if( p != NULL ){
        if( g_ack_cfg.rate_adapt &&
            p->tx_mcs != HALOW_MCS_DEFAULT &&
            peer_is_stale(p) ){
            p->tx_mcs            = init_mcs;
            p->loss_ewma_q8      = 0;
            p->acks_since_step   = 0;
            p->next_step_allowed = 0;
            p->compat            = HALOW_COMPAT_LEGACY;
            p->rx_seq_seen       = false;
            p->rx_seq_win        = 0u;
            log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x re-heard after stale -> MCS %u",
                     p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
                     (unsigned)init_mcs);
        }
        p->last_seen = os_jiffies();
        return p;
    }
    return peer_create(mac, init_mcs);
}

static bool dedup_seen( ack_peer_t *p, uint32_t hash ){
    for( uint32_t i = 0; i < ACK_DEDUP_WIN; i++ )
        if( p->dedup[i] == hash ) return true;
    return false;
}

static void dedup_remember( ack_peer_t *p, uint32_t hash ){
    p->dedup[p->dedup_idx] = hash;
    p->dedup_idx = (uint8_t)((p->dedup_idx + 1u) % ACK_DEDUP_WIN);
}

static void peer_rx_seq( ack_peer_t *p, uint16_t seq ){
    if( !p->rx_seq_seen ){
        p->rx_seq_seen = true;
        p->rx_seq_last = seq;
        p->rx_seq_win  = 1u;
        return;
    }
    uint16_t fwd = (uint16_t)(seq - p->rx_seq_last);
    if( fwd == 0u ) return;
    if( fwd >= HALOW_ACK_SEQ_WINDOW ){
        p->rx_seq_last = seq;
        p->rx_seq_win  = 1u;
        return;
    }
    p->rx_seq_win = (p->rx_seq_win << fwd) | 1u;
    p->rx_seq_last = seq;
}

static void peer_note_dead_bundle( ack_peer_t *p ){
    p->l0_strikes++;
    if( p->compat != HALOW_COMPAT_LEGACY || p->l0_strikes < ACK_L0_STRIKES ) return;
    p->compat   = HALOW_COMPAT_PLAIN;
    p->l0_strikes = 0u;
    p->l0_falls++;
    log_warn("ack: peer %02x:%02x:%02x:%02x:%02x:%02x -> L0 (plain-only, dead bundles)",
             p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5]);
}

/* ================= default MCS cache ================= */

static void dflt_mcs_refresh( void ){
    uint64_t now = os_jiffies();
    if( g_dflt_mcs_cache != 0xFFu &&
        (now - g_dflt_mcs_jiff) < os_msecs_to_jiffies(DFLT_MCS_TTL_MS) ){
        return;
    }
    halow_config_t hcfg;
    halow_config_load(&hcfg);
    g_dflt_mcs_cache = hcfg.mcs;
    g_dflt_mcs_jiff  = now;
}

static uint8_t dflt_mcs( void ){
    return (g_dflt_mcs_cache != 0xFFu) ? g_dflt_mcs_cache : 7u;
}

/* ================= sizing ================= */

static uint16_t max_payload_mcs( uint8_t mcs ){
    switch( mcs ){
        case 0u:  return 700u;
        case 1u:  return 1450u;
        case 2u:  return 2200u;
        case 3u:  return 3000u;
        case 4u:  return 4500u;
        case 5u:  return 6050u;
        case 6u:  return 6800u;
        case 7u:  return 7600u;
        case 10u: return 500u;
        default:  return 700u;
    }
}

static uint16_t eff_agg_bytes( uint8_t pmcs ){
    uint16_t cap = g_ack_cfg.agg_bytes;
    uint8_t  eff_mcs = (pmcs == HALOW_MCS_DEFAULT) ? dflt_mcs() : pmcs;
    uint16_t mcs_cap = max_payload_mcs(eff_mcs);
    if( mcs_cap < cap ) cap = mcs_cap;
    return cap;
}

static uint32_t slot_life_ms( void ){
    uint32_t tmo  = g_ack_cfg.timeout_ms;
    uint32_t life = 150u;
    uint32_t first_cap = tmo * 4u;
    if( first_cap < (uint32_t)g_ack_stats.ack_rtt_ewma_ms * 2u ){
        first_cap = (uint32_t)g_ack_stats.ack_rtt_ewma_ms * 2u;
    }
    life += first_cap;
    for( uint32_t i = 0u; i < g_ack_cfg.max_retries; i++ ){
        life += tmo << ((i < 3u) ? i : 3u);
        if( life >= ACK_SLOT_LIFE_MAX_MS ) return ACK_SLOT_LIFE_MAX_MS;
    }
    return life;
}

/* ================= rate adaptation ================= */

static uint8_t ra_ceiling( const ack_peer_t *p ){
    int8_t e = p->evm_ewma_slow;
    if( e == 0 ) e = p->evm_ewma;
    if( e == 0 && p->last_rx_evm != 0 ) e = p->last_rx_evm;
    if( e == 0 ) return 4u;
    if( e >= -14 ) return 7u;
    if( e >= -17 ) return 6u;
    if( e >= -19 ) return 5u;
    if( e >= -21 ) return 4u;
    if( e >= -23 ) return 3u;
    if( e >= -26 ) return 2u;
    return 1u;
}

static uint8_t ra_floor( const ack_peer_t *p ){
    uint8_t c = ra_ceiling(p);
    return ( c >= 3u ) ? (uint8_t)(c - 2u) : 1u;
}

static void ra_log_mcs( const char *verb, ack_peer_t *p ){
    uint32_t pct_x100 = (uint32_t)p->loss_ewma_q8 * 100u * 100u / 256u;
    (void)pct_x100;
    log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x MCS %s -> %u (loss=%u.%02u%%)",
             p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
             verb, (unsigned)p->tx_mcs,
             (unsigned)(pct_x100 / 100u), (unsigned)(pct_x100 % 100u));
}

static void ra_on_ack( ack_peer_t *p ){
    p->last_ack_jiff = os_jiffies();
    p->loss_ewma_q8 = (uint16_t)(((uint32_t)p->loss_ewma_q8 * (RA_EWMA_W - 1u)) >> 3);
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;

    g_ack_stats.ra_ack_calls++;
    if( p->acks_since_step != 0xFFFFu ) p->acks_since_step++;

    uint8_t ceil_mcs = ra_ceiling(p);
    if( ceil_mcs > RA_MAX_MCS ) ceil_mcs = RA_MAX_MCS;
    bool ready = ( p->tx_mcs + 1u < ceil_mcs )
               ? ( p->loss_ewma_q8 <= RA_Q8(g_ack_cfg.ra_loss_down) )
               : ( p->loss_ewma_q8 <= RA_Q8(g_ack_cfg.ra_loss_up) );

    if( !ready ){
        g_ack_stats.ra_blocked_loss++;
    }else if( p->tx_mcs >= ceil_mcs ){
        g_ack_stats.ra_blocked_max++;
    }else if( os_jiffies() < p->next_step_allowed ){
        g_ack_stats.ra_blocked_gap++;
    }else{
        p->tx_mcs++;
        p->acks_since_step   = 0;
        p->next_step_allowed = os_jiffies() + os_msecs_to_jiffies(HALOW_ACK_RA_STEP_GAP_MS);
        g_ack_stats.ra_upshifts++;
        ra_log_mcs("up", p);
    }
}

static void ra_on_drop( ack_peer_t *p ){
    if( p->created_jiff != 0u &&
        (os_jiffies() - p->created_jiff) < os_msecs_to_jiffies(RA_GRACE_MS) ){
        return;
    }
    p->loss_ewma_q8 = (uint16_t)((((uint32_t)p->loss_ewma_q8 * (RA_EWMA_W - 1u)) >> 3)
                                 + (256u / RA_EWMA_W));
    p->acks_since_step = 0;
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;
    if( p->loss_ewma_q8 >= RA_Q8(g_ack_cfg.ra_loss_down) ){
        uint8_t floor_d = ra_floor(p);
        if( p->tx_mcs > floor_d ){
            p->tx_mcs--;
            p->next_step_allowed = os_jiffies() + os_msecs_to_jiffies(HALOW_ACK_RA_STEP_GAP_MS * 8u);
            g_ack_stats.ra_downshifts++;
            ra_log_mcs("down", p);
        }
    }
}

static void ra_check_stale( ack_peer_t *p ){
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;
    if( !peer_is_stale(p) ) return;

    uint8_t init_mcs = peer_init_mcs(p);
    p->tx_mcs            = init_mcs;
    p->loss_ewma_q8      = 0;
    p->acks_since_step   = 0;
    p->next_step_allowed = os_jiffies() + os_msecs_to_jiffies(HALOW_ACK_RA_COOLDOWN_MS);
    log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x MCS stale -> ceiling %u",
             p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
             (unsigned)init_mcs);
}

/* ================= config ================= */

void halow_ack_config_set_default( halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    cfg->max_retries   = HALOW_ACK_DEFAULT_MAX_RETRIES;
    cfg->timeout_ms    = HALOW_ACK_DEFAULT_TIMEOUT_MS;
    cfg->rate_adapt    = HALOW_ACK_DEFAULT_RATE_ADAPT;
    cfg->ra_loss_up    = HALOW_ACK_DEFAULT_RA_LOSS_UP;
    cfg->ra_loss_down  = HALOW_ACK_DEFAULT_RA_LOSS_DOWN;
    cfg->window        = HALOW_ACK_DEFAULT_WINDOW;
    cfg->ack_fids      = HALOW_ACK_DEFAULT_ACK_FIDS;
    cfg->agg           = 1u;
    cfg->agg_bytes     = ACK_FRAME_MAX;
    cfg->agg_hold_ms   = HALOW_ACK_AGG_HOLD_MS_DEF;
    cfg->ack_hold_ms   = HALOW_ACK_ACK_HOLD_MS_DEF;
    cfg->bc_repeat     = HALOW_ACK_BC_REPEAT_DEF;
    cfg->env           = 1u;
    cfg->data_gap_ms   = HALOW_ACK_DATA_GAP_MS_DEF;
}

static void config_clamp( halow_ack_config_t *cfg ){
    if( cfg->max_retries > 8u )    cfg->max_retries = 8u;
    if( cfg->timeout_ms < 5u )     cfg->timeout_ms = 5u;
    if( cfg->timeout_ms > 300u )   cfg->timeout_ms = 300u;
    if( cfg->ra_loss_up   > 100u ) cfg->ra_loss_up   = HALOW_ACK_DEFAULT_RA_LOSS_UP;
    if( cfg->ra_loss_down > 100u ) cfg->ra_loss_down = HALOW_ACK_DEFAULT_RA_LOSS_DOWN;
    if( cfg->ra_loss_up >= cfg->ra_loss_down ){
        cfg->ra_loss_up   = HALOW_ACK_DEFAULT_RA_LOSS_UP;
        cfg->ra_loss_down = HALOW_ACK_DEFAULT_RA_LOSS_DOWN;
    }
    if( cfg->max_retries == 0u )   cfg->rate_adapt = 0u;
    if( cfg->window == 0u ) cfg->window = HALOW_ACK_DEFAULT_WINDOW;
    if( cfg->window > HALOW_ACK_SLOTS_MAX ) cfg->window = HALOW_ACK_SLOTS_MAX;
    if( cfg->ack_fids == 0u ) cfg->ack_fids = 1u;
    if( cfg->ack_fids > HALOW_ACK_ACK_FIDS_MAX ) cfg->ack_fids = HALOW_ACK_ACK_FIDS_MAX;
    cfg->agg = cfg->agg ? 1u : 0u;
    cfg->agg_bytes = (uint16_t)ACK_FRAME_MAX;
    if( cfg->agg_hold_ms == 0u ) cfg->agg_hold_ms = 1u;
    if( cfg->agg_hold_ms > 100u ) cfg->agg_hold_ms = 100u;
    if( cfg->ack_hold_ms > 100u ) cfg->ack_hold_ms = 100u;
    if( cfg->timeout_ms > 2u && cfg->ack_hold_ms > (uint16_t)(cfg->timeout_ms / 2u) )
        cfg->ack_hold_ms = (uint16_t)(cfg->timeout_ms / 2u);
    if( cfg->bc_repeat < 1u )                      cfg->bc_repeat = 1u;
    if( cfg->bc_repeat > HALOW_ACK_BC_REPEAT_MAX ) cfg->bc_repeat = HALOW_ACK_BC_REPEAT_MAX;
    cfg->env = cfg->env ? 1u : 0u;
    if( cfg->data_gap_ms > 250u ) cfg->data_gap_ms = 250u;
}

void halow_ack_config_load( halow_ack_config_t *cfg ){
    int16_t ver = 0;

    if( cfg == NULL ) return;
    halow_ack_config_set_default(cfg);

    if( configdb_get_i16(ACK_CFG("ver"), &ver) != 0 ||
        ver != (int16_t)ACK_CFG_VER ){
        log_info("ack: cfg gen %d -> %d, re-seeding defaults", (int)ver, ACK_CFG_VER);
        mcu_watchdog_feed();
        halow_ack_config_save(cfg);
        mcu_watchdog_feed();
        ver = (int16_t)ACK_CFG_VER;
        configdb_set_i16(ACK_CFG("ver"), (const int16_t *)&ver);
        mcu_watchdog_feed();
        config_clamp(cfg);
        return;
    }

    configdb_get_i8 (ACK_CFG("retry"),    (int8_t *)&cfg->max_retries);
    configdb_get_i16(ACK_CFG("tmo"),      (int16_t *)&cfg->timeout_ms);
    configdb_get_i8 (ACK_CFG("ra"),       (int8_t *)&cfg->rate_adapt);
    configdb_get_i8 (ACK_CFG("rlup"),     (int8_t *)&cfg->ra_loss_up);
    configdb_get_i8 (ACK_CFG("rldn"),     (int8_t *)&cfg->ra_loss_down);
    configdb_get_i8 (ACK_CFG("window"),   (int8_t *)&cfg->window);
    configdb_get_i8 (ACK_CFG("fids"),     (int8_t *)&cfg->ack_fids);
    configdb_get_i8 (ACK_CFG("agg"),      (int8_t *)&cfg->agg);
    configdb_get_i16(ACK_CFG("aggbytes"), (int16_t *)&cfg->agg_bytes);
    configdb_get_i16(ACK_CFG("agghold"),  (int16_t *)&cfg->agg_hold_ms);
    configdb_get_i16(ACK_CFG("ackhold"),  (int16_t *)&cfg->ack_hold_ms);
    configdb_get_i8 (ACK_CFG("bcrep"),    (int8_t *)&cfg->bc_repeat);
    configdb_get_i8 (ACK_CFG("env"),      (int8_t *)&cfg->env);
    configdb_get_i16(ACK_CFG("gapms"),    (int16_t *)&cfg->data_gap_ms);
    config_clamp(cfg);
}

void halow_ack_config_save( const halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    configdb_set_i8 (ACK_CFG("retry"),    (int8_t *)&cfg->max_retries);
    configdb_set_i16(ACK_CFG("tmo"),      (int16_t *)&cfg->timeout_ms);
    configdb_set_i8 (ACK_CFG("ra"),       (int8_t *)&cfg->rate_adapt);
    configdb_set_i8 (ACK_CFG("rlup"),     (int8_t *)&cfg->ra_loss_up);
    configdb_set_i8 (ACK_CFG("rldn"),     (int8_t *)&cfg->ra_loss_down);
    configdb_set_i8 (ACK_CFG("window"),   (int8_t *)&cfg->window);
    configdb_set_i8 (ACK_CFG("fids"),     (int8_t *)&cfg->ack_fids);
    configdb_set_i8 (ACK_CFG("agg"),      (int8_t *)&cfg->agg);
    configdb_set_i16(ACK_CFG("aggbytes"), (int16_t *)&cfg->agg_bytes);
    configdb_set_i16(ACK_CFG("agghold"),  (int16_t *)&cfg->agg_hold_ms);
    configdb_set_i16(ACK_CFG("ackhold"),  (int16_t *)&cfg->ack_hold_ms);
    configdb_set_i8 (ACK_CFG("bcrep"),    (int8_t *)&cfg->bc_repeat);
    configdb_set_i8 (ACK_CFG("env"),      (int8_t *)&cfg->env);
    configdb_set_i16(ACK_CFG("gapms"),    (int16_t *)&cfg->data_gap_ms);
}

void halow_ack_config_get_live( halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    ack_lock();
    *cfg = g_ack_cfg;
    ack_unlock();
}

void halow_ack_config_apply( const halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    halow_ack_config_t c = *cfg;
    config_clamp(&c);

    dflt_mcs_refresh();

    ack_lock();
    g_ack_cfg = c;
    if( c.window != g_slot_count || g_slots == NULL ){
        (void)slots_resize_locked(c.window);
        if( g_slot_count != c.window ) g_ack_cfg.window = (uint8_t)g_slot_count;
    }
    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        ack_peer_t *p = &g_peers[i];
        if( !p->in_use ) continue;
        if( p->cur_retries > c.max_retries ) p->cur_retries = c.max_retries;
        if( !c.rate_adapt ){
            p->tx_mcs = HALOW_MCS_DEFAULT;
            p->loss_ewma_q8 = 0;
        }else if( p->tx_mcs == HALOW_MCS_DEFAULT ){
            p->tx_mcs = peer_init_mcs(p);
            p->loss_ewma_q8 = 0;
        }
        p->acks_since_step   = 0;
        p->next_step_allowed = 0;
    }
    ack_unlock();
    halow_ack_config_save(&g_ack_cfg);
    log_info("ack: apply retries=%u tmo=%ums ra=%u up=%u%% down=%u%% window=%lu fids=%u",
             (unsigned)g_ack_cfg.max_retries, (unsigned)g_ack_cfg.timeout_ms,
             (unsigned)g_ack_cfg.rate_adapt,
             (unsigned)g_ack_cfg.ra_loss_up, (unsigned)g_ack_cfg.ra_loss_down,
             (unsigned long)g_slot_count, (unsigned)g_ack_cfg.ack_fids);
}

/* ================= RTT accounting ================= */

static void rtt_record( uint32_t born_rtt, uint32_t lasttx_rtt, uint8_t retries_used ){
    if( g_ack_stats.ack_rtt_hits >= 1000000u ){
        g_ack_stats.ack_rtt_sum_ms /= 2u;
        g_ack_stats.ack_rtt_hits   /= 2u;
    }
    g_ack_stats.ack_rtt_hits++;
    if( born_rtt > 10000u ) born_rtt = 10000u;
    g_ack_stats.ack_rtt_sum_ms += born_rtt;
    if( retries_used != 0u ) return;
    if( lasttx_rtt > 1000u ) lasttx_rtt = 1000u;
    g_ack_stats.ack_rtt_ewma_ms = (g_ack_stats.ack_rtt_ewma_ms == 0u)
        ? lasttx_rtt
        : (g_ack_stats.ack_rtt_ewma_ms * 3u + lasttx_rtt) / 4u;
}

/* ================= ACK transmit ================= */

static void build_fids_locked( ack_peer_t *p, uint16_t fids[HALOW_ACK_ACK_FIDS_MAX] ){
    uint8_t want = g_ack_cfg.ack_fids;
    if( want > HALOW_ACK_ACK_FIDS_MAX ) want = HALOW_ACK_ACK_FIDS_MAX;
    for( uint32_t i = 0; i < want; i++ ){
        uint32_t idx = (p->dedup_idx + ACK_DEDUP_WIN - 1u - i) % ACK_DEDUP_WIN;
        uint16_t fid = (uint16_t)(p->dedup[idx] & 0xFFFFu);
        if( fid == 0u ) fid = 0xFFFFu;
        fids[i] = fid;
    }
}

static uint8_t ack_mcs_for_peer( const uint8_t dest_mac[6] ){
    uint8_t ack_mcs = HALOW_ACK_ACK_MCS_MAX;
    ack_lock();
    ack_peer_t *p = peer_find(dest_mac);
    if( p != NULL ){
        uint8_t c = ra_ceiling(p);
        if( c > HALOW_ACK_ACK_MCS_MAX ) c = HALOW_ACK_ACK_MCS_MAX;
        if( c < HALOW_ACK_ACK_MCS_MIN ) c = HALOW_ACK_ACK_MCS_MIN;
        ack_mcs = c;
    }
    ack_unlock();
    return ack_mcs;
}

static bool env_ack_capture_locked( ack_peer_t *p, uint16_t *base, uint64_t *bm ){
    bool probe = ( p->compat < HALOW_COMPAT_ENVELOPE ) && ( g_ack_cfg.env != 0u )
                 && ( ++p->ack_probe_cnt >= 8u );
    if( probe ) p->ack_probe_cnt = 0u;
    if( !( ( p->compat == HALOW_COMPAT_ENVELOPE ) || probe ) ) return false;
    if( g_ack_cfg.env == 0u ) return false;

    *base = (uint16_t)(p->rx_seq_last - (HALOW_ACK_SEQ_WINDOW - 1u));
    *bm   = 0u;
    for( uint32_t i = 0u; i < HALOW_ACK_SEQ_WINDOW; i++ ){
        if( (p->rx_seq_win >> (HALOW_ACK_SEQ_WINDOW - 1u - i)) & 1u ){
            *bm |= (uint64_t)1u << i;
        }
    }
    return true;
}

static void send_env_ack( int8_t evm, const uint8_t dest_mac[6],
                          uint16_t base, uint64_t bm, uint8_t ack_mcs ){
    uint8_t e[HALOW_ENV_ACK_LEN];
    e[0] = HALOW_ENV_MAGIC0;
    e[1] = HALOW_ENV_MAGIC1;
    e[2] = (uint8_t)((HALOW_ENV_VER << 4) | HALOW_ENV_TYPE_ACK);
    e[3] = (uint8_t)evm;
    e[4] = (uint8_t)(base & 0xFFu);
    e[5] = (uint8_t)(base >> 8);
    for( uint32_t b = 0u; b < 8u; b++ ){
        e[6u + b] = (uint8_t)((bm >> (8u * b)) & 0xFFu);
    }
    if( halow_tx_p(e, HALOW_ENV_ACK_LEN, dest_mac, ack_mcs, 7u) == 0 ){
        g_ack_stats.acks_sent++;
        g_ack_stats.env_tx_acks++;
    }else{
        g_ack_stats.acks_tx_fail++;
    }
}

static void send_fid_ack( int8_t evm, const uint8_t dest_mac[6],
                          const uint16_t fids[HALOW_ACK_ACK_FIDS_MAX], uint8_t ack_mcs ){
    uint8_t nfids = g_ack_cfg.ack_fids;
    if( nfids > HALOW_ACK_ACK_FIDS_MAX ) nfids = HALOW_ACK_ACK_FIDS_MAX;
    if( nfids == 0u ) nfids = 1u;

    uint8_t a[HALOW_ACK_ACK_LEN_MAX];
    a[0] = HALOW_ACK_MAGIC0;
    a[1] = HALOW_ACK_MAGIC1;
    a[2] = (uint8_t)evm;
    for( uint32_t i = 0; i < nfids; i++ ){
        a[3u + 2u*i]      = (uint8_t)(fids[i] & 0xFFu);
        a[3u + 2u*i + 1u] = (uint8_t)((fids[i] >> 8) & 0xFFu);
    }
    if( halow_tx_p(a, 3u + 2u*nfids, dest_mac, ack_mcs, 7u) == 0 ){
        g_ack_stats.acks_sent++;
    }else{
        g_ack_stats.acks_tx_fail++;
    }
}

static void send_ack( int8_t evm, const uint8_t dest_mac[6],
                      const uint16_t fids[HALOW_ACK_ACK_FIDS_MAX] ){
    uint8_t ack_mcs = ack_mcs_for_peer(dest_mac);
    g_ack_stats.ack_mcs_last = ack_mcs;

    uint16_t base = 0u;
    uint64_t bm = 0u;
    bool env = false;
    ack_lock();
    ack_peer_t *p = peer_find(dest_mac);
    if( p != NULL ) env = env_ack_capture_locked(p, &base, &bm);
    ack_unlock();

    if( env ) send_env_ack(evm, dest_mac, base, bm, ack_mcs);
    else      send_fid_ack(evm, dest_mac, fids, ack_mcs);
}

/* ================= bundle flush ================= */

static void agg_reset( ack_peer_t *p ){
    p->agg_len = 0u;
    p->agg_nsub = 0u;
    p->agg_first_jiff = 0u;
}

static void slot_prepare( ack_slot_t *s, const uint8_t *src, uint16_t flen ){
    s->frame_len = flen;
    s->fid = (uint16_t)(fnv1a(src, flen) & 0xFFFFu);
    if( s->fid == 0u ) s->fid = 0xFFFFu;
    memcpy(s->frame, src, flen);
}

static void peer_note_tx( ack_peer_t *p, uint32_t wire_bytes, uint16_t flen ){
    p->tx++;
    p->tx_bytes += wire_bytes;
    p->last_tx_s = (int32_t)time(NULL);
    statistics_radio_register_tx_package(flen);
}

static void slot_tx_release_locked( ack_slot_t *s, uint8_t pmcs ){
    ack_unlock();
    (void)halow_tx(s->frame, s->frame_len, s->dest_mac, pmcs);
    g_last_data_tx_jiff = os_jiffies();
    ack_lock();
}

static void flush_build_envelope( ack_peer_t *p, ack_slot_t *s, uint16_t blen ){
    uint16_t seq = p->tx_seq++;
    if( seq == 0xFFFFu ) seq = p->tx_seq++;
    s->seq = seq;
    s->frame[0] = HALOW_ENV_MAGIC0;
    s->frame[1] = HALOW_ENV_MAGIC1;
    s->frame[2] = (uint8_t)((HALOW_ENV_VER << 4) | HALOW_ENV_TYPE_BUNDLE);
    s->frame[3] = (uint8_t)(seq & 0xFFu);
    s->frame[4] = (uint8_t)(seq >> 8);
    s->frame[5] = p->agg_nsub;
    s->frame_len = (uint16_t)(HALOW_ENV_BUNDLE_HDR + (blen - 3u));
    memcpy(&s->frame[HALOW_ENV_BUNDLE_HDR], &p->agg_buf[3], (uint32_t)(blen - 3u));
    s->fid = (uint16_t)(fnv1a(s->frame, s->frame_len) & 0xFFFFu);
    if( s->fid == 0u ) s->fid = 0xFFFFu;
}

static bool agg_flush_locked( ack_peer_t *p ){
    if( p == NULL || p->agg_nsub == 0u ) return true;
    if( (os_jiffies() - g_last_data_tx_jiff) < os_msecs_to_jiffies(g_ack_cfg.data_gap_ms) ){
        return false;
    }
    if( halow_get_tx_vacancy() < ACK_TX_VACANCY_LOW ) return false;

    ack_slot_t *s = slot_claim_locked();
    if( s == NULL ) return false;

    uint16_t blen = p->agg_len;
    uint8_t  pmcs = p->tx_mcs;
    s->retries_used = 0u;
    s->tx_jiff      = os_jiffies();
    memcpy(s->dest_mac, p->mac, 6);

    if( p->compat == HALOW_COMPAT_ENVELOPE && g_ack_cfg.env != 0u ){
        flush_build_envelope(p, s, blen);
        peer_note_tx(p, blen, s->frame_len);
        agg_reset(p);
        slot_tx_release_locked(s, pmcs);
        g_ack_stats.env_tx_bundles++;
        return true;
    }

    if( p->agg_nsub == 1u ){
        uint16_t plen = (uint16_t)((uint16_t)p->agg_buf[3] | ((uint16_t)p->agg_buf[4] << 8));
        agg_reset(p);
        if( plen == 0u || (uint32_t)plen + 5u > blen ){
            slot_free_locked(s);
            g_ack_stats.dropped++;
            p->dropped++;
            return true;
        }
        slot_prepare(s, &p->agg_buf[5], plen);
        peer_note_tx(p, plen, plen);
        slot_tx_release_locked(s, pmcs);
        return true;
    }

    slot_prepare(s, p->agg_buf, blen);
    peer_note_tx(p, blen, blen);
    agg_reset(p);
    slot_tx_release_locked(s, pmcs);
    return true;
}

/* ================= data transmit ================= */

bool halow_ack_tx_ready( void ){
    if( g_ack_cfg.max_retries == 0u ) return true;
    if( halow_get_tx_vacancy() < ACK_TX_VACANCY_LOW ) return false;

    uint32_t free_slots = 0;
    ack_lock();
    for( uint32_t i = 0; i < g_slot_count; i++ ){
        if( !g_slots[i].in_use ) free_slots++;
    }
    ack_unlock();
    return free_slots >= 2u;
}

static int32_t tx_plain_untracked( const uint8_t *payload, uint16_t len,
                                   const uint8_t dest_mac[6], uint8_t mcs ){
    int32_t r = halow_tx(payload, len, dest_mac, mcs);
    if( r < 0 ) return HALOW_ACK_TX_THROTTLE;
    statistics_radio_register_tx_package(len);
    return r;
}

static int32_t tx_broadcast( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] ){
    uint8_t copies = (memcmp(dest_mac, mac_broadcast, 6) == 0 &&
                      g_ack_cfg.bc_repeat > 1u)
                   ? g_ack_cfg.bc_repeat : 1u;
    int32_t r = halow_tx(payload, len, dest_mac, HALOW_MCS_DEFAULT);
    bool first_ok = (r >= 0);
    if( first_ok ) statistics_radio_register_tx_package(len);
    for( uint8_t i = 1u; (i < copies) && (r >= 0); i++ ){
        if( halow_get_tx_vacancy() < ((uint32_t)len + 64u) ) break;
        r = halow_tx(payload, len, dest_mac, HALOW_MCS_DEFAULT);
        if( r >= 0 ){
            g_ack_stats.tx_frames++;
            g_ack_stats.bc_repeats++;
            statistics_radio_register_tx_package(len);
        }
    }
    return first_ok ? 0 : HALOW_ACK_TX_THROTTLE;
}

static bool bundle_full_for( ack_peer_t *p, uint16_t len, uint16_t eff_bytes ){
    return (uint32_t)p->agg_len + 2u + len > eff_bytes ||
           p->agg_nsub + 1u > HALOW_ACK_AGG_MAX_SUB;
}

static int32_t tx_bundle_locked( ack_peer_t *p, const uint8_t *payload,
                                 uint16_t len, const uint8_t dest_mac[6],
                                 uint8_t pmcs, uint16_t eff_bytes ){
    if( p->agg_nsub > 0u && bundle_full_for(p, len, eff_bytes) ){
        (void)agg_flush_locked(p);
    }
    if( p->agg_nsub > 0u && bundle_full_for(p, len, eff_bytes) ){
        ack_unlock();
        return HALOW_ACK_TX_THROTTLE;
    }

    if( p->agg_nsub == 0u ){
        if( p->agg_buf == NULL ){
            p->agg_buf = (uint8_t *)os_malloc(ACK_FRAME_MAX);
            if( p->agg_buf == NULL ){
                ack_unlock();
                return tx_plain_untracked(payload, len, dest_mac, pmcs);
            }
        }
        p->agg_buf[0] = HALOW_ACK_AGG_MAGIC0;
        p->agg_buf[1] = HALOW_ACK_AGG_MAGIC1;
        p->agg_buf[2] = 0u;
        p->agg_len = 3u;
        p->agg_first_jiff = os_jiffies();
    }

    uint16_t off = p->agg_len;
    p->agg_buf[off]     = (uint8_t)(len & 0xFFu);
    p->agg_buf[off + 1] = (uint8_t)((len >> 8) & 0xFFu);
    memcpy(&p->agg_buf[off + 2], payload, len);
    p->agg_len  = (uint16_t)(off + 2u + len);
    p->agg_nsub = (uint8_t)(p->agg_nsub + 1u);
    p->agg_buf[2] = p->agg_nsub;

    if( p->agg_nsub >= HALOW_ACK_AGG_MAX_SUB ||
        (uint32_t)p->agg_len + 6u > eff_bytes ){
        agg_flush_locked(p);
    }
    ack_unlock();
    return 0;
}

static int32_t tx_plain_locked( ack_peer_t *p, const uint8_t *payload,
                                uint16_t len, const uint8_t dest_mac[6], uint8_t pmcs ){
    if( halow_get_tx_vacancy() < ACK_TX_VACANCY_LOW ){
        ack_unlock();
        return HALOW_ACK_TX_THROTTLE;
    }
    ack_slot_t *s = slot_claim_locked();
    if( s == NULL ){
        ack_unlock();
        return HALOW_ACK_TX_THROTTLE;
    }
    s->retries_used = 0;
    s->tx_jiff      = os_jiffies();
    memcpy(s->dest_mac, dest_mac, 6);
    slot_prepare(s, payload, len);
    peer_note_tx(p, len, len);
    ack_unlock();

    int32_t pr = halow_tx(payload, len, dest_mac, pmcs);
    if( pr == 0 ) g_last_data_tx_jiff = os_jiffies();
    return pr;
}

static int32_t ack_tx_uc( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] );

static void pend_drain( void );

int32_t halow_ack_tx( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] ){
    if( payload == NULL || dest_mac == NULL ) return -1;

    pend_drain();

    int32_t r = ack_tx_uc(payload, len, dest_mac);
    if( r == HALOW_ACK_TX_THROTTLE ){
        ack_lock();
        if( g_pend_count < ACK_PEND_N && len <= ACK_FRAME_MAX ){
            uint32_t idx = (g_pend_head + g_pend_count) % ACK_PEND_N;
            memcpy(g_pend_buf[idx], payload, len);
            g_pend_len[idx] = len;
            memcpy(g_pend_mac[idx], dest_mac, 6);
            g_pend_tries[idx] = 0u;
            g_pend_count++;
            ack_unlock();
            return 0;
        }
        ack_unlock();
        return HALOW_ACK_TX_THROTTLE;
    }
    g_ack_stats.tx_frames++;
    return r;
}

static void pend_drain( void ){
    ack_lock();
    if( g_pend_draining || g_pend_count == 0u ){
        ack_unlock();
        return;
    }
    g_pend_draining = true;
    ack_unlock();

    while( g_pend_count > 0u ){
        uint32_t idx = g_pend_head % ACK_PEND_N;
        int32_t r = ack_tx_uc(g_pend_buf[idx], g_pend_len[idx], g_pend_mac[idx]);
        if( r == HALOW_ACK_TX_THROTTLE ){
            if( ++g_pend_tries[idx] >= ACK_PEND_MAX_TRIES ){
                log_warn("pend: frame to %02x:%02x:%02x:%02x:%02x:%02x undeliverable, dropping",
                         g_pend_mac[idx][0],g_pend_mac[idx][1],g_pend_mac[idx][2],
                         g_pend_mac[idx][3],g_pend_mac[idx][4],g_pend_mac[idx][5]);
                g_ack_stats.dropped++;
                g_ack_stats.drop_throttle++;
                ack_lock();
                g_pend_head = (g_pend_head + 1u) % ACK_PEND_N;
                g_pend_count--;
                ack_unlock();
                continue;
            }
            break;
        }
        ack_lock();
        g_pend_head = (g_pend_head + 1u) % ACK_PEND_N;
        g_pend_count--;
        ack_unlock();
    }

    ack_lock();
    g_pend_draining = false;
    ack_unlock();
}

static int32_t ack_tx_uc( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] ){
    bool noack = ( g_ack_cfg.max_retries == 0u ) ||
                 ( memcmp(dest_mac, mac_broadcast, 6) == 0 ) ||
                 ( (uint32_t)len > ACK_FRAME_MAX );
    if( noack ) return tx_broadcast(payload, len, dest_mac);

    ack_lock();
    ack_peer_t *p = peer_get(dest_mac);
    if( p == NULL ){
        ack_unlock();
        return tx_plain_untracked(payload, len, dest_mac, HALOW_MCS_DEFAULT);
    }
    uint8_t pmcs = p->tx_mcs;
    if( p->cur_retries == 0u ){
        ack_unlock();
        return tx_plain_untracked(payload, len, dest_mac, pmcs);
    }

    uint16_t eff_bytes = eff_agg_bytes(pmcs);
    if( g_ack_cfg.agg != 0u &&
        (uint32_t)len + 5u <= eff_bytes &&
        (uint32_t)len + 5u <= ACK_FRAME_MAX ){
        return tx_bundle_locked(p, payload, len, dest_mac, pmcs, eff_bytes);
    }
    return tx_plain_locked(p, payload, len, dest_mac, pmcs);
}

/* ================= receive ================= */

static int8_t ewma_i8( int8_t cur, int8_t sample, int16_t w ){
    return (int8_t)(((int16_t)cur * (w - 1) + (int16_t)sample) / w);
}

static void rx_env_ack_locked( ack_peer_t *p, const uint8_t *payload ){
    int8_t ack_evm = (int8_t)payload[3];
    g_ack_stats.last_evm = ack_evm;
    g_ack_stats.acks_rx_frames++;
    g_ack_stats.env_rx_acks++;
    p->cur_retries    = g_ack_cfg.max_retries;
    p->evm_ewma       = ewma_i8(p->evm_ewma, ack_evm, 8);
    p->evm_ewma_slow  = ewma_i8(p->evm_ewma_slow, ack_evm, 32);
    ra_on_ack(p);

    uint16_t base = (uint16_t)((uint16_t)payload[4] | ((uint16_t)payload[5] << 8));
    uint64_t bm = 0u;
    for( uint32_t b = 0u; b < 8u; b++ ){
        bm |= (uint64_t)payload[6u + b] << (8u * b);
    }
    for( uint32_t i = 0u; i < g_slot_count; i++ ){
        ack_slot_t *s = &g_slots[i];
        if( !s->in_use || memcmp(s->dest_mac, p->mac, 6) != 0 ) continue;
        if( s->seq == 0xFFFFu ) continue;
        uint16_t diff = (uint16_t)(s->seq - base);
        if( diff < HALOW_ACK_SEQ_WINDOW && ((bm >> diff) & 1u) ){
            rtt_record( (uint32_t)(os_jiffies() - s->born_jiff),
                        (uint32_t)(os_jiffies() - s->tx_jiff),
                        s->retries_used );
            slot_free_locked(s);
            g_ack_stats.acked++;
            p->acked++;
        }
    }
}

static bool rx_env( const uint8_t *payload, uint16_t len, const uint8_t src_mac[6] ){
    uint8_t ver  = halow_env_ver(payload);
    uint8_t type = halow_env_type(payload);
    bool is_ack    = ( ver == HALOW_ENV_VER ) && ( type == HALOW_ENV_TYPE_ACK )
                     && ( len == HALOW_ENV_ACK_LEN );
    bool is_bundle = ( ver == HALOW_ENV_VER ) && ( type == HALOW_ENV_TYPE_BUNDLE )
                     && ( len >= HALOW_ENV_BUNDLE_HDR + 2u );
    if( !is_ack && !is_bundle ){
        g_ack_stats.rx_env_unk++;
        return true;
    }

    ack_lock();
    ack_peer_t *p = peer_find(src_mac);
    if( p != NULL && p->compat < HALOW_COMPAT_ENVELOPE ){
        p->compat = HALOW_COMPAT_ENVELOPE;
        p->l0_strikes = 0u;
    }
    if( is_ack ){
        if( p != NULL ) rx_env_ack_locked(p, payload);
        ack_unlock();
        return true;
    }
    if( p != NULL ){
        uint16_t seq = (uint16_t)((uint16_t)payload[3] | ((uint16_t)payload[4] << 8));
        peer_rx_seq(p, seq);
        g_ack_stats.env_rx_bundles++;
    }
    ack_unlock();
    return false;
}

static void rx_ack( const uint8_t *payload, uint16_t len, const uint8_t src_mac[6] ){
    int8_t ack_evm = (int8_t)payload[2];
    g_ack_stats.last_evm = ack_evm;
    g_ack_stats.acks_rx_frames++;

    ack_lock();
    ack_peer_t *p = peer_find(src_mac);
    if( p != NULL ){
        p->cur_retries   = g_ack_cfg.max_retries;
        p->evm_ewma      = ewma_i8(p->evm_ewma, ack_evm, 8);
        p->evm_ewma_slow = ewma_i8(p->evm_ewma_slow, ack_evm, 32);
        ra_on_ack(p);
    }

    uint32_t nfids = (len - 3u) / 2u;
    if( nfids > HALOW_ACK_ACK_FIDS_MAX ) nfids = HALOW_ACK_ACK_FIDS_MAX;
    for( uint32_t k = 0; k < nfids; k++ ){
        uint16_t ack_fid = (uint16_t)((uint16_t)payload[3u + 2u*k]
                                      | ((uint16_t)payload[3u + 2u*k + 1] << 8));
        if( ack_fid == 0u ) continue;
        ack_slot_t *s = slot_match(src_mac, ack_fid);
        if( s != NULL ){
            if( p != NULL ) p->l0_strikes = 0u;
            rtt_record( (uint32_t)(os_jiffies() - s->born_jiff),
                        (uint32_t)(os_jiffies() - s->tx_jiff),
                        s->retries_used );
            slot_free_locked(s);
            g_ack_stats.acked++;
            if( p != NULL ) p->acked++;
        }else{
            g_ack_stats.acks_rx_dup++;
        }
    }
    ack_unlock();
}

static void rx_note_magic_seen( const uint8_t src_mac[6] ){
    ack_lock();
    ack_peer_t *p = peer_find(src_mac);
    if( p != NULL && p->compat == HALOW_COMPAT_PLAIN ){
        p->compat = HALOW_COMPAT_LEGACY;
        log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x L0 -> L1 (magic traffic seen)",
                 p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5]);
    }
    ack_unlock();
}

static bool ack_decide_locked( ack_peer_t *p, uint16_t fids[HALOW_ACK_ACK_FIDS_MAX] ){
    if( g_ack_cfg.ack_hold_ms == 0u ){
        p->rx_since_ack = 0;
        p->ack_due = false;
        build_fids_locked(p, fids);
        return true;
    }
    if( ++p->rx_since_ack >= (uint16_t)g_ack_cfg.ack_fids ){
        p->rx_since_ack = 0;
        p->ack_due = false;
        build_fids_locked(p, fids);
        return true;
    }
    if( !p->ack_due ){
        p->ack_due = true;
        p->ack_due_jiff = os_jiffies() + os_msecs_to_jiffies(g_ack_cfg.ack_hold_ms);
    }
    return false;
}

static bool rx_data( const uint8_t *payload, uint16_t len, const uint8_t src_mac[6],
                     const uint8_t dst_mac[6], int8_t evm,
                     const uint8_t **out_payload, uint16_t *out_len ){
    uint32_t hash = fnv1a(payload, len);
    uint16_t fids[HALOW_ACK_ACK_FIDS_MAX] = {0};
    bool to_me = ( dst_mac != NULL && memcmp(dst_mac, mac_broadcast, 6) != 0 );

    ack_lock();
    ack_peer_t *p = to_me ? peer_get(src_mac) : peer_find(src_mac);
    bool deliver = true;
    bool ack_now = false;
    if( p != NULL ){
        p->last_rx_evm = evm;
        if( to_me ){
            deliver = !dedup_seen(p, hash);
            if( deliver ) dedup_remember(p, hash);
            ack_now = ack_decide_locked(p, fids);
        }
    }else if( to_me ){
        g_ack_stats.noack_hits++;
    }
    ack_unlock();

    if( ack_now ) send_ack(evm, src_mac, fids);

    if( !deliver ) return false;
    *out_payload = payload;
    *out_len     = len;
    return true;
}

bool halow_ack_on_rx( const uint8_t *payload, uint16_t len, const uint8_t src_mac[6],
                      const uint8_t dst_mac[6], int8_t evm,
                      const uint8_t **out_payload, uint16_t *out_len ){
    if( payload == NULL || out_payload == NULL || out_len == NULL ){
        if( out_payload ) *out_payload = payload;
        if( out_len )     *out_len     = len;
        return true;
    }

    if( is_env_frame(payload, len) ){
        if( rx_env(payload, len, src_mac) ) return false;
    }else if( is_ack_frame(payload, len) ){
        rx_ack(payload, len, src_mac);
        return false;
    }else if( len >= 3u &&
              payload[0] == HALOW_ACK_AGG_MAGIC0 && payload[1] == HALOW_ACK_AGG_MAGIC1 ){
        rx_note_magic_seen(src_mac);
    }

    return rx_data(payload, len, src_mac, dst_mac, evm, out_payload, out_len);
}

/* ================= tick ================= */

static void tick_free_retired_slots( void ){
    if( g_retire_n == 0u ) return;
    ack_lock();
    for( uint32_t i = 0u; i < g_retire_n; ){
        if( (os_jiffies() - g_retire_jiff[i]) >= os_msecs_to_jiffies(ACK_SLOTS_RETIRE_MS) ){
            ack_slot_t *old = g_retire_q[i];
            g_retire_q[i]    = g_retire_q[g_retire_n - 1u];
            g_retire_jiff[i] = g_retire_jiff[g_retire_n - 1u];
            g_retire_n--;
            ack_unlock();
            os_free(old);
            ack_lock();
        }else{
            i++;
        }
    }
    ack_unlock();
}

static void tick_sample_peer_loss( void ){
    static uint64_t loss_samp_jiff;
    if( (os_jiffies() - loss_samp_jiff) < os_msecs_to_jiffies(1000u) ) return;
    loss_samp_jiff = os_jiffies();

    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        ack_peer_t *p = &g_peers[i];
        if( !p->in_use ) continue;
        uint32_t dack = p->acked - p->samp_acked;
        uint32_t ddrp = p->dropped - p->samp_dropped;
        p->samp_acked   = p->acked;
        p->samp_dropped = p->dropped;
        uint32_t n4 = p->loss_ev_n - (p->loss_ev_n >> 1);
        p->loss_ev_n = n4;
        p->pend_res  += dack + ddrp;
        p->pend_fail += ddrp;
        if( p->pend_res < 5u ) continue;
        uint32_t inst = p->pend_fail * 100u / p->pend_res;
        uint32_t Aw = (p->pend_res > 1000u) ? 1000u : p->pend_res;
        uint32_t den = Aw + n4 + 10u;
        p->loss_iir_pct = (uint16_t)(
            ( (uint32_t)p->loss_iir_pct * (den - Aw) + inst * Aw ) / den );
        p->loss_ev_n = n4 + Aw;
        p->pend_res  = 0u;
        p->pend_fail = 0u;
    }
}

static void slot_drop_deadline( ack_slot_t *s ){
    ack_peer_t *p = peer_find(s->dest_mac);
    slot_free_locked(s);
    g_ack_stats.dropped++;
    g_ack_stats.drop_deadline++;
    if( p != NULL ){
        p->dropped++;
        peer_note_dead_bundle(p);
        if( halow_get_tx_vacancy() >= ACK_TX_VACANCY_LOW ){
            ra_on_drop(p);
        }
    }
}

static uint64_t slot_backoff_jiffies( ack_slot_t *s, uint64_t timeout_j ){
    if( s->retries_used > 0u ){
        uint32_t shift = s->retries_used;
        if( shift > ACK_BACKOFF_SHIFT_MAX ) shift = ACK_BACKOFF_SHIFT_MAX;
        return timeout_j << shift;
    }
    if( g_ack_stats.ack_rtt_ewma_ms == 0u ){
        return timeout_j;
    }
    uint32_t floor_ms = g_ack_stats.ack_rtt_ewma_ms
                      + (g_ack_stats.ack_rtt_ewma_ms >> 2) + 10u;
    uint32_t cap_ms  = g_ack_cfg.timeout_ms * 4u;
    if( cap_ms < (uint32_t)g_ack_stats.ack_rtt_ewma_ms * 2u ){
        cap_ms = (uint32_t)g_ack_stats.ack_rtt_ewma_ms * 2u;
    }
    if( floor_ms > cap_ms ) floor_ms = cap_ms;
    if( floor_ms <= g_ack_cfg.timeout_ms ){
        return timeout_j;
    }
    uint64_t j = os_msecs_to_jiffies(floor_ms);
    return (j > timeout_j) ? j : timeout_j;
}

static void slot_retransmit_or_drop( ack_slot_t *s, uint64_t now ){
    ack_peer_t *p = peer_find(s->dest_mac);
    if( p == NULL ){
        slot_free_locked(s);
        return;
    }
    if( s->retries_used >= g_ack_cfg.max_retries ){
        slot_free_locked(s);
        g_ack_stats.dropped++;
        g_ack_stats.drop_exhaust++;
        p->dropped++;
        peer_note_dead_bundle(p);
        ra_on_drop(p);
        return;
    }

    static uint8_t retx_buf[ACK_FRAME_MAX];   /* 4 KB must not sit on the tick stack */
    s->retries_used++;
    s->tx_jiff = now;
    g_ack_stats.retransmitted++;
    p->retransmitted++;
    uint16_t retx_len = s->frame_len;
    uint8_t  retx_mac[6];
    uint8_t  pmcs = p->tx_mcs;
    memcpy(retx_buf, s->frame, retx_len);
    memcpy(retx_mac, s->dest_mac, 6);
    ack_unlock();
    (void)halow_tx(retx_buf, retx_len, retx_mac, pmcs);
    ack_lock();
}

static void tick_service_slots( uint64_t now ){
    uint64_t timeout_j = os_msecs_to_jiffies(g_ack_cfg.timeout_ms);
    if( timeout_j == 0u ) timeout_j = 1u;

    for( uint32_t i = 0; i < g_slot_count; i++ ){
        ack_slot_t *s = &g_slots[i];
        if( !s->in_use ) continue;
        if( (now - s->born_jiff) >= os_msecs_to_jiffies(slot_life_ms()) ){
            slot_drop_deadline(s);
            continue;
        }
        if( (now - s->tx_jiff) < slot_backoff_jiffies(s, timeout_j) ) continue;
        if( halow_get_tx_vacancy() < ACK_TX_VACANCY_LOW ) continue;
        slot_retransmit_or_drop(s, now);
    }
}

static void tick_flush_held_bundles( uint64_t now ){
    if( g_ack_cfg.agg == 0u ) return;

    uint64_t hold_j = os_msecs_to_jiffies(g_ack_cfg.agg_hold_ms);
    if( hold_j == 0u ) hold_j = 1u;
    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        ack_peer_t *p = &g_peers[i];
        if( !p->in_use || p->agg_nsub == 0u ) continue;
        if( (now - p->agg_first_jiff) < hold_j ) continue;
        if( agg_flush_locked(p) ) continue;
        if( (now - p->agg_first_jiff) >= os_msecs_to_jiffies(ACK_AGG_MAX_HOLD_MS) ){
            g_ack_stats.dropped += p->agg_nsub;
            p->dropped         += p->agg_nsub;
            p->agg_nsub = 0u;
            p->agg_len  = 0u;
        }
    }
}

static void tick_flush_deferred_acks( uint64_t now ){
    if( g_ack_cfg.ack_hold_ms == 0u ) return;

    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        ack_peer_t *p = &g_peers[i];
        if( !p->in_use || !p->ack_due ) continue;
        if( (int64_t)(now - p->ack_due_jiff) < 0 ) continue;
        uint16_t fids[HALOW_ACK_ACK_FIDS_MAX] = {0};
        int8_t aevm = p->last_rx_evm;
        uint8_t mac[6];
        build_fids_locked(p, fids);
        memcpy(mac, p->mac, 6);
        p->ack_due = false;
        p->rx_since_ack = 0;
        ack_unlock();
        send_ack(aevm, mac, fids);
        ack_lock();
    }
}

void halow_ack_tick( void ){
    halow_tx_vacancy_watchdog();
    tick_free_retired_slots();
    pend_drain();

    ack_lock();
    tick_sample_peer_loss();
    ack_unlock();

    if( g_ack_cfg.max_retries == 0u ) return;
    uint64_t now = os_jiffies();

    dflt_mcs_refresh();
    ack_lock();
    tick_service_slots(now);
    tick_flush_held_bundles(now);
    tick_flush_deferred_acks(now);
    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        if( g_peers[i].in_use ) ra_check_stale(&g_peers[i]);
    }
    ack_unlock();
}

static struct os_task g_ack_tick_task;
volatile uint32_t g_ack_tick_count = 0u;

static void ack_tick_task_fn( void *arg ){
    (void)arg;
    for( ;; ){
        halow_ack_tick();
        g_ack_tick_count++;
        mcu_watchdog_feed();
        os_sleep_ms(ACK_TICK_MS);
    }
}

/* ================= init & stats ================= */

bool halow_ack_radio_quiet( void ){
    if( g_slots != NULL ){
        for( uint32_t i = 0u; i < g_slot_count; i++ ){
            if( g_slots[i].in_use ) return false;
        }
    }
    return (os_jiffies() - g_last_data_tx_jiff) >= os_msecs_to_jiffies(RADIO_QUIET_MS);
}

bool halow_ack_link_busy( void ){
    if( g_slots != NULL ){
        for( uint32_t i = 0u; i < g_slot_count; i++ ){
            if( g_slots[i].in_use ) return true;
        }
    }
    return (os_jiffies() - g_last_data_tx_jiff) < os_msecs_to_jiffies(RADIO_BUSY_MS);
}

void halow_ack_init( void ){
    dflt_mcs_refresh();
    halow_ack_config_load(&g_ack_cfg);
    memset(g_peers, 0, sizeof(g_peers));
    memset(&g_ack_stats, 0, sizeof(g_ack_stats));
    g_slots = NULL;
    g_slot_count = 0;

    (void)os_mutex_init(&g_ack_mutex);
    os_mutex_unlock(&g_ack_mutex);

    ack_lock();
    (void)slots_resize_locked(g_ack_cfg.window);
    ack_unlock();

    os_task_init((const uint8 *)"acktk", &g_ack_tick_task, ack_tick_task_fn, 0);
    os_task_set_stacksize(&g_ack_tick_task, 4048);
    os_task_set_priority(&g_ack_tick_task, OS_TASK_PRIORITY_REALTIME);
    os_task_run(&g_ack_tick_task);

    log_info("ack: init retries=%u tmo=%ums window=%lu fids=%u",
             (unsigned)g_ack_cfg.max_retries, (unsigned)g_ack_cfg.timeout_ms,
             (unsigned long)g_slot_count, (unsigned)g_ack_cfg.ack_fids);
}

void halow_ack_stats_get( halow_ack_stats_t *out ){
    if( out == NULL ) return;
    ack_lock();
    *out = g_ack_stats;
    uint32_t n = 0, peers = 0;
    for( uint32_t i = 0; i < g_slot_count; i++ )    if( g_slots[i].in_use ) n++;
    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ )   if( g_peers[i].in_use ) peers++;
    out->outstanding = (uint8_t)n;
    out->peers       = (uint8_t)peers;
    ack_unlock();
}

bool halow_ack_peer_stats_by_mac( const uint8_t mac[6], halow_ack_peer_stats_t *out ){
    if( out == NULL ) return false;
    memset(out, 0, sizeof(*out));
    out->tx_mcs = HALOW_MCS_DEFAULT;
    if( mac == NULL ) return false;

    ack_lock();
    ack_peer_t *p = peer_find(mac);
    bool found = (p != NULL);
    if( p != NULL ){
        out->tx_mcs         = p->tx_mcs;
        out->cur_retries    = p->cur_retries;
        out->tx_frames      = p->tx;
        out->acked          = p->acked;
        out->dropped        = p->dropped;
        out->evm            = p->evm_ewma;
        out->tx_bytes       = p->tx_bytes;
        out->retransmitted  = p->retransmitted;
        out->last_tx_s      = p->last_tx_s;
        out->loss_pct       = (uint8_t)p->loss_iir_pct;
        out->acks_since_step = p->acks_since_step;
        out->loss_q8        = p->loss_ewma_q8;
        out->compat         = p->compat;
        out->l0_falls       = p->l0_falls;
        int64_t rem = (int64_t)p->next_step_allowed - (int64_t)os_jiffies();
        out->gap_ms = (rem <= 0) ? 0 : (int32_t)os_jiffies_to_msecs((uint64_t)rem);
    }
    ack_unlock();
    return found;
}
