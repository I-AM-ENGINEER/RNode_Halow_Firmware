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
#define ACK_CFG_VER     4

#define ACK_BUF_N       16u
/* One ACK-tracked wire frame: payload sum <= HALOW_ACK_AGG_PAYLOAD_MAX
 * (2x2000 or 8x500 RNS packets); wire adds env hdr 6 + per-sub len 2*8. */
#define ACK_WIRE_MAX    (HALOW_ACK_AGG_PAYLOAD_MAX + 6u + 2u*HALOW_ACK_AGG_MAX_SUB)
#define ACK_MAX_PEERS   16u
#define ACK_DEDUP_WIN   HALOW_ACK_ACK_FIDS_MAX
#define ACK_TICK_MS     10u

#define ACK_AGG_RESERVE 6u
#define ACK_TX_VACANCY_LOW    8000u
#define ACK_SLOT_LIFE_MAX_MS  6000u
#define ACK_AGG_MAX_HOLD_MS   1000u

#define ACK_L0_STRIKES        12u
#define ACK_BACKOFF_SHIFT_MAX 3u

#define RA_MAX_MCS    7u
#define RA_EWMA_W     8u
#define RA_GRACE_MS   2000u

/* ck803: no 64-bit ALU and no cheap divide -- module time is 32-bit jiffies,
 * thresholds are precomputed once per config change. */
typedef uint32_t jiffy_t;

static jiffy_t now_j( void ){
    return (jiffy_t)os_jiffies();
}

static jiffy_t ms_j( uint32_t ms ){
    return (jiffy_t)os_msecs_to_jiffies(ms);
}

enum halow_l1_compat {
    HALOW_COMPAT_PLAIN    = 0,
    HALOW_COMPAT_LEGACY   = 1,
    HALOW_COMPAT_ENVELOPE = 2,
};

enum ack_buf_state {
    ACK_BUF_STAGING  = 2,
    ACK_BUF_INFLIGHT = 3,
    ACK_BUF_SENDING  = 4,
};

/* One heap node per frame, sized to the peer's rate: a far MCS0 peer burns
 * ~730 B, a near MCS7 peer ~4 KB. The 16-slot pointer table below is the
 * only static buffer storage left. */
typedef struct {
    uint8_t  state;
    uint8_t  retries_used;
    uint8_t  ofs;
    uint8_t  idx;
    uint16_t len;
    uint16_t cap;
    uint16_t fid;
    uint16_t seq;
    uint8_t  dest_mac[6];
    jiffy_t  born_jiff;
    jiffy_t  tx_jiff;
    uint8_t  data[];
} ack_buf_t;

typedef struct {
    uint8_t  in_use;
    uint8_t  mac[6];
    uint8_t  cur_retries;
    uint8_t  tx_mcs;
    int8_t   evm_ewma;
    int8_t   evm_ewma_slow;
    uint16_t loss_q8;
    uint32_t tx;
    uint32_t acked;
    uint32_t dropped;
    uint32_t tx_bytes;
    uint32_t retransmitted;
    int32_t  last_tx_s;
    jiffy_t  last_ack_jiff;
    uint16_t acks_since_step;
    jiffy_t  next_step_allowed;
    jiffy_t  last_seen;
    uint32_t dedup[ACK_DEDUP_WIN];
    uint8_t  dedup_idx;
    uint16_t rx_since_ack;
    bool     ack_due;
    jiffy_t  ack_due_jiff;
    int8_t   last_rx_evm;
    uint8_t  agg_idx;
    uint16_t agg_len;
    uint8_t  agg_nsub;
    jiffy_t  agg_first_jiff;
    uint8_t  compat;
    uint16_t tx_seq;
    uint16_t rx_seq_last;
    uint64_t rx_seq_win;
    bool     rx_seq_seen;
    uint32_t l0_strikes;
    uint8_t  ack_probe_cnt;
    uint32_t l0_falls;
    jiffy_t  created_jiff;
} ack_peer_t;

static halow_ack_config_t g_ack_cfg;
static halow_ack_stats_t  g_ack_stats;
static struct os_mutex    g_ack_mutex;

static ack_buf_t   *g_bufs[ACK_BUF_N];
static uint8_t     g_window;
static ack_peer_t  g_peers[ACK_MAX_PEERS];

static uint8_t  g_used_n;
static uint8_t  g_inflight_n;
static uint8_t  g_peers_n;
static uint32_t g_heap_bytes;

static jiffy_t g_last_data_tx_jiff;

static jiffy_t g_ack_hold_j;
static jiffy_t g_stale_j;
static jiffy_t g_quiet_j;
static jiffy_t g_busy_j;
static jiffy_t g_step_gap_j;
static jiffy_t g_step_gap8_j;
static jiffy_t g_dflt_ttl_j;
static uint16_t g_ra_up_q8;
static uint16_t g_ra_down_q8;

static uint8_t  g_dflt_mcs_cache = 0xFFu;
static jiffy_t  g_dflt_mcs_jiff;

static void ack_lock(void)   { (void)os_mutex_lock(&g_ack_mutex, -1); }
static void ack_unlock(void) { os_mutex_unlock(&g_ack_mutex); }

static bool mac_eq( const uint8_t *a, const uint8_t *b ){
    return ( (a[0]^b[0]) | (a[1]^b[1]) | (a[2]^b[2]) |
             (a[3]^b[3]) | (a[4]^b[4]) | (a[5]^b[5]) ) == 0u;
}

static bool is_broadcast( const uint8_t *m ){
    return (m[0] & m[1] & m[2] & m[3] & m[4] & m[5]) == 0xFFu;
}

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

/* ================= frame buffers (heap, exact size per frame) ================= */

static uint32_t buf_alloc_sz( uint16_t cap ){
    return (uint32_t)sizeof(ack_buf_t) + (uint32_t)cap;
}

static ack_buf_t *buf_alloc( uint8_t state, const uint8_t mac[6], uint16_t cap ){
    for( uint32_t i = 0; i < ACK_BUF_N; i++ ){
        if( g_bufs[i] != NULL ) continue;
        ack_buf_t *b = os_malloc(buf_alloc_sz(cap));
        if( b == NULL ){
            g_ack_stats.heap_fail++;
            return NULL;
        }
        b->state        = state;
        b->retries_used = 0;
        b->ofs          = 0;
        b->idx          = (uint8_t)i;
        b->len          = 0;
        b->cap          = cap;
        b->seq          = 0xFFFFu;
        b->born_jiff    = now_j();
        memcpy(b->dest_mac, mac, 6);
        g_bufs[i]    = b;
        g_used_n++;
        g_heap_bytes += buf_alloc_sz(cap);
        if( state == ACK_BUF_INFLIGHT ) g_inflight_n++;
        return b;
    }
    return NULL;
}

static void buf_release( ack_buf_t *b ){
    if( b->state >= ACK_BUF_INFLIGHT ) g_inflight_n--;
    g_heap_bytes -= buf_alloc_sz(b->cap);
    g_bufs[b->idx] = NULL;
    os_free(b);
    g_used_n--;
}

static ack_buf_t *buf_claim_inflight( const uint8_t mac[6], uint16_t wire_len ){
    if( g_inflight_n >= g_window ) return NULL;
    return buf_alloc(ACK_BUF_INFLIGHT, mac, wire_len);
}

static ack_buf_t *buf_match( const uint8_t mac[6], uint16_t fid ){
    for( uint32_t i = 0; i < ACK_BUF_N; i++ ){
        ack_buf_t *b = g_bufs[i];
        if( b != NULL &&
            b->state == ACK_BUF_INFLIGHT &&
            b->fid == fid &&
            mac_eq(b->dest_mac, mac) )
            return b;
    }
    return NULL;
}

static ack_buf_t *buf_for_peer( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < ACK_BUF_N; i++ ){
        ack_buf_t *b = g_bufs[i];
        if( b != NULL && mac_eq(b->dest_mac, mac) )
            return b;
    }
    return NULL;
}

static void buf_tx_send( ack_buf_t *b, uint8_t pmcs ){
    if( b->state == ACK_BUF_STAGING ) g_inflight_n++;
    b->state = ACK_BUF_SENDING;
    ack_unlock();
    (void)halow_tx(&b->data[b->ofs], b->len, b->dest_mac, pmcs);
    g_last_data_tx_jiff = now_j();
    ack_lock();
    if( b->state == ACK_BUF_SENDING ) b->state = ACK_BUF_INFLIGHT;
}

/* ================= peers ================= */

static ack_peer_t *peer_find( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ )
        if( g_peers[i].in_use && mac_eq(g_peers[i].mac, mac) )
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
             (jiffy_t)(now_j() - p->last_ack_jiff) > g_stale_j );
}

static ack_peer_t *peer_evict_pick( void ){
    ack_peer_t *victim = NULL;
    jiffy_t oldest = (jiffy_t)-1;
    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        ack_peer_t *c = &g_peers[i];
        if( !c->in_use ){ victim = c; break; }
        if( buf_for_peer(c->mac) != NULL ) continue;
        if( c->last_seen < oldest ){ oldest = c->last_seen; victim = c; }
    }
    return victim;
}

static ack_peer_t *peer_create( const uint8_t mac[6], uint8_t init_mcs ){
    ack_peer_t *p = peer_evict_pick();
    if( p == NULL ) return NULL;
    if( !p->in_use ) g_peers_n++;
    memset(p, 0, sizeof(*p));
    p->in_use       = 1;
    memcpy(p->mac, mac, 6);
    p->cur_retries  = g_ack_cfg.max_retries;
    p->tx_mcs       = init_mcs;
    p->created_jiff = now_j();
    p->compat       = HALOW_COMPAT_LEGACY;
    p->last_seen    = now_j();
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
            p->loss_q8           = 0;
            p->acks_since_step   = 0;
            p->next_step_allowed = 0;
            p->compat            = HALOW_COMPAT_LEGACY;
            p->rx_seq_seen       = false;
            p->rx_seq_win        = 0u;
            log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x re-heard after stale -> MCS %u",
                     p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
                     (unsigned)init_mcs);
        }
        p->last_seen = now_j();
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
    jiffy_t now = now_j();
    if( g_dflt_mcs_cache != 0xFFu &&
        (jiffy_t)(now - g_dflt_mcs_jiff) < g_dflt_ttl_j ){
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
    uint32_t pct_x100 = (uint32_t)p->loss_q8 * 100u * 100u / 256u;
    (void)pct_x100;
    log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x MCS %s -> %u (loss=%u.%02u%%)",
             p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
             verb, (unsigned)p->tx_mcs,
             (unsigned)(pct_x100 / 100u), (unsigned)(pct_x100 % 100u));
}

static void ra_on_ack( ack_peer_t *p ){
    p->last_ack_jiff = now_j();
    p->loss_q8 = (uint16_t)(((uint32_t)p->loss_q8 * (RA_EWMA_W - 1u)) >> 3);
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;

    g_ack_stats.ra_ack_calls++;
    if( p->acks_since_step != 0xFFFFu ) p->acks_since_step++;

    uint8_t ceil_mcs = ra_ceiling(p);
    if( ceil_mcs > RA_MAX_MCS ) ceil_mcs = RA_MAX_MCS;
    bool ready = ( p->tx_mcs + 1u < ceil_mcs )
               ? ( p->loss_q8 <= g_ra_down_q8 )
               : ( p->loss_q8 <= g_ra_up_q8 );

    if( !ready ){
        g_ack_stats.ra_blocked_loss++;
    }else if( p->tx_mcs >= ceil_mcs ){
        g_ack_stats.ra_blocked_max++;
    }else if( now_j() < p->next_step_allowed ){
        g_ack_stats.ra_blocked_gap++;
    }else{
        p->tx_mcs++;
        p->acks_since_step   = 0;
        p->next_step_allowed = now_j() + g_step_gap_j;
        g_ack_stats.ra_upshifts++;
        ra_log_mcs("up", p);
    }
}

static void ra_on_drop( ack_peer_t *p ){
    if( p->created_jiff != 0u &&
        (jiffy_t)(now_j() - p->created_jiff) < ms_j(RA_GRACE_MS) ){
        return;
    }
    p->loss_q8 = (uint16_t)((((uint32_t)p->loss_q8 * (RA_EWMA_W - 1u)) >> 3)
                            + (256u / RA_EWMA_W));
    p->acks_since_step = 0;
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;
    if( p->loss_q8 >= g_ra_down_q8 ){
        uint8_t floor_d = ra_floor(p);
        if( p->tx_mcs > floor_d ){
            p->tx_mcs--;
            p->next_step_allowed = now_j() + g_step_gap8_j;
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
    p->loss_q8           = 0;
    p->acks_since_step   = 0;
    p->next_step_allowed = now_j() + ms_j(HALOW_ACK_RA_COOLDOWN_MS);
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
    cfg->agg_bytes     = HALOW_ACK_AGG_PAYLOAD_MAX;
    cfg->ack_hold_ms   = HALOW_ACK_ACK_HOLD_MS_DEF;
    cfg->bc_repeat     = HALOW_ACK_BC_REPEAT_DEF;
    cfg->env           = 1u;
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
    if( cfg->agg_bytes == 0u || cfg->agg_bytes > HALOW_ACK_AGG_PAYLOAD_MAX )
        cfg->agg_bytes = HALOW_ACK_AGG_PAYLOAD_MAX;
    if( cfg->ack_hold_ms > 100u ) cfg->ack_hold_ms = 100u;
    if( cfg->timeout_ms > 2u && cfg->ack_hold_ms > (uint16_t)(cfg->timeout_ms / 2u) )
        cfg->ack_hold_ms = (uint16_t)(cfg->timeout_ms / 2u);
    if( cfg->bc_repeat < 1u )                      cfg->bc_repeat = 1u;
    if( cfg->bc_repeat > HALOW_ACK_BC_REPEAT_MAX ) cfg->bc_repeat = HALOW_ACK_BC_REPEAT_MAX;
    cfg->env = cfg->env ? 1u : 0u;
}

static void config_cache( void ){
    g_ack_hold_j  = ms_j(g_ack_cfg.ack_hold_ms);
    g_stale_j     = ms_j(HALOW_ACK_RA_STALE_MS);
    g_quiet_j     = ms_j(1000u);
    g_busy_j      = ms_j(10000u);
    g_step_gap_j  = ms_j(HALOW_ACK_RA_STEP_GAP_MS);
    g_step_gap8_j = ms_j(HALOW_ACK_RA_STEP_GAP_MS * 8u);
    g_dflt_ttl_j  = ms_j(5000u);
    g_ra_up_q8    = (uint16_t)((uint32_t)g_ack_cfg.ra_loss_up * 256u / 100u);
    g_ra_down_q8  = (uint16_t)((uint32_t)g_ack_cfg.ra_loss_down * 256u / 100u);
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
    configdb_get_i8 (ACK_CFG("ackhold"),  (int8_t *)&cfg->ack_hold_ms);
    configdb_get_i8 (ACK_CFG("bcrep"),    (int8_t *)&cfg->bc_repeat);
    configdb_get_i8 (ACK_CFG("env"),      (int8_t *)&cfg->env);
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
    configdb_set_i8 (ACK_CFG("ackhold"),  (int8_t *)&cfg->ack_hold_ms);
    configdb_set_i8 (ACK_CFG("bcrep"),    (int8_t *)&cfg->bc_repeat);
    configdb_set_i8 (ACK_CFG("env"),      (int8_t *)&cfg->env);
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
    g_window  = c.window;
    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        ack_peer_t *p = &g_peers[i];
        if( !p->in_use ) continue;
        if( p->cur_retries > c.max_retries ) p->cur_retries = c.max_retries;
        if( !c.rate_adapt ){
            p->tx_mcs = HALOW_MCS_DEFAULT;
            p->loss_q8 = 0;
        }else if( p->tx_mcs == HALOW_MCS_DEFAULT ){
            p->tx_mcs = peer_init_mcs(p);
            p->loss_q8 = 0;
        }
        p->acks_since_step   = 0;
        p->next_step_allowed = 0;
    }
    ack_unlock();
    ack_lock();
    config_cache();
    ack_unlock();
    halow_ack_config_save(&g_ack_cfg);
    log_info("ack: apply retries=%u tmo=%ums ra=%u window=%u fids=%u",
             (unsigned)g_ack_cfg.max_retries, (unsigned)g_ack_cfg.timeout_ms,
             (unsigned)g_ack_cfg.rate_adapt,
             (unsigned)g_window, (unsigned)g_ack_cfg.ack_fids);
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
    a[2] = (uint8_t)( evm != 0 ? evm : (int8_t)0x80 );
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

/* ================= bundle staging & flush ================= */

static void agg_reset( ack_peer_t *p ){
    if( p->agg_idx != 0u && g_bufs[p->agg_idx - 1u] != NULL ){
        buf_release(g_bufs[p->agg_idx - 1u]);
    }
    p->agg_idx = 0u;
    p->agg_len = 0u;
    p->agg_nsub = 0u;
    p->agg_first_jiff = 0u;
}

static void peer_note_tx( ack_peer_t *p, uint32_t wire_bytes, uint16_t flen ){
    p->tx++;
    p->tx_bytes += wire_bytes;
    p->last_tx_s = (int32_t)time(NULL);
    statistics_radio_register_tx_package(flen);
}

/* Gates are hard HW limits only (DMA room, in-flight window); the hold/gap
 * waits are gone -- assembly rides the TCP window, and the incomplete frame
 * goes out the moment the TCP side has nothing more buffered. */
static bool agg_flush_locked( ack_peer_t *p ){
    if( p == NULL || p->agg_idx == 0u ) return true;
    if( halow_get_tx_vacancy() < ACK_TX_VACANCY_LOW ) return false;
    if( g_inflight_n >= g_window ) return false;

    ack_buf_t *b = g_bufs[p->agg_idx - 1u];
    uint8_t  pmcs   = p->tx_mcs;
    uint16_t staged = p->agg_len;
    uint8_t  nsub   = p->agg_nsub;
    p->agg_idx        = 0u;
    p->agg_len        = 0u;
    p->agg_nsub       = 0u;
    p->agg_first_jiff = 0u;

    b->retries_used = 0u;
    b->tx_jiff      = now_j();
    b->born_jiff    = now_j();
    b->seq          = 0xFFFFu;

    if( p->compat == HALOW_COMPAT_ENVELOPE && g_ack_cfg.env != 0u ){
        uint16_t seq = p->tx_seq++;
        if( seq == 0xFFFFu ) seq = p->tx_seq++;
        b->seq    = seq;
        b->ofs    = 0u;
        b->len    = staged;
        b->data[0] = HALOW_ENV_MAGIC0;
        b->data[1] = HALOW_ENV_MAGIC1;
        b->data[2] = (uint8_t)((HALOW_ENV_VER << 4) | HALOW_ENV_TYPE_BUNDLE);
        b->data[3] = (uint8_t)(seq & 0xFFu);
        b->data[4] = (uint8_t)(seq >> 8);
        b->data[5] = nsub;
        b->fid = (uint16_t)(fnv1a(b->data, b->len) & 0xFFFFu);
        if( b->fid == 0u ) b->fid = 0xFFFFu;
        peer_note_tx(p, staged, staged);
        g_ack_stats.env_tx_bundles++;
        buf_tx_send(b, pmcs);
        return true;
    }

    if( nsub == 1u ){
        uint16_t plen = (uint16_t)((uint16_t)b->data[ACK_AGG_RESERVE] |
                                   ((uint16_t)b->data[ACK_AGG_RESERVE + 1u] << 8));
        if( plen == 0u || (uint32_t)plen + 2u > staged - ACK_AGG_RESERVE ){
            buf_release(b);
            g_ack_stats.dropped++;
            p->dropped++;
            return true;
        }
        b->ofs = ACK_AGG_RESERVE + 2u;
        b->len = plen;
        b->fid = (uint16_t)(fnv1a(&b->data[b->ofs], plen) & 0xFFFFu);
        if( b->fid == 0u ) b->fid = 0xFFFFu;
        peer_note_tx(p, plen, plen);
        buf_tx_send(b, pmcs);
        return true;
    }

    b->ofs = ACK_AGG_RESERVE - 3u;
    b->len = (uint16_t)(staged - (ACK_AGG_RESERVE - 3u));
    b->data[b->ofs]     = HALOW_ACK_AGG_MAGIC0;
    b->data[b->ofs + 1] = HALOW_ACK_AGG_MAGIC1;
    b->data[b->ofs + 2] = nsub;
    b->fid = (uint16_t)(fnv1a(&b->data[b->ofs], b->len) & 0xFFFFu);
    if( b->fid == 0u ) b->fid = 0xFFFFu;
    peer_note_tx(p, b->len, b->len);
    buf_tx_send(b, pmcs);
    return true;
}

/* ================= data transmit ================= */

bool halow_ack_tx_ready( void ){
    if( g_ack_cfg.max_retries == 0u ) return true;
    if( halow_get_tx_vacancy() < ACK_TX_VACANCY_LOW ) return false;
    ack_lock();
    bool ok = ( (uint32_t)g_inflight_n + 2u <= g_window ) &&
              ( (uint32_t)(ACK_BUF_N - g_used_n) >= 2u );
    ack_unlock();
    return ok;
}

static int32_t tx_plain_untracked( const uint8_t *payload, uint16_t len,
                                   const uint8_t dest_mac[6], uint8_t mcs ){
    int32_t r = halow_tx(payload, len, dest_mac, mcs);
    if( r < 0 ) return HALOW_ACK_TX_THROTTLE;
    statistics_radio_register_tx_package(len);
    return r;
}

static int32_t tx_broadcast( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] ){
    uint8_t copies = ( is_broadcast(dest_mac) && g_ack_cfg.bc_repeat > 1u )
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

static bool bundle_full_for( ack_peer_t *p, ack_buf_t *sb,
                             uint16_t len, uint16_t eff_payload ){
    uint32_t payload_now = (uint32_t)p->agg_len - ACK_AGG_RESERVE - 2u*p->agg_nsub;
    uint32_t wire_now    = (uint32_t)p->agg_len + 2u + len;
    return ( payload_now + len > eff_payload ) ||
           ( wire_now > ACK_WIRE_MAX ) ||
           ( wire_now > (uint32_t)sb->cap ) ||
           ( p->agg_nsub + 1u > HALOW_ACK_AGG_MAX_SUB );
}

static uint16_t staging_alloc_cap( uint16_t eff_payload ){
    uint32_t cap = (uint32_t)ACK_AGG_RESERVE + eff_payload
                 + 2u*HALOW_ACK_AGG_MAX_SUB;
    return ( cap > ACK_WIRE_MAX ) ? (uint16_t)ACK_WIRE_MAX : (uint16_t)cap;
}

static int32_t tx_bundle_locked( ack_peer_t *p, const uint8_t *payload,
                                 uint16_t len, const uint8_t dest_mac[6],
                                 uint8_t pmcs, uint16_t eff_payload ){
    ack_buf_t *sb = ( p->agg_idx != 0u ) ? g_bufs[p->agg_idx - 1u] : NULL;
    if( sb != NULL && bundle_full_for(p, sb, len, eff_payload) ){
        (void)agg_flush_locked(p);
        sb = ( p->agg_idx != 0u ) ? g_bufs[p->agg_idx - 1u] : NULL;
        if( sb != NULL && bundle_full_for(p, sb, len, eff_payload) ){
            ack_unlock();
            return HALOW_ACK_TX_THROTTLE;
        }
    }

    if( p->agg_idx == 0u ){
        ack_buf_t *b = buf_alloc(ACK_BUF_STAGING, dest_mac,
                                 staging_alloc_cap(eff_payload));
        if( b == NULL ){
            ack_unlock();
            return HALOW_ACK_TX_THROTTLE;
        }
        p->agg_idx        = (uint8_t)((uint32_t)b->idx + 1u);
        p->agg_len        = ACK_AGG_RESERVE;
        p->agg_nsub       = 0u;
        p->agg_first_jiff = now_j();
        sb = b;
    }

    sb->data[p->agg_len]     = (uint8_t)(len & 0xFFu);
    sb->data[p->agg_len + 1] = (uint8_t)((len >> 8) & 0xFFu);
    memcpy(&sb->data[p->agg_len + 2u], payload, len);
    p->agg_len  = (uint16_t)(p->agg_len + 2u + len);
    p->agg_nsub++;

    uint32_t payload_sum = (uint32_t)p->agg_len - ACK_AGG_RESERVE - 2u*p->agg_nsub;
    if( p->agg_nsub >= HALOW_ACK_AGG_MAX_SUB ||
        (uint32_t)p->agg_len + 2u > sb->cap ||
        payload_sum >= eff_payload ){
        (void)agg_flush_locked(p);
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
    ack_buf_t *b = buf_claim_inflight(dest_mac, len);
    if( b == NULL ){
        ack_unlock();
        return HALOW_ACK_TX_THROTTLE;
    }
    b->tx_jiff = now_j();
    b->ofs = 0u;
    b->len = len;
    memcpy(b->data, payload, len);
    b->fid = (uint16_t)(fnv1a(payload, len) & 0xFFFFu);
    if( b->fid == 0u ) b->fid = 0xFFFFu;
    peer_note_tx(p, len, len);
    buf_tx_send(b, pmcs);
    return 0;
}

static int32_t ack_tx_uc( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] );

int32_t halow_ack_tx( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] ){
    if( payload == NULL || dest_mac == NULL ) return -1;

    int32_t r = ack_tx_uc(payload, len, dest_mac);
    if( r == 0 ) g_ack_stats.tx_frames++;
    return r;
}

void halow_ack_flush( void ){
    ack_lock();
    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        ack_peer_t *p = &g_peers[i];
        if( p->in_use && p->agg_idx != 0u ) (void)agg_flush_locked(p);
    }
    ack_unlock();
}

static int32_t ack_tx_uc( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] ){
    bool noack = ( g_ack_cfg.max_retries == 0u ) ||
                 is_broadcast(dest_mac) ||
                 ( (uint32_t)len > ACK_WIRE_MAX );
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

    uint16_t eff_payload = eff_agg_bytes(pmcs);
    if( g_ack_cfg.agg != 0u && (uint32_t)len <= eff_payload ){
        return tx_bundle_locked(p, payload, len, dest_mac, pmcs, eff_payload);
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
    for( uint32_t i = 0u; i < ACK_BUF_N; i++ ){
        ack_buf_t *b = g_bufs[i];
        if( b == NULL || b->state != ACK_BUF_INFLIGHT ) continue;
        if( !mac_eq(b->dest_mac, p->mac) ) continue;
        if( b->seq == 0xFFFFu ) continue;
        uint16_t diff = (uint16_t)(b->seq - base);
        if( diff < HALOW_ACK_SEQ_WINDOW && ((bm >> diff) & 1u) ){
            rtt_record( now_j() - b->born_jiff,
                        now_j() - b->tx_jiff,
                        b->retries_used );
            buf_release(b);
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
        ack_buf_t *b = buf_match(src_mac, ack_fid);
        if( b != NULL ){
            if( p != NULL ) p->l0_strikes = 0u;
            rtt_record( now_j() - b->born_jiff,
                        now_j() - b->tx_jiff,
                        b->retries_used );
            buf_release(b);
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
        p->ack_due_jiff = now_j() + g_ack_hold_j;
    }
    return false;
}

static bool rx_data( const uint8_t *payload, uint16_t len, const uint8_t src_mac[6],
                     const uint8_t dst_mac[6], int8_t evm,
                     const uint8_t **out_payload, uint16_t *out_len ){
    uint32_t hash = fnv1a(payload, len);
    uint16_t fids[HALOW_ACK_ACK_FIDS_MAX] = {0};
    bool to_me = ( dst_mac != NULL && !is_broadcast(dst_mac) );

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

static void buf_drop_deadline( ack_buf_t *b ){
    ack_peer_t *p = peer_find(b->dest_mac);
    buf_release(b);
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

static jiffy_t buf_backoff_jiffies( ack_buf_t *b, jiffy_t timeout_j ){
    if( b->retries_used > 0u ){
        uint32_t shift = b->retries_used;
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
    jiffy_t j = ms_j(floor_ms);
    return (j > timeout_j) ? j : timeout_j;
}

static void buf_retransmit_or_drop( ack_buf_t *b, jiffy_t now ){
    ack_peer_t *p = peer_find(b->dest_mac);
    if( p == NULL ){
        buf_release(b);
        return;
    }
    if( b->retries_used >= g_ack_cfg.max_retries ){
        buf_release(b);
        g_ack_stats.dropped++;
        g_ack_stats.drop_exhaust++;
        p->dropped++;
        peer_note_dead_bundle(p);
        ra_on_drop(p);
        return;
    }

    b->retries_used++;
    b->tx_jiff = now;
    g_ack_stats.retransmitted++;
    p->retransmitted++;
    buf_tx_send(b, p->tx_mcs);
}

static void tick_service_bufs( jiffy_t now ){
    jiffy_t timeout_j = ms_j(g_ack_cfg.timeout_ms);
    jiffy_t life_j    = ms_j(slot_life_ms());
    if( timeout_j == 0u ) timeout_j = 1u;

    for( uint32_t i = 0; i < ACK_BUF_N; i++ ){
        ack_buf_t *b = g_bufs[i];
        if( b == NULL || b->state != ACK_BUF_INFLIGHT ) continue;
        if( (now - b->born_jiff) >= life_j ){
            buf_drop_deadline(b);
            continue;
        }
        if( (now - b->tx_jiff) < buf_backoff_jiffies(b, timeout_j) ) continue;
        if( halow_get_tx_vacancy() < ACK_TX_VACANCY_LOW ) continue;
        buf_retransmit_or_drop(b, now);
    }
}

/* Safety net only: bundles normally leave via halow_ack_flush() the moment
 * the TCP side runs dry. A bundle still staged here means the RF gates have
 * been closed for a full second -- drop rather than wedge the peer. */
static void tick_flush_held_bundles( jiffy_t now ){
    if( g_ack_cfg.agg == 0u ) return;

    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        ack_peer_t *p = &g_peers[i];
        if( !p->in_use || p->agg_idx == 0u ) continue;
        if( agg_flush_locked(p) ) continue;
        if( (now - p->agg_first_jiff) >= ms_j(ACK_AGG_MAX_HOLD_MS) ){
            g_ack_stats.dropped       += p->agg_nsub;
            g_ack_stats.drop_throttle += p->agg_nsub;
            p->dropped               += p->agg_nsub;
            agg_reset(p);
        }
    }
}

static void tick_flush_deferred_acks( jiffy_t now ){
    if( g_ack_cfg.ack_hold_ms == 0u ) return;

    for( uint32_t i = 0; i < ACK_MAX_PEERS; i++ ){
        ack_peer_t *p = &g_peers[i];
        if( !p->in_use || !p->ack_due ) continue;
        if( (int32_t)(now - p->ack_due_jiff) < 0 ) continue;
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

    if( g_ack_cfg.max_retries == 0u ) return;
    jiffy_t now = now_j();

    dflt_mcs_refresh();
    ack_lock();
    tick_service_bufs(now);
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
    return ( g_used_n == 0u ) && ( (now_j() - g_last_data_tx_jiff) >= g_quiet_j );
}

bool halow_ack_link_busy( void ){
    return ( g_used_n != 0u ) || ( (now_j() - g_last_data_tx_jiff) < g_busy_j );
}

void halow_ack_init( void ){
    dflt_mcs_refresh();
    halow_ack_config_load(&g_ack_cfg);
    memset(g_bufs, 0, sizeof(g_bufs));
    memset(g_peers, 0, sizeof(g_peers));
    memset(&g_ack_stats, 0, sizeof(g_ack_stats));
    g_used_n = 0;
    g_inflight_n = 0;
    g_peers_n = 0;
    g_heap_bytes = 0;
    g_window = g_ack_cfg.window;
    config_cache();

    (void)os_mutex_init(&g_ack_mutex);
    os_mutex_unlock(&g_ack_mutex);

    os_task_init((const uint8 *)"acktk", &g_ack_tick_task, ack_tick_task_fn, 0);
    os_task_set_stacksize(&g_ack_tick_task, 4048);
    os_task_set_priority(&g_ack_tick_task, OS_TASK_PRIORITY_REALTIME);
    os_task_run(&g_ack_tick_task);

    log_info("ack: init retries=%u tmo=%ums window=%u fids=%u",
             (unsigned)g_ack_cfg.max_retries, (unsigned)g_ack_cfg.timeout_ms,
             (unsigned)g_window, (unsigned)g_ack_cfg.ack_fids);
}

void halow_ack_stats_get( halow_ack_stats_t *out ){
    if( out == NULL ) return;
    ack_lock();
    *out = g_ack_stats;
    out->outstanding = g_inflight_n;
    out->peers       = g_peers_n;
    out->heap_bytes  = g_heap_bytes;
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
        out->loss_pct       = (uint8_t)((uint32_t)p->loss_q8 * 100u / 256u);
        out->acks_since_step = p->acks_since_step;
        out->loss_q8        = p->loss_q8;
        out->compat         = p->compat;
        out->l0_falls       = p->l0_falls;
        int32_t rem = (int32_t)(p->next_step_allowed - now_j());
        out->gap_ms = (rem <= 0) ? 0 : (int32_t)os_jiffies_to_msecs((uint64_t)(jiffy_t)rem);
    }
    ack_unlock();
    return found;
}
