#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW_PKG_HANDLER
#include "basic_include.h"
#include "lib/logc/log.h"
#include "halow_pkg_handler.h"
#include "halow_ack.h"
#include "rns/link_db.h"
#include "rns/link_parser.h"
#include "rns/link_utils.h"
#include "rns/stream_parser.h"
#include "utils.h"
#include "halow.h"
#include "statistics.h"
#include "configdb.h"
#include "tcp_server.h"
#include "chip/txw4002ack803/sysctrl.h"   /* mcu_watchdog_feed() */

#define RNS_MTU_LIMIT_KEY   CONFIGDB_ADD_MODULE("rns") ".mtu"
#define RNS_MTU_LIMIT_DEF   (500U)

volatile uint32_t g_dbg_rns_rx_calls;
volatile uint32_t g_dbg_rns_rx_parse_fail;
volatile uint32_t g_dbg_rns_rx_valid;
volatile uint32_t g_dbg_rns_rx_reg_ok;
volatile uint32_t g_dbg_rns_rx_reg_fail;
volatile uint32_t g_dbg_rns_tx_parse_fail;

#define HALOW_ACK_CFG_PREFIX   CONFIGDB_ADD_MODULE("hack")
#define HALOW_ACK_CFG(k)       HALOW_ACK_CFG_PREFIX "." k
/* Bump when code defaults change semantics: stale configdb "hack.*" keys re-seed once. */
#define HALOW_ACK_CFG_VER      2

#define HALOW_ACK_MAX_PEERS    4u
/* Every slot copy, pend FIFO, retx scratch and peer agg_buf is FRAME_MAX-sized;
 * 7600 would cost ~100 KB of RAM on a chip where code shares RAM with data. */
#define HALOW_ACK_FRAME_MAX    4000u
#define HALOW_ACK_DEDUP_WIN    HALOW_ACK_ACK_FIDS_MAX
#define HALOW_ACK_TICK_MS      10u

#define HALOW_ACK_RA_MAX_MCS     7u
#define HALOW_ACK_RA_EWMA_WEIGHT 8u
#define HALOW_ACK_RA_Q8(pct)     ((uint16_t)((uint32_t)(pct) * 256u / 100u))
/* Below this the ACK layer holds instead of calling halow_tx; set just above
 * the largest possible skb so normal drain variance never sheds load. */
#define HALOW_ACK_TX_VACANCY_LOW 8000u
/* Block cap for the data-path slot claim; only the dead-link case ever hits it. */
#define HALOW_ACK_SLOT_WAIT_MS  2000u
/* Hard lifetime: past it the slot drops regardless of retries (TCP above
 * retransmits end-to-end). Effective lifetime follows the retry schedule
 * (halow_ack_slot_life_ms) so every paid-for retry fires. */
#define HALOW_ACK_SLOT_LIFE_MAX_MS  6000u
/* Max age of a coalesced bundle before the tick drops it; bounds latency. */
#define HALOW_ACK_AGG_MAX_HOLD_MS   1000u

typedef struct {
    uint8_t  in_use;
    uint8_t  retries_used;
    uint64_t tx_jiff;
    uint64_t born_jiff;       /* claim time: hard lifetime cap (zombie guard) */
    uint16_t frame_len;
    uint16_t fid;             /* fnv1a(payload) & 0xFFFF, matches the legacy ACK */
    uint16_t seq;             /* per-peer bundle seq (envelope v1 Block-ACK) */
    uint8_t  dest_mac[6];
    uint8_t  frame[HALOW_ACK_FRAME_MAX + 4u];
} halow_ack_slot_t;

typedef struct {
    uint8_t  in_use;
    uint8_t  mac[6];
    uint8_t  cur_retries;
    uint8_t  tx_mcs;            /* 0xFF = global default */
    int8_t   evm_ewma;
    /* slow (tau ~32) EVM for the RA ceiling: the fast ewma is bimodal on this
     * link and made RA oscillate every few seconds. */
    int8_t   evm_ewma_slow;
    uint16_t loss_ewma_q8;      /* /256 == 0..1 */
    uint32_t tx;
    uint32_t acked;
    uint32_t dropped;
    /* Per-peer TX accounting for the stats view; broadcast/NOACK/plain sends
     * bypass it (no per-peer feedback exists on those paths). */
    uint32_t tx_bytes;
    uint32_t retransmitted;
    int32_t  last_tx_s;
    uint64_t last_ack_jiff;
    uint64_t cooldown_until;
    uint16_t acks_since_step;    /* consecutive ACKs since last MCS step (climb fuel) */
    uint64_t next_step_allowed;  /* jiffies before which no further up-step is allowed */
    uint64_t last_seen;
    uint32_t dedup[HALOW_ACK_DEDUP_WIN];
    uint8_t  dedup_idx;
    /* ACK coalescing: rx_since_ack counts frames since the last ACK;
     * ack_due/ack_due_jiff mark a deferred ACK; last_rx_evm rides the ACK. */
    uint16_t rx_since_ack;
    bool     ack_due;
    uint64_t ack_due_jiff;
    int8_t   last_rx_evm;
    /* A-MSDU coalescing: agg_buf holds the in-progress wire bundle,
     * agg_first_jiff marks the first subframe for the agg_hold_ms flush. */
    uint16_t agg_len;
    uint8_t  agg_nsub;
    uint64_t agg_first_jiff;
    /* L1 compatibility: 2 = envelope v1, 1 = legacy magics, 0 = plain-only.
     * Raised by a received v1 frame; lowered by the dead-bundle heuristic. */
    uint8_t  compat;
    uint16_t tx_seq;          /* next bundle seq we will send to this peer */
    /* RX seq window for Block-ACK: bit i of rx_seq_win == seq (rx_seq_last-i)
     * was received (dedup hits included). rx_seq_last valid when rx_seq_seen. */
    uint16_t rx_seq_last;
    uint64_t rx_seq_win;
    bool     rx_seq_seen;
    uint32_t l0_strikes;      /* consecutive un-ACKed bundle deaths (L0 heur) */
    /* Windowed TX-loss display, loss AFTER retries (what the user lost).
     * Evidence-weighted IIR: n *= 0.5/s decay, per-second resolved frames
     * accumulate in pend_res/pend_fail, alpha = A/(A + n + 10) once the merged
     * evidence reaches 5. loss_ewma_q8 above is the separate MCS-tuning signal. */
    uint32_t samp_acked, samp_dropped;
    uint32_t pend_res, pend_fail;   /* sub-threshold evidence carry-over */
    uint32_t loss_ev_n;
    uint16_t loss_iir_pct;
    /* Envelope bootstrap: every 8th ACK to a peer still below L2 is sent as an
     * envelope probe; a G1/G0 peer just fails the parse and drops it. */
    uint8_t  ack_probe_cnt;
    uint32_t l0_falls;        /* times we downgraded this peer to L0 */
    /* RA grace: a fresh peer's first drops are negotiation noise. */
    uint64_t created_jiff;
    /* Lazily os_malloc'd on first coalesce, kept for the peer's lifetime,
     * freed on eviction. NULL when no bundle is in flight. */
    uint8_t *agg_buf;
} halow_ack_peer_t;

/* Park frames here instead of dropping them when the guards are full;
 * drained by the tick and opportunistically before each new frame. */
#define HALOW_ACK_PEND_N 2u
/* ~15 s of drain attempts: control-frame floods can hold the RF for seconds. */
#define HALOW_ACK_PEND_MAX_TRIES  1500u
static uint8_t  g_pend_buf[HALOW_ACK_PEND_N][HALOW_ACK_FRAME_MAX];
static uint16_t g_pend_len[HALOW_ACK_PEND_N];
static uint8_t  g_pend_mac[HALOW_ACK_PEND_N][6];
static uint32_t g_pend_head, g_pend_count;
static uint16_t g_pend_tries[HALOW_ACK_PEND_N];   /* failed drain attempts */
static bool     g_pend_draining;   /* tcps and tick drain concurrently */

static uint64_t g_last_data_tx_jiff;

static halow_ack_slot_t  *g_ack_slots;
static uint32_t           g_ack_slot_count;

/* Nothing in flight and no data TX for 1 s: an ADC conversion (which briefly
 * deafens the RX) cannot kill a frame. Drives the 15 s measurement cadence. */
bool halow_ack_radio_quiet( void ){
    if( g_ack_slots == NULL ) return true;
    for( uint32_t i = 0u; i < g_ack_slot_count; i++ ){
        if( g_ack_slots[i].in_use ) return false;
    }
    return (os_jiffies() - g_last_data_tx_jiff) >= os_msecs_to_jiffies(1000u);
}

bool halow_ack_link_busy( void ){
    if( g_ack_slots != NULL ){
        for( uint32_t i = 0u; i < g_ack_slot_count; i++ ){
            if( g_ack_slots[i].in_use ) return true;
        }
    }
    return (os_jiffies() - g_last_data_tx_jiff) < os_msecs_to_jiffies(10000u);
}

static halow_ack_config_t g_ack_cfg;
/* Last time an ACK matched and freed a live slot (jiffies). Drives the
 * pressure mode of the slot lifetime: matches drying up = mutual deafness. */
static uint64_t           g_ack_last_match_jiff;
static halow_ack_peer_t   g_ack_peers[HALOW_ACK_MAX_PEERS];
static halow_ack_stats_t  g_ack_stats;
static struct os_mutex    g_ack_mutex;
/* Counting semaphore of FREE retry slots (== window at init). Claims are
 * non-blocking (a full window means THROTTLE, not a blocked thread);
 * halow_ack_slots_resize_locked adjusts the count by deltas to keep it exact. */
static struct os_semaphore g_ack_slot_sem;
/* Shrink-resize debt: tokens that must leave the semaphore but were in
 * flight when the window shrank; collected by swallowing a token return. */
static uint32_t g_ack_sem_debt;

/* Return one free-slot token. All callers hold g_ack_mutex. */
static void halow_ack_token_return( void ){
    if( g_ack_sem_debt > 0u ){
        g_ack_sem_debt--;
    }else{
        os_sema_up(&g_ack_slot_sem);
    }
}

static void halow_ack_lock(void)   { (void)os_mutex_lock(&g_ack_mutex, -1); }
static void halow_ack_unlock(void) { os_mutex_unlock(&g_ack_mutex); }

#define HALOW_ACK_RETIRE_Q   2u
static halow_ack_slot_t *g_ack_retire_q[HALOW_ACK_RETIRE_Q];
static uint64_t           g_ack_retire_jiff[HALOW_ACK_RETIRE_Q];
static uint32_t           g_ack_retire_n;
#define HALOW_ACK_SLOTS_RETIRE_MS  2000u

static void halow_ack_slots_retire( halow_ack_slot_t *old ){
    if( old == NULL ) return;
    if( g_ack_retire_n == HALOW_ACK_RETIRE_Q ){
        uint32_t victim = 0u;
        for( uint32_t i = 1u; i < HALOW_ACK_RETIRE_Q; i++ ){
            if( (os_jiffies() - g_ack_retire_jiff[i]) >
                (os_jiffies() - g_ack_retire_jiff[victim]) ) victim = i;
        }
        os_free(g_ack_retire_q[victim]);
        g_ack_retire_q[victim] = g_ack_retire_q[g_ack_retire_n - 1u];
        g_ack_retire_jiff[victim] = g_ack_retire_jiff[g_ack_retire_n - 1u];
        g_ack_retire_n--;
    }
    g_ack_retire_q[g_ack_retire_n] = old;
    g_ack_retire_jiff[g_ack_retire_n] = os_jiffies();
    g_ack_retire_n++;
}

static bool halow_ack_slots_resize_locked( uint8_t window ){
    if( window == 0u ) window = HALOW_ACK_DEFAULT_WINDOW;
    if( window > HALOW_ACK_SLOTS_MAX ) window = HALOW_ACK_SLOTS_MAX;
    if( window == g_ack_slot_count && g_ack_slots != NULL ) return true;
    halow_ack_slot_t *nw = (halow_ack_slot_t *)os_malloc((uint32_t)window * sizeof(halow_ack_slot_t));
    if( nw == NULL ){
        log_warn("ack: slot malloc failed window=%u (keep %lu)",
                 (unsigned)window, (unsigned long)g_ack_slot_count);
        return false;
    }
    memset(nw, 0, (uint32_t)window * sizeof(halow_ack_slot_t));
    uint32_t dropped_inuse = 0u;
    for( uint32_t i = 0; i < g_ack_slot_count; i++ )
        if( g_ack_slots != NULL && g_ack_slots[i].in_use ) dropped_inuse++;
    g_ack_stats.dropped += dropped_inuse;
    bool had_old = ( g_ack_slots != NULL );
    uint8_t old_count = g_ack_slot_count;
    /* Freeing here is a use-after-free window: callers that dropped the mutex
     * still hold slot pointers into the old array -- retire instead. */
    if( had_old ){
        halow_ack_slots_retire(g_ack_slots);
    }
    g_ack_slots = nw;
    g_ack_slot_count = window;
    if( !had_old ){
        os_sema_init(&g_ack_slot_sem, (int32)g_ack_slot_count);
        return true;
    }
    /* Adjust the token count instead of re-initializing: a wholesale
     * os_sema_init races a claimer that already took a token, leaving a
     * permanent phantom token. Grow: up() the delta; shrink: try down(),
     * remembering unreclaimable tokens as debt collected at the next return. */
    while( dropped_inuse-- > 0u ) os_sema_up(&g_ack_slot_sem);
    int32 delta = (int32)window - (int32)old_count;
    while( delta > 0 ){ os_sema_up(&g_ack_slot_sem); delta--; }
    while( delta < 0 ){
        if( os_sema_down(&g_ack_slot_sem, 0) == 0 ){
            delta++;
        }else{
            g_ack_sem_debt++;   /* token in flight: swallow a future return */
            delta++;
        }
    }
    return true;
}

/* Cached default MCS: the real lookup is a configdb read; cache it with a
 * coarse TTL. 0xFF = not loaded yet. */
#define HALOW_ACK_DFLT_MCS_TTL_MS   5000u
static uint8_t g_dflt_mcs_cache = 0xFFu;
static uint64_t g_dflt_mcs_jiff = 0;

/* MUST NOT run under g_ack_mutex: the flash mutexes can stall for seconds
 * behind a config-save GC, and the tick feeds the hardware watchdog. */
static void halow_ack_default_mcs_refresh( void ){
    uint64_t now = os_jiffies();
    if( g_dflt_mcs_cache != 0xFFu &&
        (now - g_dflt_mcs_jiff) < os_msecs_to_jiffies(HALOW_ACK_DFLT_MCS_TTL_MS) ){
        return;
    }
    halow_config_t hcfg;
    halow_config_load(&hcfg);
    g_dflt_mcs_cache = hcfg.mcs;
    g_dflt_mcs_jiff  = now;
}

/* Pure cached read, safe under the mutex. 7 = mid-table default until the
 * first refresh. */
static uint8_t halow_ack_default_mcs( void ){
    return (g_dflt_mcs_cache != 0xFFu) ? g_dflt_mcs_cache : 7u;
}

/* 802.11ah S1G 1 MHz max PPDU payload per MCS: a bundle above this is
 * physically untransmittable at that rate. Bundle sizing MUST consult it. */
static uint16_t halow_ack_max_payload_mcs( uint8_t mcs ){
    switch( mcs ){
        case 0u:  return 700u;
        case 1u:  return 1450u;
        case 2u:  return 2200u;
        case 3u:  return 3000u;
        case 4u:  return 4500u;
        case 5u:  return 6050u;
        case 6u:  return 6800u;
        case 7u:  return 7600u;
        case 10u: return 500u;   /* envelope-bundle cap; halow_tx_mcs10_frag
                                  * splits at the ~344B single-PPDU ceiling */
        default:  return 700u;   /* conservative */
    }
}

/* Effective bundle limit: min(configured agg_bytes, max payload for the MCS
 * this peer will actually use). HALOW_MCS_DEFAULT resolves to the cached
 * global default. */
static uint32_t halow_ack_slot_life_ms( void ){
    uint32_t tmo  = g_ack_cfg.timeout_ms;
    uint32_t life = 150u;
    uint32_t first_cap = tmo * 4u;
    if( first_cap < (uint32_t)g_ack_stats.ack_rtt_ewma_ms * 2u ){
        first_cap = (uint32_t)g_ack_stats.ack_rtt_ewma_ms * 2u;
    }
    life += first_cap;
    for( uint32_t i = 0u; i < g_ack_cfg.max_retries; i++ ){
        life += tmo << ((i < 3u) ? i : 3u);
        if( life >= HALOW_ACK_SLOT_LIFE_MAX_MS ) return HALOW_ACK_SLOT_LIFE_MAX_MS;
    }
    return life;
}

static uint16_t halow_ack_eff_agg_bytes( uint8_t pmcs ){
    uint16_t cap = g_ack_cfg.agg_bytes;
    uint8_t  eff_mcs = (pmcs == HALOW_MCS_DEFAULT) ? halow_ack_default_mcs() : pmcs;
    uint16_t mcs_cap = halow_ack_max_payload_mcs(eff_mcs);
    if( mcs_cap < cap ) cap = mcs_cap;
    return cap;
}

static void halow_ack_log_mcs( const char *verb, halow_ack_peer_t *p ){
    uint32_t pct_x100 = (uint32_t)p->loss_ewma_q8 * 100u * 100u / 256u;
    (void)pct_x100;
    log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x MCS %s -> %u (loss=%u.%02u%%)",
             p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
             verb, (unsigned)p->tx_mcs,
             (unsigned)(pct_x100 / 100u), (unsigned)(pct_x100 % 100u));
}

/* EVM-driven MCS ceiling: the peer's ACKs carry the EVM at which it hears us
 * (TX-side quality we cannot measure ourselves). Climb is capped by the EVM
 * headroom; loss-driven downshifts still work below it. */
static uint8_t halow_ack_ra_evm_ceiling( const halow_ack_peer_t *p ){
    int8_t e = p->evm_ewma_slow;
    if( e == 0 ) e = p->evm_ewma;                             /* warming up */
    if( e == 0 && p->last_rx_evm != 0 ) e = p->last_rx_evm;   /* pre-first-ACK */
    if( e == 0 ) return 4u;   /* fresh peer: start mid, EVM arrives with the first ACK */
    if( e >= -14 ) return 7u;
    if( e >= -17 ) return 6u;
    if( e >= -19 ) return 5u;
    if( e >= -21 ) return 4u;
    if( e >= -23 ) return 3u;
    if( e >= -26 ) return 2u;
    return 1u;
}

/* Loss-driven descent floor: EVM ceiling minus 2 (>=1). Below it the broken
 * low-rate TX regime dominates the loss and strands RA. */
static uint8_t halow_ack_ra_evm_floor( const halow_ack_peer_t *p ){
    uint8_t c = halow_ack_ra_evm_ceiling(p);
    return ( c >= 3u ) ? (uint8_t)(c - 2u) : 1u;
}

static void halow_ack_ra_on_ack( halow_ack_peer_t *p ){
    p->last_ack_jiff = os_jiffies();
    /* success: decay the loss estimate toward 0 */
    p->loss_ewma_q8 = (uint16_t)(((uint32_t)p->loss_ewma_q8 * (HALOW_ACK_RA_EWMA_WEIGHT - 1u)) >> 3);
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;
    /* Proactive climb: an up-step requires BOTH STEP_AFTER clean ACKs AND a
     * near-zero loss estimate -- climbing on a lossy direction strands the
     * peer at an unsustainable MCS. */
    g_ack_stats.ra_ack_calls++;
    if( p->acks_since_step != 0xFFFFu ) p->acks_since_step++;
    uint8_t ceil_mcs = halow_ack_ra_evm_ceiling(p);
    if( ceil_mcs > HALOW_ACK_RA_MAX_MCS ) ceil_mcs = HALOW_ACK_RA_MAX_MCS;
    bool ready = ( p->tx_mcs + 1u < ceil_mcs )
               ? ( p->loss_ewma_q8 <= HALOW_ACK_RA_Q8(g_ack_cfg.ra_loss_down) )
               : ( p->loss_ewma_q8 <= HALOW_ACK_RA_Q8(g_ack_cfg.ra_loss_up) );
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
        halow_ack_log_mcs("up", p);
    }
}

static void halow_ack_ra_on_drop( halow_ack_peer_t *p ){
    /* Grace: a fresh peer's first drops are link-negotiation noise, not
     * channel quality. */
    if( p->created_jiff != 0u &&
        (os_jiffies() - p->created_jiff) < os_msecs_to_jiffies(2000u) ){
        return;
    }
    p->loss_ewma_q8 = (uint16_t)((((uint32_t)p->loss_ewma_q8 * (HALOW_ACK_RA_EWMA_WEIGHT - 1u)) >> 3)
                                 + (256u / HALOW_ACK_RA_EWMA_WEIGHT));
    p->acks_since_step = 0;   /* a drop breaks the consecutive-success run */
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;
    if( p->loss_ewma_q8 >= HALOW_ACK_RA_Q8(g_ack_cfg.ra_loss_down) ){
        uint8_t floor_d = halow_ack_ra_evm_floor(p);
        if( p->tx_mcs > floor_d ){
            p->tx_mcs--;
            p->next_step_allowed = os_jiffies() + os_msecs_to_jiffies(HALOW_ACK_RA_STEP_GAP_MS * 8u);
            g_ack_stats.ra_downshifts++;
            halow_ack_log_mcs("down", p);
        }
        /* at/below floor: hold the rate, the soft climb gate recovers it. */
    }
}

static void halow_ack_ra_check_stale( halow_ack_peer_t *p, uint8_t dflt_mcs ){
    if( !g_ack_cfg.rate_adapt ) return;
    if( p->tx_mcs == HALOW_MCS_DEFAULT ) return;
    if( p->last_ack_jiff == 0u ) return;
    if( (os_jiffies() - p->last_ack_jiff) <= os_msecs_to_jiffies(HALOW_ACK_RA_STALE_MS) ) return;
    uint8_t init_mcs = halow_ack_ra_evm_ceiling(p);
    if( init_mcs > HALOW_ACK_RA_MAX_MCS ) init_mcs = HALOW_ACK_RA_MAX_MCS;
    if( init_mcs < 1u ) init_mcs = 1u;
    p->tx_mcs            = init_mcs;
    p->loss_ewma_q8      = 0;
    p->acks_since_step   = 0;
    p->next_step_allowed = os_jiffies() + os_msecs_to_jiffies(HALOW_ACK_RA_COOLDOWN_MS);
    log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x MCS stale -> ceiling %u (dflt %u)",
             p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
             (unsigned)init_mcs, (unsigned)dflt_mcs);
}

static uint32_t halow_ack_fnv1a( const uint8_t *p, uint16_t len ){
    uint32_t h = 2166136261u;
    while( len-- ){
        h ^= (uint32_t)(*p++);
        h *= 16777619u;
    }
    return h;
}

bool halow_ack_is_ack_frame( const uint8_t *data, uint16_t len ){
    /* Legacy fid-list ACK: [A5][5A][evm>=0x80][fid16 x n]. The int8 dB evm
     * byte is always >= 0x80 on the wire -- disjoint from the envelope, whose
     * byte 2 (ver|type) stays < 0x80. */
    return (data != NULL &&
            len >= HALOW_ACK_ACK_LEN_MIN &&
            len <= HALOW_ACK_ACK_LEN_MAX &&
            (((uint32_t)len - 3u) & 1u) == 0u &&
            data[0] == HALOW_ACK_MAGIC0 &&
            data[1] == HALOW_ACK_MAGIC1 &&
            data[2] >= 0x80u);
}

/* Envelope v1 frame: [A5][5A][ver<=7 | type][body]. Byte 2 < 0x80 by the
 * version-numbering rule -- disjoint from the legacy ACK's evm byte forever. */
static bool halow_ack_is_env_frame( const uint8_t *data, uint16_t len ){
    return (data != NULL &&
            len >= 3u &&
            data[0] == HALOW_ENV_MAGIC0 &&
            data[1] == HALOW_ENV_MAGIC1 &&
            data[2] < 0x80u);
}

static uint8_t halow_env_ver( const uint8_t *d ){ return (uint8_t)(d[2] >> 4); }
static uint8_t halow_env_type( const uint8_t *d ){ return (uint8_t)(d[2] & 0x0Fu); }

/* Internal reliability plumbing (fid-ACK or Block-ACK): stays out of user-
 * facing RX accounting -- ACKs run at their own robust MCS and would fake
 * the displayed RX rate. */
bool halow_ack_is_internal_frame( const uint8_t *data, uint16_t len ){
    if( halow_ack_is_ack_frame(data, len) ) return true;
    return (halow_ack_is_env_frame(data, len) &&
            halow_env_type(data) == HALOW_ENV_TYPE_ACK);
}

/* Record a received bundle seq into the Block-ACK window: bit 0 of rx_seq_win
 * == rx_seq_last (newest); dups keep their bit set. Jumps beyond the window
 * reset it. Caller holds the mutex. */
static void halow_ack_peer_rx_seq( halow_ack_peer_t *p, uint16_t seq ){
    if( !p->rx_seq_seen ){
        p->rx_seq_seen = true;
        p->rx_seq_last = seq;
        p->rx_seq_win  = 1u;
        return;
    }
    uint16_t fwd = (uint16_t)(seq - p->rx_seq_last);   /* wrap-safe distance */
    if( fwd == 0u ) return;                            /* dup / retransmit */
    if( fwd >= HALOW_ACK_SEQ_WINDOW ){
        p->rx_seq_last = seq;
        p->rx_seq_win  = 1u;
        return;
    }
    p->rx_seq_win = (p->rx_seq_win << fwd) | 1u;
    p->rx_seq_last = seq;
}

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
    /* agg_bytes is always the frame max: halow_ack_eff_agg_bytes caps per-MCS
     * at runtime. */
    cfg->agg_bytes     = HALOW_ACK_FRAME_MAX;
    cfg->agg_hold_ms   = HALOW_ACK_AGG_HOLD_MS_DEF;
    cfg->ack_hold_ms   = HALOW_ACK_ACK_HOLD_MS_DEF;
    cfg->bc_repeat     = HALOW_ACK_BC_REPEAT_DEF;
    cfg->env           = 1u;
    cfg->data_gap_ms   = HALOW_ACK_DATA_GAP_MS_DEF;
}

static void halow_ack_config_clamp( halow_ack_config_t *cfg ){
    if( cfg->max_retries > 8u )    cfg->max_retries = 8u;
    if( cfg->timeout_ms < 5u )     cfg->timeout_ms = 5u;
    /* The slot lifetime scales with the retry schedule; 300 ms is a plain
     * sanity bound on a single wait. */
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
    /* agg_bytes is not user-configurable anymore: always the frame max. The
     * effective per-bundle cap is computed at runtime from the peer's current
     * MCS (halow_ack_eff_agg_bytes), so this stays optimal for any link. */
    cfg->agg_bytes = (uint16_t)HALOW_ACK_FRAME_MAX;
    if( cfg->agg_hold_ms == 0u ) cfg->agg_hold_ms = 1u;
    if( cfg->agg_hold_ms > 100u ) cfg->agg_hold_ms = 100u;
    /* ack_hold must stay well under the retry timeout; cap at half of it. */
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

    /* One-time migration: stale configdb keys from an older fw generation
     * silently override the defaults. On a marker mismatch, re-seed with the
     * current defaults and stamp it. Boot-only. */
    if( configdb_get_i16(HALOW_ACK_CFG("ver"), &ver) != 0 ||
        ver != (int16_t)HALOW_ACK_CFG_VER ){
        log_info("ack: cfg gen %d -> %d, re-seeding defaults (stale overrides dropped)",
                 (int)ver, HALOW_ACK_CFG_VER);
        /* Feed the watchdog around every write: a flashdb GC chain can
         * outlast the 3 s boot timeout. */
        mcu_watchdog_feed();
        halow_ack_config_save(cfg);
        mcu_watchdog_feed();
        ver = (int16_t)HALOW_ACK_CFG_VER;
        configdb_set_i16(HALOW_ACK_CFG("ver"), (const int16_t *)&ver);
        mcu_watchdog_feed();
        halow_ack_config_clamp(cfg);
        return;
    }

    configdb_get_i8 (HALOW_ACK_CFG("retry"),  (int8_t *)&cfg->max_retries);
    configdb_get_i16(HALOW_ACK_CFG("tmo"),    (int16_t *)&cfg->timeout_ms);
    configdb_get_i8 (HALOW_ACK_CFG("ra"),     (int8_t *)&cfg->rate_adapt);
    configdb_get_i8 (HALOW_ACK_CFG("rlup"),   (int8_t *)&cfg->ra_loss_up);
    configdb_get_i8 (HALOW_ACK_CFG("rldn"),   (int8_t *)&cfg->ra_loss_down);
    configdb_get_i8 (HALOW_ACK_CFG("window"), (int8_t *)&cfg->window);
    configdb_get_i8 (HALOW_ACK_CFG("fids"),   (int8_t *)&cfg->ack_fids);
    configdb_get_i8 (HALOW_ACK_CFG("agg"),    (int8_t *)&cfg->agg);
    configdb_get_i16(HALOW_ACK_CFG("aggbytes"), (int16_t *)&cfg->agg_bytes);
    configdb_get_i16(HALOW_ACK_CFG("agghold"),  (int16_t *)&cfg->agg_hold_ms);
    configdb_get_i16(HALOW_ACK_CFG("ackhold"),  (int16_t *)&cfg->ack_hold_ms);
    configdb_get_i8 (HALOW_ACK_CFG("bcrep"),    (int8_t *)&cfg->bc_repeat);
    configdb_get_i8 (HALOW_ACK_CFG("env"),     (int8_t *)&cfg->env);
    configdb_get_i16(HALOW_ACK_CFG("gapms"),   (int16_t *)&cfg->data_gap_ms);
    halow_ack_config_clamp(cfg);
}

void halow_ack_config_save( const halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    configdb_set_i8 (HALOW_ACK_CFG("retry"),  (int8_t *)&cfg->max_retries);
    configdb_set_i16(HALOW_ACK_CFG("tmo"),    (int16_t *)&cfg->timeout_ms);
    configdb_set_i8 (HALOW_ACK_CFG("ra"),     (int8_t *)&cfg->rate_adapt);
    configdb_set_i8 (HALOW_ACK_CFG("rlup"),   (int8_t *)&cfg->ra_loss_up);
    configdb_set_i8 (HALOW_ACK_CFG("rldn"),   (int8_t *)&cfg->ra_loss_down);
    configdb_set_i8 (HALOW_ACK_CFG("window"), (int8_t *)&cfg->window);
    configdb_set_i8 (HALOW_ACK_CFG("fids"),   (int8_t *)&cfg->ack_fids);
    configdb_set_i8 (HALOW_ACK_CFG("agg"),    (int8_t *)&cfg->agg);
    configdb_set_i16(HALOW_ACK_CFG("aggbytes"), (int16_t *)&cfg->agg_bytes);
    configdb_set_i16(HALOW_ACK_CFG("agghold"),  (int16_t *)&cfg->agg_hold_ms);
    configdb_set_i16(HALOW_ACK_CFG("ackhold"),  (int16_t *)&cfg->ack_hold_ms);
    configdb_set_i8 (HALOW_ACK_CFG("bcrep"),    (int8_t *)&cfg->bc_repeat);
    configdb_set_i8 (HALOW_ACK_CFG("env"),     (int8_t *)&cfg->env);
    configdb_set_i16(HALOW_ACK_CFG("gapms"),   (int16_t *)&cfg->data_gap_ms);
}

void halow_ack_config_get_live( halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    halow_ack_lock();
    *cfg = g_ack_cfg;
    halow_ack_unlock();
}

void halow_ack_config_apply( const halow_ack_config_t *cfg ){
    if( cfg == NULL ) return;
    halow_ack_config_t c = *cfg;
    halow_ack_config_clamp(&c);

    halow_ack_default_mcs_refresh();   /* outside g_ack_mutex: flash read */

    halow_ack_lock();
    g_ack_cfg = c;
    /* grow/shrink the sliding-window slot pool if window changed */
    if( c.window != g_ack_slot_count || g_ack_slots == NULL ){
        (void)halow_ack_slots_resize_locked(c.window);
        if( g_ack_slot_count != c.window ) g_ack_cfg.window = (uint8_t)g_ack_slot_count;
    }
    for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ ){
        halow_ack_peer_t *p = &g_ack_peers[i];
        if( !p->in_use ) continue;
        if( p->cur_retries > c.max_retries ) p->cur_retries = c.max_retries;
        if( !c.rate_adapt ){
            p->tx_mcs = HALOW_MCS_DEFAULT;
            p->loss_ewma_q8 = 0;
        }else if( p->tx_mcs == HALOW_MCS_DEFAULT ){
            uint8_t init_mcs = halow_ack_ra_evm_ceiling(p);
            if( init_mcs > HALOW_ACK_RA_MAX_MCS ) init_mcs = HALOW_ACK_RA_MAX_MCS;
            p->tx_mcs = init_mcs;
            p->loss_ewma_q8 = 0;
        }
        /* let the proactive climb engage immediately after a (re)apply */
        p->acks_since_step   = 0;
        p->next_step_allowed = 0;
    }
    halow_ack_unlock();
    halow_ack_config_save(&g_ack_cfg);
    log_info("ack: apply retries=%u tmo=%ums ra=%u up=%u%% down=%u%% window=%lu fids=%u",
             (unsigned)g_ack_cfg.max_retries, (unsigned)g_ack_cfg.timeout_ms,
             (unsigned)g_ack_cfg.rate_adapt,
             (unsigned)g_ack_cfg.ra_loss_up, (unsigned)g_ack_cfg.ra_loss_down,
             (unsigned long)g_ack_slot_count, (unsigned)g_ack_cfg.ack_fids);
}

static halow_ack_peer_t *halow_ack_peer_find( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ )
        if( g_ack_peers[i].in_use && memcmp(g_ack_peers[i].mac, mac, 6) == 0 )
            return &g_ack_peers[i];
    return NULL;
}

static halow_ack_slot_t *halow_ack_slot_for_peer( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < g_ack_slot_count; i++ )
        if( g_ack_slots[i].in_use && memcmp(g_ack_slots[i].dest_mac, mac, 6) == 0 )
            return &g_ack_slots[i];
    return NULL;
}

/* Find the outstanding slot for (mac, fid). */
static halow_ack_slot_t *halow_ack_slot_match( const uint8_t mac[6], uint16_t fid ){
    for( uint32_t i = 0; i < g_ack_slot_count; i++ )
        if( g_ack_slots[i].in_use &&
            g_ack_slots[i].fid == fid &&
            memcmp(g_ack_slots[i].dest_mac, mac, 6) == 0 )
            return &g_ack_slots[i];
    return NULL;
}

static halow_ack_peer_t *halow_ack_peer_get( const uint8_t mac[6] ){
    /* RA startup: begin at the EVM ceiling and let real retry-exhaustion walk
     * the rate down. Starting at MCS0 is a death spiral on a half-duplex
     * channel: an MCS0 frame is ~10x longer on air and collides far more. */
    halow_ack_peer_t *p = halow_ack_peer_find(mac);
    uint8_t init_mcs;
    if( g_ack_cfg.rate_adapt ){
        /* known peer: EVM ceiling from its own feedback; unknown starts mid */
        init_mcs = ( p != NULL ) ? halow_ack_ra_evm_ceiling(p) : 4u;
        if( init_mcs > HALOW_ACK_RA_MAX_MCS ) init_mcs = HALOW_ACK_RA_MAX_MCS;
    }else{
        init_mcs = HALOW_MCS_DEFAULT;
    }
    if( p != NULL ){
        if( g_ack_cfg.rate_adapt &&
            p->tx_mcs != HALOW_MCS_DEFAULT &&
            p->last_ack_jiff != 0u &&
            (os_jiffies() - p->last_ack_jiff) > os_msecs_to_jiffies(HALOW_ACK_RA_STALE_MS) ){
            p->tx_mcs            = init_mcs;
            p->loss_ewma_q8      = 0;
            p->acks_since_step   = 0;
            p->next_step_allowed = 0;   /* re-heard: allow immediate climb */
            p->compat            = 1u;  /* re-init: legacy until the beacon re-raises G2 */
            p->rx_seq_seen       = false;
            p->rx_seq_win        = 0u;
            log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x re-heard after stale -> MCS %u",
                     p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],
                     (unsigned)init_mcs);
        }
        p->last_seen = os_jiffies();
        return p;
    }
    halow_ack_peer_t *victim = NULL;
    uint64_t oldest = (uint64_t)-1;
    for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ ){
        halow_ack_peer_t *c = &g_ack_peers[i];
        if( !c->in_use ){ victim = c; break; }
        if( halow_ack_slot_for_peer(c->mac) != NULL ) continue;
        if( c->agg_nsub > 0u ) continue;   /* partial bundle on board: evicting
                                            * here silently loses its frames */
        if( c->last_seen < oldest ){ oldest = c->last_seen; victim = c; }
    }
    if( victim == NULL ) return NULL;

    /* Free the evicted peer's agg_buf before zeroing the slot; a partial
     * bundle's frames count as drops. */
    if( victim->agg_nsub > 0u ){
        g_ack_stats.dropped += victim->agg_nsub;
    }
    if( victim->agg_buf != NULL ){
        os_free(victim->agg_buf);
    }
    memset(victim, 0, sizeof(*victim));
    victim->in_use      = 1;
    memcpy(victim->mac, mac, 6);
    victim->cur_retries = g_ack_cfg.max_retries;
    victim->tx_mcs      = init_mcs;
    victim->created_jiff = os_jiffies();
    victim->compat      = 1u;   /* assume G1 until a v1 beacon or the G0 heuristic */
    /* fresh peer: default MCS, climb gated by STEP_GAP_MS. */
    victim->last_seen   = os_jiffies();
    return victim;
}

static bool halow_ack_peer_dedup_seen( halow_ack_peer_t *p, uint32_t hash ){
    for( uint32_t i = 0; i < HALOW_ACK_DEDUP_WIN; i++ )
        if( p->dedup[i] == hash ) return true;
    return false;
}

static void halow_ack_peer_dedup_remember( halow_ack_peer_t *p, uint32_t hash ){
    p->dedup[p->dedup_idx] = hash;
    p->dedup_idx = (uint8_t)((p->dedup_idx + 1u) % HALOW_ACK_DEDUP_WIN);
}

static halow_ack_slot_t *halow_ack_slot_alloc( void ){
    for( uint32_t i = 0; i < g_ack_slot_count; i++ )
        if( !g_ack_slots[i].in_use ) return &g_ack_slots[i];
    return NULL;
}

/* Claim a retry slot. Caller MUST hold g_ack_mutex; it is RELEASED across
 * os_sema_down so the tick/ACK-RX can free slots, then reacquired. The
 * token-then-alloc ordering keeps the count exact, so the post-wait
 * halow_ack_slot_alloc() always finds a slot. tmo_ms==0 -> non-blocking try.
 * Returns the reserved slot (in_use==1) with the lock held, or NULL. */
static halow_ack_slot_t *halow_ack_slot_claim_locked( uint32_t tmo_ms ){
    halow_ack_unlock();
    int32 r = os_sema_down(&g_ack_slot_sem, (int32)tmo_ms);
    halow_ack_lock();
    if( r != 0 ) return NULL;                 /* timeout / non-blocking fail */
    halow_ack_slot_t *s = halow_ack_slot_alloc();   /* guaranteed by the token */
    if( s == NULL ){                          /* defensive: invariant should hold */
        halow_ack_token_return();          /* return the unused token */
        return NULL;
    }
    s->in_use = 1;                            /* reserve under the lock */
    s->born_jiff = os_jiffies();
    s->seq = 0xFFFFu;
    return s;
}

static void halow_ack_send_ack( int8_t evm, const uint8_t dest_mac[6],
                                const uint16_t fids[HALOW_ACK_ACK_FIDS_MAX] ){
    /* Rate-scale the ACK by the peer's EVM ceiling: it measures how well THIS
     * peer hears our signal, which is what governs whether our ACK reaches it. */
    uint8_t ack_mcs = HALOW_ACK_ACK_MCS_MAX;
    bool env_ack = false;
    uint16_t base = 0u;
    uint64_t bm = 0u;
    halow_ack_lock();
    halow_ack_peer_t *ap = halow_ack_peer_find(dest_mac);
    if( ap != NULL ){
        uint8_t c = halow_ack_ra_evm_ceiling(ap);
        if( c > HALOW_ACK_ACK_MCS_MAX ) c = HALOW_ACK_ACK_MCS_MAX;
        if( c < HALOW_ACK_ACK_MCS_MIN ) c = HALOW_ACK_ACK_MCS_MIN;
        ack_mcs = c;
        /* Envelope Block-ACK: [evm][base:2][bitmap:8], bit i == seq base+i
         * received; base is the OLDEST seq, so bitmap bit i mirrors window
         * bit (63-i). */
        bool probe = (ap->compat < 2u) && (g_ack_cfg.env != 0u)
                     && (++ap->ack_probe_cnt >= 8u);
        if( probe ) ap->ack_probe_cnt = 0u;
        /* An empty window (base 0, bitmap 0) is a valid probe: requiring
         * rx_seq_seen deadlocked the bootstrap. */
        if( ((ap->compat == 2u) || probe) && g_ack_cfg.env != 0u ){
            env_ack = true;
            base = (uint16_t)(ap->rx_seq_last - (HALOW_ACK_SEQ_WINDOW - 1u));
            for( uint32_t i = 0u; i < HALOW_ACK_SEQ_WINDOW; i++ ){
                if( (ap->rx_seq_win >> (HALOW_ACK_SEQ_WINDOW - 1u - i)) & 1u ){
                    bm |= (uint64_t)1u << i;
                }
            }
        }
    }
    halow_ack_unlock();
    g_ack_stats.ack_mcs_last = ack_mcs;
    if( env_ack ){
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
        return;
    }

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

/* Emit a peer's coalesce buffer as one bundle: claim one retry slot keyed by
 * fnv1a(bundle), send, reset. Caller holds g_ack_mutex; it is released across
 * the slot wait and across halow_tx. A 1-subframe bundle is unwrapped to a
 * plain frame. can_block=true (tcps) blocks on the slot semaphore when the
 * window is full; can_block=false (tick) holds the bundle and returns false. */
static bool halow_ack_agg_flush_locked( halow_ack_peer_t *p, bool can_block ){
    (void)can_block;   /* reserved for the decoupled-TX-backpressure path */
    if( p == NULL || p->agg_nsub == 0u ) return true;
    /* post-TX gap: give the peer's ACK for our previous bundle the air */
    if( (os_jiffies() - g_last_data_tx_jiff) < os_msecs_to_jiffies(g_ack_cfg.data_gap_ms) ){
        return false;   /* held; tick/next frame retries after the gap */
    }
    /* flow control: hold the bundle when the LMAC TX buffer is nearly full. */
    if( halow_get_tx_vacancy() < HALOW_ACK_TX_VACANCY_LOW ) return false;

    halow_ack_slot_t *s = halow_ack_slot_claim_locked( 0u );   /* non-blocking: tcps
     * also drains the RF->TCP ring and must not block here */
    if( s == NULL ){
        /* ACK window full: HOLD the bundle (return false, leave agg_buf
         * intact) -> the caller returns THROTTLE for TCP backpressure; the
         * tick or the next frame flushes it. No fire-and-forget. */
        return false;
    }
    /* Re-validate under the lock: a racing flush may have sent this bundle
     * while we waited for the slot. */
    if( p->agg_nsub == 0u ){
        s->in_use = 0;
        halow_ack_token_return();
        return true;
    }

    uint16_t blen = p->agg_len;
    uint8_t  pmcs = p->tx_mcs;
    s->retries_used = 0u;
    s->tx_jiff      = os_jiffies();
    memcpy(s->dest_mac, p->mac, 6);

    if( p->compat == 2u && g_ack_cfg.env != 0u ){
        /* Envelope v1 bundle: [A5][5A][ver|type][seq:2][nsub:1]{len,payload};
         * the agg_buf body is layout-identical to the legacy body, so we just
         * re-prefix. Single-sub bundles stay wrapped (G2 peers parse nsub=1). */
        uint16_t seq = p->tx_seq++;
        if( seq == 0xFFFFu ) seq = p->tx_seq++;
        s->seq      = seq;
        s->frame[0] = HALOW_ENV_MAGIC0;
        s->frame[1] = HALOW_ENV_MAGIC1;
        s->frame[2] = (uint8_t)((HALOW_ENV_VER << 4) | HALOW_ENV_TYPE_BUNDLE);
        s->frame[3] = (uint8_t)(seq & 0xFFu);
        s->frame[4] = (uint8_t)(seq >> 8);
        s->frame[5] = p->agg_nsub;
        uint16_t flen = (uint16_t)(HALOW_ENV_BUNDLE_HDR + (blen - 3u));
        memcpy(&s->frame[HALOW_ENV_BUNDLE_HDR], &p->agg_buf[3], (uint32_t)(blen - 3u));
        s->frame_len = flen;
        s->fid = (uint16_t)(halow_ack_fnv1a(s->frame, flen) & 0xFFFFu);
        p->tx++;
        p->tx_bytes   += blen;
        statistics_radio_register_tx_package(flen);   /* wire frame, no retx */
        p->last_tx_s   = (int32_t)time(NULL);
        p->agg_len = 0u; p->agg_nsub = 0u; p->agg_first_jiff = 0u;
        halow_ack_unlock();
        (void)halow_tx(s->frame, flen, s->dest_mac, pmcs);
        g_last_data_tx_jiff = os_jiffies();
        g_ack_stats.env_tx_bundles++;
        halow_ack_lock();
        return true;
    }

    if( p->agg_nsub == 1u ){
        /* unwrap: agg_buf == [hdr3][len2][payload]; send payload as a plain frame */
        uint16_t plen = (uint16_t)((uint16_t)p->agg_buf[3] | ((uint16_t)p->agg_buf[4] << 8));
        p->agg_len = 0u; p->agg_nsub = 0u; p->agg_first_jiff = 0u;
        if( plen == 0u || (uint32_t)plen + 5u > blen ){
            s->in_use = 0; halow_ack_token_return();   /* malformed: free slot, drop */
            g_ack_stats.dropped++;                        /* keep the no-silent-loss invariant */
            p->dropped++;
            return true;
        }
        s->frame_len = plen;
        s->fid = (uint16_t)(halow_ack_fnv1a(&p->agg_buf[5], plen) & 0xFFFFu);
        if( s->fid == 0u ) s->fid = 0xFFFFu;   /* 0 == "no fid" on the ACK-RX side */
        memcpy(s->frame, &p->agg_buf[5], plen);
        p->tx++;
        p->tx_bytes   += plen;
        statistics_radio_register_tx_package(plen);   /* wire frame, no retx */
        p->last_tx_s   = (int32_t)time(NULL);
        halow_ack_unlock();
        (void)halow_tx(s->frame, plen, s->dest_mac, pmcs);
        g_last_data_tx_jiff = os_jiffies();
        halow_ack_lock();
    }else{
        s->frame_len = blen;
        s->fid = (uint16_t)(halow_ack_fnv1a(p->agg_buf, blen) & 0xFFFFu);
        if( s->fid == 0u ) s->fid = 0xFFFFu;   /* 0 == "no fid" on the ACK-RX side */
        memcpy(s->frame, p->agg_buf, blen);
        p->tx++;
        p->tx_bytes   += blen;
        statistics_radio_register_tx_package(blen);   /* wire frame, no retx */
        p->last_tx_s   = (int32_t)time(NULL);
        p->agg_len = 0u; p->agg_nsub = 0u; p->agg_first_jiff = 0u;
        halow_ack_unlock();
        (void)halow_tx(s->frame, blen, s->dest_mac, pmcs);
        g_last_data_tx_jiff = os_jiffies();
        halow_ack_lock();
    }
    return true;
}

bool halow_ack_tx_ready( void ){
    /* ACK disabled (broadcast/plain path) -> always accept. */
    if( g_ack_cfg.max_retries == 0u ) return true;
    /* The LMAC TX budget must have room or nothing can leave (flush hold,
     * plain-path claim, tick retx all gate on this). */
    if( halow_get_tx_vacancy() < HALOW_ACK_TX_VACANCY_LOW ) return false;
    halow_ack_lock();
    /* Accept only when a retry slot is (or is about to be) free: the ACK
     * window IS the pacer. */
    /* Require TWO free slots: one spare covers the pending agg bundle, so a
     * full window THROTTLEs instead of consuming-then-dropping. */
    uint32_t free_slots = 0;
    for( uint32_t i = 0; i < g_ack_slot_count; i++){
        if( !g_ack_slots[i].in_use ) free_slots++;
    }
    halow_ack_unlock();
    return free_slots >= 2u;
}

static int32_t halow_ack_tx_uc( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] );
static void halow_ack_pend_drain( void );

int32_t halow_ack_tx( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] ){
    if( payload == NULL || dest_mac == NULL ) return -1;

    halow_ack_pend_drain();   /* older parked frames leave first */

    int32_t r = halow_ack_tx_uc(payload, len, dest_mac);
    if( r == HALOW_ACK_TX_THROTTLE ){
        halow_ack_lock();
        if( g_pend_count < HALOW_ACK_PEND_N && len <= HALOW_ACK_FRAME_MAX ){
            uint32_t idx = (g_pend_head + g_pend_count) % HALOW_ACK_PEND_N;
            memcpy(g_pend_buf[idx], payload, len);
            g_pend_len[idx] = len;
            memcpy(g_pend_mac[idx], dest_mac, 6);
            g_pend_tries[idx] = 0u;
            g_pend_count++;
            halow_ack_unlock();
            return 0;   /* accepted, deferred -- NOT a loss */
        }
        halow_ack_unlock();
        /* CONTRACT: a frame consumed from TCP must reach the air. Parking is
         * full -> THROTTLE so the caller holds the frame. NEVER drop here. */
        return HALOW_ACK_TX_THROTTLE;
    }
    g_ack_stats.tx_frames++;
    return r;
}

static void halow_ack_pend_drain( void ){
    halow_ack_lock();
    if( g_pend_draining || g_pend_count == 0u ){
        halow_ack_unlock();
        return;
    }
    g_pend_draining = true;
    halow_ack_unlock();
    while( g_pend_count > 0u ){
        uint32_t idx = g_pend_head % HALOW_ACK_PEND_N;
        int32_t r = halow_ack_tx_uc(g_pend_buf[idx], g_pend_len[idx], g_pend_mac[idx]);
        if( r == HALOW_ACK_TX_THROTTLE ){
            /* Still saturated: bounded patience, then a loud drop so a frame
             * that can never leave does not head-of-line block the FIFO. */
            if( ++g_pend_tries[idx] >= HALOW_ACK_PEND_MAX_TRIES ){
                log_warn("pend: frame to %02x:%02x:%02x:%02x:%02x:%02x undeliverable "
                         "(%u tries), len=%u -- dropping",
                         g_pend_mac[idx][0],g_pend_mac[idx][1],g_pend_mac[idx][2],
                         g_pend_mac[idx][3],g_pend_mac[idx][4],g_pend_mac[idx][5],
                         (unsigned)g_pend_tries[idx], (unsigned)g_pend_len[idx]);
                g_ack_stats.dropped++;
                g_ack_stats.drop_throttle++;
                halow_ack_lock();
                g_pend_head = (g_pend_head + 1u) % HALOW_ACK_PEND_N;
                g_pend_count--;
                halow_ack_unlock();
                continue;
            }
            break;   /* still saturated */
        }
        halow_ack_lock();
        g_pend_head = (g_pend_head + 1u) % HALOW_ACK_PEND_N;
        g_pend_count--;
        halow_ack_unlock();
    }
    halow_ack_lock();
    g_pend_draining = false;
    halow_ack_unlock();
}

static int32_t halow_ack_tx_uc( const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6] ){

    if( g_ack_cfg.max_retries == 0u ||
        memcmp(dest_mac, mac_broadcast, 6) == 0 ||
        (uint32_t)len > HALOW_ACK_FRAME_MAX ){

        /* Broadcast can never be ACKed, so no retry slot covers it: transmit
         * each copy bc_repeat times back-to-back (RX skips broadcast dedup,
         * RNS dedups by hash). Repeats are best-effort: stop at the first
         * failed send or when the TX budget runs low. Unicast NOACK and
         * oversized frames keep a single copy. */
        uint8_t copies = (memcmp(dest_mac, mac_broadcast, 6) == 0 &&
                          g_ack_cfg.bc_repeat > 1u)
                       ? g_ack_cfg.bc_repeat : 1u;
        int32_t r = halow_tx(payload, len, dest_mac, HALOW_MCS_DEFAULT);
        bool first_ok = (r >= 0);
        if( first_ok ) statistics_radio_register_tx_package(len);   /* 1st copy */
        for( uint8_t i = 1u; (i < copies) && (r >= 0); i++ ){
            if( halow_get_tx_vacancy() < ((uint32_t)len + 64u) ) break;
            r = halow_tx(payload, len, dest_mac, HALOW_MCS_DEFAULT);
            if( r >= 0 ){
                g_ack_stats.tx_frames++;   /* keep tx_frames == wire frames */
                g_ack_stats.bc_repeats++;
                /* RX counts every broadcast copy it hears; mirror it on TX. */
                statistics_radio_register_tx_package(len);
            }
        }
        /* First copy out = delivered; a failed FIRST copy is THROTTLE, not a
         * loss: the caller parks the frame and we retry. */
        return first_ok ? 0 : HALOW_ACK_TX_THROTTLE;
    }

    halow_ack_lock();
    halow_ack_peer_t *p = halow_ack_peer_get(dest_mac);
    if( p == NULL ){
        halow_ack_unlock();
        int32_t r = halow_tx(payload, len, dest_mac, HALOW_MCS_DEFAULT);
        if( r < 0 ) return HALOW_ACK_TX_THROTTLE;   /* park & retry, never drop */
        statistics_radio_register_tx_package(len);
        return r;
    }
    uint8_t pmcs = p->tx_mcs;
    /* NOACK peer (cur_retries slid to 0): a lost bundle would lose every
     * frame in it with no retry -- send plain. */
    if( p->cur_retries == 0u ){
        halow_ack_unlock();
        int32_t r = halow_tx(payload, len, dest_mac, pmcs);
        if( r < 0 ) return HALOW_ACK_TX_THROTTLE;   /* park & retry, never drop */
        statistics_radio_register_tx_package(len);
        return r;
    }

    /* ---- A-MSDU coalescing: pack per-peer frames into one bundle/MPDU/ACK.
     * The bundle limit is MCS-aware (max payload for the peer's current MCS);
     * frames that cannot fit fall through to the plain per-frame path. */
    uint16_t eff_bytes = halow_ack_eff_agg_bytes(pmcs);
    if( g_ack_cfg.agg != 0u &&
        (uint32_t)len + 5u <= eff_bytes &&
        (uint32_t)len + 5u <= HALOW_ACK_FRAME_MAX ){

        /* if this frame won't fit the current bundle, flush it first */
        if( p->agg_nsub > 0u &&
            ( (uint32_t)p->agg_len + 2u + len > eff_bytes ||
              p->agg_nsub + 1u > HALOW_ACK_AGG_MAX_SUB ) ){
            (void)halow_ack_agg_flush_locked(p, true);
        }
        /* flush was HELD (window full or TX buffer low) and this frame won't
         * fit: THROTTLE for TCP backpressure. The frame was already consumed
         * from TCP, so count it. */
        if( p->agg_nsub > 0u &&
            ( (uint32_t)p->agg_len + 2u + len > eff_bytes ||
              p->agg_nsub + 1u > HALOW_ACK_AGG_MAX_SUB ) ){
            halow_ack_unlock();
            return HALOW_ACK_TX_THROTTLE;   /* the wrapper parks or counts */
        }
        /* start a fresh bundle if empty */
        if( p->agg_nsub == 0u ){
            /* lazy-alloc coalesce buffer; on heap exhaustion send this frame
             * plain -- correct, just no throughput gain. */
            if( p->agg_buf == NULL ){
                p->agg_buf = (uint8_t *)os_malloc(HALOW_ACK_FRAME_MAX);
                if( p->agg_buf == NULL ){
                    halow_ack_unlock();
                    int32_t r = halow_tx(payload, len, dest_mac, pmcs);
                    if( r < 0 ) return HALOW_ACK_TX_THROTTLE;  /* park & retry */
                    statistics_radio_register_tx_package(len);
                    return r;
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

        /* flush now if the bundle can't take another minimal subframe -- under
         * saturation this is the dominant flush path (no hold latency). */
        if( p->agg_nsub >= HALOW_ACK_AGG_MAX_SUB ||
            (uint32_t)p->agg_len + 6u > eff_bytes ){   /* 6 = envelope hdr */
            halow_ack_agg_flush_locked(p, true);
        }
        halow_ack_unlock();
        return 0;
    }

    /* ---- plain per-frame path (aggregation off / oversized / cap) ----
     * Non-blocking claim: a full window THROTTLEs so the TCP recv loop
     * backpressures the sender. */
    if( halow_get_tx_vacancy() < HALOW_ACK_TX_VACANCY_LOW ){
        halow_ack_unlock();
        return HALOW_ACK_TX_THROTTLE;   /* the wrapper parks or counts */
    }
    halow_ack_slot_t *s = halow_ack_slot_claim_locked( 0u );
    if( s == NULL ){
        halow_ack_unlock();
        return HALOW_ACK_TX_THROTTLE;   /* the wrapper parks or counts */
    }
    s->retries_used = 0;
    s->tx_jiff      = os_jiffies();
    s->frame_len    = len;
    s->fid          = (uint16_t)(halow_ack_fnv1a(payload, len) & 0xFFFFu);
    if( s->fid == 0u ) s->fid = 0xFFFFu;   /* 0 == "no fid" on the ACK-RX side */
    memcpy(s->dest_mac, dest_mac, 6);
    memcpy(s->frame, payload, len);
    p->tx++;
    p->tx_bytes   += len;
    statistics_radio_register_tx_package(len);   /* wire frame, no retx */
    p->last_tx_s   = (int32_t)time(NULL);
    halow_ack_unlock();

    int32_t pr = halow_tx(payload, len, dest_mac, pmcs);
    if( pr == 0 ) g_last_data_tx_jiff = os_jiffies();
    return pr;
}

/* Snapshot the most-recent ack_fids entries of the rolling dedup window
 * (most recent first) as low-16 fids for a cumulative ACK. */
static void halow_ack_build_fids_locked( halow_ack_peer_t *p, uint16_t fids[HALOW_ACK_ACK_FIDS_MAX] ){
    uint8_t want = g_ack_cfg.ack_fids;
    if( want > HALOW_ACK_ACK_FIDS_MAX ) want = HALOW_ACK_ACK_FIDS_MAX;
    for( uint32_t i = 0; i < want; i++ ){
        uint32_t idx = (p->dedup_idx + HALOW_ACK_DEDUP_WIN - 1u - i) % HALOW_ACK_DEDUP_WIN;
        uint16_t fid = (uint16_t)(p->dedup[idx] & 0xFFFFu);
        if( fid == 0u ) fid = 0xFFFFu;   /* match the sender-side 0->0xFFFF map;
                                          * ACK-parse skips fid==0 as "unused" */
        fids[i] = fid;
    }
}

/* Record one ACK round trip. The EWMA tracks ONLY first-attempt TX->ACK
 * latency (retries_used==0) -- a retransmitted slot carries its backoff
 * waits in the timestamp distance and would inflate the pacing estimate. */
static void halow_ack_rtt_record( uint32_t born_rtt, uint32_t lasttx_rtt, uint8_t retries_used ){
    g_ack_last_match_jiff = os_jiffies();
    if( g_ack_stats.ack_rtt_hits >= 1000000u ){
        g_ack_stats.ack_rtt_sum_ms /= 2u;
        g_ack_stats.ack_rtt_hits   /= 2u;
    }
    g_ack_stats.ack_rtt_hits++;
    if( born_rtt > 10000u ) born_rtt = 10000u;
    g_ack_stats.ack_rtt_sum_ms += born_rtt;
    if( retries_used != 0u ) return;
    if( lasttx_rtt > 1000u ) lasttx_rtt = 1000u;   /* deep stalls must not set pacing */
    g_ack_stats.ack_rtt_ewma_ms = (g_ack_stats.ack_rtt_ewma_ms == 0u)
        ? lasttx_rtt
        : (g_ack_stats.ack_rtt_ewma_ms * 3u + lasttx_rtt) / 4u;
}

bool halow_ack_on_rx( const uint8_t *payload, uint16_t len, const uint8_t src_mac[6],
                      const uint8_t dst_mac[6],
                      int8_t evm,
                      const uint8_t **out_payload, uint16_t *out_len ){
    if( payload == NULL || out_payload == NULL || out_len == NULL ){
        if( out_payload ) *out_payload = payload;
        if( out_len )     *out_len     = len;
        return true;
    }

    /* ---- envelope v1 frames ----
     * Any v1 frame doubles as the capability beacon (the peer speaks G2).
     * ACK -> process the bitmap; BUNDLE -> record the seq window and fall
     * through to the data path; anything else -> count and drop. */
    if( halow_ack_is_env_frame(payload, len) ){
        uint8_t ev = halow_env_ver(payload);
        uint8_t et = halow_env_type(payload);
        bool is_ack = (ev == HALOW_ENV_VER) && (et == HALOW_ENV_TYPE_ACK)
                      && (len == HALOW_ENV_ACK_LEN);
        bool is_bundle = (ev == HALOW_ENV_VER) && (et == HALOW_ENV_TYPE_BUNDLE)
                         && (len >= HALOW_ENV_BUNDLE_HDR + 2u);
        if( !is_ack && !is_bundle ){
            g_ack_stats.rx_env_unk++;
            return false;
        }
        halow_ack_lock();
        halow_ack_peer_t *ep = halow_ack_peer_find(src_mac);
        if( ep != NULL ){
            if( ep->compat < 2u ){
                ep->compat = 2u;   /* beacon: peer speaks envelope v1 */
                ep->l0_strikes = 0u;
            }
        }
        if( is_ack && ep != NULL ){
            int8_t ack_evm = (int8_t)payload[3];
            g_ack_stats.last_evm = ack_evm;
            g_ack_stats.acks_rx_frames++;
            g_ack_stats.env_rx_acks++;
            ep->cur_retries = g_ack_cfg.max_retries;
            ep->evm_ewma = (int8_t)(((int16_t)ep->evm_ewma * 7 + (int16_t)ack_evm) / 8);
            ep->evm_ewma_slow = (int8_t)(((int16_t)ep->evm_ewma_slow * 31 + (int16_t)ack_evm) / 32);
            halow_ack_ra_on_ack(ep);
            uint16_t base = (uint16_t)((uint16_t)payload[4] | ((uint16_t)payload[5] << 8));
            uint64_t bm = 0u;
            for( uint32_t b = 0u; b < 8u; b++ ){
                bm |= (uint64_t)payload[6u + b] << (8u * b);
            }
            /* Block-ACK: bit i covers seq base+i. Free every live slot to
             * this peer whose seq falls inside the window with its bit set. */
            for( uint32_t i = 0u; i < g_ack_slot_count; i++ ){
                halow_ack_slot_t *s = &g_ack_slots[i];
                if( !s->in_use || memcmp(s->dest_mac, src_mac, 6) != 0 ) continue;
                if( s->seq == 0xFFFFu ) continue;
                uint16_t diff = (uint16_t)(s->seq - base);   /* wrap-safe */
                if( diff < HALOW_ACK_SEQ_WINDOW && ((bm >> diff) & 1u) ){
                    halow_ack_rtt_record( (uint32_t)(os_jiffies() - s->born_jiff),
                                          (uint32_t)(os_jiffies() - s->tx_jiff),
                                          s->retries_used );
                    s->in_use = 0;
                    halow_ack_token_return();
                    g_ack_stats.acked++;
                    ep->acked++;
                }
            }
            halow_ack_unlock();
            return false;
        }
        if( is_bundle && ep != NULL ){
            /* bundle layout: [3]=seq_lo [4]=seq_hi [5]=nsub (ACK has evm at 3!) */
            uint16_t seq = (uint16_t)((uint16_t)payload[3] | ((uint16_t)payload[4] << 8));
            halow_ack_peer_rx_seq(ep, seq);   /* dedup hits keep the bit set */
            g_ack_stats.env_rx_bundles++;
        }
        halow_ack_unlock();
        if( is_ack ) return false;   /* peer gone: nothing to match anyway */
        /* envelope BUNDLE falls through to the data path below */
    }

    if( halow_ack_is_ack_frame(payload, len) ){
        int8_t ack_evm = (int8_t)payload[2];
        g_ack_stats.last_evm = ack_evm;
        g_ack_stats.acks_rx_frames++;

        halow_ack_lock();
        halow_ack_peer_t *p = halow_ack_peer_find(src_mac);
        if( p != NULL ){
            p->cur_retries = g_ack_cfg.max_retries;
            p->evm_ewma = (int8_t)(((int16_t)p->evm_ewma * 7 + (int16_t)ack_evm) / 8);
            p->evm_ewma_slow = (int8_t)(((int16_t)p->evm_ewma_slow * 31 + (int16_t)ack_evm) / 32);
            halow_ack_ra_on_ack(p);
        }
        /* Cumulative ACK: free every outstanding slot whose fid appears in
         * this ACK. Bound nfids by the RECEIVED length, not our own config:
         * a wider peer legitimately carries more fids. */
        uint32_t nfids = (len - 3u) / 2u;
        if( nfids > HALOW_ACK_ACK_FIDS_MAX ) nfids = HALOW_ACK_ACK_FIDS_MAX;
        for( uint32_t k = 0; k < nfids; k++ ){
            uint16_t ack_fid = (uint16_t)((uint16_t)payload[3u + 2u*k]
                                          | ((uint16_t)payload[3u + 2u*k + 1u] << 8));
            if( ack_fid == 0u ) continue;   /* 0 == no/unused fid slot */
            halow_ack_slot_t *s = halow_ack_slot_match(src_mac, ack_fid);
            if( s != NULL ){
                if( p != NULL ) p->l0_strikes = 0u;   /* peer acks: not G0 */
                halow_ack_rtt_record( (uint32_t)(os_jiffies() - s->born_jiff),
                                      (uint32_t)(os_jiffies() - s->tx_jiff),
                                      s->retries_used );
                s->in_use = 0;
                halow_ack_token_return();   /* wake a blocked data-path sender */
                g_ack_stats.acked++;
                if( p != NULL ) p->acked++;
            }else{
                g_ack_stats.acks_rx_dup++;
            }
        }
        halow_ack_unlock();
        return false;
    }

    /* Recovery from a wrong L0 downgrade: this peer just sent us a magic
     * frame, so it demonstrably has the protocol layer. */
    if( len >= 3u && payload[0] == HALOW_ACK_AGG_MAGIC0 && payload[1] == HALOW_ACK_AGG_MAGIC1 ){
        halow_ack_lock();
        halow_ack_peer_t *rp = halow_ack_peer_find(src_mac);
        if( rp != NULL && rp->compat == 0u ){
            rp->compat = 1u;
            log_info("ack: peer %02x:%02x:%02x:%02x:%02x:%02x L0 -> L1 (magic traffic seen)",
                     rp->mac[0],rp->mac[1],rp->mac[2],rp->mac[3],rp->mac[4],rp->mac[5]);
        }
        halow_ack_unlock();
    }

    uint32_t hash = halow_ack_fnv1a(payload, len);
    uint16_t fids[HALOW_ACK_ACK_FIDS_MAX] = {0};
    bool send_ack_now = true;       /* default: no peer -> send an empty ACK now */
    int8_t ack_evm = evm;
    /* Broadcast data gets NO ACK: the sender never claimed a retry slot for
     * it, so our ACK can never match one -- pure airtime waste. */
    bool to_me = (dst_mac != NULL && memcmp(dst_mac, mac_broadcast, 6) != 0);

    halow_ack_lock();
    halow_ack_peer_t *p = to_me ? halow_ack_peer_get(src_mac)
                                : halow_ack_peer_find(src_mac);
    bool deliver = true;
    if( p != NULL ){
        p->last_rx_evm = evm;   /* link-quality signal from any frame */
        if( to_me ){
            deliver = !halow_ack_peer_dedup_seen(p, hash);
            if( deliver ) halow_ack_peer_dedup_remember(p, hash);

            if( g_ack_cfg.ack_hold_ms == 0u ){
                /* legacy: ACK every frame */
                send_ack_now = true;
                p->rx_since_ack = 0;
                p->ack_due = false;
                halow_ack_build_fids_locked(p, fids);
            }else if( ++p->rx_since_ack >= (uint16_t)g_ack_cfg.ack_fids ){
                /* filled the cumulative ACK capacity -> flush it immediately */
                send_ack_now = true;
                p->rx_since_ack = 0;
                p->ack_due = false;
                halow_ack_build_fids_locked(p, fids);
            }else{
                /* defer: one ACK per ack_fids frames cuts the ACK-TXOP count,
                 * the main throughput limiter on 1MHz. */
                send_ack_now = false;
                if( !p->ack_due ){
                    p->ack_due = true;
                    p->ack_due_jiff = os_jiffies() + os_msecs_to_jiffies(g_ack_cfg.ack_hold_ms);
                }
            }
        }else{
            send_ack_now = false;
        }
    }else{
        send_ack_now = false;
        /* Unicast to us but no peer slot available: the frame IS delivered,
         * but it can never be ACKed -- count it. */
        if( to_me ){
            g_ack_stats.noack_hits++;
        }
    }
    halow_ack_unlock();

    if( send_ack_now ){
        halow_ack_send_ack(ack_evm, src_mac, fids);
    }

    if( deliver ){
        *out_payload = payload;
        *out_len     = len;
        return true;
    }
    return false;
}

void halow_ack_tick( void ){
    halow_tx_vacancy_watchdog();   /* self-heal TX budget after lost TX-completes */
    /* Free a retired slot array once its grace period has passed; the
     * check+swap runs under g_ack_mutex. */
    if( g_ack_retire_n > 0u ){
        halow_ack_lock();
        for( uint32_t i = 0u; i < g_ack_retire_n; ){
            if( (os_jiffies() - g_ack_retire_jiff[i]) >= os_msecs_to_jiffies(HALOW_ACK_SLOTS_RETIRE_MS) ){
                halow_ack_slot_t *old = g_ack_retire_q[i];
                g_ack_retire_q[i] = g_ack_retire_q[g_ack_retire_n - 1u];
                g_ack_retire_jiff[i] = g_ack_retire_jiff[g_ack_retire_n - 1u];
                g_ack_retire_n--;
                halow_ack_unlock();
                os_free(old);
                halow_ack_lock();
            }else{
                i++;
            }
        }
        halow_ack_unlock();
    }
    halow_ack_pend_drain();
    /* 1 s windowed-loss sampler (runs in every config mode, also NOACK) */
    {
        static uint64_t loss_samp_jiff;
        uint64_t ln = os_jiffies();
        if( (ln - loss_samp_jiff) >= os_msecs_to_jiffies(1000u) ){
            loss_samp_jiff = ln;
            for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ ){
                halow_ack_peer_t *p = &g_ack_peers[i];
                if( !p->in_use ) continue;
                uint32_t dack = p->acked - p->samp_acked;
                uint32_t ddrp = p->dropped - p->samp_dropped;
                p->samp_acked   = p->acked;
                p->samp_dropped = p->dropped;
                uint32_t n4 = p->loss_ev_n - (p->loss_ev_n >> 1);   /* x0.5 */
                p->loss_ev_n = n4;
                p->pend_res  += dack + ddrp;   /* carry sub-threshold windows */
                p->pend_fail += ddrp;
                if( p->pend_res >= 5u ){       /* merged evidence noise gate */
                    uint32_t inst = p->pend_fail * 100u / p->pend_res;
                    uint32_t Aw = (p->pend_res > 1000u) ? 1000u : p->pend_res;
                    uint32_t den = Aw + n4 + 10u;  /* N0 = 10 prior */
                    p->loss_iir_pct = (uint16_t)(
                        ( (uint32_t)p->loss_iir_pct * (den - Aw) + inst * Aw ) / den );
                    p->loss_ev_n = n4 + Aw;
                    p->pend_res  = 0u;
                    p->pend_fail = 0u;
                }
            }
        }
    }
    if( g_ack_cfg.max_retries == 0u ) return;
    uint64_t now = os_jiffies();
    uint64_t timeout_j = os_msecs_to_jiffies(g_ack_cfg.timeout_ms);
    if( timeout_j == 0u ) timeout_j = 1u;

    halow_ack_default_mcs_refresh();   /* BEFORE the lock: 5 s-TTL flash read */
    halow_ack_lock();
    uint8_t dflt_mcs = halow_ack_default_mcs();
    for( uint32_t i = 0; i < g_ack_slot_count; i++ ){
        halow_ack_slot_t *s = &g_ack_slots[i];
        if( !s->in_use ) continue;
        /* Hard lifetime FIRST and UNGATED: dropping needs no TX budget. */
        /* NOTE: an earlier "adaptive" variant halved the lifetime to 400 ms
         * when the window pinned full -- it MURDERED slots whose ACKs were
         * merely slow (bidir RTT stretches to 400-800 ms), converting
         * would-be deliveries into deadline drops + dup-ACK floods (8K dups
         * per minute). The right lever for a pinned window is MORE SLOTS
         * (window size), never a shorter life. */
        if( (now - s->born_jiff) >= os_msecs_to_jiffies(halow_ack_slot_life_ms()) ){
            halow_ack_peer_t *pdead = halow_ack_peer_find(s->dest_mac);
            s->in_use = 0;
            halow_ack_token_return();   /* deadline: free the token */
            g_ack_stats.dropped++;
            g_ack_stats.drop_deadline++;
            if( pdead != NULL ){
                pdead->dropped++;
                /* G0 heuristic: 12 bundles dead without a single ACK == the
                 * peer has no ACK layer -> plain-only. */
                pdead->l0_strikes++;
                if( pdead->compat == 1u && pdead->l0_strikes >= 12u ){
                    pdead->compat = 0u;
                    pdead->l0_strikes = 0u;
                    pdead->l0_falls++;
                    log_warn("ack: peer %02x:%02x:%02x:%02x:%02x:%02x -> L0 (plain-only, dead bundles)",
                             pdead->mac[0],pdead->mac[1],pdead->mac[2],
                             pdead->mac[3],pdead->mac[4],pdead->mac[5]);
                }
                /* Feed RA only when the TX path is NOT saturated: a deadline
                 * drop under a stuffed buffer is congestion, not channel loss.
                 * Retry-exhaustion drops (real air attempts, no ACK) still
                 * feed RA below. */
                if( halow_get_tx_vacancy() >= HALOW_ACK_TX_VACANCY_LOW ){
                    halow_ack_ra_on_drop(pdead);
                }
            }
            continue;
        }
        /* Exponential retransmit backoff: each retry waits twice as long as
         * the previous one. Without it, a frame whose ACK was lost retransmits
         * every timeout_ms and the flood deafens the sender to the peer's
         * late ACKs -- a bidirectional livelock. Shift cap 3: a stale frame
         * must still drop within bounded time (TCP retransmits anyway). */
        uint64_t backoff_j = timeout_j;
        if( s->retries_used > 0u ){
            uint32_t shift = s->retries_used;
            if( shift > 3u ) shift = 3u;
            backoff_j = timeout_j << shift;
        }else if( g_ack_stats.ack_rtt_ewma_ms != 0u ){
            uint32_t floor_ms = g_ack_stats.ack_rtt_ewma_ms
                              + (g_ack_stats.ack_rtt_ewma_ms >> 2) + 10u;
            uint32_t cap_ms  = g_ack_cfg.timeout_ms * 4u;
            if( cap_ms < (uint32_t)g_ack_stats.ack_rtt_ewma_ms * 2u ){
                cap_ms = (uint32_t)g_ack_stats.ack_rtt_ewma_ms * 2u;
            }
            if( floor_ms > cap_ms ) floor_ms = cap_ms;
            if( floor_ms > g_ack_cfg.timeout_ms ){
                uint64_t j = os_msecs_to_jiffies(floor_ms);
                if( j > backoff_j ) backoff_j = j;
            }
        }
        if( (now - s->tx_jiff) < backoff_j ) continue;
        /* TX buffer nearly full: skip this slot THIS round (budget and timer
         * untouched) and let the queue drain. */
        if( halow_get_tx_vacancy() < HALOW_ACK_TX_VACANCY_LOW ) continue;

        halow_ack_peer_t *p = halow_ack_peer_find(s->dest_mac);
        if( p == NULL ){
            s->in_use = 0;
            halow_ack_token_return();   /* peer gone: free the slot token */
            continue;
        }
        /* Per-slot retry budget: a budget shared via the peer's cur_retries
         * would let several dropping slots slide the peer to NOACK. */
        if( s->retries_used < g_ack_cfg.max_retries ){
            s->retries_used++;
            s->tx_jiff = now;
            g_ack_stats.retransmitted++;
            p->retransmitted++;
            uint8_t pmcs = p->tx_mcs;
            /* Copy out under the lock: once the mutex is dropped, an ACK can
             * free this slot and a claim can reuse it -- memcpy'ing a new
             * frame over s->frame mid-send would put a torn frame on air. */
            static uint8_t retx_buf[HALOW_ACK_FRAME_MAX];
            uint16_t retx_len = s->frame_len;
            uint8_t  retx_mac[6];
            memcpy(retx_buf, s->frame, retx_len);
            memcpy(retx_mac,  s->dest_mac, 6);
            halow_ack_unlock();
            (void)halow_tx(retx_buf, retx_len, retx_mac, pmcs);
            halow_ack_lock();
        }else{
            s->in_use = 0;
            halow_ack_token_return();   /* retries exhausted: free the token */
            g_ack_stats.dropped++;
            g_ack_stats.drop_exhaust++;
            p->dropped++;
            p->l0_strikes++;
            if( p->compat == 1u && p->l0_strikes >= 12u ){
                p->compat = 0u;
                p->l0_strikes = 0u;
                p->l0_falls++;
                log_warn("ack: peer %02x:%02x:%02x:%02x:%02x:%02x -> L0 (plain-only)",
                         p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5]);
            }
            halow_ack_ra_on_drop(p);
        }
    }
    /* Drain A-MSDU coalesce buffers held past agg_hold_ms; the flush releases
     * the lock across halow_tx and reacquires. */
    if( g_ack_cfg.agg != 0u ){
        uint64_t hold_j = os_msecs_to_jiffies(g_ack_cfg.agg_hold_ms);
        if( hold_j == 0u ) hold_j = 1u;
        for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ ){
            halow_ack_peer_t *p = &g_ack_peers[i];
            if( !p->in_use || p->agg_nsub == 0u ) continue;
            if( (now - p->agg_first_jiff) >= hold_j ){
                /* Flush the partial bundle as soon as agg_hold_ms elapses:
                 * holding stragglers longer added ~1 s of latency to every
                 * request/response round trip. A tick claim beating the tcps
                 * probe to the window is harmless: extra frames park for a
                 * tick or two, nothing is dropped. */
                if( !halow_ack_agg_flush_locked(p, false) ){
                    /* Bundle past 1 s with no way out: drop it; TCP above
                     * retransmits end-to-end. */
                    if( (now - p->agg_first_jiff) >= os_msecs_to_jiffies(HALOW_ACK_AGG_MAX_HOLD_MS) ){
                        g_ack_stats.dropped += p->agg_nsub;
                        p->dropped         += p->agg_nsub;
                        p->agg_nsub = 0u;
                        p->agg_len  = 0u;
                    }
                }
            }
        }
    }
    /* Flush deferred (coalesced) ACKs whose ack_hold_ms window has elapsed. */
    if( g_ack_cfg.ack_hold_ms != 0u ){
        for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ ){
            halow_ack_peer_t *p = &g_ack_peers[i];
            if( !p->in_use || !p->ack_due ) continue;
            if( (int64_t)(now - p->ack_due_jiff) < 0 ) continue;   /* not due yet / wrap */
            uint16_t fids[HALOW_ACK_ACK_FIDS_MAX] = {0};
            int8_t aevm = p->last_rx_evm;
            uint8_t mac[6];
            halow_ack_build_fids_locked(p, fids);
            memcpy(mac, p->mac, 6);
            p->ack_due = false;
            p->rx_since_ack = 0;
            halow_ack_unlock();
            halow_ack_send_ack(aevm, mac, fids);
            halow_ack_lock();
        }
    }
    for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ ){
        if( g_ack_peers[i].in_use ) halow_ack_ra_check_stale(&g_ack_peers[i], dflt_mcs);
    }
    halow_ack_unlock();
}

/* Dedicated task, not the shared os_work queue: it feeds the hardware
 * watchdog, and if the tick itself dies the node resets in <=10 s. */
static struct os_task g_ack_tick_task;
volatile uint32_t g_ack_tick_count = 0u;   /* tick heartbeat, exposed via /api/tx_dbg */

static void halow_ack_tick_task_fn( void *arg ){
    (void)arg;
    for( ;; ){
        halow_ack_tick();
        g_ack_tick_count++;
        mcu_watchdog_feed();
        os_sleep_ms(HALOW_ACK_TICK_MS);
    }
}

void halow_ack_init( void ){
    halow_ack_default_mcs_refresh();   /* warm the cache before any task runs */
    halow_ack_config_load(&g_ack_cfg);
    memset(g_ack_peers, 0, sizeof(g_ack_peers));
    memset(&g_ack_stats, 0, sizeof(g_ack_stats));
    g_ack_slots = NULL;
    g_ack_slot_count = 0;

    (void)os_mutex_init(&g_ack_mutex);
    os_mutex_unlock(&g_ack_mutex);

    /* allocate the sliding-window slot pool on the heap (sized by config) */
    halow_ack_lock();
    (void)halow_ack_slots_resize_locked(g_ack_cfg.window);
    halow_ack_unlock();

    os_task_init((const uint8 *)"acktk", &g_ack_tick_task, halow_ack_tick_task_fn, 0);
    /* 4048 = the MAIN workqueue stack this tick used to run on. */
    os_task_set_stacksize(&g_ack_tick_task, 4048);
    /* REALTIME, above the LMAC RX tasks: under a heavy blast they can consume
     * the CPU for longer than the watchdog window with the tick never
     * scheduled. Safe because the tick body is bounded (no flash reads in
     * its locked path); RHINO mutex PI keeps it from starving lock holders. */
    os_task_set_priority(&g_ack_tick_task, OS_TASK_PRIORITY_REALTIME);
    os_task_run(&g_ack_tick_task);

    log_info("ack: init retries=%u tmo=%ums window=%lu fids=%u",
             (unsigned)g_ack_cfg.max_retries, (unsigned)g_ack_cfg.timeout_ms,
             (unsigned long)g_ack_slot_count, (unsigned)g_ack_cfg.ack_fids);
}

void halow_ack_stats_get( halow_ack_stats_t *out ){
    if( out == NULL ) return;
    halow_ack_lock();
    *out = g_ack_stats;
    uint32_t n = 0, peers = 0;
    for( uint32_t i = 0; i < g_ack_slot_count; i++ )     if( g_ack_slots[i].in_use ) n++;
    for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ )  if( g_ack_peers[i].in_use ) peers++;
    out->outstanding = (uint8_t)n;
    out->peers       = (uint8_t)peers;
    halow_ack_unlock();
}

bool halow_ack_peer_stats_by_mac( const uint8_t mac[6], halow_ack_peer_stats_t *out ){
    if( out == NULL ) return false;
    memset(out, 0, sizeof(*out));
    out->tx_mcs = HALOW_MCS_DEFAULT;
    if( mac == NULL ) return false;
    halow_ack_lock();
    halow_ack_peer_t *p = halow_ack_peer_find(mac);
    bool found = (p != NULL);
    if( p != NULL ){
        out->tx_mcs      = p->tx_mcs;
        out->cur_retries = p->cur_retries;
        out->tx_frames   = p->tx;
        out->acked       = p->acked;
        out->dropped     = p->dropped;
        out->evm         = p->evm_ewma;
        out->tx_bytes       = p->tx_bytes;
        out->retransmitted  = p->retransmitted;
        out->last_tx_s      = p->last_tx_s;
        /* TX loss AFTER retries (windowed IIR): what the user actually lost.
         * Per-attempt loss stays derivable from retransmitted/(tx_frames+
         * retransmitted); loss_q8 below is the RA's tuning signal. */
        out->loss_pct = (uint8_t)p->loss_iir_pct;
        out->acks_since_step = p->acks_since_step;
        out->loss_q8     = p->loss_ewma_q8;
        out->compat      = p->compat;
        out->l0_falls    = p->l0_falls;
        int64_t rem = (int64_t)p->next_step_allowed - (int64_t)os_jiffies();
        out->gap_ms = (rem <= 0) ? 0 : (int32_t)os_jiffies_to_msecs((uint64_t)rem);
    }
    halow_ack_unlock();
    return found;
}

static bool halow_peer_mac_known( const uint8_t mac[6] ){
    for( uint32_t i = 0; i < 6; i++ )
        if( mac[i] != RNS_LINK_MAC_UNKNOWN_BYTE ) return true;
    return false;
}

/* Effective link MTU: advertised==0 (standard Reticulum, no signalling
 * extension) or above the hw/rns limit -> the limit; otherwise clamp. */
static uint32_t halow_link_effective_mtu( uint32_t advertised ){
    uint32_t hw;
    uint32_t lim;
    int16_t rl;

    hw = halow_get_mtu(halow_cfg_mcs_get_cached());
    rl = rns_mtu_limit_get();
    lim = ((uint32_t)rl < hw) ? (uint32_t)rl : hw;
    return (advertised == 0u || advertised > lim) ? lim : advertised;
}

/* Deliver one decoded RNS frame to the TCP side; split out so rf_to_tcp can
 * call it per bundle subframe. */
static void deliver_rns_frame( const uint8_t *pkg, uint16_t len,
                               const uint8_t *src_mac, bool unicast_to_me ){
    int32_t res;
    rns_link_packet_info_t packet_info;
    uint8_t *allocated_rx = NULL;
    uint32_t allocated_len = 0u;

    res = rns_link_parser_parse(pkg, len, &packet_info);
    if( res != RNS_RET_OK ){
        g_dbg_rns_rx_parse_fail++;
        log_warn("rx rns package parse error=%d len=%u", (int)res, (unsigned int)len);
        return;
    }

    if( packet_info.valid ){
        int32_t rr;
        bool is_linkrequest = (packet_info.packet_type == RNS_PACKET_TYPE_LINKREQUEST);
        uint32_t rx_mtu = 0;
        /* Capture the peer's advertised MTU when present, else default to
         * the hw/rns limit; update effective_mtu on a LinkRequest. */
        if( is_linkrequest ){
            (void)rns_link_utils_get_mtu(pkg, len, &packet_info, &rx_mtu);
            rx_mtu = halow_link_effective_mtu(rx_mtu);
        }
        g_dbg_rns_rx_valid++;
        rr = rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_RX,
                                          src_mac, rx_mtu, is_linkrequest,
                                          unicast_to_me);
        if( rr == RNS_RET_OK ) g_dbg_rns_rx_reg_ok++;
        else                   g_dbg_rns_rx_reg_fail++;
    }

    res = rns_stream_encode_alloc(pkg, len, &allocated_rx, &allocated_len);
    if( res != 0 || allocated_rx == NULL || allocated_len == 0u ){
        log_warn("rx rns tcp encoding fail res=%d in_len=%u out_len=%u",
                 (int)res, (unsigned int)len, (unsigned int)allocated_len);
        return;
    }
    res = tcp_server_send(allocated_rx, allocated_len);
    if( res != 0 ){
        log_warn("rf->tcp ring full res=%d, drop len=%u", (int)res, (unsigned int)allocated_len);
        /* RF->TCP loss must be visible in /api/tx_dbg, not log-only. */
        { extern halow_tx_dbg_t g_tx_dbg; g_tx_dbg.rf_tcp_dropped++; }
    }
    free(allocated_rx);
}

void halow_pkg_handler_rf_to_tcp( uint8_t* pkg, uint16_t len,
                                  const uint8_t *src_mac, const uint8_t *dst_mac,
                                  int8_t evm ){
    const uint8_t *inner;
    uint16_t inner_len;

    if( !halow_ack_on_rx(pkg, len, src_mac, dst_mac, evm, &inner, &inner_len) ) return;
    pkg = (uint8_t *)inner;
    len = inner_len;
    g_dbg_rns_rx_calls++;
    /* Frames actually addressed to us: only these may re-write a learned
     * peer MAC in the link DB. */
    bool unicast_to_me = (dst_mac != NULL && memcmp(dst_mac, mac_broadcast, 6) != 0);

    /* Envelope v1 bundle: [A5][5A][0x1X][seq:2][nsub:1]{len,payload}.
     * Strict walk, subframes deliver individually; seq was already recorded
     * into the Block-ACK window before the dedup decision. */
    if( len >= (uint16_t)(HALOW_ENV_BUNDLE_HDR + 2u) &&
        pkg[0] == HALOW_ENV_MAGIC0 && pkg[1] == HALOW_ENV_MAGIC1 &&
        halow_env_type(pkg) == HALOW_ENV_TYPE_BUNDLE && halow_env_ver(pkg) == HALOW_ENV_VER ){
        uint8_t nsub = pkg[5];
        if( nsub >= 1u ){
            uint32_t off = HALOW_ENV_BUNDLE_HDR;
            bool valid = true;
            for( uint32_t i = 0u; i < nsub; i++ ){
                if( off + 2u > len ){ valid = false; break; }
                uint16_t slen = (uint16_t)((uint16_t)pkg[off] | ((uint16_t)pkg[off + 1] << 8));
                off += 2u;
                if( (uint32_t)off + slen > len ){ valid = false; break; }
                off += slen;
            }
            if( valid && off != len ) valid = false;
            if( valid ){
                uint32_t o = HALOW_ENV_BUNDLE_HDR;
                for( uint32_t i = 0u; i < nsub; i++ ){
                    uint16_t slen = (uint16_t)((uint16_t)pkg[o] | ((uint16_t)pkg[o + 1] << 8));
                    o += 2u;
                    deliver_rns_frame(&pkg[o], slen, src_mac, unicast_to_me);
                    o += slen;
                }
                return;
            }
        }
        /* malformed envelope bundle: drop explicitly */
        g_ack_stats.rx_env_unk++;
        return;
    }

    /* A-MSDU bundle? Validate (nsub/lens consume the frame exactly, nsub>=2)
     * then split into subframes and deliver each. */
    if( len >= 4u && pkg[0] == HALOW_ACK_AGG_MAGIC0 && pkg[1] == HALOW_ACK_AGG_MAGIC1 ){
        uint8_t nsub = pkg[2];
        if( nsub >= 2u ){
            uint32_t off = 3u;
            bool valid = true;
            for( uint32_t i = 0u; i < nsub; i++ ){
                if( off + 2u > len ){ valid = false; break; }
                uint16_t slen = (uint16_t)((uint16_t)pkg[off] | ((uint16_t)pkg[off + 1] << 8));
                off += 2u;
                if( (uint32_t)off + slen > len ){ valid = false; break; }
                off += slen;
            }
            if( valid && off != len ) valid = false;
            if( valid ){
                uint32_t o = 3u;
                for( uint32_t i = 0u; i < nsub; i++ ){
                    uint16_t slen = (uint16_t)((uint16_t)pkg[o] | ((uint16_t)pkg[o + 1] << 8));
                    o += 2u;
                    deliver_rns_frame(&pkg[o], slen, src_mac, unicast_to_me);
                    o += slen;
                }
                return;
            }
        }
    }

    deliver_rns_frame(pkg, len, src_mac, unicast_to_me);
}

int32_t halow_pkg_handler_tcp_to_rf( uint8_t* pkg, uint16_t len ){
    int32_t res;
    rns_link_packet_info_t packet_info;

    res = rns_link_parser_parse(pkg, len, &packet_info);
    if(res != RNS_RET_OK){
        g_dbg_rns_tx_parse_fail++;
        log_warn("tx rns package parse error=%d", res);
        return 0;
    }

    log_trace("receive pkg type=%d", (int)packet_info.packet_type);

    if( packet_info.valid && packet_info.packet_type == RNS_PACKET_TYPE_LINKREQUEST ){
        uint32_t original_mtu = 0;
        uint32_t hw_mtu;
        uint32_t mtu_limit;
        uint32_t stored_mtu;
        int16_t rns_mtu_limit;

        /* cached config: a LINKREQUEST flood must not hammer the flash mutex */
        hw_mtu = halow_get_mtu(halow_cfg_mcs_get_cached());
        rns_mtu_limit = rns_mtu_limit_get();

        if ((uint32_t)rns_mtu_limit < hw_mtu) {
            mtu_limit = (uint32_t)rns_mtu_limit;
        } else {
            mtu_limit = hw_mtu;
        }

        rns_link_utils_clamp_mtu(pkg, len, &packet_info, mtu_limit, &original_mtu);
        log_info("cap link MTU from %db to %db", (int)original_mtu, (int)mtu_limit);

        /* original_mtu==0: standard Reticulum, no signalling extension --
         * default to the hw/rns limit instead of 0. */
        stored_mtu = halow_link_effective_mtu(original_mtu);

        rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_TX,
                                     NULL, stored_mtu, true, false);
    }else if( packet_info.valid ){
        rns_link_db_package_register(&packet_info, RNS_PACKET_DIRECTION_TX,
                                     NULL, 0, false, false);
    }

    rns_link_db_link_t link;
    const uint8_t *dest;
    dest = (packet_info.valid &&
            rns_link_db_link_snapshot_by_id(packet_info.link_id, &link) &&
            halow_peer_mac_known(link.remote_mac))
           ? link.remote_mac : mac_broadcast;

    return halow_ack_tx(pkg, len, dest);
}

void halow_pkg_handler_init( void ){
    rns_link_db_init();
    halow_ack_init();
}

static int16_t g_rns_mtu_cache;
static uint64_t g_rns_mtu_cache_jiff;
static bool g_rns_mtu_cache_valid;

int16_t rns_mtu_limit_get( void ){
    if( !g_rns_mtu_cache_valid ||
        (os_jiffies() - g_rns_mtu_cache_jiff) >= os_msecs_to_jiffies(5000u) ){
        int16_t val = RNS_MTU_LIMIT_DEF;
        configdb_get_i16(RNS_MTU_LIMIT_KEY, &val);
        g_rns_mtu_cache = val;
        g_rns_mtu_cache_jiff = os_jiffies();
        g_rns_mtu_cache_valid = true;
    }
    return g_rns_mtu_cache;
}

void rns_mtu_limit_set( int16_t mtu ){
    configdb_set_i16(RNS_MTU_LIMIT_KEY, &mtu);
    g_rns_mtu_cache = mtu;
    g_rns_mtu_cache_jiff = os_jiffies();
    g_rns_mtu_cache_valid = true;
}
