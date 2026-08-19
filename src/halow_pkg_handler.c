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
/* Config-generation marker. Bump whenever code defaults change semantics: on
 * the first boot after upgrade the stale configdb "hack.*" keys (left over
 * from debug-session POSTs of a previous fw generation) are re-seeded with
 * the current defaults exactly once, then user-tuned values persist again. */
#define HALOW_ACK_CFG_VER      2

#define HALOW_ACK_MAX_PEERS    4u
/* 4000, not 7600: every slot frame copy, the pend FIFO, the retx scratch and
 * each peer agg_buf are FRAME_MAX-sized -- at 7600 that is ~100 KB of RAM on
 * a chip where the CODE also lives in RAM. The 1 MHz bundle caps by MCS are
 * 700..7600, but RA realistically settles at MCS2-4 (<=3000); capping at
 * 4000 only trims per-PPDU efficiency at MCS5-7 (bundle 4000 instead of
 * 6050-7600) and frees ~40 KB. */
#define HALOW_ACK_FRAME_MAX    4000u
#define HALOW_ACK_DEDUP_WIN    HALOW_ACK_ACK_FIDS_MAX
#define HALOW_ACK_TICK_MS      10u

#define HALOW_ACK_RA_MAX_MCS     7u
#define HALOW_ACK_RA_EWMA_WEIGHT 8u
#define HALOW_ACK_RA_Q8(pct)     ((uint16_t)((uint32_t)(pct) * 256u / 100u))
/* TX flow-control: when the bounded LMAC TX buffer has fewer free bytes than
 * this, the ACK layer applies backpressure (hold a bundle / drop a frame) INSTEAD
 * of calling halow_tx -- because halow_send_frame would block on the vacancy
 * semaphore in the TCP RX handler, stalling the connection. The threshold is set
 * just above the largest possible skb (a 2 KB A-MSDU bundle + headroom) so we
 * ONLY shed load at the very edge of blocking -- normal drain variance does NOT
 * trigger drops (a tighter value was tested and needlessly turned latency into
 * loss). */
#define HALOW_ACK_TX_VACANCY_LOW 8000u
/* ACK-window-gated TX flow control. Data-path sends BLOCK on g_ack_slot_sem
 * (counting semaphore of free retry slots) instead of fire-and-forget/drop when
 * the window is full. halow_ack_tx runs only in the tcps thread, so blocking it
 * stops netconn_recv -> lwIP closes the TCP recv window -> the blasting sender
 * is paced by real TCP flow control. Meanwhile halow_ack_tick (separate
 * workqueue) keeps freeing slots (ACK clears / retry-exhaustion drops) and
 * os_sema_up's, so the block is bounded and deadlock-free. This is the
 * "send a batch <= window, wait ACK, send next batch" pacer the link needs:
 * no frame leaves the data path without a retry slot, so every frame is either
 * delivered or retried to exhaustion -- never silently lost. Cap only bounds
 * the dead-link case (the tick drops exhausted slots well within this). */
#define HALOW_ACK_SLOT_WAIT_MS  2000u
/* Hard lifetime of one frame in a retry slot. Above this the slot is dropped
 * regardless of remaining retries: the TCP layer above retransmits end-to-end,
 * so a stale frame is worth less than a free slot. Without a bound, overload
 * turned the whole window into 6-second zombies and bidir acceptance collapsed
 * to ~1 frame/s (bench 2026-08-17: 96-98% loss at MAX blast).
 *
 * The effective lifetime is computed from the configured retry schedule
 * (halow_ack_slot_life_ms) so every paid-for retry actually fires: with the old
 * fixed 1100 ms and retries=5/timeout=100 the schedule 100+200+400+800+800
 * reached only 3 attempts -- deadline kills were the ENTIRE residual A->B loss
 * on a 1 dBm link (420/420 lost frames were drop_deadline, 2 retries unused). */
#define HALOW_ACK_SLOT_LIFE_MAX_MS  6000u
/* Max age of a coalesced bundle before the tick drops it (frames inside are
 * stale; TCP retransmits). Bounds end-to-end latency under saturation. */
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
    /* slow (tau ~32 samples) EVM for RA ceiling decisions: the fast ewma is
     * bimodal on this link (swings -17..-25 dB) and the RA corridor chased it,
     * oscillating the rate every few seconds -- each rate change disturbs the
     * very measurement that caused it. The ceiling must move on sustained
     * trends only. */
    int8_t   evm_ewma_slow;
    uint16_t loss_ewma_q8;      /* /256 == 0..1 */
    uint32_t tx;
    uint32_t acked;
    uint32_t dropped;
    /* Per-peer TX accounting for the Nearby/peer stats view. tx_bytes is
     * cumulative wire bytes of unicast frames (matches how RX counts wire
     * bytes); retransmitted counts PHY re-send attempts; last_tx_s is the unix
     * ts of the most recent TX to this peer. Broadcast/NOACK/plain sends bypass
     * these (no per-peer feedback), which is the intended scope: "TX stats
     * only on the unicast path". */
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
    /* ACK coalescing. rx_since_ack counts frames received since the last ACK was
     * sent; ack_due/ack_due_jiff mark a deferred ACK waiting for the time trigger
     * or the ack_fids-frame count trigger. last_rx_evm is the evm carried by the
     * (possibly deferred) ACK. */
    uint16_t rx_since_ack;
    bool     ack_due;
    uint64_t ack_due_jiff;
    int8_t   last_rx_evm;
    /* A-MSDU coalescing. agg_buf holds the in-progress wire-format bundle
     * ([0xA5][0xAD][nsub] then [len_le16][payload] per subframe); agg_len is its
     * current total length, agg_nsub the subframe count. agg_first_jiff marks the
     * first subframe so the tick can flush partial bundles past agg_hold_ms. */
    uint16_t agg_len;
    uint8_t  agg_nsub;
    uint64_t agg_first_jiff;
    /* ---- L1 protocol compatibility level (PROTOCOL_DESIGN.md §7.3) ----
     * 2 = envelope v1, 1 = legacy magics, 0 = plain-only (G0 peer, no MSDU,
     * no ACK layer at all). Raised by the capability beacon (any received
     * v1 frame); lowered by the dead-bundle heuristic or link re-init. */
    uint8_t  compat;
    uint16_t tx_seq;          /* next bundle seq we will send to this peer */
    /* RX seq window for Block-ACK: bit i of rx_seq_win == seq (rx_seq_last-i)
     * was received (dedup hits included). rx_seq_last valid when rx_seq_seen. */
    uint16_t rx_seq_last;
    uint64_t rx_seq_win;
    bool     rx_seq_seen;
    uint32_t l0_strikes;      /* consecutive un-ACKed bundle deaths (L0 heur) */
    /* Windowed TX-loss display -- evidence-weighted IIR (algorithm tested in
     * utils/test_loss_iir.py BEFORE this implementation):
     *   n *= 0.5 per second (confidence decay, idle included);
     *   per 1 s window, resolved frames (dacked+ddropped) ACCUMULATE into
     *   pend_res/pend_fail; once the merged evidence reaches 5 (capped at
     *   1000 when applied): alpha = A/(A + n + N0), N0 = 10;
     *   y = y*(1-alpha) + inst*alpha;  n += A;  pend cleared.
     * TWO loss counters by design:
     *   - THIS one is the STATISTICS counter: loss AFTER retries -- the share
     *     of frames whose final fate was decided (ACKed or retry-exhausted)
     *     that ultimately failed. A frame rescued by a retransmit is NOT a
     *     loss here; "TX Loss" must show what the user actually lost.
     *   - loss_ewma_q8 is the MCS-TUNING counter (halow_ack_ra_on_ack/
     *     on_drop): event-driven EWMA feeding the RA stepping logic.
     * Speed requirements (user): converge within a couple dozen seconds
     * under traffic. The earlier 0.75 decay pinned alpha at ~0.2 (30 s+
     * settling, minutes after a heavy-blast n inflation), and discarding
     * sub-5 windows froze the display under sparse resolution rates
     * (bundle-level accounting under aggregation) -- hence 0.5 decay +
     * pending-evidence carry-over. Idle still HOLDS the last estimate (no
     * new evidence != zero loss). */
    uint32_t samp_acked, samp_dropped;
    uint32_t pend_res, pend_fail;   /* sub-threshold evidence carry-over */
    uint32_t loss_ev_n;
    uint16_t loss_iir_pct;
    uint8_t  ack_probe_cnt;   /* envelope bootstrap: every 8th ACK to a peer
                               * still below L2 is sent as an envelope probe.
                               * Safe: an ACK carries no user data; a G1/G0
                               * peer just fails its RNS parse and drops it.
                               * Without the probe two G2 peers start at L1,
                               * nobody beacons, nobody ever switches. */
    uint32_t l0_falls;        /* times we downgraded this peer to L0 */
    /* RA grace: drops within the first moments of a peer's life (RNS link
     * negotiation, announce floods) must not feed the loss estimator -- they
     * once walked a freshly-booted peer 7->0 before any real traffic. */
    uint64_t created_jiff;
    /* Lazily os_malloc'd (HALOW_ACK_FRAME_MAX) on the peer's first coalesce and
     * kept for the peer's lifetime so flushes don't churn the heap under
     * saturation; freed on eviction (halow_ack_peer_get). NULL when no bundle
     * is in flight or aggregation was never used for this peer. Replaces a
     * fixed 4x7600 B static BSS hog with ~0 bytes when idle. */
    uint8_t *agg_buf;
} halow_ack_peer_t;

/* Pending-frame FIFO: when the agg guard / slot window / TX vacancy can't take
 * a frame RIGHT NOW, park it here instead of dropping it (the measured TX loss
 * at moderate offered rates was ~20% pure queue-shedding). Drained by the acktk
 * tick and opportunistically before each new frame. Two frames deep: enough to
 * ride out a ~20 ms burst; deeper is pointless because the TCP recv-window
 * probe (halow_ack_tx_ready) throttles further consumption. */
#define HALOW_ACK_PEND_N 2u
/* Parking patience: drain attempts (tick runs ~100/s) before a parked frame is
 * declared undeliverable and dropped loudly. ~5 s. */
/* 1500 ticks (~15 s): a control-frame flood (e.g. a node joining a mesh and
 * receiving hundreds of LINKREQUESTs) holds the RF for multiple seconds;
 * data frames parked behind it used to hit the old 5 s patience and die
 * (bench: 260-link flood -> 100% data loss during the following 10 s).
 * Genuine undeliverable frames (dead peer) still drop loudly, just later. */
#define HALOW_ACK_PEND_MAX_TRIES  1500u
static uint8_t  g_pend_buf[HALOW_ACK_PEND_N][HALOW_ACK_FRAME_MAX];
static uint16_t g_pend_len[HALOW_ACK_PEND_N];
static uint8_t  g_pend_mac[HALOW_ACK_PEND_N][6];
static uint32_t g_pend_head, g_pend_count;
static uint16_t g_pend_tries[HALOW_ACK_PEND_N];   /* failed drain attempts */
static bool     g_pend_draining;   /* tcps and tick drain concurrently: a flag
                                    * under g_ack_mutex prevents double-sending
                                    * the head element */

static uint64_t g_last_data_tx_jiff;

static halow_ack_slot_t  *g_ack_slots;
static uint32_t           g_ack_slot_count;

/* True when nothing is in flight and no data TX happened in the last second:
 * the radio is quiet enough that an ADC conversion (which briefly deafens
 * the RX) cannot kill a frame. The measurement throttle in halow_debug.c
 * uses this to run temp/supply compensation at 15 s cadence when idle
 * instead of 60 s under traffic. */
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
/* Counting semaphore of FREE retry slots (== window at init). Every slot
 * claim takes one token; every slot free returns one (halow_ack_token_return).
 * Claims are non-blocking (tmo=0) -- a full window means THROTTLE backpressure
 * to the TCP recv loop, not a blocked thread. halow_ack_slots_resize_locked
 * adjusts the count by up/down deltas so it stays exact across resizes. */
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
    /* The tick / agg-flush paths drop g_ack_mutex around halow_tx() while still
     * holding a slot pointer INTO the old array -- freeing it here is a
     * use-after-free window. Retire it instead; the tick frees it after a
     * grace period far longer than any halow_tx call can run. */
    if( had_old ){
        halow_ack_slots_retire(g_ack_slots);
    }
    g_ack_slots = nw;
    g_ack_slot_count = window;
    if( !had_old ){
        os_sema_init(&g_ack_slot_sem, (int32)g_ack_slot_count);
        return true;
    }
    /* Adjust the token count instead of re-initializing the semaphore. A
     * wholesale os_sema_init here races a claimer that already took a token
     * from the old sem and is only waiting to re-lock: the new sem would hold
     * `window` tokens while that claimer also holds one -> a permanent +1
     * phantom token (window overcommit, one spurious THROTTLE/drop per
     * saturation cycle, forever). Exact bookkeeping instead:
     *  - every dropped in-use old slot conceptually frees -> return its token
     *  - grow: up() the delta;  shrink: try down(), remember unreclaimable
     *    tokens as debt collected at the next slot-free (halow_ack_token_return) */
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

/* Cached default MCS. The real lookup is halow_config_load() which reads
 * configdb (flash) -- calling that from the 10ms tick (and per-frame in
 * halow_ack_peer_get) meant ~100+ flash reads/sec and was the bulk of the MAIN
 * workqueue's idle CPU. The configured MCS changes rarely, so cache it with a
 * coarse TTL (refresh at most once per few seconds). 0xFF = not loaded yet. */
#define HALOW_ACK_DFLT_MCS_TTL_MS   5000u
static uint8_t g_dflt_mcs_cache = 0xFFu;
static uint64_t g_dflt_mcs_jiff = 0;

/* Refresh the default-MCS cache from configdb. MUST NOT be called while
 * holding g_ack_mutex (or anywhere on the tick's locked path): the KV reads
 * take the configdb/flash mutexes with WAIT_FOREVER and can stall behind a
 * config-save GC chain for seconds -- with the tick (the hardware-watchdog
 * feeder) blocked, that is a silent node reset (observed twice, both <5 min
 * after an OTA + heavy blast). Refreshed from the tick preamble (before the
 * lock) and at init. */
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

/* Pure cached read -- safe under g_ack_mutex and inside the tick body.
 * 7 = conservative mid-table default until the first refresh lands. */
static uint8_t halow_ack_default_mcs( void ){
    return (g_dflt_mcs_cache != 0xFFu) ? g_dflt_mcs_cache : 7u;
}

/* 802.11ah S1G 1 MHz max PPDU payload (data bytes) per MCS, set by the
 * maximum allowed TX time of a 1 MHz S1G PPDU.  A bundle that exceeds this
 * limit for the current MCS is physically untransmittable — the LMAC TX path
 * rejects it (or truncates), the frame is endlessly retried, and the channel
 * drowns in retransmissions with zero delivery.  This table MUST be consulted
 * whenever deciding the A-MSDU bundle size so aggregation scales with RA. */
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
        case 10u: return 500u;   /* ENVELOPE-bundle cap at MCS10, NOT the PPDU limit: the
                                * single-PPDU ceiling is ~344B (duplicate mode halves the
                                * MCS0 budget); halow_tx_mcs10_frag splits at 340B */
        default:  return 700u;   /* conservative */
    }
}

/* Effective A-MSDU bundle limit: min(configured agg_bytes, max payload for
 * the MCS that will actually be used for this peer).  Resolves HALOW_MCS_DEFAULT
 * to the cached global default so the cap tracks reality even before RA assigns
 * a per-peer MCS. */
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

/* EVM-driven MCS ceiling. The peer's ACKs carry the EVM at which IT hears OUR
 * signal (tx-side link quality we cannot measure ourselves). Loss-driven RA
 * alone oscillates into 64QAM rates the EVM cannot sustain: on this link
 * (EVM -16..-24 dB) MCS7 data lost 50-67% per attempt and survived only via
 * retries, while QPSK/16QAM rates deliver cleanly. Climb is capped by the
 * EVM headroom; loss-driven downshifts still work below it. */
static uint8_t halow_ack_ra_evm_ceiling( const halow_ack_peer_t *p ){
    int8_t e = p->evm_ewma_slow;
    if( e == 0 ) e = p->evm_ewma;                             /* warming up */
    if( e == 0 && p->last_rx_evm != 0 ) e = p->last_rx_evm;   /* pre-first-ACK */
    if( e == 0 ) return 4u;   /* unknown (fresh peer): start mid, EVM arrives
                               * with the first ACK; low rates are the least
                               * reliable TX regime on this HW, don't start there */
    if( e >= -14 ) return 7u;
    if( e >= -17 ) return 6u;
    if( e >= -19 ) return 5u;
    if( e >= -21 ) return 4u;
    if( e >= -23 ) return 3u;
    if( e >= -26 ) return 2u;
    return 1u;
}

/* Loss-driven descent floor: EVM ceiling minus 2 steps of hysteresis (>=1).
 * Below this rate the per-attempt loss on this HW is dominated by the broken
 * low-rate TX regime (long frames), not by channel quality -- descending
 * further only makes loss worse and strands RA (the <=5% climb gate can never
 * open at 60-80% loss). The EVM floor tracks the channel as it degrades. */
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
    /* Proactive climb: STEP_AFTER clean ACKs in a row (or a near-zero loss
     * estimate) earns one MCS step up, gated by STEP_GAP_MS so a clean link ramps
     * from the conservative startup MCS up to the channel ceiling in ~1s without
     * banging on the PHY ceiling every ACK. No global entry cooldown anymore.
     * NOTE: an up-step requires BOTH STEP_AFTER clean ACKs AND a near-zero loss
     * estimate. The earlier "OR" let RA keep climbing on a lossy direction (where
     * the ACK path is clean but the data path loses ~half the frames) and strand
     * the peer at an unsustainable MCS with huge loss -- so it never reached the
     * low-loss operating point. Requiring low loss makes RA throughput-aware. */
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
    /* Grace: a fresh peer's first drops are link-negotiation noise, not channel
     * quality. Feeding them walked a just-booted peer 7->0 within a second
     * (LINKREQUEST retries), stranding it in the worst-TX-regime trap. */
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
        /* at/below floor: hold the rate -- descending into the broken low-rate
         * regime would only raise loss and strand RA (climb-out gate cannot
         * open there). The soft climb gate in ra_on_ack recovers the rate. */
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
    /* LEGACY fid-list ACK: [A5][5A][evm>=0x80][fid16 x n]. The evm byte is an
     * int8 dB value -- always >= 0x80 on the wire -- which is exactly what
     * distinguishes it from the envelope (whose byte 2 = ver|type is always
     * < 0x80 while versions stay <= 7). PROTOCOL_DESIGN.md section 7.1/7.2.
     * Length must match the wire format and stay within capacity. */
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

/* True for any internal reliability-plumbing frame (legacy fid-ACK or
 * envelope Block-ACK) that must stay out of user-facing RX accounting:
 * nearby-table mcs/rssi/rx counters, the RX LED and the radio rx stats.
 * ACKs deliberately run at their own robust adaptive MCS (see
 * halow_ack_send_ack), so letting them update nearby.mcs made the display
 * read the ACK rate (e.g. MCS2) while data frames go at the RA rate (MCS7)
 * -- "TX MCS7 here, RX MCS2 there" on a perfectly healthy link. */
bool halow_ack_is_internal_frame( const uint8_t *data, uint16_t len ){
    if( halow_ack_is_ack_frame(data, len) ) return true;
    return (halow_ack_is_env_frame(data, len) &&
            halow_env_type(data) == HALOW_ENV_TYPE_ACK);
}

/* Record a received bundle seq into the peer's Block-ACK window.
 * bit 0 of rx_seq_win == rx_seq_last (newest); retransmitted dups keep the
 * bit set (idempotent). Jumps beyond the window reset it. Caller holds the
 * mutex. */
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
    /* always max: bundles fill as large as the current MCS allows anyway
     * (halow_ack_eff_agg_bytes caps per-MCS at runtime); a smaller configured
     * value only throttles throughput and is no longer user-settable. */
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
    /* The slot lifetime scales with the retry schedule (halow_ack_slot_life_ms),
     * so any timeout/retries combination is internally consistent now; 300 ms
     * stays as a plain sanity bound on a single wait. */
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
    /* ack_hold must stay well under the retry timeout or batching would cause
     * spurious retransmits; cap at half the timeout (after timeout is clamped). */
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

    /* One-time migration: configdb keys written by an older fw generation (or
     * by debug-session POSTs) silently override the code defaults and have
     * bricked throughput before (ra=0/tmo=200/window=4/aggbytes=2000 left in
     * configdb pinned MCS to 1 and throttled the window). If the generation
     * marker doesn't match, ignore the stale keys, re-seed configdb with the
     * current defaults and stamp the marker. Called only from halow_ack_init
     * (boot), so this runs exactly once per fw upgrade. */
    if( configdb_get_i16(HALOW_ACK_CFG("ver"), &ver) != 0 ||
        ver != (int16_t)HALOW_ACK_CFG_VER ){
        log_info("ack: cfg gen %d -> %d, re-seeding defaults (stale overrides dropped)",
                 (int)ver, HALOW_ACK_CFG_VER);
        /* The re-seed rewrites every ack key; on a flashdb sector dirtied by an
         * earlier watchdog-aborted save, the GC erase/rewrite chain can run
         * longer than the 3 s boot watchdog -> reset mid-save -> dirtier sector
         * -> longer GC next boot: a permanent reboot spiral (observed after
         * OTA: device never finished booting until the sector got wiped).
         * Feed the watchdog around every write so one boot always completes. */
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

/* Find the outstanding slot for (mac, fid). Used to free the exact frame the
 * incoming ACK is confirming. Replaces the old "free the single peer slot". */
static halow_ack_slot_t *halow_ack_slot_match( const uint8_t mac[6], uint16_t fid ){
    for( uint32_t i = 0; i < g_ack_slot_count; i++ )
        if( g_ack_slots[i].in_use &&
            g_ack_slots[i].fid == fid &&
            memcmp(g_ack_slots[i].dest_mac, mac, 6) == 0 )
            return &g_ack_slots[i];
    return NULL;
}

static halow_ack_peer_t *halow_ack_peer_get( const uint8_t mac[6] ){
    /* RA startup: begin at the RA ceiling and let real retry-exhaustion loss
     * walk the rate down. Starting at the global default (MCS0 here) is a
     * death spiral on a contended half-duplex channel: an MCS0 frame is ~10x
     * longer on air than MCS6 for the same payload, so it collides with the
     * peer's traffic far more often; the collision loss then pins RA at MCS0
     * forever (observed: 80% per-attempt loss at MCS0 with SNR 17 while the
     * same link ran MCS6 at <10%). Down-shifts need ~30% ewma loss, so a
     * genuinely bad link settles to its sustainable rate within a few
     * hundred ms. */
    halow_ack_peer_t *p = halow_ack_peer_find(mac);
    uint8_t init_mcs;
    if( g_ack_cfg.rate_adapt ){
        /* known peer: EVM ceiling from its own feedback; fresh victim below
         * starts mid (helper returns 4 for unknown EVM -- see evm_ceiling) */
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
            p->compat            = 1u;  /* link re-init: fall back to legacy,
                                          * the beacon re-raises G2 if due */
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

    /* free the evicted peer's coalesce buffer before zeroing the slot
     * (memset would otherwise drop the pointer and leak the allocation).
     * A partial bundle's subframes were already consumed from TCP: count them
     * as drops or the loss stays invisible (invariant 3). */
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
    victim->compat      = 1u;   /* assume G1 (legacy magics) until a received
                                 * v1 frame beacons G2 or the dead-bundle
                                 * heuristic falls it to G0 */
    /* fresh peer: start at the conservative default MCS and climb immediately as
     * ACKs arrive (gated only by STEP_GAP_MS). memset above zeroed the counters. */
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

/* Claim a retry slot, BLOCKING (tcps thread) until one frees -- i.e. until an
 * ACK clears a slot (halow_ack_on_rx) or a retry-exhausted slot is dropped
 * (halow_ack_tick), both of which os_sema_up g_ack_slot_sem.
 *
 * Caller MUST hold g_ack_mutex; the mutex is RELEASED across os_sema_down so the
 * tick/ACK-RX can run and free slots -> no deadlock, then reacquired before
 * returning. sema-down-FIRST ordering keeps the count == free-slots exactly
 * (every claim consumes a token, every free returns one), so the post-wait
 * halow_ack_slot_alloc() always finds a slot. While the mutex is released no
 * other flush can proceed (it would need its own slot/token, and none is free
 * while we wait), so caller-held state (e.g. agg_buf) is safe across the wait.
 * tmo_ms==0 -> non-blocking try (used by the tick flush). Returns the slot
 * reserved (in_use==1) with the lock held, or NULL on timeout/non-blocking
 * failure. */
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
    /* Rate-scale the ACK like the data RA does: the peer's EVM ceiling is a
     * direct measure of how well THIS peer hears our signal, which is exactly
     * what governs whether OUR ACK frame reaches it. Fixed-rate ACKs (first
     * MCS10, then a fixed 6) each broke a link regime: fast modes die on weak
     * links, and on this HW the very low modes are their own broken regime.
     * Callers hold no lock here (both drop g_ack_mutex before send_ack). */
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
        /* Envelope Block-ACK when the peer is G2 and we have a seq window:
         * [evm][base:2][bitmap:8], bit i == seq base+i received. base is the
         * OLDEST seq in the window (rx_seq_last-63); window bit0 == newest,
         * so bitmap bit i mirrors window bit (63-i). */
        bool probe = (ap->compat < 2u) && (g_ack_cfg.env != 0u)
                     && (++ap->ack_probe_cnt >= 8u);
        if( probe ) ap->ack_probe_cnt = 0u;
        /* rx_seq_seen not required: an empty window (base 0, bitmap 0) is a
         * valid probe/beacon frame -- it announces "we speak envelope" and
         * frees nothing. Requiring it here deadlocked the bootstrap: the
         * window only fills from env bundles, which nobody sends until the
         * beacon works. */
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

/* Emit a peer's accumulated coalesce buffer as one A-MSDU bundle: claim a
 * single retry slot keyed by fnv1a(bundle), hand it to halow_tx, reset the
 * buffer. Caller MUST hold g_ack_mutex; it is released across the slot wait
 * (claim_locked) and across halow_tx (mirrors the retry path). A 1-subframe
 * bundle is unwrapped to a plain frame so a lone frame pays no bundle overhead.
 *
 * can_block=true (data path, tcps thread): BLOCKS on the slot semaphore when the
 * ACK window is full, so the window paces TX and TCP recv-window backpressure
 * engages -- no frame is ever fire-and-forget. can_block=false (tick): holds the
 * bundle (returns false) when no slot is free, retrying next tick. */
static bool halow_ack_agg_flush_locked( halow_ack_peer_t *p, bool can_block ){
    (void)can_block;   /* reserved for the decoupled-TX-backpressure path */
    if( p == NULL || p->agg_nsub == 0u ) return true;
    /* post-TX gap: give the peer's ACK for our previous bundle the air */
    if( (os_jiffies() - g_last_data_tx_jiff) < os_msecs_to_jiffies(g_ack_cfg.data_gap_ms) ){
        return false;   /* held; tick/next frame retries after the gap */
    }
    /* flow control: hold the bundle (don't enqueue, don't reset agg_buf) if the
     * LMAC TX buffer is nearly full. The tick / next-frame call retries once the
     * queue drains. Returns false when held. */
    if( halow_get_tx_vacancy() < HALOW_ACK_TX_VACANCY_LOW ) return false;

    halow_ack_slot_t *s = halow_ack_slot_claim_locked( 0u );   /* non-blocking: the tcps
     * thread drains the RF->TCP ring too, so blocking it here would starve RX
     * delivery (verified: a blocking claim turned B->A into 98% loss). */
    if( s == NULL ){
        /* ACK window full: HOLD the bundle (return false, leave agg_buf intact).
         * The caller (halow_ack_tx) then returns HALOW_ACK_TX_THROTTLE so the TCP
         * recv loop skips netconn_recv -> the blasting sender paces itself; the
         * tick (or the next frame once a slot frees) flushes this bundle. No
         * fire-and-forget -- every bundle keeps its delivery guarantee. */
        return false;
    }
    /* Re-validate under the lock: a racing flush for the same peer may have sent
     * this bundle while we waited for the slot (two flushers each claimed a
     * token when the window had room). If so, release our slot and leave. */
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
        /* Envelope v1 bundle: [A5][5A][ver|type][seq:2][nsub:1]{len,payload}.
         * agg_buf body (offset 3 onward) is layout-identical to the legacy
         * body, so we just re-prefix. Single-sub bundles stay wrapped -- the
         * type byte discriminates, no unwrap needed (G2 peers parse nsub=1).
         * s->seq feeds the Block-ACK match on our side of the retx path. */
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
     * window IS the pacer. The previous extra branch ("agg buffer can absorb
     * one more frame") let the recv loop keep consuming while the window was
     * pinned full -- bundles piled into agg_buf, flushes held, and every
     * over-capacity frame was consumed-then-THROTTLE-dropped (measured: ACK
     * RTT ~220 ms under bidir load, window 8 -> ~36 fps capacity, 40 fps
     * offered -> ~20% loss). With slot-gated acceptance the TCP recv loop
     * skips instead, the sender's TCP window closes, offered rate tracks the
     * ACK recycling rate, the TX backlog drains, RTT falls and capacity
     * rises: no frame is consumed without a delivery guarantee behind it. */
    /* Require TWO free slots: the probe passing with exactly one free slot
     * let the recv loop consume a chunk whose 4th frame flushed the coalesce
     * bundle into that last slot; the NEXT frame then hit a full window and
     * was consumed-then-THROTTLE-dropped (measured: ~10% loss at 40 fps with
     * RTT 150-220 ms). One spare slot covers the pending agg bundle; frames
     * beyond that stay in the TCP socket and the sender paces. */
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
         * full -> return THROTTLE and let the caller HOLD the frame (the
         * tcps stash): TCP recv pauses, the window closes, the sender paces
         * itself while the tick drains parking. NEVER drop here. */
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
            /* Still saturated. Bounded patience: a frame that can NEVER leave
             * (peer gone, frame permanently rejected) must not head-of-line
             * block the FIFO forever -- after ~5 s of failed ticks, drop it
             * loudly. Normal saturation never gets close: slots free within
             * one retry cycle (~100 ms). */
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

        /* Broadcast (or plain-path) send. Broadcast frames can never be ACKed,
         * so no retry slot can cover them: one faded preamble and the frame is
         * gone forever. Poor-conditions mitigation: transmit each broadcast
         * bc_repeat times back-to-back (the LMAC TX queue serialises the
         * copies). RX deliberately skips broadcast dedup -- RNS above dedups by
         * packet hash -- so the copies arrive as harmless duplicates. Repeats
         * are strictly best-effort: stop at the first failed send or when the
         * LMAC TX budget runs low, so the extra copies never displace live
         * unicast/ACK traffic. Unicast NOACK (max_retries==0) and oversized
         * frames keep a single copy. */
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
                /* RX counts every broadcast copy it hears; mirror it on TX or
                 * the main-page TX/RX numbers skew apart on announce-heavy
                 * links (user-exempted from strict matching, keep symmetric). */
                statistics_radio_register_tx_package(len);
            }
        }
        /* The frame was delivered if the FIRST copy left; a failed extra copy
         * (budget ran out mid-repeat) must not be reported as a drop of a
         * frame that actually went out. A failed FIRST copy is THROTTLE, not
         * a loss: the caller parks/stashes the frame and we retry (contract:
         * anything consumed from TCP must reach the air). */
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
    /* NOACK peer (cur_retries slid to 0): don't bundle -- a lost bundle would
     * lose every frame in it with no retry. Send plain. */
    if( p->cur_retries == 0u ){
        halow_ack_unlock();
        int32_t r = halow_tx(payload, len, dest_mac, pmcs);
        if( r < 0 ) return HALOW_ACK_TX_THROTTLE;   /* park & retry, never drop */
        statistics_radio_register_tx_package(len);
        return r;
    }

    /* ---- A-MSDU coalescing: pack per-peer frames into one bundle/MPDU/ACK ----
     * Guard ensures the frame (hdr3+len2+payload) fits a bundle and the fixed
     * agg_buf/FRAME_MAX; otherwise fall through to the plain per-frame path.
     * The bundle limit is MCS-aware: capped to the 802.11ah max payload for the
     * peer's current MCS so the LMAC can actually transmit the resulting MPDU. */
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
        /* flush was HELD (ACK window full or TX buffer low) -> the old bundle is
         * still here and this frame won't fit. Signal THROTTLE: the TCP recv loop
         * skips netconn_recv (TCP backpressure) while still draining RF->TCP. The
         * tick/next-frame flushes the held bundle once a slot frees. This replaces
         * the old drop-on-full -- under decoupled backpressure the sender paces
         * itself, so this path is reached only on transient saturation.
         * The frame was already consumed from TCP, so a THROTTLE here IS a real
         * loss for the sender -- count it, or thousands of frames vanish without
         * a trace in the stats (observed: 720/s eaten silently). */
        if( p->agg_nsub > 0u &&
            ( (uint32_t)p->agg_len + 2u + len > eff_bytes ||
              p->agg_nsub + 1u > HALOW_ACK_AGG_MAX_SUB ) ){
            halow_ack_unlock();
            return HALOW_ACK_TX_THROTTLE;   /* the wrapper parks or counts */
        }
        /* start a fresh bundle if empty */
        if( p->agg_nsub == 0u ){
            /* lazy-alloc coalesce buffer (kept for peer lifetime; freed on
             * eviction). On heap exhaustion, skip aggregation for this frame
             * and send it plain -- correct, just no throughput gain. */
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
     * Claim a retry slot NON-blocking (the tcps thread also drains the RF->TCP
     * ring, so it must not block here). On a full window, signal THROTTLE so the
     * TCP recv loop backpressures the sender; with agg on (default) this path is
     * rare anyway. Pacing: a saturated LMAC TX buffer must THROTTLE (frame
     * stays unconsumed) rather than -6-drop -- a lost frame here burns retry
     * budget for nothing. */
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

/* Snapshot the most-recent ack_fids entries of the rolling dedup window (most
 * recent first) as low-16 fids for a cumulative ACK. Caller MUST hold g_ack_mutex. */
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

/* Record one ACK round trip. born_rtt keeps the historical born-based stat;
 * the EWMA tracks ONLY first-attempt TX->ACK latency (retries_used==0), which
 * is what the first-retry pacing needs -- a slot that already retransmitted
 * carries its backoff waits in the timestamp distance and would inflate the
 * estimate with exactly the stalls we are trying to avoid. */
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

    /* ---- envelope v1 frames (PROTOCOL_DESIGN.md) ----
     * Any v1 frame doubles as the capability beacon: the peer demonstrably
     * speaks G2. ACK -> process the bitmap; BUNDLE -> record the seq window
     * (dedup hits included) and fall through to the normal data path;
     * anything else -> count and drop, never guess-parse (rule R3). */
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
        /* Cumulative ACK: free every outstanding slot whose fid appears among
         * the fids carried in this ACK frame. Bound nfids by the RECEIVED
         * LENGTH only, not our own ack_fids config: a peer configured with a
         * larger ack_fids legitimately carries more fids than we would send,
         * and capping them here silently dropped the tail -- those slots
         * stalled, retransmitted and died as "loss" (32 vs 16 = half the ACK
         * information thrown away). Protocol hard cap: HALOW_ACK_ACK_FIDS_MAX. */
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
     * frame (we are in the data path with an ACK/bundle-shaped payload or it
     * fell through from the envelope branch) -- it demonstrably has the
     * protocol layer. Legacy bundle magic check here covers G1 traffic. */
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
    /* Broadcast-destined data (addr3 == broadcast, e.g. RNS announce/transport
     * traffic or a peer that has not learned our MAC yet) gets NO ACK: the
     * sender never claimed a retry slot for it, so our ACK can never match one
     * -- it is pure airtime waste plus acks_rx_dup noise on the sender (one
     * small test showed ~1200 useless duplicate-fid hits). The RNS layer above
     * handles broadcast duplicates itself, so dedup is skipped too and the
     * rolling fid window stays pure-unicast for the cumulative ACKs. */
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
                /* defer: one ACK per ack_fids frames cuts the ACK-TXOP count, which is
                 * the main throughput limiter on 1MHz. The tick sends it after
                 * ack_hold_ms (well under the retry timeout). */
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
        /* Unicast to us but no peer slot available (table full of peers with
         * bundles/slots in flight): the frame IS delivered, but it can never
         * be ACKed -- the sender will retransmit to exhaustion. Count it so
         * the "why is the peer retransmitting" question has an answer. */
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
    /* Free a retired slot array once its grace period has passed (see
     * halow_ack_slots_retire). Check+swap under g_ack_mutex: the retire path
     * (config apply from the HTTP task) could otherwise free the same pointer
     * concurrently, or swap in a NEW retired array that we then freed
     * immediately -- defeating the grace period entirely. */
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
    /* NOTE: an ACK-starvation "pressure mode" (recycle slots at 1100 ms when
     * matches dry up) was tried here and REVERTED: starvation cannot tell
     * mutual-deaf saturation (recycle helps) from an ACK path that is simply
     * lossy while the data path is clean (B->A here: A's ACKs cross the 1 dBm
     * direction). In the latter case recycling murdered slots whose ACKs were
     * merely late/lost-in-flight -- the clean direction went 0.3% -> 5.1%
     * loss. The full-schedule lifetime stays unconditional; sustained MAX
     * offered bidir on a half-duplex link with a 65%-loss direction is a
     * collapse by physics, and real traffic (TCP window + RNS windowing)
     * never offers it. */
    for( uint32_t i = 0; i < g_ack_slot_count; i++ ){
        halow_ack_slot_t *s = &g_ack_slots[i];
        if( !s->in_use ) continue;
        /* Hard lifetime FIRST and UNGATED: a slot past its deadline is dropped
         * no matter what -- the deadline check used to sit below the backoff
         * `continue` and the TX-vacancy gate, so under mutual saturation (both
         * peers blasting) slots were neither retransmitted NOR dropped: the
         * window pinned at 8/8, acceptance stopped, goodput hit zero while
         * both CPUs idled (bench MAX blast, build 42). Dropping needs no TX
         * budget by definition. */
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
                /* G0 heuristic (the MAIN death path under a silent peer):
                 * 12 bundles dead without a single ACK == the peer has no ACK
                 * layer -> plain-only, stop wasting bundles its RNS parser
                 * cannot read. Measured: 406 deadline deaths with compat
                 * still L1 while a 2.2.0b peer dropped every bundle. */
                pdead->l0_strikes++;
                if( pdead->compat == 1u && pdead->l0_strikes >= 12u ){
                    pdead->compat = 0u;
                    pdead->l0_strikes = 0u;
                    pdead->l0_falls++;
                    log_warn("ack: peer %02x:%02x:%02x:%02x:%02x:%02x -> L0 (plain-only, dead bundles)",
                             pdead->mac[0],pdead->mac[1],pdead->mac[2],
                             pdead->mac[3],pdead->mac[4],pdead->mac[5]);
                }
                /* Feed RA only when the TX path is NOT saturated. A deadline
                 * drop under a stuffed TX buffer is congestion (our own queue
                 * couldn't drain), not channel loss -- punishing RA for it
                 * pins the peer at a low MCS, which drains even slower, which
                 * drops even more: a congestion death spiral (observed: one
                 * direction stuck at MCS0 ~60% "loss" while the peer ran
                 * MCS7 at 600+ kbit/s on the same channel). Retry-exhaustion
                 * drops (4 real air attempts, no ACK) still feed RA below. */
                if( halow_get_tx_vacancy() >= HALOW_ACK_TX_VACANCY_LOW ){
                    halow_ack_ra_on_drop(pdead);
                }
            }
            continue;
        }
        /* Exponential retransmit backoff: each retry waits twice as long as the
         * previous one. Without this, a frame whose ACK was lost retransmits
         * every timeout_ms; on a half-duplex link the retransmit flood deafens
         * the sender to the peer's (late-arriving) ACKs, so it retransmits yet
         * more -- a bidirectional livelock where one direction captures the
         * channel and the other starves to 100% loss even at trivial offered
         * load. Backing off exponentially drains the retransmit noise within
         * ~1 s so the reverse-direction ACKs can get through and break the
         * cycle. retries_used is the count already attempted; cap the shift so
         * a genuinely-lost frame still drops within bounded time.
         * Shift cap 3 (8x, ~800 ms at timeout=100): the old cap 5 (32x, 3.2 s)
         * let an overloaded frame ZOMBIE a slot for 6+ s -- under a bidir blast
         * the whole 8-slot window filled with zombies, acceptance collapsed to
         * ~1 frame/s and both directions died (bench: 96-98% loss). The layer
         * above (TCP) retransmits end-to-end anyway; a stale frame is worth
         * less than a free slot. */
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
         * untouched) and let the queue drain -- retransmitting into a saturated
         * LMAC would -6-drop silently and waste the retry budget. */
        if( halow_get_tx_vacancy() < HALOW_ACK_TX_VACANCY_LOW ) continue;

        halow_ack_peer_t *p = halow_ack_peer_find(s->dest_mac);
        if( p == NULL ){
            s->in_use = 0;
            halow_ack_token_return();   /* peer gone: free the slot token */
            continue;
        }
        /* Per-slot retry budget (fixed = max_retries; the lifetime cap above
         * already removed everything older). Was shared via the peer's
         * cur_retries, which with a sliding window would let several dropping
         * slots slide the peer to NOACK and disable retries entirely. */
        if( s->retries_used < g_ack_cfg.max_retries ){
            s->retries_used++;
            s->tx_jiff = now;
            g_ack_stats.retransmitted++;
            p->retransmitted++;
            uint8_t pmcs = p->tx_mcs;
            /* Copy out under the lock: once g_ack_mutex is dropped, an ACK for
             * this very fid can arrive, free the slot, and a tcps-thread claim
             * can immediately reuse it (lowest-index alloc) -- memcpy'ing a new
             * frame over s->frame while the halow_tx below still reads it: a
             * torn frame goes on air and the retry budget is already spent.
             * The tick task is the only retransmit context, so one static
             * scratch is safe. */
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
    /* Drain A-MSDU coalesce buffers held past agg_hold_ms (partial bundles that
     * never reached the size threshold in halow_ack_tx). Under saturation the
     * inline flush dominates; this only releases sparse/stragglers so a low-rate
     * peer isn't delayed indefinitely. Lock is held here; flush releases it
     * across halow_tx and reacquires. */
    if( g_ack_cfg.agg != 0u ){
        uint64_t hold_j = os_msecs_to_jiffies(g_ack_cfg.agg_hold_ms);
        if( hold_j == 0u ) hold_j = 1u;
        for( uint32_t i = 0; i < HALOW_ACK_MAX_PEERS; i++ ){
            halow_ack_peer_t *p = &g_ack_peers[i];
            if( !p->in_use || p->agg_nsub == 0u ) continue;
            if( (now - p->agg_first_jiff) >= hold_j ){
                /* Flush the partial bundle as soon as agg_hold_ms (2 ms default,
                 * i.e. the next tick) elapses. The old gate held stragglers until
                 * MAX_HOLD-50 (~950 ms): under saturation the inline flush fills
                 * bundles anyway, so the gate only ever fired on SPARSE traffic --
                 * and request/response protocols (RNS Resource windows: one small
                 * RESOURCE_REQ per round, partial tail bundle per window) round-
                 * tripped through ~1 s of coalesce hold each way, capping file
                 * transfers at 10-20 kbit/s over an otherwise idle link.
                 *
                 * The tick claiming a slot here can beat the tcps probe
                 * (halow_ack_tx_ready) to the window and make it over-read free
                 * slots -- but the extra frames are no longer consumed-then-
                 * dropped: the THROTTLE path parks them (bounded patience), so
                 * they go out a tick or two later. No loss, just a short park. */
                if( !halow_ack_agg_flush_locked(p, false) ){
                    /* Bundle lifetime cap: a bundle that still can't leave (no
                     * free slot, dead peer) must not sit forever -- past 1 s,
                     * drop it; TCP above retransmits end-to-end and late-but-
                     * sent is worth less than bounded latency. */
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
    /* Flush deferred (coalesced) ACKs whose ack_hold_ms window has elapsed. Lock
     * is held; released across halow_ack_send_ack/halow_tx and reacquired. */
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

/* The tick used to live on the SHARED os_work queue together with LED/telemetry/
 * watchdog-feed works: ONE work that blocked forever (observed on the bench:
 * 38+ s TX stall with wedges frozen -- tick dead, TX watchdog dead, no
 * recovery, no reboot) killed the ACK/retx/deferred-ACK machinery with it.
 * A dedicated task cannot be starved by unrelated works. It also FEEDS the
 * hardware watchdog: if the tick itself ever dies, the node resets in <=10 s
 * instead of hanging silently. */
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
    /* 4048 = the MAIN workqueue stack this tick used to run on; 3*1024 was
     * SMALLER than its old home while the call chain had grown -- prime
     * suspect for the mid-soak crash (stack overflow) seen on the bench. */
    os_task_set_stacksize(&g_ack_tick_task, 4048);
    /* REALTIME -- ABOVE the LMAC RX tasks (osal prio 86/87), which outrank
     * every app task and, under a heavy blast, can consume the CPU for longer
     * than the 10 s hardware-watchdog window with the tick (at NORMAL) never
     * scheduled: the node then resets SILENTLY -- no panic output, no tick-
     * stall canary (the statistics task starves too). Observed on the bench
     * ~15 min into a mixed soak (b113). This is safe now that the tick body
     * is bounded: the configdb/flash reads were moved out of its locked path
     * (halow_ack_default_mcs_refresh before the lock, halow_cfg_mcs_bw_refresh
     * from the statistics task) -- the earlier b50 web-UI freeze under an
     * ABOVE_NORMAL tick was this same multi-second flash read looping inside
     * the body, not the priority itself. RHINO mutex PI keeps a blocked
     * REALTIME tick from starving the lock holder. */
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
        /* TX loss AFTER retries: share of resolved frames (ACKed or retry-
         * exhausted) that ultimately failed -- the delivery loss the user
         * cares about. Frames rescued by retransmits are NOT a loss here.
         * The per-attempt RF loss stays derivable from the raw counters
         * (retransmitted / (tx_frames+retransmitted)); the RA's internal
         * EWMA (loss_q8 below) is the separate MCS-tuning signal. */
        out->loss_pct = (uint8_t)p->loss_iir_pct;   /* windowed IIR, not
            * lifetime-cumulative: conditions change, the display must too */
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

/* Effective link MTU from a peer-advertised value. advertised==0 means the
 * LinkRequest did not carry the (optional, HaLow-only) 3-byte signalling MTU --
 * standard Reticulum sends only the 64-byte core. The link's real MTU is still
 * bounded by the hardware (1MHz S1G max MSDU per MCS) and the configured RNS
 * limit, so default to that limit. Otherwise clamp the advertised value to it.
 * Stops the link stats showing MTU=0 for every standard-Reticulum link. */
static uint32_t halow_link_effective_mtu( uint32_t advertised ){
    uint32_t hw;
    uint32_t lim;
    int16_t rl;

    hw = halow_get_mtu(halow_cfg_mcs_get_cached());
    rl = rns_mtu_limit_get();
    lim = ((uint32_t)rl < hw) ? (uint32_t)rl : hw;
    return (advertised == 0u || advertised > lim) ? lim : advertised;
}

/* Deliver one decoded RNS frame to the TCP side: parse/register, HDLC-encode,
 * push into the TCP ring. Extracted so rf_to_tcp can call it once per subframe
 * when an A-MSDU bundle is received. */
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
        /* Capture the peer's advertised MTU if the (optional) signalling field is
         * present; otherwise default to the hw/rns limit so the link shows a real
         * MTU instead of 0. Either way, update the link's effective_mtu on a
         * LinkRequest. */
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
    /* Frames actually addressed to us (addr3 == our MAC, not broadcast): only
     * these may re-write an already-learned peer MAC in the link DB. */
    bool unicast_to_me = (dst_mac != NULL && memcmp(dst_mac, mac_broadcast, 6) != 0);

    /* Envelope v1 bundle: [A5][5A][0x1X][seq:2][nsub:1]{len,payload}.
     * Same strict walk as the legacy bundle; subframes deliver individually.
     * (seq was already recorded into the Block-ACK window by halow_ack_on_rx
     * BEFORE the dedup decision -- retransmitted dups keep their bit set.) */
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
        /* malformed envelope bundle: fall through would feed the raw envelope
         * to the RNS parser (guaranteed parse failure) -- drop explicitly */
        g_ack_stats.rx_env_unk++;
        return;
    }

    /* A-MSDU bundle? Validate (nsub/lens consume the frame exactly, nsub>=2)
     * then split into subframes and deliver each. A real bundle always parses;
     * on the astronomically unlikely magic collision the frame falls through to
     * single-frame delivery (which will simply fail the RNS parse and drop). */
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

        /* cached config (statistics task refreshes it): a LINKREQUEST flood
         * must not hammer the configdb/flash mutex on the tcps path */
        hw_mtu = halow_get_mtu(halow_cfg_mcs_get_cached());
        rns_mtu_limit = rns_mtu_limit_get();

        if ((uint32_t)rns_mtu_limit < hw_mtu) {
            mtu_limit = (uint32_t)rns_mtu_limit;
        } else {
            mtu_limit = hw_mtu;
        }

        rns_link_utils_clamp_mtu(pkg, len, &packet_info, mtu_limit, &original_mtu);
        log_info("cap link MTU from %db to %db", (int)original_mtu, (int)mtu_limit);

        /* original_mtu==0 means the LinkRequest did NOT carry the 3-byte signalling
         * extension (standard Reticulum sends only the 64-byte core). Default to the
         * hw/rns limit instead of leaving 0 (was showing as MTU=0 in link stats). */
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
