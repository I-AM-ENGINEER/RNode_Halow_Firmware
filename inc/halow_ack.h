#ifndef __HALOW_ACK_H__
#define __HALOW_ACK_H__

#include <stdint.h>
#include <stdbool.h>


#define HALOW_ACK_MAGIC0           0xA5u
#define HALOW_ACK_MAGIC1           0x5Au
#define HALOW_ACK_ACK_LEN_MIN      5u
#define HALOW_ACK_ACK_LEN_MAX      (3u + 2u * HALOW_ACK_ACK_FIDS_MAX)
/* ACK rate follows the peer's EVM ceiling; a fixed high MCS kills weak links. */
#define HALOW_ACK_ACK_MCS_MIN      1u
#define HALOW_ACK_ACK_MCS_MAX      6u

/* Bundle: [0xA5][0xAD][nsub]([len_le16][payload])* -- one MPDU, one TXOP, one ACK. */
#define HALOW_ACK_AGG_MAGIC0          0xA5u
#define HALOW_ACK_AGG_MAGIC1          0xADu
#define HALOW_ACK_AGG_MAX_SUB         8u
#define HALOW_ACK_AGG_HOLD_MS_DEF     2u
/* One ACK per ack_fids frames or ack_hold_ms, whichever is first; keep
 * ack_hold_ms < timeout_ms/2 so the ACK beats the sender's retry timer. */
#define HALOW_ACK_ACK_HOLD_MS_DEF     20u

#define HALOW_ACK_DEFAULT_MAX_RETRIES   3u
/* Must clear the ACK turnaround (ack_hold + ACK airtime + LBT) or peers
 * retransmit every frame. */
#define HALOW_ACK_DEFAULT_TIMEOUT_MS    100u
#define HALOW_ACK_DEFAULT_RATE_ADAPT    1u
#define HALOW_ACK_DEFAULT_RA_LOSS_UP    5u
#define HALOW_ACK_DEFAULT_RA_LOSS_DOWN  30u
#define HALOW_ACK_RA_STALE_MS           60000u
#define HALOW_ACK_RA_COOLDOWN_MS        500u
#define HALOW_ACK_RA_STEP_AFTER         10u
#define HALOW_ACK_RA_STEP_GAP_MS        250u

/* Broadcast gets no ACK: bc_repeat back-to-back copies are its only loss protection. */
#define HALOW_ACK_BC_REPEAT_DEF         2u
#define HALOW_ACK_BC_REPEAT_MAX         3u

#define HALOW_ACK_DEFAULT_WINDOW        10u
#define HALOW_ACK_DEFAULT_ACK_FIDS      32u
#define HALOW_ACK_SLOTS_MAX             32u
/* Must cover every bundle still in flight plus the rolling dedup window. */
#define HALOW_ACK_ACK_FIDS_MAX          32u

/* ==== L1 envelope v1 ====
 * [0xA5][0x5A][ver:4|type:4][body] -- type 0 BUNDLE, 1 ACK. ver<=7 keeps
 * byte2<0x80, clear of the legacy ACK's int8 evm byte. */
#define HALOW_ENV_MAGIC0                 0xA5u
#define HALOW_ENV_MAGIC1                 0x5Au
#define HALOW_ENV_VER                    1u
#define HALOW_ENV_TYPE_BUNDLE            0u
#define HALOW_ENV_TYPE_ACK               1u
#define HALOW_ENV_TYPE_EXT               15u
#define HALOW_ENV_BUNDLE_HDR             6u   /* magic2 + seq2 + nsub1 */
#define HALOW_ENV_ACK_LEN                14u  /* magic2 + ver|type + evm + base2 + bitmap8 */
#define HALOW_ACK_SEQ_WINDOW             64u

typedef struct {
    uint8_t  max_retries;
    uint16_t timeout_ms;
    uint8_t  rate_adapt;
    uint8_t  ra_loss_up;
    uint8_t  ra_loss_down;
    uint8_t  window;
    uint8_t  ack_fids;
    uint8_t  agg;          /* 1 = coalesce per-peer RNS frames into A-MSDU bundles */
    uint16_t agg_bytes;    /* flush threshold: emit a bundle once it reaches this size */
    uint16_t agg_hold_ms;  /* max ms a partial bundle waits before the tick flushes it */
    uint16_t ack_hold_ms;  /* ACK coalescing: send ACK every ack_fids frames or after this many ms (0=every frame) */
    uint8_t  bc_repeat;    /* broadcast TX copies per frame, 1..3 (no ACK exists for broadcast; repeats are its only loss protection) */
    uint8_t  env;          /* 1 = speak envelope v1 to G2 peers (0 forces legacy formats everywhere; RX always understands both) */
    uint16_t data_gap_ms;
} halow_ack_config_t;

#define HALOW_ACK_DATA_GAP_MS_DEF       40u

typedef struct {
    uint32_t tx_frames;
    uint32_t acked;
    uint32_t retransmitted;
    uint32_t dropped;
    uint32_t acks_sent;
    uint32_t acks_tx_fail;    /* ACK frames the TX path refused (budget/alloc) */
    uint32_t acks_rx_dup;
    uint32_t acks_rx_frames;  /* ACK frames received (fid-hits = acked+dups) */
    uint32_t drop_deadline;   /* slot hit the 800 ms lifetime (incl. congestion) */
    uint32_t drop_exhaust;    /* retries exhausted: real RF loss after 4 tries */
    uint32_t drop_throttle;   /* THROTTLE/congestion drops at accept time */
    uint32_t drop_agg_full;   /* throttle site: agg guard, held bundle + no fit */
    uint32_t drop_plain_vac;  /* throttle site: plain path, TX vacancy low */
    uint32_t drop_plain_slot; /* throttle site: plain path, no free slot */
    uint32_t env_tx_bundles; /* envelope v1 bundles transmitted */
    uint32_t env_rx_bundles; /* envelope v1 bundles received */
    uint32_t env_tx_acks;    /* envelope v1 Block-ACKs transmitted */
    uint32_t env_rx_acks;    /* envelope v1 Block-ACKs received */
    uint32_t rx_env_unk;     /* envelope frames with unknown (ver,type): dropped */
    uint8_t  ack_mcs_last;    /* rate of the most recent ACK frame (adaptive) */
    uint32_t ack_rtt_hits;    /* ACK matches that freed a live slot */
    uint32_t ack_rtt_sum_ms;  /* sum of (match_time - slot born) [ms]; avg = sum/hits */
    uint32_t ack_rtt_ewma_ms; /* EWMA of FIRST-attempt TX->ACK latency [ms]; 0 = no
                               * clean sample yet. Paces the first retransmit so it
                               * never fires while the ACK can still be in flight. */
    uint32_t noack_hits;
    int8_t   last_evm;
    uint8_t  outstanding;
    uint8_t  peers;
    /* RA diagnostics: why tx_mcs does/doesn't climb. */
    uint32_t ra_ack_calls;     /* on_ack reached the climb logic */
    uint32_t ra_upshifts;      /* actual MCS steps up */
    uint32_t ra_downshifts;    /* actual MCS steps down */
    uint32_t ra_blocked_loss;  /* ready=false (loss > ra_loss_up) */
    uint32_t ra_blocked_gap;   /* ready but now < next_step_allowed */
    uint32_t ra_blocked_max;   /* tx_mcs already at RA_MAX_MCS */
    uint32_t bc_repeats;       /* extra broadcast copies transmitted (bc_repeat > 1) */
} halow_ack_stats_t;

typedef struct {
    uint8_t  tx_mcs;        /* 0xFF = global default */
    uint8_t  cur_retries;
    uint32_t tx_frames;
    uint32_t acked;
    uint32_t dropped;
    int8_t   evm;
    uint8_t  loss_pct;      /* TX loss AFTER retries (windowed IIR):
                             * dropped/(acked+dropped)*100 -- frames rescued
                             * by retransmits are not a loss here */
    /* cumulative TX accounting (unicast ACK-tracked path only) */
    uint32_t tx_bytes;
    uint32_t retransmitted; /* per-attempt RF loss signal: retransmitted/
                             * (tx_frames+retransmitted) -- NOT the display
                             * metric, kept for diagnostics */
    int32_t  last_tx_s;     /* unix ts of last TX to this peer (0 = never) */
    /* live RA state (diagnostics) */
    uint16_t acks_since_step;
    uint16_t loss_q8;       /* RA/MCS-tuning loss EWMA (0..256 == 0..100%);
                             * event-driven on ACK/drop, separate from
                             * loss_pct by design */
    int32_t  gap_ms;        /* ms remaining before next up-step is allowed (<0 = allowed now) */
    uint8_t  compat;        /* 0 plain-only (G0), 1 legacy magics (G1), 2 envelope (G2) */
    uint32_t l0_falls;      /* times downgraded to plain-only */
} halow_ack_peer_stats_t;

void halow_ack_config_set_default(halow_ack_config_t *cfg);
void halow_ack_config_load(halow_ack_config_t *cfg);
void halow_ack_config_save(const halow_ack_config_t *cfg);
void halow_ack_config_get_live(halow_ack_config_t *cfg);
void halow_ack_config_apply(const halow_ack_config_t *cfg);

void     halow_ack_init(void);
bool     halow_ack_is_ack_frame(const uint8_t *data, uint16_t len);
bool     halow_ack_radio_quiet( void );   /* no in-flight slots and no TX for 1 s */
bool     halow_ack_link_busy( void );
bool     halow_ack_is_internal_frame(const uint8_t *data, uint16_t len);
int32_t  halow_ack_tx(const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6]);
/* Proactive TX-backpressure probe: returns true if the TX path can accept another
 * frame right now (a retry slot is free, or some peer's coalesce buffer still has
 * room). tcp_server's recv loop calls this BEFORE netconn_recv so that, when the
 * path is saturated, it simply doesn't pull another chunk from the TCP client
 * (the sender paces itself via its recv window) -- the frame is never consumed,
 * so it is never dropped. This is what makes a full TCP blast lossless. */
bool     halow_ack_tx_ready(void);
/* halow_ack_tx / halow_pkg_handler_tcp_to_rf return this when the TX path can't
 * accept another frame right now (ACK retry-window full AND coalesce buffer full
 * AND the LMAC TX buffer low). It is NOT an error: it is a backpressure signal
 * propagated up to tcp_server's recv loop, which then SKIPS netconn_recv (so the
 * blasting TCP sender is paced by its own recv window) while CONTINUING to drain
 * the RF->TCP ring (RX delivery unaffected). This is the only way to pace a full
 * TCP blast without dropping frames or starving the receive path. */
#define HALOW_ACK_TX_THROTTLE   (-7)

bool     halow_ack_on_rx(const uint8_t *payload, uint16_t len,
                         const uint8_t src_mac[6], const uint8_t dst_mac[6],
                         int8_t evm,
                         const uint8_t **out_payload, uint16_t *out_len);

void     halow_ack_tick(void);
void     halow_ack_stats_get(halow_ack_stats_t *out);
bool     halow_ack_peer_stats_by_mac(const uint8_t mac[6], halow_ack_peer_stats_t *out);

#endif /* __HALOW_ACK_H__ */
