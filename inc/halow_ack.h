#ifndef __HALOW_ACK_H__
#define __HALOW_ACK_H__

#include <stdint.h>
#include <stdbool.h>

/* legacy fid-list ACK: [A5][5A][evm int8][fid16 x n]; evm >= 0x80 */
#define HALOW_ACK_MAGIC0           0xA5u
#define HALOW_ACK_MAGIC1           0x5Au
#define HALOW_ACK_ACK_LEN_MIN      5u
#define HALOW_ACK_ACK_LEN_MAX      (3u + 2u * HALOW_ACK_ACK_FIDS_MAX)
#define HALOW_ACK_ACK_MCS_MIN      1u
#define HALOW_ACK_ACK_MCS_MAX      6u

/* A-MSDU bundle: [A5][AD][nsub]([len_le16][payload])* */
#define HALOW_ACK_AGG_MAGIC0          0xA5u
#define HALOW_ACK_AGG_MAGIC1          0xADu
#define HALOW_ACK_AGG_MAX_SUB         8u
#define HALOW_ACK_AGG_HOLD_MS_DEF     2u
#define HALOW_ACK_ACK_HOLD_MS_DEF     20u   /* < timeout_ms/2 */

#define HALOW_ACK_DEFAULT_MAX_RETRIES   3u
#define HALOW_ACK_DEFAULT_TIMEOUT_MS    100u  /* > ACK turnaround */
#define HALOW_ACK_DEFAULT_RATE_ADAPT    1u
#define HALOW_ACK_DEFAULT_RA_LOSS_UP    5u
#define HALOW_ACK_DEFAULT_RA_LOSS_DOWN  30u
#define HALOW_ACK_RA_STALE_MS           60000u
#define HALOW_ACK_RA_COOLDOWN_MS        500u
#define HALOW_ACK_RA_STEP_GAP_MS        250u

#define HALOW_ACK_BC_REPEAT_DEF         2u
#define HALOW_ACK_BC_REPEAT_MAX         3u

#define HALOW_ACK_DEFAULT_WINDOW        10u
#define HALOW_ACK_DEFAULT_ACK_FIDS      16u
#define HALOW_ACK_SLOTS_MAX             16u
#define HALOW_ACK_ACK_FIDS_MAX          16u

/* envelope v1: [A5][5A][ver:4|type:4][body]; ver<=7 keeps byte2 < 0x80 */
#define HALOW_ENV_MAGIC0                 0xA5u
#define HALOW_ENV_MAGIC1                 0x5Au
#define HALOW_ENV_VER                    1u
#define HALOW_ENV_TYPE_BUNDLE            0u
#define HALOW_ENV_TYPE_ACK               1u
#define HALOW_ENV_TYPE_EXT               15u
#define HALOW_ENV_BUNDLE_HDR             6u   /* magic2 + seq2 + nsub1 */
#define HALOW_ENV_ACK_LEN                14u  /* magic2 + evm + base2 + bitmap8 */
#define HALOW_ACK_SEQ_WINDOW             64u

static inline uint8_t halow_env_ver( const uint8_t *d ){ return (uint8_t)(d[2] >> 4); }
static inline uint8_t halow_env_type( const uint8_t *d ){ return (uint8_t)(d[2] & 0x0Fu); }

typedef struct {
    uint8_t  max_retries;
    uint16_t timeout_ms;
    uint8_t  rate_adapt;
    uint8_t  ra_loss_up;
    uint8_t  ra_loss_down;
    uint8_t  window;
    uint8_t  ack_fids;
    uint8_t  agg;
    uint16_t agg_bytes;
    uint16_t agg_hold_ms;
    uint16_t ack_hold_ms;
    uint8_t  bc_repeat;
    uint8_t  env;
    uint16_t data_gap_ms;
} halow_ack_config_t;

#define HALOW_ACK_DATA_GAP_MS_DEF       40u

typedef struct {
    uint32_t tx_frames;
    uint32_t acked;
    uint32_t retransmitted;
    uint32_t dropped;
    uint32_t acks_sent;
    uint32_t acks_tx_fail;
    uint32_t acks_rx_dup;
    uint32_t acks_rx_frames;
    uint32_t drop_deadline;   /* slot lifetime hit */
    uint32_t drop_exhaust;    /* retries exhausted */
    uint32_t drop_throttle;   /* pend FIFO overflow after THROTTLE */
    uint32_t drop_agg_full;
    uint32_t drop_plain_vac;
    uint32_t drop_plain_slot;
    uint32_t env_tx_bundles;
    uint32_t env_rx_bundles;
    uint32_t env_tx_acks;
    uint32_t env_rx_acks;
    uint32_t rx_env_unk;      /* envelope frames dropped: unknown (ver,type) or malformed */
    uint8_t  ack_mcs_last;
    uint32_t ack_rtt_hits;
    uint32_t ack_rtt_sum_ms;  /* avg = sum/hits over slot born->ACK-match */
    uint32_t ack_rtt_ewma_ms; /* first-attempt TX->ACK latency; paces first retx */
    uint32_t noack_hits;
    int8_t   last_evm;
    uint8_t  outstanding;
    uint8_t  peers;
    uint32_t ra_ack_calls;
    uint32_t ra_upshifts;
    uint32_t ra_downshifts;
    uint32_t ra_blocked_loss;
    uint32_t ra_blocked_gap;
    uint32_t ra_blocked_max;
    uint32_t bc_repeats;
} halow_ack_stats_t;

typedef struct {
    uint8_t  tx_mcs;        /* HALOW_MCS_DEFAULT = global config MCS */
    uint8_t  cur_retries;
    uint32_t tx_frames;
    uint32_t acked;
    uint32_t dropped;
    int8_t   evm;
    uint8_t  loss_pct;      /* TX loss AFTER retries, windowed IIR */
    uint32_t tx_bytes;
    uint32_t retransmitted;
    int32_t  last_tx_s;
    uint16_t acks_since_step;
    uint16_t loss_q8;       /* RA tuning loss EWMA, 0..256 == 0..100% */
    int32_t  gap_ms;
    uint8_t  compat;        /* 0 plain-only, 1 legacy magics, 2 envelope */
    uint32_t l0_falls;
} halow_ack_peer_stats_t;

void halow_ack_config_set_default(halow_ack_config_t *cfg);
void halow_ack_config_load(halow_ack_config_t *cfg);
void halow_ack_config_save(const halow_ack_config_t *cfg);
void halow_ack_config_get_live(halow_ack_config_t *cfg);
void halow_ack_config_apply(const halow_ack_config_t *cfg);

void     halow_ack_init(void);
bool     halow_ack_radio_quiet(void);
bool     halow_ack_link_busy(void);
bool     halow_ack_is_internal_frame(const uint8_t *data, uint16_t len);
void     halow_ack_env_malformed(void);
int32_t  halow_ack_tx(const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6]);
bool     halow_ack_tx_ready(void);

/* TX path saturated: backpressure for the TCP recv loop, not an error. */
#define HALOW_ACK_TX_THROTTLE   (-7)

bool     halow_ack_on_rx(const uint8_t *payload, uint16_t len,
                         const uint8_t src_mac[6], const uint8_t dst_mac[6],
                         int8_t evm,
                         const uint8_t **out_payload, uint16_t *out_len);

void     halow_ack_tick(void);
void     halow_ack_stats_get(halow_ack_stats_t *out);
bool     halow_ack_peer_stats_by_mac(const uint8_t mac[6], halow_ack_peer_stats_t *out);

#endif /* __HALOW_ACK_H__ */
