#ifndef __HALOW_ACK_H__
#define __HALOW_ACK_H__

#include <stdint.h>
#include <stdbool.h>


#define HALOW_ACK_MAGIC0           0xA5u
#define HALOW_ACK_MAGIC1           0x5Au
#define HALOW_ACK_ACK_LEN_MIN      5u
#define HALOW_ACK_ACK_LEN_MAX      (3u + 2u * HALOW_ACK_ACK_FIDS_MAX)
#define HALOW_ACK_ACK_MCS          10u

#define HALOW_ACK_DEFAULT_MAX_RETRIES   3u
#define HALOW_ACK_DEFAULT_TIMEOUT_MS    40u
#define HALOW_ACK_DEFAULT_RATE_ADAPT    0u
#define HALOW_ACK_DEFAULT_RA_LOSS_UP    5u
#define HALOW_ACK_DEFAULT_RA_LOSS_DOWN  30u
#define HALOW_ACK_RA_STALE_MS           60000u
#define HALOW_ACK_RA_COOLDOWN_MS        60000u

#define HALOW_ACK_DEFAULT_WINDOW        8u
#define HALOW_ACK_DEFAULT_ACK_FIDS      4u
#define HALOW_ACK_SLOTS_MAX             32u
#define HALOW_ACK_ACK_FIDS_MAX          8u

typedef struct {
    uint8_t  max_retries;
    uint16_t timeout_ms;
    uint8_t  rate_adapt;
    uint8_t  ra_loss_up;
    uint8_t  ra_loss_down;
    uint8_t  window;
    uint8_t  ack_fids;
} halow_ack_config_t;

typedef struct {
    uint32_t tx_frames;
    uint32_t acked;
    uint32_t retransmitted;
    uint32_t dropped;
    uint32_t acks_sent;
    uint32_t acks_rx_dup;
    uint32_t noack_hits;
    int8_t   last_evm;
    uint8_t  outstanding;
    uint8_t  peers;
} halow_ack_stats_t;

typedef struct {
    uint8_t  tx_mcs;        /* 0xFF = global default */
    uint8_t  cur_retries;
    uint32_t tx_frames;
    uint32_t acked;
    uint32_t dropped;
    int8_t   evm;
    uint8_t  loss_pct;
} halow_ack_peer_stats_t;

void halow_ack_config_set_default(halow_ack_config_t *cfg);
void halow_ack_config_load(halow_ack_config_t *cfg);
void halow_ack_config_save(const halow_ack_config_t *cfg);
void halow_ack_config_get_live(halow_ack_config_t *cfg);
void halow_ack_config_apply(const halow_ack_config_t *cfg);

void     halow_ack_init(void);
bool     halow_ack_is_ack_frame(const uint8_t *data, uint16_t len);
int32_t  halow_ack_tx(const uint8_t *payload, uint16_t len, const uint8_t dest_mac[6]);

bool     halow_ack_on_rx(const uint8_t *payload, uint16_t len, const uint8_t src_mac[6],
                         int8_t evm,
                         const uint8_t **out_payload, uint16_t *out_len);

void     halow_ack_tick(void);
void     halow_ack_stats_get(halow_ack_stats_t *out);
bool     halow_ack_peer_stats_by_mac(const uint8_t mac[6], halow_ack_peer_stats_t *out);

#endif /* __HALOW_ACK_H__ */
