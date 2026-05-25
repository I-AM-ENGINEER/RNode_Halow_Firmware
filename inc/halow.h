#ifndef __HALOW_H_
#define __HALOW_H_

#include "lib/lmac/ieee802_11_defs.h"
#include <stdint.h>
#include <stdbool.h>

struct hgic_rx_info;

typedef void (*halow_rx_cb)(
    struct hgic_rx_info *info,
    struct ieee80211_hdr *hdr,
    uint8_t *data,
    int32_t len);

typedef struct {
    uint16_t central_freq;
    uint8_t bandwidth;
    uint8_t mcs;
    uint8_t rf_power;
    uint8_t rf_super_power;
} halow_config_t;

bool halow_init(uint32_t rxbuf, uint32_t rxbuf_size,
                uint32_t tdma_buf, uint32_t tdma_buf_size);

void halow_set_rx_cb(halow_rx_cb cb);
int32_t halow_tx(const uint8_t *data, uint32_t len, const uint8_t destination_mac[6], uint8_t mcs);
void halow_config_set_bandwidth(uint8_t bw);
void halow_config_load(halow_config_t *cfg);
void halow_config_save(const halow_config_t *cfg);
void halow_config_apply(const halow_config_t *cfg);
void halow_config_set_mcs(uint8_t mcs);
void halow_set_cca_enabled(uint8_t enabled);

#define HALOW_MCS_DEFAULT 0xFF  /* use globally configured MCS */

#endif //__HALOW_H_
