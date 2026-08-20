#ifndef TEST_STUB_HALOW_H
#define TEST_STUB_HALOW_H

#include <stdint.h>
#include <stdbool.h>

#define HALOW_MCS_DEFAULT 0xFFu

typedef struct {
    uint8_t mcs;
} halow_config_t;

typedef struct {
    uint32_t rf_tcp_dropped;
    uint32_t tcps_held;
    uint32_t tcps_beat;
    uint32_t tcps_recv_ok;
    int32_t  tcps_last_err;
} halow_tx_dbg_t;

extern halow_tx_dbg_t g_tx_dbg;

void     halow_config_load(halow_config_t *cfg);
int32_t  halow_tx(const uint8_t *buf, uint16_t len, const uint8_t dest_mac[6], uint8_t mcs);
int32_t  halow_tx_p(const uint8_t *buf, uint16_t len, const uint8_t dest_mac[6],
                    uint8_t mcs, uint8_t bw);
uint32_t halow_get_tx_vacancy(void);
void     halow_tx_vacancy_watchdog(void);
uint32_t halow_get_mtu(uint8_t mcs);
uint8_t  halow_cfg_mcs_get_cached(void);

#endif
