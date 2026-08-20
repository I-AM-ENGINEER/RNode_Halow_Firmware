#ifndef TEST_STUB_HALOW_H
#define TEST_STUB_HALOW_H

#include <stdint.h>
#include <stdbool.h>

#define HALOW_MCS_DEFAULT 0xFFu

typedef struct {
    uint8_t mcs;
} halow_config_t;

void     halow_config_load(halow_config_t *cfg);
int32_t  halow_tx(const uint8_t *buf, uint16_t len, const uint8_t dest_mac[6], uint8_t mcs);
int32_t  halow_tx_p(const uint8_t *buf, uint16_t len, const uint8_t dest_mac[6],
                    uint8_t mcs, uint8_t bw);
uint32_t halow_get_tx_vacancy(void);
void     halow_tx_vacancy_watchdog(void);

#endif
