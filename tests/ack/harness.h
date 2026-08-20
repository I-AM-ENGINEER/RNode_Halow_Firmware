#ifndef TEST_ACK_HARNESS_H
#define TEST_ACK_HARNESS_H

#include <stdint.h>
#include <stdbool.h>

#define TEST_TX_CAP_LEN 4200
#define TEST_TX_CAP_N   128

typedef struct {
    uint8_t buf[TEST_TX_CAP_LEN];
    uint16_t len;
    uint8_t mac[6];
    uint8_t mcs;
} test_tx_cap_t;

void test_time_reset(void);
void test_advance_ms(uint32_t ms);

void test_vacancy_set(uint32_t v);

void test_tx_reset(void);
int  test_tx_count(void);
const test_tx_cap_t *test_tx_at(int i);
const test_tx_cap_t *test_tx_last(void);

void configdb_reset(void);
int  test_kv_get(const char *key, int16_t *val);
void test_kv_set(const char *key, int16_t val);

uint32_t test_watchdog_feeds(void);
int      test_task_inits(void);

#endif
