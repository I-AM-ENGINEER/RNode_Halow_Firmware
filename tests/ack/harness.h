#ifndef TEST_ACK_HARNESS_H
#define TEST_ACK_HARNESS_H

#include <stdint.h>
#include <stdbool.h>

#define TEST_TX_CAP_LEN 4200
#define TEST_TX_CAP_N   1024

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

/* RF TX fault injection + no-wait audit */
void     test_tx_fail_next(int n);     /* next N halow_tx/halow_tx_p fail (-5) */
uint32_t test_sleep_calls(void);       /* os_sleep_ms/os_sleep invocations */
uint64_t test_time_jiff(void);         /* current virtual jiffies */

/* heap accounting + fault injection for os_malloc/os_free */
void     test_malloc_reset(void);
void     test_malloc_fail_next(int n);
uint32_t test_malloc_live_blocks(void);
uint32_t test_malloc_live_bytes(void);

/* RF->TCP delivery capture (tcp_server_send) */
#define TEST_TCP_CAP_LEN 4400
#define TEST_TCP_CAP_N   256

typedef struct {
    uint8_t buf[TEST_TCP_CAP_LEN];
    uint16_t len;
    uint64_t at_jiff;   /* virtual time of the tcp_server_send call */
} test_tcp_cap_t;

void test_tcp_reset(void);
int  test_tcp_count(void);
const test_tcp_cap_t *test_tcp_at(int i);
void test_tcp_full_set(int full);

/* halow_get_mtu row override (per-MCS max MSDU) */
void test_mtu_row_set(const uint32_t row[8]);

void configdb_reset(void);
int  test_kv_get(const char *key, int16_t *val);
void test_kv_set(const char *key, int16_t val);

uint32_t test_watchdog_feeds(void);
int      test_task_inits(void);

#endif
