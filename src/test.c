#define LOG_LOCAL_LEVEL LOG_DEBUG
#include "test.h"
#include "halow.h"
#include "lib/logc/log.h"
#include "utils.h"
#include "osal/sleep.h"
#include <string.h>

#define TEST_BATCH      4
#define TEST_DURATION_S 3
#define MCS10_PKT_LEN   450

static void test_mcs10_quick(void)
{
    static uint8_t pkt[MCS10_PKT_LEN];
    for (uint32_t i = 0; i < MCS10_PKT_LEN; i++) pkt[i] = i;

    halow_config_set_bandwidth(1);

    log_info("=== MCS10 BW1 TEST len=%u ===", MCS10_PKT_LEN);

    uint32_t n = 0;
    int64_t t0 = get_time_ms();

    while (1) {
        int64_t now = get_time_ms();
        if (now - t0 >= TEST_DURATION_S * 1000) break;

        int32_t ret = halow_tx_batch(pkt, MCS10_PKT_LEN, mac_broadcast, TEST_BATCH, 10);
        if (ret > 0) {
            n += (uint32_t)ret;
            log_info("  MCS10 tx_batch ret=%d total=%u", ret, n);
        } else {
            log_warn("  MCS10 tx_batch ret=%d total=%u", ret, n);
        }
    }

    os_sleep_ms(500);

    uint32_t pps = n / TEST_DURATION_S;
    uint32_t kbps = (uint32_t)(((uint64_t)n * MCS10_PKT_LEN * 8) / (TEST_DURATION_S * 1024));
    log_info("=== MCS10 BW1 DONE: %u pkt, %u pkt/s, %u Kbit/s ===", n, pps, kbps);
}

void test_run_all(void)
{
    os_sleep_ms(2000);
    test_mcs10_quick();
    log_info("MCS10 test complete");
}
