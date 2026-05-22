#define LOG_LOCAL_LEVEL LOG_DEBUG
#include "test.h"
#include "halow.h"
#include "lib/logc/log.h"
#include "utils.h"
#include "osal/sleep.h"
#include <string.h>

static void test_speed_mcs10(uint16_t pkt_len, uint32_t duration_sec)
{
    static uint8_t pkt[704];
    for (uint32_t i = 0; i < pkt_len && i < 704; i++) pkt[i] = i;

    uint32_t total_sent = 0;
    uint32_t total_bytes = 0;
    uint32_t t_start = (uint32_t)os_jiffies();

    log_info("=== MCS10 speed: len=%u dur=%us ===", pkt_len, duration_sec);

    while (((uint32_t)os_jiffies() - t_start) < (duration_sec * 1000u)) {
        int32_t ret = halow_tx(pkt, pkt_len, mac_broadcast, 10);
        if (ret == 0) {
            total_sent++;
            total_bytes += pkt_len;
        }
    }

    uint32_t elapsed_ms = (uint32_t)os_jiffies() - t_start;
    uint32_t kbps = (elapsed_ms > 0) ? (total_bytes * 8u / (elapsed_ms / 1000u)) / 1000u : 0;
    uint32_t pps = (elapsed_ms > 0) ? (total_sent * 1000u / elapsed_ms) : 0;

    log_info("=== MCS10 speed result: %u pkts %u KB %u ms => %u kbps %u pps ===",
             total_sent, total_bytes / 1024u, elapsed_ms, kbps, pps);
}

void test_run_all(void)
{
    os_sleep_ms(2000);
    test_speed_mcs10(260, 30);
}
