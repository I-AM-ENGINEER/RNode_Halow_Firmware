#define LOG_LOCAL_LEVEL LOG_DEBUG
#include "test.h"
#include "halow.h"
#include "lib/logc/log.h"
#include "utils.h"
#include "osal/sleep.h"
#include "chip/txw4002ack803/sysctrl.h"
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

static void test_temperature(void)
{
    log_info("=== Temperature test ===");

    int temp_before = tsensor_meas(0);
    log_info("temp before TX: %d C", temp_before);

    /* Run heavy TX for 5 seconds to heat up the chip */
    static uint8_t pkt[260];
    for (uint32_t i = 0; i < 260; i++) pkt[i] = (uint8_t)i;

    uint32_t t_start = (uint32_t)os_jiffies();
    uint32_t sent = 0;
    while (((uint32_t)os_jiffies() - t_start) < 5000u) {
        if (halow_tx(pkt, 260, mac_broadcast, 10) == 0)
            sent++;
    }
    log_info("TX done: %u pkts in 5s", sent);

    /* Read temperature after TX */
    int temp_after = tsensor_meas(0);
    log_info("temp after TX:  %d C  (delta=%d)", temp_after, temp_after - temp_before);

    /* Keep reading for another 10 seconds to watch it cool down */
    for (int i = 0; i < 10; i++) {
        os_sleep_ms(1000);
        int temp = tsensor_meas(0);
        log_info("temp +%ds: %d C", i + 1, temp);
    }

    log_info("=== Temperature test done ===");
}

void test_run_all(void)
{
    os_sleep_ms(2000);
    //test_speed_mcs10(260, 30);
}
