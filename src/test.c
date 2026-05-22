#define LOG_LOCAL_LEVEL LOG_DEBUG
#include "test.h"
#include "halow.h"
#include "lib/logc/log.h"
#include "utils.h"
#include "osal/sleep.h"
#include <string.h>

static void test_mcs_burst(uint8_t mcs, uint32_t count, uint16_t pkt_len)
{
    static uint8_t pkt[704];
    for (uint32_t i = 0; i < pkt_len && i < 704; i++) pkt[i] = i;

    log_info("=== MCS%u burst: %u pkts len=%u ===", mcs, count, pkt_len);
    int32_t ret = halow_tx_batch(pkt, pkt_len, mac_broadcast, count, mcs);
    log_info("  MCS%u ret=%d", mcs, ret);
    os_sleep_ms(2000);
}

void test_run_all(void)
{
    os_sleep_ms(2000);

    /* MCS10 fine sweep: find exact payload limit */
    test_mcs_burst(10, 1, 450);
    test_mcs_burst(10, 1, 460);
    test_mcs_burst(10, 1, 470);
    test_mcs_burst(10, 1, 475);
    test_mcs_burst(10, 1, 480);

    /* MCS0 regression */
    test_mcs_burst(0,  2, 500);

    log_info("MCS10 fine sweep complete");
}
