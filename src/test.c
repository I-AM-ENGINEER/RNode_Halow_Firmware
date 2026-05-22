#define LOG_LOCAL_LEVEL LOG_DEBUG
#include "test.h"
#include "halow.h"
#include "lib/logc/log.h"
#include "utils.h"
#include "osal/sleep.h"
#include <string.h>

static void test_mcs_burst(uint8_t mcs, uint32_t count, uint16_t pkt_len)
{
    static uint8_t pkt[512];
    for (uint32_t i = 0; i < pkt_len && i < 512; i++) pkt[i] = i;

    log_info("=== MCS%u burst: %u pkts len=%u ===", mcs, count, pkt_len);
    int32_t ret = halow_tx_batch(pkt, pkt_len, mac_broadcast, count, mcs);
    log_info("  MCS%u ret=%d", mcs, ret);
    os_sleep_ms(3000);
}

void test_run_all(void)
{
    os_sleep_ms(2000);

    /* MCS10: verify up to 400B works, 450B rejected */
    test_mcs_burst(10, 2, 200);
    test_mcs_burst(10, 2, 400);
    test_mcs_burst(10, 2, 450);

    /* MCS0: verify still works at 450B */
    test_mcs_burst(0,  2, 450);

    log_info("MCS10 limit + MCS0 verification complete");
}
