#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_DEBUG
#include "lib/logc/log.h"
#include "test.h"
#include "halow.h"
#include "utils.h"
#include "osal/sleep.h"
#include "osal/task.h"
#include "osal/string.h"   /* os_malloc/os_free */
#include "chip/txw4002ack803/sysctrl.h"
#include <string.h>

/* ---- individual tests ---- */

static void test_tx_loop(uint16_t pkt_len) {
    static uint8_t pkt[704];
    for (uint32_t i = 0; i < pkt_len && i < 704; i++) pkt[i] = (uint8_t)i;

    uint32_t total_sent = 0;
    log_info("=== TX loop: len=%u ===", pkt_len);

    while (1) {
        if (halow_tx(pkt, pkt_len, mac_broadcast, 1) == 0)
            total_sent++;
        if ((total_sent % 100) == 0)
            log_info("sent: %u", total_sent);
    }
}

static void test_temperature(void) {
    int temp_before = tsensor_meas(0);
    log_info("temp before TX: %d C", temp_before);

    static uint8_t pkt[260];
    for (uint32_t i = 0; i < 260; i++) pkt[i] = (uint8_t)i;

    uint32_t t_start = (uint32_t)os_jiffies();
    uint32_t sent = 0;
    while (((uint32_t)os_jiffies() - t_start) < 5000u) {
        if (halow_tx(pkt, 260, mac_broadcast, 10) == 0)
            sent++;
    }
    log_info("TX done: %u pkts in 5s", sent);

    int temp_after = tsensor_meas(0);
    log_info("temp after TX:  %d C  (delta=%d)", temp_after, temp_after - temp_before);

    for (int i = 0; i < 10; i++) {
        os_sleep_ms(1000);
        log_info("temp +%ds: %d C", i + 1, tsensor_meas(0));
    }
}

static void test_throughput(void) {
    static const uint8_t mcs_list[] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
    static const uint8_t bw_list[]  = {1, 2, 4, 8};
    /* heap, not static: 8 KiB parked forever in .bss for a debug-only sweep
     * on a chip where code shares RAM with data */
    uint8_t *pkt = (uint8_t *)os_malloc(8192);
    if (pkt == NULL) {
        log_warn("test_throughput: no mem for pkt");
        return;
    }
    for (uint32_t i = 0; i < 8192; i++) pkt[i] = (uint8_t)i;

    /* Max payload per MCS/BW: MCS0-7 use 511 sym limit, MCS10 uses 685 sym limit, 40B overhead margin */
    static const uint16_t max_pkt[9][4] = {
        /* MCS0  */ { 700, 1600, 3400, 7400 },
        /* MCS1  */ { 1450, 3200, 6800, 8192 },
        /* MCS2  */ { 2200, 4900, 8192, 8192 },
        /* MCS3  */ { 3000, 6500, 8192, 8192 },
        /* MCS4  */ { 4500, 8192, 8192, 8192 },
        /* MCS5  */ { 6050, 8192, 8192, 8192 },
        /* MCS6  */ { 6800, 8192, 8192, 8192 },
        /* MCS7  */ { 7600, 8192, 8192, 8192 },
        /* MCS10 */ { 500, 0, 0, 0 },  /* 685 sym, ndbps=6, 1MHz only */
    };
    static const uint8_t bw_idx_map[] = {0, 0, 1, 0, 2, 0, 0, 0, 3}; /* bw->idx: 1→0 2→1 4→2 8→3 */

    log_info("=== THROUGHPUT TEST ===");

    for (uint32_t bi = 0; bi < 4; bi++) {
        uint8_t bw = bw_list[bi];
        halow_config_set_bandwidth(bw);

        for (uint32_t mi = 0; mi < sizeof(mcs_list); mi++) {
            uint8_t mcs = mcs_list[mi];
            /* MCS10 only valid at 1 MHz */
            if (mcs == 10 && bw != 1)
                continue;
            //uint16_t pkt_len = (mcs == 10) ? 450 : 500;
            uint16_t pkt_len = (mcs == 10) ? 450 : max_pkt[mcs][bw_idx_map[bw]];

            /* warmup: send for 1 second */
            uint32_t t0 = (uint32_t)os_jiffies();
            while (((uint32_t)os_jiffies() - t0) < 1000u) {
                halow_tx(pkt, pkt_len, mac_broadcast, mcs);
            }

            /* measure: count packets over 5 seconds */
            uint32_t t_start = (uint32_t)os_jiffies();
            uint32_t sent = 0;
            while (((uint32_t)os_jiffies() - t_start) < 5000u) {
                if (halow_tx(pkt, pkt_len, mac_broadcast, mcs) == 0)
                    sent++;
            }
            uint32_t elapsed_ms = (uint32_t)os_jiffies() - t_start;

            uint32_t pps = sent * 1000u / elapsed_ms;
            /* kbit/s = sent * pkt_len * 8 / (elapsed_ms / 1000), split to avoid overflow */
            uint32_t kbps = (uint32_t)((uint64_t)sent * (uint64_t)pkt_len * 8ull / (uint64_t)elapsed_ms);

            log_info("MCS%u %uMHz  %uB  %u pkts/%lums  %lu pps  %lu kbit/s",
                     mcs, bw, pkt_len, sent, (unsigned long)elapsed_ms,
                     (unsigned long)pps,
                     (unsigned long)kbps);
        }
    }

    os_free(pkt);
    log_info("=== THROUGHPUT TEST DONE ===");
}

/* ---- task entry point ---- */

static void test_task_fn(void *arg) {
    (void)arg;
    os_sleep_ms(2000);

    /* Uncomment the test you want to run: */
    // test_tx_loop(500);
    // test_temperature();
    test_throughput();
}

/* ---- public API (called from main) ---- */

void test_start(void) {
    static struct os_task task;
    os_task_init((const uint8 *)"test", &task, test_task_fn, 0);
    os_task_set_stacksize(&task, 2048);
    extern int32_t _os_task_set_priority(struct os_task *task, uint8_t priority);
    _os_task_set_priority(&task, OS_TASK_PRIORITY_ABOVE_NORMAL + 1);
    os_task_run(&task);
}
