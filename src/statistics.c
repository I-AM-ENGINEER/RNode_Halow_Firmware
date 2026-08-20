#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_STATISTICS

#include "basic_include.h"
#include "statistics.h"
#include "halow_lbt.h"
#include "halow.h"
#include "lib/logc/log.h"
#include <string.h>
#include <time.h>

extern __bobj uint64 cpu_loading_tick;

volatile statistics_radio_t g_stat_radio;

static struct os_task g_stat_task;

void statistics_radio_register_rx_package( uint32_t len ) {
    g_stat_radio.rx_packets++;
    g_stat_radio.rx_bytes += len;
}

void statistics_radio_register_tx_package( uint32_t len ) {
    g_stat_radio.tx_packets++;
    g_stat_radio.tx_bytes += len;
}

statistics_radio_t statistics_radio_get( void ) {
    return g_stat_radio;
}

void statistics_radio_reset( void ) {
    g_stat_radio.rx_bytes = 0;
    g_stat_radio.tx_bytes = 0;
    g_stat_radio.rx_packets = 0;
    g_stat_radio.tx_packets = 0;
    g_stat_radio.rx_bitps = 0;
    g_stat_radio.tx_bitps = 0;
}

void statistics_cpu_load_get( char *return_str, uint32_t max_len ) {
    struct os_task_info tsk_info[2];
    uint32 count;
    uint32 diff_tick;
    uint64 jiff;
    uint32 idle_pct;
    uint32 cpu_pct;

    if (return_str == NULL || max_len == 0) {
        return;
    }

    jiff = os_jiffies();
    diff_tick = DIFF_JIFFIES(cpu_loading_tick, jiff);
    cpu_loading_tick = jiff;

    if (diff_tick == 0) {
        os_snprintf(return_str, max_len, "0%%");
        return;
    }

    count = os_task_runtime(tsk_info, 2);
    if (count < 2) {
        os_snprintf(return_str, max_len, "0%%");
        return;
    }

    idle_pct = (tsk_info[1].time * 100U) / diff_tick;
    if (idle_pct > 100U) {
        idle_pct = 100U;
    }

    cpu_pct = 100U - idle_pct;
    os_snprintf(return_str, max_len, "%u%%", cpu_pct);
}

void statistics_heap_usage_get( char *return_str, uint32_t max_len ) {
    uint32_t total;
    uint32_t free;
    uint32_t used;
    uint32_t used_pct;

    if (return_str == NULL || max_len == 0) {
        return;
    }

    total = sysheap_totalsize(&sram_heap);
    free  = sysheap_freesize(&sram_heap);

    if (free > total) {
        free = total;
    }

    if (total == 0) {
        os_snprintf(return_str, max_len, "---");
        return;
    }

    used = total - free;
    used_pct = (used * 100U) / total;

    os_snprintf(return_str, max_len,
                "%u/%u KiB (%u%%)",
                used / 1024,
                total / 1024,
                used_pct);
}

void statistics_uptime_get( char *return_str, uint32_t max_len ) {
    char tmp_str[32];
    struct timespec tm;
    uint32_t time_s;
    uint32_t time_m;
    uint32_t time_h;
    uint32_t time_d;

    if (return_str == NULL) {
        return;
    }

    tmp_str[0] = '\0';

    os_systime(&tm);
    time_s = tm.tv_sec;
    time_m = tm.tv_sec / 60;
    time_h = time_m / 60;
    time_d = time_h / 24;

    time_s %= 60;
    time_m %= 60;
    time_h %= 24;

    if (time_d != 0) {
        snprintf(tmp_str,
                 sizeof(tmp_str),
                 "%ud ",
                 time_d);
    }

    if ((time_h != 0) || (time_d != 0)) {
        snprintf(tmp_str + strlen(tmp_str),
                 sizeof(tmp_str) - strlen(tmp_str),
                 "%uh ",
                 time_h);
    }

    if ((time_m != 0) || (time_h != 0) || (time_d != 0)) {
        snprintf(tmp_str + strlen(tmp_str),
                 sizeof(tmp_str) - strlen(tmp_str),
                 "%um ",
                 time_m);
    }

    snprintf(tmp_str + strlen(tmp_str),
             sizeof(tmp_str) - strlen(tmp_str),
             "%us",
             time_s);

    strncpy(return_str, tmp_str, max_len);
}

static void statistics_task( void *arg ) {
    static uint32_t rx_bytes_previous;
    static uint32_t tx_bytes_previous;
    static uint8_t  rx_idle_s, tx_idle_s;

    (void)arg;

    while(1) {
        uint32_t rx_bytes_now = g_stat_radio.rx_bytes;
        uint32_t tx_bytes_now = g_stat_radio.tx_bytes;

        uint32_t rx_delta = (rx_bytes_now >= rx_bytes_previous) ? (rx_bytes_now - rx_bytes_previous) : 0;
        uint32_t tx_delta = (tx_bytes_now >= tx_bytes_previous) ? (tx_bytes_now - tx_bytes_previous) : 0;

        /* IIR runs every second, traffic or not: y = (3y + x)/4. The output
         * decays progressively in silence instead of freezing; 10 idle
         * seconds clamp the tail to zero. */
        g_stat_radio.rx_bitps = (g_stat_radio.rx_bitps * 3u + rx_delta * 8u) / 4u;
        g_stat_radio.tx_bitps = (g_stat_radio.tx_bitps * 3u + tx_delta * 8u) / 4u;
        if( rx_delta != 0u ) rx_idle_s = 0u;
        else if( ++rx_idle_s >= 10u ) g_stat_radio.rx_bitps = 0u;
        if( tx_delta != 0u ) tx_idle_s = 0u;
        else if( ++tx_idle_s >= 10u ) g_stat_radio.tx_bitps = 0u;
        (void)rx_idle_s; (void)tx_idle_s;

        rx_bytes_previous = rx_bytes_now;
        tx_bytes_previous = tx_bytes_now;

        /* ACK-tick stall canary: the tick feeds the hardware watchdog, so a
         * frozen tick resets the node silently. This task is independent of
         * g_ack_mutex and can still log while the tick is stuck. */
        {
            static uint32_t last_tick_count;
            static uint8_t  stalled_secs;
            extern volatile uint32_t g_ack_tick_count;
            uint32_t tc = g_ack_tick_count;
            if( tc == last_tick_count ){
                if( ++stalled_secs >= 3u ){
                    log_warn("stat: ack tick STALLED %us (count=%u)",
                             (unsigned)stalled_secs, (unsigned)tc);
                }
            }else{
                if( stalled_secs >= 3u ){
                    log_info("stat: ack tick recovered after %us stall",
                             (unsigned)stalled_secs);
                }
                stalled_secs   = 0u;
                last_tick_count = tc;
            }
        }

        g_stat_radio.bkgnd_noise_dbm = halow_lbt_background_long_dbm_get();
        g_stat_radio.bkgnd_noise_dbm_now = halow_lbt_background_short_dbm_get();
        g_stat_radio.airtime = halow_lbt_airtime_get();
        g_stat_radio.ch_util = halow_lbt_ch_util_get();

        /* Keep the TX-path MCS/BW cache warm from this low-stakes context:
         * the TX hot path must never block on the flash mutexes (it feeds
         * the hardware watchdog). */
        halow_cfg_mcs_bw_refresh();

        halow_gain_pilot_tick();

        os_sleep(1);
    }
}

void statistics_init( void ) {
    os_task_init((const uint8 *)"stat", &g_stat_task, statistics_task, 0);
    os_task_set_stacksize(&g_stat_task, STATISTICS_TASK_STACK);
    os_task_set_priority(&g_stat_task, STATISTICS_TASK_PRIO);
    os_task_run(&g_stat_task);

    log_info("statistics init ok");
}
