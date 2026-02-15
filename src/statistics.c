#include "basic_include.h"
#include "statistics.h"
#include "halow_lbt.h"
#include <string.h>
#include <time.h>

#define STATISTICS_DEBUG

#ifdef STATISTICS_DEBUG
#define stat_debug(fmt, ...)  os_printf("[STAT] " fmt "\r\n", ##__VA_ARGS__)
#else
#define stat_debug(fmt, ...)  do { } while (0)
#endif

volatile statistics_radio_t g_stat_radio;

static struct os_task g_stat_task;

void statistics_radio_register_rx_package(uint32_t len){
    g_stat_radio.rx_packets++;
    g_stat_radio.rx_bytes += len;
}

void statistics_radio_register_tx_package(uint32_t len){
    g_stat_radio.tx_packets++;
    g_stat_radio.tx_bytes += len;
}

statistics_radio_t statistics_radio_get(void){
    return g_stat_radio;
}

void statistics_radio_reset(void){
    memset(&g_stat_radio, 0, sizeof(statistics_radio_t));
}

void statistics_uptime_get(char* return_str, uint32_t max_len){
    char tmp_str[32];
    if(return_str == NULL){
        return;
    }
    tmp_str[0] = '\0';
    struct timespec tm;
    os_systime(&tm);
    uint32_t time_s = tm.tv_sec;
    uint32_t time_m = tm.tv_sec / 60;
    uint32_t time_h = time_m / 60;
    uint32_t time_d = time_h / 24;

    time_s %= 60;
    time_m %= 60;
    time_h %= 24;
    
    if(time_d != 0){
        snprintf(
            tmp_str, 
            sizeof(tmp_str), 
            "%ud ", 
            time_d
        );
    }

    if((time_h != 0) || (time_d != 0)){
        snprintf(
            tmp_str + strlen(tmp_str), 
            sizeof(tmp_str) - strlen(tmp_str), 
            "%uh ", 
            time_h
        );
    }
    
    if((time_m != 0) || (time_h != 0) || (time_d != 0)){
        snprintf(
            tmp_str + strlen(tmp_str), 
            sizeof(tmp_str) - strlen(tmp_str), 
            "%um ", 
            time_m
        );
    }

    snprintf(
        tmp_str + strlen(tmp_str), 
        sizeof(tmp_str) - strlen(tmp_str), 
        "%us", 
        time_s
    );

    strncpy(return_str, tmp_str, max_len);
}

static void statistics_task(void *arg){
    (void)arg;
    static uint32_t rx_bytes_previous;
    static uint32_t tx_bytes_previous;
    while(1){
        uint32_t rx_bytes_now = g_stat_radio.rx_bytes;
        uint32_t tx_bytes_now = g_stat_radio.tx_bytes;

        uint32_t rx_delta = rx_bytes_now - rx_bytes_previous;
        uint32_t tx_delta = tx_bytes_now - tx_bytes_previous;

        g_stat_radio.rx_bitps = rx_delta*8;
        g_stat_radio.tx_bitps = tx_delta*8;

        rx_bytes_previous = rx_bytes_now;
        tx_bytes_previous = tx_bytes_now;
        
        g_stat_radio.bkgnd_noise_dbm = halow_lbt_background_long_dbm_get();
        g_stat_radio.bkgnd_noise_dbm_now = halow_lbt_background_short_dbm_get();
        g_stat_radio.airtime = halow_lbt_airtime_get();
        g_stat_radio.ch_util = halow_lbt_ch_util_get();
        os_sleep(1);
    }
}

int32_t statistics_init( void ){
    int32_t ret;

    ret = os_task_init((const uint8 *)"stat", &g_stat_task, statistics_task, 0);
    stat_debug("os_task_init -> %d", (int)ret);
    if (ret != 0) {
        return ret;
    }

    ret = os_task_set_stacksize(&g_stat_task, STATISTICS_TASK_STACK);
    stat_debug("os_task_set_stacksize -> %d", (int)ret);

    ret = os_task_set_priority(&g_stat_task, STATISTICS_TASK_PRIO);
    stat_debug("os_task_set_priority -> %d", (int)ret);

    ret = os_task_run(&g_stat_task);
    stat_debug("os_task_run -> %d", (int)ret);
    return ret;
}
