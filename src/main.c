#include "basic_include.h"
#include "lib/lmac/lmac.h"
#include "lib/skb/skb.h"
#include "lib/skb/skb_list.h"
#include "lib/bus/macbus/mac_bus.h"
#include "lib/atcmd/libatcmd.h"
#include "lib/bus/xmodem/xmodem.h"
#include "lib/net/skmonitor/skmonitor.h"
#include "lib/net/dhcpd/dhcpd.h"
#include "lib/net/utils.h"
#include "lib/umac/ieee80211.h"
#include "lib/umac/wifi_mgr.h"
#include "lib/umac/wifi_cfg.h"
#include "lib/common/atcmd.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/sys.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "netif/ethernetif.h"
#include "lib/net/skmonitor/skmonitor.h"
#include "pairled.h"
#include "syscfg.h"
#include "lib/lmac/lmac_def.h"
#ifdef MULTI_WAKEUP
#include "lib/common/sleep_api.h"
#include "hal/gpio.h"
#include "lib/lmac/lmac.h"
#include "lib/common/dsleepdata.h"
#endif
//#include "atcmd.c"

static struct os_work main_wk;
extern uint32_t srampool_start;
extern uint32_t srampool_end;

extern void lmac_transceive_statics(uint8 en);


static void sys_dbginfo_print(void){
    static uint8 _print_buf[512];

    cpu_loading_print(sys_status.dbg_top == 2, (struct os_task_info *)_print_buf, sizeof(_print_buf)/sizeof(struct os_task_info));
    sysheap_status(&sram_heap, (uint32 *)_print_buf, sizeof(_print_buf)/4, 0);
    skbpool_status((uint32 *)_print_buf, sizeof(_print_buf)/4, 0);
    lmac_transceive_statics(sys_status.dbg_lmac);
    irq_status();
}

static uint32_t crc32_simple(const uint8_t *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFF;

    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint32_t b = 0; b < 8; b++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }

    return ~crc;
}

struct rx_stats {
    uint32_t rx_ok;
    uint32_t rx_crc_err;
    uint32_t rx_len_err;
    uint32_t rx_loss;

    uint32_t rx_bytes;     /* суммарно принятый payload */

    uint32_t last_seq;
    uint8_t  seq_valid;
};

static struct rx_stats g_rx_stats;

static void lmac_rx_handler(struct hgic_rx_info *info,
                            uint8 *data,
                            int32 len)
{
    (void)info;

    const int hdr_len = 12;

    if (!data || len < hdr_len) {
        g_rx_stats.rx_len_err++;
        return;
    }

    uint32_t seq       = *(uint32_t *)(data + 0);
    uint32_t total_len = *(uint32_t *)(data + 4);
    uint32_t rx_crc    = *(uint32_t *)(data + 8);

    if (total_len != (uint32_t)len) {
        g_rx_stats.rx_len_err++;
        return;
    }

    uint32_t payload_len = (uint32_t)len - hdr_len;
    uint8_t *payload     = data + hdr_len;

    uint32_t calc_crc = crc32_simple(payload, payload_len);
    if (calc_crc != rx_crc) {
        g_rx_stats.rx_crc_err++;
        return;
    }

    /* packet loss */
    if (g_rx_stats.seq_valid) {
        uint32_t exp = g_rx_stats.last_seq + 1;
        if (seq > exp) {
            g_rx_stats.rx_loss += (seq - exp);
        }
    }

    g_rx_stats.last_seq  = seq;
    g_rx_stats.seq_valid = 1;

    g_rx_stats.rx_ok++;
    g_rx_stats.rx_bytes += payload_len;
}

static void lmac_rx_stats_print(void)
{
    static uint32_t sec_cnt = 0;
    static uint32_t last_bytes = 0;

    uint32_t ok   = g_rx_stats.rx_ok;
    uint32_t crc  = g_rx_stats.rx_crc_err;
    uint32_t len  = g_rx_stats.rx_len_err;
    uint32_t loss = g_rx_stats.rx_loss;

    uint32_t total = ok + crc + len + loss;
    uint32_t per   = total ? ((crc + loss) * 1000 / total) : 0;

    /* bitrate for last interval (bps) */
    uint32_t cur_bytes = g_rx_stats.rx_bytes;
    uint32_t delta_b   = cur_bytes - last_bytes;
    last_bytes = cur_bytes;

    uint32_t bitrate = delta_b * 8; /* bits per second */

    os_printf(
        "RX: ok=%u loss=%u crc=%u len=%u PER=%u.%u%% rate=%u bps\r\n",
        ok, loss, crc, len,
        per / 10, per % 10,
        bitrate
    );

    sec_cnt++;

    /* reset every 60 seconds */
    if (sec_cnt >= 60) {
        memset(&g_rx_stats, 0, sizeof(g_rx_stats));
        sec_cnt = 0;
        last_bytes = 0;
        os_printf("RX stats reset\r\n");
    }
}

static int32 sys_main_loop(struct os_work *work){
    static uint8_t  pa7_val = 0;
    static uint8_t  tmp[500];
    static uint32_t seq = 0;

    (void)work;

    /* Blink LED */
    pa7_val = !pa7_val;
    gpio_set_val(PA_7, pa7_val);

    /* header size */
    const uint32_t hdr_len = 12;

    /* random total length: hdr + payload (>=1 byte payload) */
    uint32_t total_len = hdr_len + ((uint32_t)(sizeof(tmp) - hdr_len));

    uint8_t *p = tmp;

    /* packet number */
    *(uint32_t *)(p + 0) = seq;

    /* total length */
    *(uint32_t *)(p + 4) = total_len;

    /* payload start */
    uint8_t *payload = p + hdr_len;
    uint32_t payload_len = total_len - hdr_len;

    static const char pattern[] = "123456789";
    const uint32_t pattern_len = sizeof(pattern) - 1;

    for (uint32_t i = 0; i < payload_len; i++) {
        payload[i] = pattern[i % pattern_len];
    }

    uint32_t crc = crc32_simple(payload, payload_len);
    *(uint32_t *)(p + 8) = crc;

    lmac_raw_tx_bcast(tmp, (int32_t)total_len);

    seq++;

    os_run_work_delay(&main_wk, 10);
    return 0;
}

static int32_t rx_stat_loop(struct os_work *work)
{
    (void)work;

    lmac_rx_stats_print();
    os_run_work_delay(work, 1000);
    return 0;
}

__init int main(void){
    extern uint32 __sinit, __einit;
    mcu_watchdog_timeout(0);
    os_printf("use default params.\r\n");
    syscfg_set_default_val();
    syscfg_save();

    syscfg_check();
	
	gpio_set_dir(PA_7, GPIO_DIR_OUTPUT);
    gpio_set_val(PA_7, 0);
	
    skbpool_init(SKB_POOL_ADDR, (uint32)SKB_POOL_SIZE, 90, 0);
    lmac_only_init(WIFI_RX_BUFF_ADDR, WIFI_RX_BUFF_SIZE, TDMA_BUFF_ADDR, TDMA_BUFF_SIZE);
    lmac_raw_register_rx_cb(lmac_rx_handler);
	OS_WORK_INIT(&main_wk, sys_main_loop, 0);
    //OS_WORK_INIT(&main_wk, rx_stat_loop, 0);
    os_run_work(&main_wk);
    sysheap_collect_init(&sram_heap, (uint32)&__sinit, (uint32)&__einit); // delete init code from heap
    return 0;
}

