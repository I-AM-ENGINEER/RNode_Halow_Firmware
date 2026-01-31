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

static void lmac_rx_handler(struct lmac_ops *ops, struct hgic_rx_info *info, uint8 *data, int32 len){
    (void)info;

    _os_printf("\r\n");
    os_printf("RX len=%u: ", len);
    for (uint32 i = 0; i < len; i++) {
        uint8 c = data[i];
        if (c >= 32 && c <= 126) {
            _os_printf("%c", c);
        } else {
            _os_printf(".");
        }
    }
    _os_printf("\r\n");
}

static void sys_dbginfo_print(void){
    static uint8 _print_buf[512];

    cpu_loading_print(sys_status.dbg_top == 2, (struct os_task_info *)_print_buf, sizeof(_print_buf)/sizeof(struct os_task_info));
    sysheap_status(&sram_heap, (uint32 *)_print_buf, sizeof(_print_buf)/4, 0);
    skbpool_status((uint32 *)_print_buf, sizeof(_print_buf)/4, 0);
    lmac_transceive_statics(sys_status.dbg_lmac);
    irq_status();
}

static int32 sys_main_loop(struct os_work *work)
{
    static uint8_t pa7_val = 0;
    static uint8_t tmp[500];

    (void)work;

    while (1) {
        /* Blink LED */
        pa7_val = !pa7_val;
        gpio_set_val(PA_7, pa7_val);

        /* random length: 1..500 */
        uint32_t len = ((uint32_t)rand() % sizeof(tmp)) + 1;

        /* random payload */
        for (uint32_t i = 0; i < len; i++) {
            tmp[i] = (uint8_t)rand();
        }

        lmac_raw_tx(tmp, (int32_t)len);

        os_sleep_ms(300);
    }
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
    os_run_work(&main_wk);
    sysheap_collect_init(&sram_heap, (uint32)&__sinit, (uint32)&__einit); // delete init code from heap
    return 0;
}

