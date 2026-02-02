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
#include "syscfg.h"
#include "lib/lmac/lmac_def.h"
#include "halow.h"
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

static void halow_rx_handler(struct hgic_rx_info *info,
                            uint8 *data,
                            int32 len){
    (void)info;

    if (!data || len <= 0) {
        return;
    }

    os_printf("RX %d bytes: ", len);

    for (int32 i = 0; i < len; i++) {
        uint8 c = data[i];
        if (c >= 32 && c <= 126) {
            _os_printf("%c", c);
        } else {
            _os_printf(".");
        }
    }

    _os_printf("\r\n");
}


__init static void sys_network_init(void)
{
#if SYS_NETWORK_SUPPORT
    ip_addr_t ipaddr, netmask, gw;
    struct netdev *ndev;

    tcpip_init(NULL, NULL);
    sock_monitor_init();

    /*register gmac netif: e0, can not enable WIFI_BRIDGE_EN*/
    ndev = (struct netdev *)dev_get(HG_GMAC_DEVID);
    if (ndev) {
        lwip_netif_add(ndev, "e0", NULL, NULL, NULL);
        lwip_netif_set_default(ndev);
        lwip_netif_set_dhcp2("e0", 1);
        os_printf("add e0 interface!\r\n");
    }

#endif
}

int sys_sleepcb_init( void ){

}

static int32 sys_main_loop(struct os_work *work){
    static uint8_t  pa7_val = 0;
    static uint32_t seq = 0;
    char buf[32];

    (void)work;

    pa7_val = !pa7_val;
    gpio_set_val(PA_7, pa7_val);

    int32_t len = os_snprintf(buf, sizeof(buf), "SEQ=%lu", (unsigned long)seq++);
    halow_tx((const uint8_t *)buf, len);

    
	ip_addr_t ip = lwip_netif_get_ip2("e0");
	if (ip.addr == 0) {
		lwip_netif_set_dhcp2("e0", 1);
	}

    os_run_work_delay(&main_wk, 300);
    return 0;
}

//void sys_sleepdata_init(void){}

__init static void sys_cfg_load(void)
{
    if (syscfg_init(&sys_cfgs, sizeof(sys_cfgs)) == RET_OK) {
        return;
    }

    os_printf("use default params.\r\n");
    syscfg_set_default_val();
    syscfg_save();
}

sysevt_hdl_res sys_event_hdl(uint32 event_id, uint32 data, uint32 priv)
{
#if SYS_NETWORK_SUPPORT
    struct netif *nif;
#endif
	switch (event_id) {
#if SYS_NETWORK_SUPPORT
        case SYS_EVENT(SYS_EVENT_NETWORK, SYSEVT_LWIP_DHCPC_DONE):
            nif = netif_find("e0");
            break;
#endif
    }
    return SYSEVT_CONTINUE;
}

__init int main(void){
    extern uint32 __sinit, __einit;
    mcu_watchdog_timeout(0);
    os_printf("use default params.\r\n");
    sys_cfg_load();
    syscfg_save();

    syscfg_check();
    sys_event_init(32);
    sys_event_take(0xffffffff, sys_event_hdl, 0);
	
    os_printf("LED GPIO output.\r\n");
	gpio_set_dir(PA_7, GPIO_DIR_OUTPUT);
    gpio_set_val(PA_7, 0);
	
    sys_network_init();
    skbpool_init(SKB_POOL_ADDR, (uint32)SKB_POOL_SIZE, 90, 0);
    halow_init(WIFI_RX_BUFF_ADDR, WIFI_RX_BUFF_SIZE, TDMA_BUFF_ADDR, TDMA_BUFF_SIZE);
    halow_set_rx_cb(halow_rx_handler);
	OS_WORK_INIT(&main_wk, sys_main_loop, 0);
    os_run_work(&main_wk);
    sysheap_collect_init(&sram_heap, (uint32)&__sinit, (uint32)&__einit); // delete init code from heap
    return 0;
}

