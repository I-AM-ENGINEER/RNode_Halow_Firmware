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
#include "lib/lmac/lmac_def.h"
#include "halow.h"
#include "tcp_server.h"
#include "hal/spi_nor.h"
#include <lib/fal/fal.h>
#include <lib/flashdb/flashdb.h>
#include "littelfs_port.h"
#include "configdb.h"
#include "tftp_server.h"
#include "config_page.h"
#include "net_ip.h"
#include "ota.h"
#ifdef MULTI_WAKEUP
#include "lib/common/sleep_api.h"
#include "hal/gpio.h"
#include "lib/lmac/lmac.h"
#include "lib/common/dsleepdata.h"
#endif
// #include "atcmd.c"

static struct os_work main_wk;
extern uint32_t srampool_start;
extern uint32_t srampool_end;
uint8 g_mac[6];

__attribute__((used))
struct system_status sys_status;

//extern void lmac_transceive_statics(uint8 en);

static void halow_rx_handler(struct hgic_rx_info *info,
                             const uint8 *data,
                             int32 len) {
    (void)info;

    if (!data || len <= 0) {
        return;
    }
    //os_printf("RX: %db\n", len);
    tcp_server_send(data, len);
}

__init static void sys_network_init(void) {
    struct netdev *ndev;
    struct netif  *nif;
    static char hostname[sizeof("RNode-Halow-XXXXXX")];

    tcpip_init(NULL, NULL);
    sock_monitor_init();

    sysctrl_efuse_mac_addr_calc(g_mac);
    ndev = (struct netdev *)dev_get(HG_GMAC_DEVID);
    netdev_set_macaddr(ndev, g_mac);
    if (ndev) {
        lwip_netif_add(ndev, "e0", NULL, NULL, NULL);
        lwip_netif_set_default(ndev);
        
        nif = netif_find("e0");
        if (nif) {
            snprintf(hostname,sizeof(hostname),"RNode-Halow-%02X%02X%02X",nif->hwaddr[3],nif->hwaddr[4],nif->hwaddr[5]);
            nif->hostname = hostname;
        }

        //lwip_netif_set_dhcp2("e0", 1);
        os_printf("add e0 interface!\r\n");
    }else{
        os_printf("Ethernet GMAC not found!");
    }
}

static int32 sys_main_loop(struct os_work *work) {
    static uint8_t  pa7_val  = 0;
    static uint32_t seq      = 0;
    char buf[32];

    (void)work;

    pa7_val = !pa7_val;
    gpio_set_val(PA_7, pa7_val);

    //int32_t len = os_snprintf(buf, sizeof(buf), "SEQ=%lu", (unsigned long)seq++);
    //halow_tx((const uint8_t *)buf, len);
    //int8_t  (int64_t sample_time_us);
    //os_printf("%d\r\n", (int32_t)halow_lbt_noise_dbm_now(1000LL));
    os_run_work_delay(&main_wk, 300);
    return 0;
}

sysevt_hdl_res sys_event_hdl(uint32 event_id, uint32 data, uint32 priv) {
    struct netif *nif;
    ip4_addr_t ip;
    switch (event_id) {
        case SYS_EVENT(SYS_EVENT_NETWORK, SYSEVT_LWIP_DHCPC_DONE):
            nif = netif_find("e0");
            ip = *netif_ip4_addr(nif);

            hgprintf("DHCP new ip assign: %u.%u.%u.%u\r\n",
                     ip4_addr1(&ip),
                     ip4_addr2(&ip),
                     ip4_addr3(&ip),
                     ip4_addr4(&ip));
            break;
    }
    return SYSEVT_CONTINUE;
}

int32_t tcp_to_halow_send(const uint8_t* data, uint32_t len){
    if(data == NULL){
        return -100;
    }
    if(len == 0){
        return -200;
    }
    return halow_tx(data, len);
}

void assert_printf(char *msg, int line, char *file){
    os_printf("assert %s: %d, %s", msg, line, file);
    for (;;) {}
}


static void boot_counter_update(void){
    int32_t pwr_on_cnt = 0;
    configdb_get_i32("pwr_on_cnt", &pwr_on_cnt);
    pwr_on_cnt++;
    configdb_set_i32("pwr_on_cnt", &pwr_on_cnt);
    printf("Boot counter = %d\n", pwr_on_cnt);
}

__init int main(void) {
    extern uint32 __sinit, __einit;
    mcu_watchdog_timeout(5);

    gpio_set_dir(PA_7, GPIO_DIR_OUTPUT);
    gpio_set_val(PA_7, 0);
    configdb_init();
    littlefs_init();
    //ota_reset_to_default();
    boot_counter_update();
    sys_event_init(32);
    sys_event_take(0xffffffff, sys_event_hdl, 0);

    skbpool_init(SKB_POOL_ADDR, (uint32)SKB_POOL_SIZE, 90, 0);
    halow_init(WIFI_RX_BUFF_ADDR, WIFI_RX_BUFF_SIZE, TDMA_BUFF_ADDR, TDMA_BUFF_SIZE);
    halow_set_rx_cb(halow_rx_handler);
    sys_network_init();
    config_page_init();
    tftp_server_init();
    net_ip_init();
    tcp_server_init(tcp_to_halow_send);
    OS_WORK_INIT(&main_wk, sys_main_loop,0);
    os_run_work_delay(&main_wk, 1000);
    sysheap_collect_init(&sram_heap, (uint32)&__sinit, (uint32)&__einit); // delete init code from heap
    return 0;
}
