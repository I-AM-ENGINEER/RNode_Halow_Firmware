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
#include "halow_lbt.h"
#include "tcp_server.h"
#include "hal/spi_nor.h"
#include <lib/fal/fal.h>
#include <lib/flashdb/flashdb.h>
#include "littelfs_port.h"
#include "configdb.h"
#include "tftp_server.h"
#include "config_page/config_page.h"
#include "config_page/config_api_calls.h"
#include "net_ip.h"
#include "ota.h"
#include "statistics.h"
#include "indication.h"
#include "telemetry.h"
#include "device.h"
#include "utils.h"
#ifdef MULTI_WAKEUP
#include "lib/common/sleep_api.h"
#include "hal/gpio.h"
#include "lib/lmac/lmac.h"
#include "lib/common/dsleepdata.h"
#endif
// #include "atcmd.c"

static struct os_work blink_wk;
static struct os_work stats_wk;
extern uint32_t srampool_start;
extern uint32_t srampool_end;

//extern void lmac_transceive_statics(uint8 en);

static void halow_rx_handler(struct hgic_rx_info *info,
                             const uint8 *data,
                             int32 len) {
    (void)info;

    if (data == NULL || len <= 0) {
        return;
    }
    //os_printf("RX: %db\n", len);
    indication_led_rx();
    statistics_radio_register_rx_package(len);
    int32_t res = tcp_server_send(data, len);
    if(res != 0){
        //os_printf("rf->tcp send error: %d\n", res);
    }
}

int32_t tcp_to_halow_send(const uint8_t* data, uint32_t len){
    if(data == NULL){
        return -100;
    }
    if(len == 0){
        return -200;
    }
    int32_t res = halow_tx(data, len);
    if(res != 0){
        //os_printf("tcp->rf send error: %d\n", res);
        return res;
    }
    statistics_radio_register_tx_package(len);  
    return 0;
}

__init static void sys_network_init(void) {
    struct netdev *ndev;
    struct netif  *nif;
    static char hostname[sizeof("RNode-Halow-XXXXXX")];

    tcpip_init(NULL, NULL);
    sock_monitor_init();

    uint8_t mac[6];
    get_mac(mac);
    ndev = (struct netdev *)dev_get(HG_GMAC_DEVID);
    netdev_set_macaddr(ndev, mac);
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

static uint32_t firmware_build_hash( void ){
    uint32_t hash = 0x811C9DC5;
    const char *s = FW_FULL_VERSION;

    while (*s) {
        hash ^= (uint8_t)(*s++);
        hash *= 0x01000193;
    }

    if (hash == 0) {
        hash = 1;
    }

    return hash;
}

static void boot_counter_update(void){
    int32_t pwr_on_cnt = 0;
    configdb_get_i32("pwr_on_cnt", &pwr_on_cnt);
    pwr_on_cnt++;
    configdb_set_i32("pwr_on_cnt", &pwr_on_cnt);
    printf("Boot counter = %d\n", pwr_on_cnt);
}

static int32 sys_blink_work(struct os_work *work) {
    static bool active = 0;
    active = !active;
    indication_led_main_set(active);
    os_run_work_delay(work, active ? 20 : 4980);
    return 0;
}

static int32 sys_stats_work(struct os_work *work) {
    const uint32_t buckets = 32;
    struct os_task_info tsk_info_buff[32];
    
    uint32_t status[buckets];
    sysheap_status(&sram_heap, status, buckets, 16);
    
    char tmp_str[32];
    statistics_cpu_load_get(tmp_str, sizeof(tmp_str));
    os_printf("CPU LOAD: %s\n", tmp_str);
    statistics_heap_usage_get(tmp_str, sizeof(tmp_str));
    os_printf("HEAP: %s\n", tmp_str);
    os_run_work_delay(work, 2000);
    return 0;
}

bool boot_recovery_check( void ){
    uint32_t t = 0;
    bool led = false;

    if (!button_get()) {
        false;
    }

    while (button_get()) {
        os_sleep_ms(50);
        t += 50;
        if (t >= 3000 && t < 10000) {
            led = !led;
            indication_led_main_set(led);
            os_sleep_ms(100);
            t += 100;
        }

        if (t >= 10000) {
            indication_led_main_set(true);
            return true;
        }
    }

    indication_led_main_set(false);

    if (t >= 3000 && t < 10000) {
        ota_reset_to_default();
        device_reboot();
    }
    return false;
}

__init int main(void) {
    extern uint32 __sinit, __einit;
    mcu_watchdog_timeout(5);
    sys_event_init(32);
    sys_event_take(0xffffffff, sys_event_hdl, 0);
    indication_init();
    fal_init();
    if(boot_recovery_check()){
        sys_network_init();
        return 0;
    }
    configdb_init();
    littlefs_init();
    boot_counter_update();
    skbpool_init(SKB_POOL_ADDR, (uint32)SKB_POOL_SIZE, 90, 0);
    halow_init(WIFI_RX_BUFF_ADDR, WIFI_RX_BUFF_SIZE, TDMA_BUFF_ADDR, TDMA_BUFF_SIZE);
    halow_lbt_init();
    halow_set_rx_cb(halow_rx_handler);
    sys_network_init();
    config_page_init(); 
    tftp_server_init();
    net_ip_init();
    statistics_init();
    tcp_server_init(tcp_to_halow_send);
    telemetry_init();
    OS_WORK_INIT(&blink_wk, sys_blink_work,0);
    OS_WORK_INIT(&stats_wk, sys_stats_work,0);
    os_run_work_delay(&blink_wk, 1000);
    //os_run_work_delay(&stats_wk, 1000);
    sysheap_collect_init(&sram_heap, (uint32)&__sinit, (uint32)&__einit); // delete init code from heap
    return 0;
}

void assert_printf( char *msg, int line, char *file ){
    os_printf("ASSERT: %s line=%d file=%s\n", msg, line, file);
    while (1){}
}
