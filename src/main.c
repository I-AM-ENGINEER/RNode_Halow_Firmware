#define LOG_LOCAL_LEVEL LOG_DEBUG
#include "lib/logc/log.h"
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
#include "netif/slipif.h"
#include "lib/net/skmonitor/skmonitor.h"
#include "lib/lmac/lmac_def.h"
#include "halow.h"
#include "halow_lbt.h"
#include "halow_cca.h"
#include "tcp_server.h"
#include "hal/spi_nor.h"
#include "hal/uart.h"
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
#include "rns/stream_parser.h"
#include "test.h"
#include "nearby_detect.h"
#include "mac_generator.h"
#include "uart_slip.h"
#include "net_log.h"
#include "halow_pkg_handler.h"
#include "halow_ack.h"
#include "lib/net/ethphy/eth_phy.h"

static struct os_work blink_wk;
static struct os_work stats_wk;
extern uint32_t srampool_start;
extern uint32_t srampool_end;
static rns_stream_decoder_t tcp_rns_decoder;
//static rns_link_packet_info_t tcp_rns_link_db;
//extern void lmac_transceive_statics(uint8 en);
extern struct hguart uart1;

#include <stdbool.h>
#include <stdint.h>

// TCP -> RF
static int32_t rns_tcp_rx_handler( uint8_t *data, uint16_t len ){
    log_trace("rns package received len=%d", len);
    /* TX radio stats are registered at the RADIO layer (halow_pkg_handler.c,
     * first-send sites), NOT here: counting TCP-ingress packets made the main
     * page show pre-aggregation RNS packets (1800) against radio-level RX
     * frames (454) on the same link -- "TX terrible vs RX". Radio-level TX
     * (wire frames, retransmits excluded) mirrors RX accounting 1:1. */
    return halow_pkg_handler_tcp_to_rf(data, len);
}

// RF -> TCP
volatile uint32_t g_rx_cls_internal;
volatile uint32_t g_rx_cls_notmine;
volatile uint32_t g_rx_cls_data;
#define RX_CAP_N 8u
volatile uint8_t g_rx_cap[RX_CAP_N][16];
static volatile uint32_t g_rx_cap_wr;

static void rx_forensics_capture( const struct ieee80211_hdr *hdr,
                                  const uint8_t *data, uint16_t len ){
    uint32_t idx = g_rx_cap_wr % RX_CAP_N;
    uint8_t *slot = (uint8_t *)g_rx_cap[idx];
    memcpy(slot, hdr->addr2, 6);
    uint32_t n = (uint32_t)len;
    if (n > 10u) n = 10u;
    memcpy(slot + 6, data, n);
    g_rx_cap_wr++;
}

static void halow_rx_handler(struct hgic_rx_info *info,
                             struct ieee80211_hdr *hdr,
                             uint8 *data,
                             int32 len) {
    (void)info;

    if (data == NULL || len <= 0) {
        return;
    }

    nearby_modem_package_info_t modem_pkg_info = {
        .len = len,
        .mcs = info->mcs,
        .rssi = info->signal,
        .snr = info->signal - halow_lbt_background_short_dbm_get(),
        .timestamp_s = (uint32_t)time(NULL)
    };
    memcpy(modem_pkg_info.mac, hdr->addr2, 6);

    /* ACK frames (legacy fid-list AND envelope Block-ACK) are internal
     * reliability plumbing, not user data: they must NOT show up in link
     * statistics (rx packets/bytes/throughput), blink the data LED, appear in
     * nearby-modem scans, or feed the nearby RX MCS -- ACKs run at their own
     * robust adaptive rate (often far below the data RA rate), which made a
     * healthy MCS7 link display as "RX MCS2". Count/deliver only real data. */
    if (!halow_ack_is_internal_frame(data, (uint16_t)len)) {
        nearby_modem_package_register(&modem_pkg_info);
        indication_led_rx();
        statistics_radio_register_rx_package(len);
    } else {
        rx_forensics_capture(hdr, data, (uint16_t)len);
        g_rx_cls_internal++;
    }

    uint8_t my_mac[6];
    /* Compare addr3 (the destination, see halow_send_frame) against the node's
     * TX identity (g_wmac via mac_generator_get, NOT get_mac() (g_efuse): the
     * peer learns our MAC from our TX addr2 == mac_generator_get, and addresses
     * us via addr3 with that same value. g_efuse != g_wmac, so the old
     * get_mac() comparison rejected every unicast-to-us frame (only never
     * noticed because addr3 was always broadcast). */
    mac_generator_get(my_mac);
    if ((memcmp(hdr->addr3, mac_broadcast, 6) != 0) &&
        (memcmp(hdr->addr3, my_mac, 6) != 0)) {
        rx_forensics_capture(hdr, data, (uint16_t)len);
        g_rx_cls_notmine++;
        return;
    }
    g_rx_cls_data++;
    halow_pkg_handler_rf_to_tcp(data, (uint16_t)len, (const uint8_t *)hdr->addr2,
                                (const uint8_t *)hdr->addr3, info->evm);
}

// TCP -> rns stream decoder
int32_t tcp_to_halow_send(const uint8_t* data, uint32_t len, uint16_t *consumed){
    if(data == NULL){
        if(consumed) *consumed = 0u;
        return -100;
    }
    if(len == 0){
        if(consumed) *consumed = 0u;
        return -200;
    }

    /* Propagate HALOW_ACK_TX_THROTTLE so tcp_server's recv loop can skip
     * netconn_recv (TCP backpressure) while still draining the RF->TCP ring.
     * *consumed tells it exactly how many bytes were taken: the unconsumed
     * tail of the netbuf must be re-fed after the TX path drains (contract:
     * bytes accepted from TCP always reach the air). */
    return rns_stream_decoder_process(&tcp_rns_decoder, data, (uint16_t)len, NULL, consumed);
}

void rns_tcp_session_reset(void){
    rns_stream_decoder_reset(&tcp_rns_decoder);
}

int32_t rns_tcp_retry_held(void){
    return rns_stream_decoder_retry_held(&tcp_rns_decoder, NULL);
}

#include "lib/net/ethphy/eth_mdio_bus.h"
#include "lib/net/ethphy/eth_phy.h"

extern struct ethernet_phy_device ethernet_phy0;
extern struct ethernet_mdio_bus mdio_bus0;

static bool eth_phy_present( void ){
    struct netdev *ndev;

    ndev = (struct netdev *)dev_get(HG_GMAC_DEVID);
    if( ndev == NULL ){
        return false;
    }

    if( pin_func(HG_GMAC_DEVID, 1) != RET_OK ){
        return false;
    }

    if( eth_mdio_bus_open(&mdio_bus0, ndev) != RET_OK ){
        return false;
    }

    ethernet_phy0.ndev = ndev;
    ethernet_phy0.bus  = &mdio_bus0;

    return eth_get_phy_device(&ethernet_phy0) ? true : false;
}

__init static void sys_network_init(void) {
    struct netdev *ndev;
    struct netif  *nif;
    static char hostname[sizeof("RNode-Halow-XXXXXX")];

    static uint8_t mac[6];
    get_mac(mac);
    ndev = (struct netdev *)dev_get(HG_GMAC_DEVID);
    if( ndev == NULL ) {
        log_error("Ethernet GMAC not found");
        return;
    }

    if( !eth_phy_present() ) {
        log_warn("Ethernet PHY not detected, skip e0");
        return;
    }
    
    log_info("Ethernet mac set");
    netdev_set_macaddr(ndev, mac);
    lwip_netif_add(ndev, "e0", NULL, NULL, NULL);
    log_info("netif added");
    lwip_netif_set_default(ndev);
    
    nif = netif_find("e0");
    if (nif) {
        log_info("Hostname set");
        snprintf(hostname,sizeof(hostname),"RNode-Halow-%02X%02X%02X",nif->hwaddr[3],nif->hwaddr[4],nif->hwaddr[5]);
        nif->hostname = hostname;
    }

    log_info("add e0 interface");
}

sysevt_hdl_res sys_event_hdl(uint32 event_id, uint32 data, uint32 priv) {
    struct netif *nif;
    ip4_addr_t ip;
    switch (event_id) {
        case SYS_EVENT(SYS_EVENT_NETWORK, SYSEVT_LWIP_DHCPC_DONE):
            nif = netif_find("e0");
            ip = *netif_ip4_addr(nif);

            log_info("DHCP new ip assign: %u.%u.%u.%u\r\n",
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
    /* Feed the boot watchdog around the flash write: on a GC-heavy flashdb
     * sector this can outlast the 3 s timeout and abort the write mid-erase,
     * dirtying the sector further (reboot-spiral hazard, see halow_ack_config_load). */
    mcu_watchdog_feed();
    configdb_get_i32("pwr_on_cnt", &pwr_on_cnt);
    pwr_on_cnt++;
    configdb_set_i32("pwr_on_cnt", &pwr_on_cnt);
    mcu_watchdog_feed();
    log_info("Boot counter = %d\n", pwr_on_cnt);
}

static int32 sys_stats_work(struct os_work *work) {
    const uint32_t buckets = 32;
    
    uint32_t status[buckets];
    sysheap_status(&sram_heap, status, buckets, 16);
    
    char tmp_str[32];
    statistics_cpu_load_get(tmp_str, sizeof(tmp_str));
    log_debug("CPU LOAD: %s", tmp_str);
    statistics_heap_usage_get(tmp_str, sizeof(tmp_str));
    log_debug("HEAP: %s", tmp_str);
    os_run_work_delay(work, 2000);
    return 0;
}

bool boot_recovery_check( void ){
    uint32_t t = 0;
    bool led = false;

    if (!button_get()) {
        return false;   /* was a bare `false;` statement -- a no-op */
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

static struct os_work blink_wk;
static struct os_work stats_wk;

__init int main(void) {
    extern uint32 __sinit, __einit;
    os_sleep_ms(5000);
    log_debug("mcu_watchdog_timeout");
    /* 10 s, not 3: boot-time flashdb/littlefs mounts can GC a sector dirtied
     * by an earlier watchdog-aborted write for several seconds. A 3 s budget
     * aborted the write mid-erase, dirtying it further -> reboot spiral that
     * never completes (observed after an OTA with a torn config sector). 10 s
     * lets one boot always finish the GC; runtime hang protection is intact. */
    mcu_watchdog_timeout(10);
    log_debug("sys_event_init");
    sys_event_init(32);
    log_debug("sys_event_take");
    sys_event_take(0xffffffff, sys_event_hdl, 0);
    log_debug("indication_init");
    indication_init();
    log_debug("fal_init");
    fal_init();

	log_debug("tcpip_init");
	tcpip_init(NULL, NULL);
    log_debug("sock_monitor_init");
    sock_monitor_init();
    log_debug("uart_slip_early_init");
    uart_slip_early_init();
    log_debug("net_log_init_early");
    net_log_init_early();

    log_debug("boot_recovery_check");
    if(boot_recovery_check()){
		log_debug("recovery mode: sys_network_init");
		sys_network_init();
        return 0;
    }
    log_debug("configdb_init");
    configdb_init();
    log_debug("boot_counter_update");
    boot_counter_update();
    log_debug("littlefs_init");
    littlefs_init();
    log_debug("halow_pkg_handler_init");
    halow_pkg_handler_init();
    log_debug("skbpool_init");
    skbpool_init(SKB_POOL_ADDR, (uint32)SKB_POOL_SIZE, 90, 0);
    log_debug("mac_generator_init");
    mac_generator_init();
    log_debug("halow_init");
    halow_init(WIFI_RX_BUFF_ADDR, WIFI_RX_BUFF_SIZE, TDMA_BUFF_ADDR, TDMA_BUFF_SIZE);

    log_debug("sys_network_init");
    sys_network_init();
    log_debug("uart_slip_init");
    uart_slip_init();
    log_debug("net_log_init");
    net_log_init();
    log_debug("net_ip_init");
    net_ip_init();
	log_debug("halow_lbt_init");
    halow_lbt_init();
    log_debug("halow_cca_init");
    halow_cca_init();
	log_debug("halow_set_rx_cb");
    halow_set_rx_cb(halow_rx_handler);
    log_debug("config_page_init");
    config_page_init();
    log_debug("tftp_server_init");
    tftp_server_init();
    log_debug("statistics_init");
    statistics_init();
    log_debug("tcp_server_init");
    tcp_server_init(tcp_to_halow_send);
    log_debug("telemetry_init");
    telemetry_init();
    log_debug("rns_stream_decoder_init");
    rns_stream_decoder_init(&tcp_rns_decoder, rns_tcp_rx_handler);
    //test_start();
    log_debug("sysheap_collect_init");
    sysheap_collect_init(&sram_heap, (uint32)&__sinit, (uint32)&__einit);
    log_info("Init done");
    log_debug("!!!!!");
    return 0;
}

void assert_printf( char *msg, int line, char *file ){
    log_fatal("ASSERT: %s line=%d file=%s", msg, line, file);
    while (1){}
}
