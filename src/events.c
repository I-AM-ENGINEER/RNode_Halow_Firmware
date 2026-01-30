#include "basic_include.h"
#include "lib/skb/skb.h"
#include "lib/skb/skb_list.h"
#include "lib/bus/macbus/mac_bus.h"
#include "lib/lmac/lmac.h"
#include "lib/bus/xmodem/xmodem.h"
#include "lib/atcmd/libatcmd.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/sys.h"
#include "lwip/dns.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "netif/ethernetif.h"
#include "lib/net/dhcpd/dhcpd.h"
#include "lib/umac/ieee80211.h"
#include "lib/umac/wifi_mgr.h"
#include "lib/umac/wifi_cfg.h"
#include "syscfg.h"

extern void sys_check_wkreason(uint8 type);
extern int32 sys_ieee80211_event_pairsta(uint8 ifidx, uint16 evt, uint32 param1, uint32 param2);
extern int32 sys_ieee80211_event_pairled(uint8 ifidx, uint16 evt, uint32 param1, uint32 param2);

sysevt_hdl_res sys_event_hdl(uint32 event_id, uint32 data, uint32 priv)
{
#if SYS_NETWORK_SUPPORT
    struct netif *nif;
    uint8 mode_ap = wificfg_get_ifidx(sys_cfgs.wifi_mode, 1);
#endif

    switch (event_id) {
        case SYS_EVENT(SYS_EVENT_WIFI, SYSEVT_WIFI_UNPAIR):
            syscfg_save();
            break;
        case SYS_EVENT(SYS_EVENT_WIFI, SYSEVT_WIFI_PAIR_DONE):
            if (data) { //pair success
                syscfg_save();
            }
            break;

        case SYS_EVENT(SYS_EVENT_WIFI, SYSEVT_WIFI_CONNECTTED):
            sys_status.wifi_connected = 1;
            if (MODE_IS_STA(sys_cfgs.wifi_mode)) {
                sys_check_wkreason(WKREASON_CONNECTTED);
            }
#if (WIFI_STA_SUPPORT || WIFI_WNBSTA_SUPPORT) && SYS_NETWORK_SUPPORT
            if (MODE_IS_REPEATER(sys_cfgs.wifi_mode) && sys_cfgs.cfg_init) {
                sys_status.dhcpc_done = 0;
                lwip_netif_set_dhcp2("w0", 1);
                //os_printf("wifi connected, start dhcp client ...\r\n");
#if WIFI_REPEATER_SUPPORT
                os_printf("repeater: start hotspot ...\r\n");
                ieee80211_conf_set_ssid(mode_ap, sys_cfgs.r_ssid);
                ieee80211_conf_set_keymgmt(mode_ap, sys_cfgs.r_key_mgmt);
                ieee80211_conf_set_psk(mode_ap, sys_cfgs.r_psk);
                ieee80211_iface_start(mode_ap);
#else
                os_printf("Not supported, please set WIFI-REPEATER_SUPPORT to 1\r\n");                
#endif
            }


            if (MODE_IS_STA(sys_cfgs.wifi_mode) && sys_cfgs.dhcpc_en) {
                sys_status.dhcpc_done = 0;
                lwip_netif_set_dhcp2("w0", 1);
                os_printf(KERN_NOTICE"wifi connected, start dhcp client ...\r\n");
            }
#endif
            break;
        case SYS_EVENT(SYS_EVENT_WIFI, SYSEVT_WIFI_DISCONNECT):
            sys_status.wifi_connected = 0;
            if (MODE_IS_AP(sys_cfgs.wifi_mode)) {
                sys_check_wkreason(WKREASON_DISCONNECT);
            }
#if (WIFI_STA_SUPPORT || WIFI_WNBSTA_SUPPORT) && SYS_NETWORK_SUPPORT
            if (MODE_IS_REPEATER(sys_cfgs.wifi_mode)) {
                ip_addr_t ipaddr, netmask, gw;
                ipaddr.addr  = sys_cfgs.ipaddr;
                netmask.addr = sys_cfgs.netmask;
                gw.addr      = sys_cfgs.gw_ip;
                lwip_netif_set_ip2("w0", &ipaddr, &netmask, &gw);
                ieee80211_iface_stop(mode_ap);
            }
#endif
            break;

#if SYS_NETWORK_SUPPORT
        case SYS_EVENT(SYS_EVENT_NETWORK, SYSEVT_LWIP_DHCPC_DONE):
            nif = netif_find("w0");
            sys_cfgs.ipaddr = nif->ip_addr.addr;
            sys_cfgs.netmask = nif->netmask.addr;
            sys_cfgs.gw_ip = nif->gw.addr;
            sys_status.dhcpc_done = 1;
            sys_status.dhcpc_result.ipaddr  = nif->ip_addr.addr;
            sys_status.dhcpc_result.netmask = nif->netmask.addr;
            sys_status.dhcpc_result.svrip   = 0;
            sys_status.dhcpc_result.router  = nif->gw.addr;
            sys_status.dhcpc_result.dns1    = (dns_getserver(0))->addr;
            sys_status.dhcpc_result.dns2    = (dns_getserver(1))->addr;
            host_event_new(HGIC_EVENT_DHCPC_DONE, (uint8 *)&sys_status.dhcpc_result, sizeof(sys_status.dhcpc_result));
            os_printf(KERN_NOTICE"dhcp done, ip:"IPSTR", mask:"IPSTR", gw:"IPSTR"\r\n",
                      IP2STR_N(sys_cfgs.ipaddr), IP2STR_N(sys_cfgs.netmask), IP2STR_N(sys_cfgs.gw_ip));
            break;
#endif
        case SYS_EVENT(SYS_EVENT_WIFI, SYSEVT_WIFI_WAKEUP_HOST):
            os_printf(KERN_NOTICE"wakeup reason: %d\r\n", data);
            sys_wakeup_host();
            break;
    }
    return SYSEVT_CONTINUE;
}


static void dump_u32(const char *tag, uint32 v)
{
    os_printf("%s=0x%08x (%u)\r\n", tag, (unsigned)v, (unsigned)v);
}

static void hex_dump32(const char *tag, const void *p, uint32 len)
{
    const uint8 *b = (const uint8 *)p;
    uint32 i;

    if (p == NULL || len == 0) {
        os_printf("%s: (null/empty)\r\n", tag);
        return;
    }

    if (len > 128) {
        len = 128;
    }

    os_printf("%s: p=%p len=%u\r\n", tag, p, (unsigned)len);

    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            os_printf("%04u: ", (unsigned)i);
        }
        os_printf("%02x ", b[i]);
        if ((i % 16) == 15 || i == (len - 1)) {
            os_printf("\r\n");
        }
    }
}

static const char *evt_name(uint16 evt)
{
    switch (evt) {
        case 22: return "ADD_EXTRA_IE";
        case 29: return "TX_BITRATE";
        case 32: return "TX_FRAME";
        case 33: return "RX_CUSTMGMT";
        case 37: return "TX_STATUS";
        default: return "?";
    }
}

int32 sys_ieee80211_event_cb(uint8 ifidx, uint16 evt, uint32 param1, uint32 param2)
{
    os_printf("EVT if=%u evt=%u(%s) p1=0x%08x p2=0x%08x\r\n",
          ifidx, evt, evt_name(evt), (unsigned)param1, (unsigned)param2);

    int32 ret = 0;

#if SYS_SAVE_PAIRSTA
    ret = sys_ieee80211_event_pairsta(ifidx, evt, param1, param2);
    if (ret) {
        return ret;
    }
#endif

#if SYS_APP_PAIR
    ret = sys_ieee80211_event_pairled(ifidx, evt, param1, param2);
    if (ret) {
        return ret;
    }
#endif

    switch (evt) {
        case IEEE80211_EVENT_CONNECTED:
            os_memcpy(sys_status.bssid, param1, 6);
            sys_status.channel = ieee80211_conf_get_channel(WIFI_MODE_STA);
            break;
        case IEEE80211_EVENT_RSSI:
            sys_status.rssi = (int8)param1;
            break;
        case IEEE80211_EVENT_EVM:
            sys_status.evm = (int8)param1;
            break;
        case IEEE80211_EVENT_PAIR_START:
            sys_status.pair_success = 0;
            break;
        case IEEE80211_EVENT_PAIR_SUCCESS:
            sys_status.pair_success = 1;
            if (sys_cfgs.pair_autostop) {
                ieee80211_pairing(ifidx, 0);
            }
            os_printf("inteface%d: sta "MACSTR" pairing success\r\n", ifidx, MAC2STR((uint8 *)param1));
            break;
        case IEEE80211_EVENT_PAIR_DONE:
            if (sys_status.pair_success && MODE_IS_STA(sys_cfgs.wifi_mode)) {
                ieee80211_conf_get_ssid(sys_cfgs.wifi_mode, sys_cfgs.ssid);
                ieee80211_conf_get_psk(sys_cfgs.wifi_mode, sys_cfgs.psk);
                sys_cfgs.key_mgmt = ieee80211_conf_get_keymgmt(sys_cfgs.wifi_mode);
                ieee80211_conf_get_bssid(sys_cfgs.wifi_mode, sys_cfgs.bssid);
            }
            sys_event_new(SYS_EVENT(SYS_EVENT_WIFI, SYSEVT_WIFI_PAIR_DONE), sys_status.pair_success);
            os_printf("inteface%d: pairing done\r\n", ifidx);
            break;
        case IEEE80211_EVENT_UNPAIR_SUCCESS:
            if (MODE_IS_STA(sys_cfgs.wifi_mode)) {
                ieee80211_conf_get_ssid(sys_cfgs.wifi_mode, sys_cfgs.ssid);
                ieee80211_conf_get_psk(sys_cfgs.wifi_mode, sys_cfgs.psk);
                sys_cfgs.key_mgmt = ieee80211_conf_get_keymgmt(sys_cfgs.wifi_mode);
                ieee80211_conf_get_bssid(sys_cfgs.wifi_mode, sys_cfgs.bssid);
            }
            sys_event_new(SYS_EVENT(SYS_EVENT_WIFI, SYSEVT_WIFI_UNPAIR), 0);
            os_printf("inteface%d unpair sta: "MACSTR"\r\n", ifidx, MAC2STR((uint8 *)param1));
            break;
        case IEEE80211_EVENT_CHANNEL_CHANGE:
            os_printf("channel change: %d -> %d\r\n", param1, param2);
            sys_cfgs.channel = param2;
            break;
            case IEEE80211_EVENT_ADD_EXTRA_IE: {
                os_printf("ADD_EXTRA_IE: skb=%p ctx=%p\r\n", (void *)param1, (void *)param2);
            
                if (param1 >= 0x20000000 && param1 < 0x200C0000) {
                    hex_dump32("skb(head)", (void *)param1, 64);
                }
                if (param2 >= 0x20000000 && param2 < 0x200C0000) {
                    hex_dump32("ctx(head)", (void *)param2, 64);
                }
            } break;
        default:
            break;
    }
    return ret;
}

