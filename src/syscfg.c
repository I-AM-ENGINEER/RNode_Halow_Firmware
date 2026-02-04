#include "sys_config.h"
#include "typesdef.h"
#include "list.h"
#include "dev.h"
#include "devid.h"
#include "osal/string.h"
#include "osal/semaphore.h"
#include "osal/mutex.h"
#include "osal/irq.h"
#include "osal/task.h"
#include "osal/sleep.h"
#include "osal/timer.h"
#include "hal/gpio.h"
#include "hal/uart.h"
#include "lib/common/common.h"
#include "lib/umac/ieee80211.h"
#include "lib/umac/wifi_cfg.h"
#include "lib/syscfg/syscfg.h"
#include "lib/atcmd/libatcmd.h"
#include "lib/net/dhcpd/dhcpd.h"
#include "lwip/ip_addr.h"
#include "lwip/netdb.h"
#include "netif/ethernetif.h"
#include "lib/lmac/lmac.h"
#include "syscfg.h"

extern void *lmacops;

struct sys_config sys_cfgs = {
    .wifi_mode        = SYS_WIFI_MODE,
    .channel          = 0,
    .beacon_int       = 500,
    .dtim_period      = 2,
    .bss_max_idle     = 300,
    .key_mgmt         = WPA_KEY_MGMT_PSK,
    .ipaddr           = 0x017BA8C0, // 192.168.123.1
    .netmask          = 0x00FFFFFF, // 255.255.255.0
    .gw_ip            = 0x017BA8C0, // 192.168.123.1
    .dhcpd_startip    = 0x027BA8C0, // 192.168.123.2
    .dhcpd_endip      = 0xFE7BA8C0, // 192.168.123.254
    .dhcpd_lease_time = 3600,
    .dhcpd_en         = SYS_DHCPD_EN,
    .dhcpc_en         = SYS_DHCPC_EN,
    .sta_max          = SYS_STA_MAX,
    .acs_enable       = 1,
    .use4addr         = 1,
    .wpa_proto        = WPA_PROTO_RSN,
    .pairwise_cipher  = WPA_CIPHER_CCMP,
    .group_cipher     = WPA_CIPHER_CCMP,
};

int32 syscfg_save(void) {
    return syscfg_write(&sys_cfgs, sizeof(sys_cfgs));
}

const char *wificfg_keymgmt_str(void) {
    return sys_cfgs.key_mgmt == WPA_KEY_MGMT_PSK ? "WPA-PSK" : "NONE";
}

const char *wificfg_wifimode_str(void) {
    switch (sys_cfgs.wifi_mode) {
        case WIFI_MODE_AP:
            return "ap";
        case WIFI_MODE_STA:
            return "sta";
        case WIFI_MODE_WNBSTA:
            return "wnbsta";
        case WIFI_MODE_WNBAP:
            return "wnbap";
        case WIFI_MODE_AP_STA:
            return "apsta";
        case WIFI_MODE_WNBAP_STA:
            return "wnbapsta";
        case WIFI_MODE_AP_WNBSTA:
            return "apwnbsta";
        case WIFI_MODE_WNBAP_WNBSTA:
            return "wnbapwnbsta";
        case WIFI_MODE_AP_WNBAP:
            return "apwnbap";
        default:
            return "none";
    }
}

int32 wificfg_get_ifidx(uint8 wifi_mode, uint8 switch_ap) {
    int32 ifidx = 0;
    switch (wifi_mode) {
        case WIFI_MODE_STA:
        case WIFI_MODE_AP:
        case WIFI_MODE_WNBSTA:
        case WIFI_MODE_WNBAP:
            ifidx = wifi_mode;
            break;
        case WIFI_MODE_AP_STA:
            ifidx = switch_ap ? WIFI_MODE_AP : WIFI_MODE_STA;
            break;
        case WIFI_MODE_WNBAP_WNBSTA:
            ifidx = switch_ap ? WIFI_MODE_WNBAP : WIFI_MODE_WNBSTA;
            break;
        case WIFI_MODE_AP_WNBSTA:
            ifidx = switch_ap ? WIFI_MODE_AP : WIFI_MODE_WNBSTA;
            break;
        case WIFI_MODE_WNBAP_STA:
            ifidx = switch_ap ? WIFI_MODE_WNBAP : WIFI_MODE_STA;
            break;
        case WIFI_MODE_AP_WNBAP:
            ifidx = -1;
            break;
        default:
            break;
    }
    return ifidx;
}

void wificfg_set_mode(uint8 mode) {
    uint8 mode_ap  = wificfg_get_ifidx(mode, 1);
    uint8 mode_sta = wificfg_get_ifidx(mode, 0);
    if (sys_cfgs.wifi_mode == mode) return;

    sys_cfgs.wifi_mode = mode;
    ieee80211_iface_stop(WIFI_MODE_AP);
    ieee80211_iface_stop(WIFI_MODE_STA);
    ieee80211_iface_stop(WIFI_MODE_WNBAP);
    ieee80211_iface_stop(WIFI_MODE_WNBSTA);

    switch (mode) {
        case WIFI_MODE_STA:
        case WIFI_MODE_WNBSTA:
        case WIFI_MODE_AP:
        case WIFI_MODE_WNBAP:
            wificfg_flush(mode);
            ieee80211_iface_start(mode);
            break;
        case WIFI_MODE_AP_STA:
        case WIFI_MODE_WNBAP_WNBSTA:
        case WIFI_MODE_AP_WNBSTA:
        case WIFI_MODE_WNBAP_STA:
            wificfg_flush(mode_ap);
            wificfg_flush(mode_sta);
            ieee80211_iface_start(mode_sta);
            break;
        case WIFI_MODE_AP_WNBAP:
            wificfg_flush(WIFI_MODE_AP);
            ieee80211_iface_start(WIFI_MODE_AP);
            wificfg_flush(WIFI_MODE_WNBAP);
            ieee80211_iface_start(WIFI_MODE_WNBAP);
            break;
        default:
            return;
    }
    os_printf("set mode:%s\r\n", wificfg_wifimode_str());
}

void syscfg_set_default_val() {
    sysctrl_efuse_mac_addr_calc(sys_cfgs.mac);
    if (IS_ZERO_ADDR(sys_cfgs.mac)) {
        os_random_bytes(sys_cfgs.mac, 6);
        sys_cfgs.mac[0] &= 0xfe;
        os_printf("use random mac " MACSTR "\r\n", MAC2STR(sys_cfgs.mac));
    }
    os_strcpy(sys_cfgs.devname, WNB_DEV_DOMAIN);
    os_snprintf((char *)sys_cfgs.ssid, SSID_MAX_LEN, "%s%02X%02X%02X", WIFI_SSID_PREFIX, sys_cfgs.mac[3], sys_cfgs.mac[4], sys_cfgs.mac[5]);
    os_strcpy(sys_cfgs.passwd, "12345678");
    //wpa_passphrase(sys_cfgs.ssid, sys_cfgs.passwd, sys_cfgs.psk);
    os_snprintf((char *)sys_cfgs.ssid, SSID_MAX_LEN, WIFI_SSID_PREFIX"%02X%02X%02X", sys_cfgs.mac[3], sys_cfgs.mac[4], sys_cfgs.mac[5]);

    if (module_efuse_info.module_type == MODULE_TYPE_750M) {
        sys_cfgs.chan_list[0] = 7640;
        sys_cfgs.chan_list[1] = 7720;
        sys_cfgs.chan_list[2] = 7800;
        sys_cfgs.chan_cnt     = 3;
        sys_cfgs.bss_bw       = 8;
    } else if (module_efuse_info.module_type == MODULE_TYPE_810M) {
        sys_cfgs.chan_list[0] = 8050;
        sys_cfgs.chan_list[1] = 8150;
        sys_cfgs.chan_cnt     = 2;
        sys_cfgs.bss_bw       = 8;
    } else if (module_efuse_info.module_type == MODULE_TYPE_850M) {
        sys_cfgs.chan_list[0] = 8450;
        sys_cfgs.chan_list[1] = 8550;
        sys_cfgs.chan_cnt     = 2;
        sys_cfgs.bss_bw       = 8;
    } else if (module_efuse_info.module_type == MODULE_TYPE_860M) {
        sys_cfgs.chan_list[0] = 8640;
        sys_cfgs.chan_list[1] = 8660;
        sys_cfgs.chan_cnt     = 2;
        sys_cfgs.bss_bw       = 2;
    } else { // 915M case
        sys_cfgs.chan_list[0] = 9080;
        sys_cfgs.chan_list[1] = 9160;
        sys_cfgs.chan_list[2] = 9240;
        sys_cfgs.chan_cnt     = 3;
        sys_cfgs.bss_bw       = 8;
    }

    sys_cfgs.txpower = WNB_TX_POWER;
    // os_printf("txpower init:%d\r\n",sys_cfgs.txpower);
}

void syscfg_check(void) {
    return;
}

int32 wificfg_flush(uint8 ifidx) {
    ip_addr_t ipaddr, netmask, gw;
    if (!IS_ZERO_ADDR(sys_cfgs.mac)) {
        ieee80211_conf_set_mac(ifidx, sys_cfgs.mac);
    }
    if (sys_cfgs.use4addr) {
        ieee80211_deliver_init(128, 60);
    }
    if (!sys_cfgs.dhcpc_en) {
        ipaddr.addr  = sys_cfgs.ipaddr;
        netmask.addr = sys_cfgs.netmask;
        gw.addr      = sys_cfgs.gw_ip;
        lwip_netif_set_ip2("w0", &ipaddr, &netmask, &gw);
    }
    ieee80211_conf_set_use4addr(ifidx, sys_cfgs.use4addr);
    ieee80211_conf_set_chanlist(ifidx, sys_cfgs.chan_list, sys_cfgs.chan_cnt);
    if (sys_cfgs.channel == 0 && sys_status.channel) {
        ieee80211_conf_set_channel(ifidx, sys_status.channel);
    } else {
        ieee80211_conf_set_channel(ifidx, sys_cfgs.channel);
    }
    ieee80211_conf_set_beacon_int(ifidx, sys_cfgs.beacon_int);
    ieee80211_conf_set_dtim_int(ifidx, sys_cfgs.dtim_period);
    ieee80211_conf_set_bss_max_idle(ifidx, sys_cfgs.bss_max_idle);
    ieee80211_conf_set_aplost_time(ifidx, 7);
    ieee80211_conf_set_ap_psmode_en(ifidx, sys_cfgs.ap_psmode);
    ieee80211_conf_set_bssbw(ifidx, sys_cfgs.bss_bw);
    if (MODE_IS_AP(ifidx) && MODE_IS_REPEATER(sys_cfgs.wifi_mode) && sys_cfgs.cfg_init) {
#if WIFI_REPEATER_SUPPORT
        ieee80211_conf_set_ssid(ifidx, sys_cfgs.r_ssid);
        ieee80211_conf_set_keymgmt(ifidx, sys_cfgs.r_key_mgmt);
        ieee80211_conf_set_psk(ifidx, sys_cfgs.r_psk);
#else
        os_printf("Not supported, please set WIFI-REPEATER_SUPPORT to 1\r\n");
#endif
    } else {
        ieee80211_conf_set_ssid(ifidx, sys_cfgs.ssid);
        ieee80211_conf_set_keymgmt(ifidx, sys_cfgs.key_mgmt);
        ieee80211_conf_set_psk(ifidx, sys_cfgs.psk);
    }
    ieee80211_conf_set_wpa_cipher(ifidx, sys_cfgs.wpa_proto, sys_cfgs.pairwise_cipher, sys_cfgs.group_cipher);
    ieee80211_conf_set_dupfilter(ifidx, 1);
    ieee80211_conf_set_wpa_group_rekey(ifidx, 0);

    lmac_set_ps_mode(lmacops, sys_cfgs.psmode);
    lmac_set_ap_psmode_en(lmacops, sys_cfgs.ap_psmode);

    lmac_set_txpower(lmacops, sys_cfgs.txpower);
    // os_printf("txpower set:%d\r\n",sys_cfgs.txpower);
    lmac_set_super_pwr(lmacops, sys_cfgs.super_pwr_set ? sys_cfgs.super_pwr : TX_PWR_SUPER_EN);

    return 0;
}

void syscfg_flush(void) {
    uint8 mode_ap  = wificfg_get_ifidx(sys_cfgs.wifi_mode, 1);
    uint8 mode_sta = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);

    if (MODE_IS_REPEATER(sys_cfgs.wifi_mode)) {
        wificfg_flush(mode_ap);
        wificfg_flush(mode_sta);
        if (sys_cfgs.cfg_init) {
            if (!sys_status.wifi_connected) {
                ieee80211_iface_stop(mode_ap);
                ieee80211_iface_start(mode_sta);
            }
        } else {
            ieee80211_iface_stop(mode_sta);
            ieee80211_iface_start(mode_ap);
        }
    } else {
        ieee80211_iface_stop(WIFI_MODE_STA);
        ieee80211_iface_stop(WIFI_MODE_AP);
        ieee80211_iface_stop(WIFI_MODE_WNBSTA);
        ieee80211_iface_stop(WIFI_MODE_WNBAP);
        if (mode_sta < 0) {
            wificfg_flush(WIFI_MODE_AP);
            ieee80211_iface_start(WIFI_MODE_AP);
            wificfg_flush(WIFI_MODE_WNBAP);
            ieee80211_iface_start(WIFI_MODE_WNBAP);
        } else {
            wificfg_flush(sys_cfgs.wifi_mode);
            ieee80211_iface_start(sys_cfgs.wifi_mode);
        }
    }

    if (!sys_cfgs.dhcpc_en) {
        sys_status.dhcpc_result.ipaddr  = sys_cfgs.ipaddr;
        sys_status.dhcpc_result.netmask = sys_cfgs.netmask;
        sys_status.dhcpc_result.router  = sys_cfgs.gw_ip;
    }
}

void syscfg_dump(void) {
    int32 i = 0;
    _os_printf("SYSCFG: %d\r\n", sys_cfgs.cfg_init);
    _os_printf("  mac:" MACSTR ", bssid:" MACSTR "\r\n", MAC2STR(sys_cfgs.mac), MAC2STR(sys_cfgs.bssid));
    _os_printf("  mode:%s, bss_bw:%d\r\n", wificfg_wifimode_str(), sys_cfgs.bss_bw);
    _os_printf("  chan_list:");
    for (i = 0; i < sys_cfgs.chan_cnt; i++) {
        _os_printf(" %d", sys_cfgs.chan_list[i]);
    }
    _os_printf(", chan_cnt:%d\r\n", sys_cfgs.chan_cnt);
    _os_printf("  ssid:%s, passwd:%s, key_mgmt:%s, mkey_set:%d\r\n", sys_cfgs.ssid, sys_cfgs.passwd, wificfg_keymgmt_str(), sys_cfgs.mkey_set);
    dump_key("  psk: ", sys_cfgs.psk, 32, 0);
#if WIFI_REPEATER_SUPPORT
    _os_printf("  r_ssid:%s, r_passwd:%s, r_key_mgmt:%s\r\n", sys_cfgs.r_ssid, sys_cfgs.r_passwd, wificfg_keymgmt_str());
    dump_key("  r_psk:", sys_cfgs.r_psk, 32, 0);
#endif
    _os_printf("  sta_max:%d, acs_enable:%d, acs_tmo:%d, ack_tmo:%d\r\n",
               sys_cfgs.sta_max,
               sys_cfgs.acs_enable,
               sys_cfgs.acs_tmo,
               sys_cfgs.ack_tmo);
    _os_printf("  txpwer:%d, pwr_super:%d\r\n",
               sys_cfgs.txpower,
               sys_cfgs.super_pwr_set ? sys_cfgs.super_pwr : TX_PWR_SUPER_EN);
    _os_printf("  bss_max_idle:%d, beacon_int:%d, dtim_period:%d\r\n",
               sys_cfgs.bss_max_idle, sys_cfgs.beacon_int, sys_cfgs.dtim_period);
    _os_printf("  dhcpc_en:%d, dhcpd_en:%d, use4addr:%d, devname:%s\n",
               sys_cfgs.dhcpc_en, sys_cfgs.dhcpd_en, sys_cfgs.use4addr, sys_cfgs.devname);
    _os_printf("  ipaddr:" IPSTR ", netmask:" IPSTR ", gw:" IPSTR "\n",
               IP2STR_N(sys_cfgs.ipaddr), IP2STR_N(sys_cfgs.netmask), IP2STR_N(sys_cfgs.gw_ip));
    _os_printf("  dhcpd_start_ip:" IPSTR ", dhcpd_end_ip:" IPSTR ", dhcpd_lease_time:%d\n",
               IP2STR_N(sys_cfgs.dhcpd_startip), IP2STR_N(sys_cfgs.dhcpd_endip), sys_cfgs.dhcpd_lease_time);
    _os_printf("  roam_start:%d, roam_rssi_th:%d, roam_rssi_diff:%d, roam_rssi_int:%d\r\n",
               sys_cfgs.roam_start,
               sys_cfgs.roam_rssi_th,
               sys_cfgs.roam_rssi_diff,
               sys_cfgs.roam_rssi_int);
#if SYS_SAVE_PAIRSTA
    if (!IS_ZERO_ADDR(sys_cfgs.pair_stas[0])) {
        _os_printf("  Pair STAs:\r\n");
    } else {
        _os_printf("  No pair STAs\r\n");
    }
    for (uint8 i = 0; i < SYS_STA_MAX; i++) {
        if (!IS_ZERO_ADDR(sys_cfgs.pair_stas[i])) {
            _os_printf("    STA%d " MACSTR "\r\n", i, MAC2STR(sys_cfgs.pair_stas[i]));
        }
    }
#endif
    _os_printf("\r\n");
}
