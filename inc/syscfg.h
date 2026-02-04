#ifndef _PROJECT_SYSCFG_H_
#define _PROJECT_SYSCFG_H_

enum WIFI_WORK_MODE {
    WIFI_MODE_NONE = 0,
    WIFI_MODE_STA,
    WIFI_MODE_WNBSTA,
    WIFI_MODE_AP,
    WIFI_MODE_WNBAP,

    WIFI_MODE_AP_STA,
    WIFI_MODE_WNBAP_WNBSTA,
    WIFI_MODE_AP_WNBSTA,
    WIFI_MODE_WNBAP_STA,

    WIFI_MODE_AP_WNBAP,
};

#define MODE_IS_AP(mode)       (mode == WIFI_MODE_AP || mode == WIFI_MODE_WNBAP)
#define MODE_IS_STA(mode)      (mode == WIFI_MODE_STA || mode == WIFI_MODE_WNBSTA)
#define MODE_IS_REPEATER(mode) (mode >= WIFI_MODE_AP_STA && mode != WIFI_MODE_AP_WNBAP)
#define MODE_INCLUDE_AP(mode)  (MODE_IS_AP(mode) || mode >= WIFI_MODE_AP_STA)

#define AH_VALID_BW(bw)        ((bw) == 1 || (bw) == 2 || (bw) == 4 || (bw) == 8)
#define AH_VALID_FREQ(f)       ((f) >= 7300 && (f) <= 9300)

struct system_status {
    uint32 dhcpc_done : 1,
        wifi_connected : 1,
        dbg_heap : 1,
        dbg_top : 2,
        dbg_lmac : 2,
        dbg_umac : 1,
        dbg_irq : 1,
        reset_wdt : 1,
        pair_success : 1,
        upgrading : 1;
    uint8 bssid[6];
    int8 rssi;
    int8 evm;
    uint8 channel;
    struct {
        uint32 ipaddr, netmask, svrip, router, dns1, dns2;
    } dhcpc_result;
};

struct sys_config {
    uint16 magic_num, crc;
    uint16 size, rev1, rev2, rev3;
    ///////////////////////////////////////

    uint8 wifi_mode, bss_bw, tx_mcs, channel;
    uint8 bssid[6], mac[6];
    uint8 wifi_hwmode, network_mode, acs_enable, acs_tmo;
    uint8 ssid[SSID_MAX_LEN + 1];
    uint8 psk[32];
    uint8 mcast_key[32];
    char passwd[PASSWD_MAX_LEN + 1];
    uint16 bss_max_idle, beacon_int;
    uint16 ack_tmo, dtim_period;
    uint32 key_mgmt;
    uint16 chan_list[16];
    uint8 chan_cnt;
    uint8 txpower;

    uint16 dhcpc_en : 1, dhcpd_en : 1, use4addr : 1, cfg_init : 1, pair_conn_only : 1, ap_hide : 1, roam_start : 1, mkey_set : 1,
        ap_psmode : 1, wkdata_save : 1, autosleep : 1, super_pwr_set : 1, super_pwr : 2, xx : 2;
    uint32 ipaddr, netmask, gw_ip;
    uint32 dhcpd_startip, dhcpd_endip, dhcpd_lease_time;
    uint8 devname[8];

#if WIFI_REPEATER_SUPPORT
    uint8 r_ssid[SSID_MAX_LEN + 1];
    uint8 r_psk[32];
    char r_passwd[PASSWD_MAX_LEN + 1];
    uint32 r_key_mgmt;
#endif

    uint8 psmode;
    uint32 auto_sleep_time;
    uint16 heartbeat_int;

    uint32 dhcpd_dns1, dhcpd_dns2, dhcpd_router;

#if SYS_SAVE_PAIRSTA
    uint8 pair_stas[SYS_STA_MAX][6];
#endif
    uint8 region_code[2];

    uint32 wpa_proto;
    uint32 pairwise_cipher;
    uint32 group_cipher;

    uint8 sta_max;
    int8 roam_rssi_th;
    uint8 roam_rssi_diff, roam_rssi_int;
};

extern struct sys_config sys_cfgs;
extern struct system_status sys_status;

void syscfg_set_default_val(void);
int32 wificfg_flush(uint8 ifidx);
void syscfg_flush(void);
void sys_wifi_scan(void);
void syscfg_check(void);
void syscfg_dump(void);

#endif
