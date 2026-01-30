#include "sys_config.h"
#include "typesdef.h"
#include "list.h"
#include "dev.h"
#include "devid.h"
#include "osal/string.h"
#include "osal/mutex.h"
#include "osal/task.h"
#include "osal/semaphore.h"
#include "osal/timer.h"
#include "osal/work.h"
#include "hal/gpio.h"
#include "hal/dma.h"
#include "lib/heap/sysheap.h"
#include "lib/syscfg/syscfg.h"
#include "lib/umac/wifi_mgr.h"
#include "lib/umac/wifi_cfg.h"
#include "lib/atcmd/libatcmd.h"
#include "lib/lmac/lmac.h"
#include "syscfg.h"

#define DSLEEP_STATE_IND                PB_0

extern void *lmacops;

struct sys_config sys_cfgs = {
    .wifi_mode      = SYS_WIFI_MODE,
    .channel        = 0,
    .beacon_int     = 500,
    .dtim_period    = 2,
    .bss_max_idle   = 300,
    .key_mgmt       = WPA_KEY_MGMT_PSK,
    .ipaddr         = 0x010A0A0A,
    .netmask        = 0x000000FF,
    .gw_ip          = 0x010A0A0A,
    .auto_save      = 1,
    .pri_chan       = 3,
    .tx_mcs         = 0xff,
    .sta_max        = SYS_STA_MAX,
    .acs_enable     = 1,
    .wkio_mode      = 0,
    .pa_pwrctrl_dis = DSLEEP_PAPWRCTL_DIS,
    .dcdc13         = DC_DC_1_3V,
    .psmode         = 0,
    .dupfilter      = 1,
    .aplost_time    = 10,
    .dhcpc_en       = 1,
    .wpa_proto      = WPA_PROTO_RSN,
    .pairwise_cipher = WPA_CIPHER_CCMP,
    .group_cipher   = WPA_CIPHER_CCMP,
    .use4addr       = 1,
    .txpower        = TX_POWER,
};

int32 syscfg_save(void)
{
    return syscfg_write(&sys_cfgs, sizeof(sys_cfgs));
}

int32 wificfg_save(int8 force)
{
    if (force || sys_cfgs.auto_save) {
        syscfg_save();
    }
    return 0;
}

const char *wificfg_keymgmt_str(void)
{
    return sys_cfgs.key_mgmt == WPA_KEY_MGMT_PSK ? "WPA-PSK" : "NONE";
}

const char *wificfg_wifimode_str(void)
{
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

int32 wificfg_get_ifidx(uint8 wifi_mode, uint8 switch_ap)
{
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

void syscfg_set_default_val(void)
{
    sysctrl_efuse_mac_addr_calc(sys_cfgs.mac);
    if (IS_ZERO_ADDR(sys_cfgs.mac)) {
        os_random_bytes(sys_cfgs.mac, 6);
        sys_cfgs.mac[0] &= 0xfe;
        os_printf("use random mac "MACSTR"\r\n", MAC2STR(sys_cfgs.mac));
    }

    os_snprintf((char *)sys_cfgs.ssid, SSID_MAX_LEN, WIFI_SSID_PREFIX"%02X%02X%02X", sys_cfgs.mac[3], sys_cfgs.mac[4], sys_cfgs.mac[5]);
    os_strcpy(sys_cfgs.passwd, "12345678");
    wpa_passphrase(sys_cfgs.ssid, sys_cfgs.passwd, sys_cfgs.psk);
    os_snprintf((char *)sys_cfgs.ssid, SSID_MAX_LEN, WIFI_SSID_PREFIX"%02X%02X%02X", sys_cfgs.mac[3], sys_cfgs.mac[4], sys_cfgs.mac[5]);

    if (module_efuse_info.module_type == MODULE_TYPE_750M) {
        sys_cfgs.chan_list[0] = 7640;
        sys_cfgs.chan_list[1] = 7720;
        sys_cfgs.chan_list[2] = 7800;
        sys_cfgs.chan_cnt = 3;
        sys_cfgs.bss_bw   = 8;
    } else if (module_efuse_info.module_type == MODULE_TYPE_810M) {
        sys_cfgs.chan_list[0] = 8050;
        sys_cfgs.chan_list[1] = 8150;
        sys_cfgs.chan_cnt = 2;
        sys_cfgs.bss_bw   = 8;
    } else if (module_efuse_info.module_type == MODULE_TYPE_850M) {
        sys_cfgs.chan_list[0] = 8450;
        sys_cfgs.chan_list[1] = 8550;
        sys_cfgs.chan_cnt = 2;
        sys_cfgs.bss_bw   = 8;
    } else if (module_efuse_info.module_type == MODULE_TYPE_860M) {
        sys_cfgs.chan_list[0] = 8640;
        sys_cfgs.chan_list[1] = 8660;
        sys_cfgs.chan_cnt = 2;
        sys_cfgs.bss_bw   = 2;
    } else { // 915M case
        sys_cfgs.chan_list[0] = 9080;
        sys_cfgs.chan_list[1] = 9160;
        sys_cfgs.chan_list[2] = 9240;
        sys_cfgs.chan_cnt = 3;
        sys_cfgs.bss_bw   = 8;
    }
}

void syscfg_check(void)
{
    if (sys_cfgs.auto_sleep_time == 0) sys_cfgs.auto_sleep_time = 10000;
    if (sys_cfgs.psconnect_period == 0) sys_cfgs.psconnect_period = 60;
    if (sys_cfgs.psconnect_roundup == 0) sys_cfgs.psconnect_roundup = 4;
    if (sys_cfgs.psmode > DSLEEP_MODE_NUM-1) sys_cfgs.psmode = 0;
    if (sys_cfgs.wait_psmode > DSLEEP_WAIT_MODE_NUM-1) sys_cfgs.wait_psmode = 0;
    if (sys_cfgs.standby_channel == 0 || sys_cfgs.standby_channel > sys_cfgs.chan_cnt) 
        sys_cfgs.standby_channel = 1;
    if (sys_cfgs.standby_period_ms == 0) sys_cfgs.standby_period_ms = 5000;
    if (sys_cfgs.chan_cnt > 16) sys_cfgs.chan_cnt = 16;
    if (!sys_cfgs.aplost_time) sys_cfgs.aplost_time = 7;
    if (!sys_cfgs.beacon_int || sys_cfgs.beacon_int > 10000) sys_cfgs.beacon_int = 500;
    if (!sys_cfgs.dtim_period) sys_cfgs.dtim_period = 2;
    if (!sys_cfgs.bss_max_idle) sys_cfgs.bss_max_idle = 300;
    if (sys_cfgs.tx_bw != 1 && sys_cfgs.tx_bw != 2 && sys_cfgs.tx_bw != 4 && sys_cfgs.tx_bw != 8) 
        sys_cfgs.tx_bw = sys_cfgs.bss_bw;
    if (sys_cfgs.frm_max == 0) sys_cfgs.frm_max = 7;
    if (sys_cfgs.rts_max == 0) sys_cfgs.rts_max = 31;
    if (!sys_cfgs.wkhost_reasons_set) {
        sys_cfgs.wkhost_reasons[0] = DSLEEP_WK_REASON_TIM;
        sys_cfgs.wkhost_reasons[1] = DSLEEP_WK_REASON_BC_TIM;
        sys_cfgs.wkhost_reasons[2] = DSLEEP_WK_REASON_IO;
        sys_cfgs.wkhost_reasons[3] = DSLEEP_WK_REASON_MCLR;
        sys_cfgs.wkhost_reasons[4] = DSLEEP_WK_REASON_PIR;
        sys_cfgs.wkhost_reasons[5] = DSLEEP_WK_REASON_WK_DATA;
        sys_cfgs.wkhost_reasons[6] = DSLEEP_WK_REASON_HB_TIMEOUT;
        sys_cfgs.wkhost_reasons[7] = DSLEEP_WK_REASON_APWK;
    }
    if (sys_cfgs.roam_rssi_diff == 0) sys_cfgs.roam_rssi_diff = 12;
    if (sys_cfgs.roam_rssi_int == 0) sys_cfgs.roam_rssi_int = 5;
    if (sys_cfgs.roam_rssi_th == 0) sys_cfgs.roam_rssi_th = -60;
}

int32 wificfg_flush(uint8 ifidx)
{
    if (!IS_ZERO_ADDR(sys_cfgs.mac)) {
        ieee80211_conf_set_mac(ifidx, sys_cfgs.mac);
    }
    if(sys_cfgs.use4addr){
        ieee80211_deliver_init(128, 60);
    }
    ieee80211_conf_set_use4addr(ifidx, sys_cfgs.use4addr);
    ieee80211_conf_set_chanlist(ifidx, sys_cfgs.chan_list, sys_cfgs.chan_cnt);
    if(sys_cfgs.channel==0 && sys_status.channel){
        ieee80211_conf_set_channel(ifidx, sys_status.channel);
    }else{
        ieee80211_conf_set_channel(ifidx, sys_cfgs.channel);
    }
    ieee80211_conf_set_bssbw(ifidx, sys_cfgs.bss_bw);
    ieee80211_conf_set_aplost_time(ifidx, sys_cfgs.aplost_time);
    ieee80211_conf_set_ap_psmode_en(ifidx, sys_cfgs.ap_psmode);
    ieee80211_conf_set_beacon_int(ifidx, sys_cfgs.beacon_int);
    ieee80211_conf_set_dtim_int(ifidx, sys_cfgs.dtim_period);
    ieee80211_conf_set_bss_max_idle(ifidx, sys_cfgs.bss_max_idle);
    if (!IS_ZERO_ADDR(sys_cfgs.bssid)) {
        ieee80211_conf_set_bssid(ifidx, sys_cfgs.bssid);
    }
    if(MODE_IS_AP(ifidx) && MODE_IS_REPEATER(sys_cfgs.wifi_mode)  && sys_cfgs.cfg_init){
#if WIFI_REPEATER_SUPPORT
        ieee80211_conf_set_ssid(ifidx, sys_cfgs.r_ssid);
        ieee80211_conf_set_keymgmt(ifidx, sys_cfgs.r_key_mgmt);
        ieee80211_conf_set_psk(ifidx, sys_cfgs.r_psk);
#else
        os_printf("Not supported, please set WIFI-REPEATER_SUPPORT to 1\r\n");                
#endif
    }else{
        ieee80211_conf_set_ssid(ifidx, sys_cfgs.ssid);
        ieee80211_conf_set_keymgmt(ifidx, sys_cfgs.key_mgmt);
        ieee80211_conf_set_psk(ifidx, sys_cfgs.psk);
    }
    ieee80211_conf_set_wpa_cipher(ifidx, sys_cfgs.wpa_proto, sys_cfgs.pairwise_cipher, sys_cfgs.group_cipher);
    ieee80211_conf_set_dupfilter(ifidx, 1);
    ieee80211_conf_set_roaming(ifidx, sys_cfgs.roam_start);
    ieee80211_conf_set_roam_config(ifidx, sys_cfgs.roam_rssi_th, sys_cfgs.roam_rssi_diff, sys_cfgs.roam_rssi_int);
    ieee80211_conf_set_wpa_group_rekey(ifidx, 0);

    lmac_set_bss_bw(lmacops, sys_cfgs.bss_bw);
    lmac_set_tx_mcs(lmacops, sys_cfgs.tx_mcs);
    lmac_set_txpower(lmacops, sys_cfgs.txpower);
    //lmac_set_pri_chan(lmacops, sys_cfgs.pri_chan);
    lmac_set_aggcnt(lmacops, sys_cfgs.agg_cnt);
    lmac_set_auto_chan_switch(lmacops, !sys_cfgs.auto_chsw);
    lmac_set_wakeup_io(lmacops, sys_cfgs.wkup_io, sys_cfgs.wkio_edge);
    lmac_set_super_pwr(lmacops, sys_cfgs.super_pwr_set?sys_cfgs.super_pwr:1);
    lmac_set_pa_pwr_ctrl(lmacops, !sys_cfgs.pa_pwrctrl_dis);
    lmac_set_vdd13(lmacops, sys_cfgs.dcdc13);
    lmac_set_ack_timeout_extra(lmacops, sys_cfgs.ack_tmo);
    if (sys_cfgs.dual_ant) {
        lmac_set_ant_auto_en(lmacops, !sys_cfgs.ant_auto_dis);
        lmac_set_ant_sel(lmacops, sys_cfgs.ant_sel);
    }
    lmac_set_ps_mode(lmacops, sys_cfgs.psmode);
    lmac_set_wait_psmode(lmacops, sys_cfgs.wait_psmode);
    lmac_set_psconnect_period(lmacops, sys_cfgs.psconnect_period);
    lmac_set_ap_psmode_en(lmacops, sys_cfgs.ap_psmode);
    lmac_set_standby(lmacops, sys_cfgs.standby_channel-1, sys_cfgs.standby_period_ms*1000);
    //lmac_set_rxg_offest(wnb->ops, wnb->cfg->rxg_offest);
    lmac_set_cca_for_ce(lmacops, sys_cfgs.cca_for_ce);
    gpio_set_val(DSLEEP_STATE_IND, sys_cfgs.wkio_mode);
    return 0;
}

void syscfg_dump(void)
{
    int32 i = 0;
    _os_printf("SYSCFG:\r\n");
    _os_printf("  mac:"MACSTR", bssid:"MACSTR"\r\n", MAC2STR(sys_cfgs.mac), MAC2STR(sys_cfgs.bssid));
    _os_printf("  mode:%s, bss_bw:%d\r\n",
              wificfg_wifimode_str(),
              sys_cfgs.bss_bw);
    _os_printf("  chan_list:");
    for (i = 0; i < sys_cfgs.chan_cnt; i++){
        _os_printf(" %d", sys_cfgs.chan_list[i]);
    }
    _os_printf(", chan_cnt:%d\r\n", sys_cfgs.chan_cnt);
    _os_printf("  ssid:%s, passwd:%s, key_mgmt:%s, mkey_set:%d\r\n", sys_cfgs.ssid, sys_cfgs.passwd, wificfg_keymgmt_str(), sys_cfgs.mkey_set);
    dump_key("  psk:", sys_cfgs.psk, 32, 0);
#if WIFI_REPEATER_SUPPORT
    _os_printf("  r_ssid:%s, r_passwd:%s, r_key_mgmt:%s\r\n",  sys_cfgs.r_ssid, sys_cfgs.r_passwd, wificfg_keymgmt_str());
    dump_key("  r_psk:", sys_cfgs.r_psk, 32, 0);
#endif
    _os_printf("  tx_mcs:%d, sta_max:%d, acs_enable:%d, acs_tmo:%d, ack_tmo:%d, pri_chan:%d, agg_cnt:%d\r\n",
              sys_cfgs.tx_mcs,
              sys_cfgs.sta_max,
              sys_cfgs.acs_enable,
              sys_cfgs.acs_tmo,
              sys_cfgs.ack_tmo,
              sys_cfgs.pri_chan,
              sys_cfgs.agg_cnt);
    _os_printf("  txpower:%d, super_pwr:%d, dcdc13:%d, pa_pwrctrl_dis:%d\r\n",
              sys_cfgs.txpower,
              sys_cfgs.super_pwr_set?sys_cfgs.super_pwr:1,
              sys_cfgs.dcdc13,
              sys_cfgs.pa_pwrctrl_dis);
    _os_printf("  bss_max_idle:%d, beacon_int:%d, dtim_period:%d, aplost_time:%d, auto_sleep_time:%d\r\n",
              sys_cfgs.bss_max_idle,
              sys_cfgs.beacon_int,
              sys_cfgs.dtim_period,
              sys_cfgs.aplost_time,
              sys_cfgs.auto_sleep_time);
    _os_printf("  wait_psmode:%d, psconnect:%d/%d, dis_psconnect:%d, standby:%d/%d\r\n",
              sys_cfgs.wait_psmode,
              sys_cfgs.psconnect_period,
              sys_cfgs.psconnect_roundup,
              sys_cfgs.dis_psconnect,
              sys_cfgs.standby_channel,
              sys_cfgs.standby_period_ms);
    _os_printf("  wkio_mode:%d, wkup_io:%d, wkio_edge:%d, psmode:%d\r\n",
              sys_cfgs.wkio_mode,
              sys_cfgs.wkup_io,
              sys_cfgs.wkio_edge,
              sys_cfgs.psmode);
    _os_printf("  reassoc_wkhost:%d, wkhost_reasons_set:%d,",
              sys_cfgs.reassoc_wkhost,
              sys_cfgs.wkhost_reasons_set);
    _os_printf("  wkhost_reasons:");
    for (i = 0; i < sizeof(sys_cfgs.wkhost_reasons); i++){
        if(sys_cfgs.wkhost_reasons[i]) _os_printf("%d ", sys_cfgs.wkhost_reasons[i]);
    }
    _os_printf("\r\n");
    _os_printf("  auto_save:%d, auto_chsw_dis:%d, auto_role:%d, pair_autostop:%d\r\n",
              sys_cfgs.auto_save,
              sys_cfgs.auto_chsw,
              sys_cfgs.auto_role,
              sys_cfgs.pair_autostop);
    _os_printf("  dhcpc_en:%d, dhcpc_update_hbdata:%d\r\n",
              sys_cfgs.dhcpc_en,
              sys_cfgs.dhcpc_update_hbdata);
    _os_printf("  dual_ant:%d, ant_auto_dis:%d, ant_sel:%d\r\n",
              sys_cfgs.dual_ant,
              sys_cfgs.ant_auto_dis,
              sys_cfgs.ant_sel);
    _os_printf("  dupfilter:%d, mac_filter_en:%d, mcast_filter:%d, use4addr:%d, bssid_set:%d\r\n",
              sys_cfgs.dupfilter,
              sys_cfgs.mac_filter_en,
              sys_cfgs.mcast_filter,
              sys_cfgs.use4addr,
              sys_cfgs.bssid_set);
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
    for (i = 0; i < SYS_STA_MAX; i++) {
        if (!IS_ZERO_ADDR(sys_cfgs.pair_stas[i])) {
            _os_printf("    STA%d "MACSTR"\r\n", i, MAC2STR(sys_cfgs.pair_stas[i]));
        }
    }
#endif
    _os_printf("\r\n");
}

void wificfg_set_mode(uint8 mode)
{
    uint8 mode_ap = wificfg_get_ifidx(mode, 1);
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
    wificfg_save(0);
}

int32 wificfg_get_mode()
{
    return sys_cfgs.wifi_mode;
}

int32 wificfg_get_conn_state(void)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    return (ieee80211_conf_get_stacnt(ifidx) != 0) ? WPA_COMPLETED : 0;
}

int32 wificfg_get_stacnt(void)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    return ieee80211_conf_get_stacnt(ifidx);
}

int32 wificfg_get_txpower(void)
{
    return sys_cfgs.txpower;
}

int32 wificfg_set_bss_bw(uint8 bss_bw)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    os_printf("set bss_bw, new:%d, cur:%d\r\n", bss_bw, sys_cfgs.bss_bw);
    if (sys_cfgs.bss_bw != bss_bw) {
        if (AH_VALID_BW(bss_bw)) {
            sys_cfgs.bss_bw = bss_bw;
            ieee80211_conf_set_bssbw(ifidx, bss_bw);
            wificfg_save(0);
        } else {
            os_printf("unvalid BSS_BW:%dM\r\n",bss_bw);
            return -EINVAL;
        }
    }
    return 0;
}

int32 wificfg_set_tx_bw(uint8 tx_bw)
{
    os_printf("set tx_bw, new:%d, cur:%d\r\n", tx_bw, sys_cfgs.tx_bw);
    if (sys_cfgs.tx_bw != tx_bw) {
        sys_cfgs.tx_bw = tx_bw;
        lmac_set_tx_bw(lmacops, tx_bw);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_get_bss_bw(void)
{
    return sys_cfgs.bss_bw;
}

int32 wificfg_get_curr_freq(void)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    uint8 chan;
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    chan = ieee80211_conf_get_channel(ifidx);
    return ieee80211_chan_center_freq(ifidx, chan);
}

int32 wificfg_set_tx_mcs(uint8 tx_mcs)
{
    os_printf("set tx_mcs, new:%d, cur:%d\r\n", tx_mcs, sys_cfgs.tx_mcs);
    if (sys_cfgs.tx_mcs != tx_mcs) {
        sys_cfgs.tx_mcs = tx_mcs;
        lmac_set_tx_mcs(lmacops, tx_mcs);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_channel(uint8 channel)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    os_printf("set channel, new:%d, cur:%d\r\n", channel, sys_cfgs.channel);
    if (sys_cfgs.channel != channel) {
        if (ifidx < 0) {
            ieee80211_conf_set_channel(WIFI_MODE_AP, channel);
            ieee80211_conf_set_channel(WIFI_MODE_WNBAP, channel);
            sys_cfgs.channel = ieee80211_conf_get_channel(WIFI_MODE_AP);
        } else {
            ieee80211_conf_set_channel(ifidx, channel);
            sys_cfgs.channel = ieee80211_conf_get_channel(ifidx);
        }
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_chan_list(uint16 *chan_list, uint8 chan_cnt)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    uint8 i;

    if(chan_cnt > 16) chan_cnt = 16;
    if (sys_cfgs.chan_cnt != chan_cnt || os_memcmp(chan_list, sys_cfgs.chan_list, chan_cnt * sizeof(uint16))) {
        for (i = 0; i < chan_cnt; ++i) {
            if (!AH_VALID_FREQ(chan_list[i])) {
                os_printf("invalid freq param\r\n");
                return -EINVAL;
            }
        }
        sys_cfgs.chan_cnt = chan_cnt;
        os_memcpy(sys_cfgs.chan_list, chan_list, chan_cnt * sizeof(uint16));
        if (ifidx < 0) {
            ieee80211_conf_set_chanlist(WIFI_MODE_AP, sys_cfgs.chan_list, sys_cfgs.chan_cnt);
            ieee80211_conf_set_channel(WIFI_MODE_AP, 1);
            ieee80211_conf_set_channel(WIFI_MODE_WNBAP, 1);
            sys_cfgs.channel = ieee80211_conf_get_channel(WIFI_MODE_AP);
        } else {
            ieee80211_conf_set_chanlist(ifidx, sys_cfgs.chan_list, sys_cfgs.chan_cnt);
            ieee80211_conf_set_channel(ifidx, 1);
            sys_cfgs.channel = ieee80211_conf_get_channel(ifidx);
        }
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_get_chan_list(uint16 *chan_list, uint8 chan_cnt)
{
    int32 count = (chan_cnt < sys_cfgs.chan_cnt ? chan_cnt : sys_cfgs.chan_cnt);
    os_memcpy(chan_list, sys_cfgs.chan_list, 2 * count);
    return count;
}

int32 wificfg_get_freq_range(uint16 *freq_start, uint16 *freq_end, uint8 *chan_bw)
{
    *freq_start = sys_cfgs.chan_list[0];
    *freq_end = sys_cfgs.chan_list[sys_cfgs.chan_cnt - 1];
    *chan_bw = (sys_cfgs.chan_list[1] - sys_cfgs.chan_list[0]) / 10;
    return 0;
}

int32 wificfg_set_macaddr(uint8 *addr)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    os_printf("set mac:"MACSTR"\r\n", MAC2STR(addr));
    if (os_memcmp(sys_cfgs.mac, addr, 6)) {
        os_memcpy(sys_cfgs.mac, addr, 6);
        if (ifidx < 0) {
            ieee80211_conf_set_mac(WIFI_MODE_AP, addr);
            ieee80211_conf_set_mac(WIFI_MODE_WNBAP, addr);
        } else {
            ieee80211_conf_set_mac(ifidx, addr);
        }
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_ssid(uint8 *ssid)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    os_printf("set ssid:%s\r\n", ssid);
    if (os_strncmp(sys_cfgs.ssid, ssid, SSID_MAX_LEN)) {
        sys_cfgs.bssid_set = 0;
        os_memset(sys_cfgs.bssid, 0, 6);
        os_strncpy(sys_cfgs.ssid, ssid, SSID_MAX_LEN);
        ieee80211_conf_set_bssid(WIFI_MODE_STA, NULL);
        ieee80211_conf_set_bssid(WIFI_MODE_WNBSTA, NULL);
        if (ifidx < 0) {
            ieee80211_conf_set_ssid(WIFI_MODE_AP, sys_cfgs.ssid);
            ieee80211_conf_set_ssid(WIFI_MODE_WNBAP, sys_cfgs.ssid);
        } else {
            ieee80211_conf_set_ssid(ifidx, sys_cfgs.ssid);
        }
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_get_ssid(uint8 ssid[32])
{
    os_strncpy(ssid, sys_cfgs.ssid, 32);
    return 0;
}

int32 wificfg_set_bssid(uint8 *bssid)
{
    os_printf("set bssid: "MACSTR"\r\n", MAC2STR(bssid));
    if (MODE_IS_STA(sys_cfgs.wifi_mode) && os_memcmp(sys_cfgs.bssid, bssid, 6)) {
        os_memcpy(sys_cfgs.bssid, bssid, 6);
        ieee80211_conf_set_bssid(WIFI_MODE_STA, bssid);
        ieee80211_conf_set_bssid(WIFI_MODE_WNBSTA, bssid);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_get_bssid(uint8 *bssid)
{
    os_memcpy(bssid, sys_cfgs.bssid, 6);
    return 0;
}

int32 wificfg_set_wpa_psk(uint8 *psk)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (os_memcmp(sys_cfgs.psk, psk, 32)) {
        os_memset(sys_cfgs.psk, 0, sizeof(sys_cfgs.psk));
        os_memcpy(sys_cfgs.psk, psk, 32);
        if (ifidx < 0) {
            ieee80211_conf_set_psk(WIFI_MODE_AP, psk);
            ieee80211_conf_set_psk(WIFI_MODE_WNBAP, psk);
        } else {
            ieee80211_conf_set_psk(ifidx, psk);
        }
        wificfg_save(0);
        dump_key("set PSK:", psk, 32, 0);
    }
    return 0;
}

int32 wificfg_get_wpa_psk(uint8 *key)
{
    os_memcpy(key, sys_cfgs.psk, 32);
    return 0;
}

int32 wificfg_set_key_mgmt(uint32 key_mgmt)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    os_printf("set key_mgmt, new:%d, cur:%d\r\n", key_mgmt, sys_cfgs.key_mgmt);
    if (sys_cfgs.key_mgmt != key_mgmt) {
        sys_cfgs.key_mgmt = key_mgmt;
        if (ifidx < 0) {
            ieee80211_conf_set_keymgmt(WIFI_MODE_AP, key_mgmt);
            ieee80211_conf_set_keymgmt(WIFI_MODE_WNBAP, key_mgmt);
        } else {
            ieee80211_conf_set_keymgmt(ifidx, key_mgmt);
        }
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_acs(uint8 acs, uint8 tmo)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    if (sys_cfgs.acs_enable != acs || sys_cfgs.acs_tmo != tmo) {
        sys_cfgs.acs_enable = acs;
        sys_cfgs.acs_tmo = tmo;
        ieee80211_conf_set_acs(ifidx, acs, tmo);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_pri_chan(uint8 pri_chan)
{
    os_printf("set pri_chan: new:%d, cur:%d\r\n", pri_chan, sys_cfgs.pri_chan);
    if (sys_cfgs.pri_chan != pri_chan) {
        sys_cfgs.pri_chan = pri_chan;
        lmac_set_pri_chan(lmacops, pri_chan);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_tx_power(uint8 txpower)
{
    os_printf("set txpower: new:%d, cur:%d\r\n", txpower, sys_cfgs.txpower);
    if (sys_cfgs.txpower != txpower) {
        lmac_set_txpower(lmacops, txpower);
        sys_cfgs.txpower = lmac_get_txpower(lmacops);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_beacon_int(uint32 beacon_int)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    os_printf("set beacon_int, new:%d, cur:%d\r\n", beacon_int, sys_cfgs.beacon_int);
    if (sys_cfgs.beacon_int != beacon_int) {
        sys_cfgs.beacon_int = beacon_int;
        if (ifidx < 0) {
            ieee80211_conf_set_beacon_int(WIFI_MODE_AP, beacon_int);
            ieee80211_conf_set_beacon_int(WIFI_MODE_WNBAP, beacon_int);
        } else {
            ieee80211_conf_set_beacon_int(ifidx, beacon_int);
        }
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_bss_maxidle(uint32 max_idle)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    os_printf("set bss_max_idle, new:%d, cur:%d\r\n", max_idle, sys_cfgs.bss_max_idle);
    if (sys_cfgs.bss_max_idle != max_idle) {
        sys_cfgs.bss_max_idle = max_idle;
        if (ifidx < 0) {
            ieee80211_conf_set_bss_max_idle(WIFI_MODE_AP, max_idle);
            ieee80211_conf_set_bss_max_idle(WIFI_MODE_WNBAP, max_idle);
        } else {
            ieee80211_conf_set_bss_max_idle(ifidx, max_idle);
        }
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_wkio_mode(uint8 mode)
{
    os_printf("set wkio_mode, new:%d, cur:%d\r\n", mode, sys_cfgs.wkio_mode);
    if (sys_cfgs.wkio_mode != mode) {
        sys_cfgs.wkio_mode = mode;
        gpio_set_val(DSLEEP_STATE_IND, sys_cfgs.wkio_mode);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_dtim_period(uint32 dtim_period)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    dtim_period = (dtim_period/sys_cfgs.beacon_int);
    os_printf("set dtim_period, new:%d, cur:%d\r\n", dtim_period, sys_cfgs.dtim_period);
    if (sys_cfgs.dtim_period != dtim_period) {
        sys_cfgs.dtim_period = dtim_period;
        if (ifidx < 0) {
            ieee80211_conf_set_dtim_int(WIFI_MODE_AP, dtim_period);
            ieee80211_conf_set_dtim_int(WIFI_MODE_WNBAP, dtim_period);
        } else {
            ieee80211_conf_set_dtim_int(ifidx, dtim_period);
        }
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_psmode(uint8 psmode)
{
    if (sys_cfgs.psmode != psmode) {
        sys_cfgs.psmode = psmode;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_wkdata_save(uint8 wkdata_save)
{
    if (sys_cfgs.wkdata_save != wkdata_save) {
        sys_cfgs.wkdata_save = wkdata_save;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_autosleep(uint8 autosleep)
{
    if (sys_cfgs.autosleep != autosleep) {
        sys_cfgs.autosleep = autosleep;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_psconnect(uint8 period, uint8 roundup)
{
    if (period == 0 || roundup == 0) {
        return -EINVAL;
    }
    if (sys_cfgs.psconnect_period != period || sys_cfgs.psconnect_roundup != roundup) {
        sys_cfgs.psconnect_period = period;
        sys_cfgs.psconnect_roundup = roundup;
        lmac_set_psconnect_period(lmacops, period);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_wait_psmode(uint8 mode)
{
    if (sys_cfgs.wait_psmode != mode && mode < DSLEEP_WAIT_MODE_NUM) {
        sys_cfgs.wait_psmode = mode;
        lmac_set_wait_psmode(lmacops, mode);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_standby(uint8 channel, uint32 period_ms)
{
    if (sys_cfgs.standby_channel != channel || sys_cfgs.standby_period_ms != period_ms) {
        if (channel == 0 || channel > sys_cfgs.chan_cnt) {
            os_printf("standby channel over range, reset default channel 1\r\n");
            channel = 1;
        }
        sys_cfgs.standby_channel = channel;
        sys_cfgs.standby_period_ms = period_ms;
        lmac_set_standby(lmacops, channel-1, period_ms*1000);
        wificfg_save(0);
    }
    os_printf("standby channel %d, period_ms:%d\r\n", sys_cfgs.standby_channel, sys_cfgs.standby_period_ms);
    return 0;
}

int32 wificfg_load_def(uint8 reset)
{
    syscfg_loaddef();
    if (reset) {
        mcu_reset();
    }
    return 0;
}

int32 wificfg_set_sleep_aplost_time(uint32 time)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    if (time > 0 && sys_cfgs.aplost_time != time) {
        sys_cfgs.aplost_time = time;
        ieee80211_conf_set_aplost_time(ifidx, time);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_agg_cnt(uint8 agg_cnt)
{
    if (sys_cfgs.agg_cnt != agg_cnt) {
        sys_cfgs.agg_cnt = agg_cnt;
        lmac_set_aggcnt(lmacops, agg_cnt);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_get_agg_cnt(void)
{
    return sys_cfgs.agg_cnt;
}

int32 wificfg_set_auto_chan_switch(uint8 disable)
{
    if (sys_cfgs.auto_chsw != disable) {
        sys_cfgs.auto_chsw = disable;
        lmac_set_auto_chan_switch(lmacops, !disable);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_reassoc_wkhost(uint8 enable)
{
    if (sys_cfgs.reassoc_wkhost != enable) {
        sys_cfgs.reassoc_wkhost = enable;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_wakeup_io(uint8 io, uint8 edge)
{
    if (sys_cfgs.wkup_io != io || sys_cfgs.wkio_edge != edge) {
        sys_cfgs.wkup_io = io;
        sys_cfgs.wkio_edge = edge;
        lmac_set_wakeup_io(lmacops, io, edge);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_auto_sleep_time(uint8 time)
{
    int16 stime = (time > 32 ? -1 : time*1000);
    if (sys_cfgs.auto_sleep_time != stime) {
        sys_cfgs.auto_sleep_time = (stime < 0) ? -1 : stime;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_pair_autostop(uint8 en)
{
    if (sys_cfgs.pair_autostop != en) {
        sys_cfgs.pair_autostop = en;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_super_pwr(uint8 super_pwr)
{
    if(sys_cfgs.super_pwr_set == 0 || sys_cfgs.super_pwr != super_pwr){
        sys_cfgs.super_pwr = super_pwr;
        sys_cfgs.super_pwr_set = 1;
        lmac_set_super_pwr(lmacops, super_pwr);
        wificfg_save(0);
        os_printf("super power = %d\r\n", super_pwr);
    }
    return 0;
}

int32 wificfg_set_repeater_ssid(uint8 *ssid)
{
#if WIFI_REPEATER_SUPPORT
    uint8 mode_sta = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    uint8 mode_ap = wificfg_get_ifidx(sys_cfgs.wifi_mode, 1);

    if (os_strcmp(sys_cfgs.r_ssid, ssid)) {
        os_memset(sys_cfgs.r_ssid, 0, sizeof(sys_cfgs.r_ssid));
        os_strncpy(sys_cfgs.r_ssid, ssid, SSID_MAX_LEN);
        sys_cfgs.r_key_mgmt = sys_cfgs.key_mgmt;
        if (os_strlen(sys_cfgs.r_passwd) > 0) {
            wpa_passphrase(sys_cfgs.r_ssid, sys_cfgs.r_passwd, sys_cfgs.r_psk);
        }
        sys_cfgs.cfg_init = 1;
        if (MODE_IS_REPEATER(sys_cfgs.wifi_mode)) {
            ieee80211_conf_set_ssid(mode_ap, sys_cfgs.r_ssid);
            ieee80211_conf_set_keymgmt(mode_ap, sys_cfgs.r_key_mgmt);
            ieee80211_conf_set_psk(mode_ap, sys_cfgs.r_psk);
            if (sys_status.wifi_connected) {
                ieee80211_iface_start(mode_ap);
            } else {
                ieee80211_iface_stop(mode_ap);
                wificfg_flush(mode_sta);
                ieee80211_iface_start(mode_sta);
            }
        }
        wificfg_save(0);
    }
#else
        os_printf("Not supported, please set WIFI-REPEATER_SUPPORT to 1\r\n");                
#endif
    return 0;
}

int32 wificfg_set_repeater_psk(uint8 *psk)
{
#if WIFI_REPEATER_SUPPORT
    uint8 mode_sta = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    uint8 mode_ap = wificfg_get_ifidx(sys_cfgs.wifi_mode, 1);

    if (os_memcmp(sys_cfgs.r_psk, psk, 32)) {
        os_memset(sys_cfgs.r_psk, 0, sizeof(sys_cfgs.r_psk));
        os_memcpy(sys_cfgs.r_psk, psk, 32);
        sys_cfgs.r_key_mgmt = sys_cfgs.key_mgmt;
        sys_cfgs.cfg_init = 1;
        if (MODE_IS_REPEATER(sys_cfgs.wifi_mode)) {
            ieee80211_conf_set_psk(mode_ap, sys_cfgs.r_psk);
            ieee80211_conf_set_keymgmt(mode_ap, sys_cfgs.r_key_mgmt);
            if (sys_status.wifi_connected) {
                ieee80211_iface_start(mode_ap);
            } else {
                ieee80211_iface_stop(mode_ap);
                wificfg_flush(mode_sta);
                ieee80211_iface_start(mode_sta);
            }
        }
        wificfg_save(0);
    }
#else
    os_printf("Not supported, please set WIFI-REPEATER_SUPPORT to 1\r\n");                
#endif
    return 0;
}

int32 wificfg_set_auto_save(uint8 on)
{
    if (sys_cfgs.auto_save != on) {
        sys_cfgs.auto_save = on;
        wificfg_save(1);
    }
    return 0;
}

int32 wificfg_set_dcdc13(uint8 en)
{
    if (sys_cfgs.dcdc13 != en) {
        sys_cfgs.dcdc13 = en;
        lmac_set_vdd13(lmacops, en);
        os_printf("set VDD 1.3v %s\r\n", en?"ON":"OFF");
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_acktmo(uint16 tmo)
{
    if (sys_cfgs.ack_tmo != tmo) {
        sys_cfgs.ack_tmo = tmo;
        wificfg_save(0);
        lmac_set_ack_timeout_extra(lmacops, tmo);
    }
    return 0;
}

int32 wificfg_set_pa_pwrctrl_dis(uint8 dis)
{
    if (sys_cfgs.pa_pwrctrl_dis != dis) {
        sys_cfgs.pa_pwrctrl_dis = dis;
        lmac_set_pa_pwr_ctrl(lmacops, !dis);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_get_reason_code(void)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    return ieee80211_conf_get_reason_code(ifidx);
}

int32 wificfg_get_status_code(void)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    return ieee80211_conf_get_status_code(ifidx);
}

int32 wificfg_set_dhcpc_en(uint8 en)
{
    if (sys_cfgs.dhcpc_en != en) {
        sys_cfgs.dhcpc_en = en;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_ant_auto_off(uint8 off)
{
    if(off != sys_cfgs.ant_auto_dis){
        sys_cfgs.ant_auto_dis = off;
        sys_cfgs.dual_ant = 1;
        lmac_set_ant_auto_en(lmacops, !off);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_ant_sel(uint8 sel)
{
    if(sel != sys_cfgs.ant_sel){
        sys_cfgs.ant_sel = sel;
        lmac_set_ant_sel(lmacops, sel);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_get_ant_sel(void)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    return ieee80211_conf_get_ant_sel(ifidx);
}

int32 wificfg_set_wkhost_reasons(uint8 *reasons, uint8 count)
{
    os_memset(sys_cfgs.wkhost_reasons, 0, sizeof(sys_cfgs.wkhost_reasons));
    os_memcpy(sys_cfgs.wkhost_reasons, reasons, count > 32 ? 32 : count);
    sys_cfgs.wkhost_reasons_set = 1;
    wificfg_save(0);
    return 0;
}

int32 wificfg_set_mac_filter_en(uint8 en)
{
    if (sys_cfgs.mac_filter_en != en) {
        sys_cfgs.mac_filter_en = en;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_roaming(uint8 *vals, uint8 count)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    uint8 chg = 0;

    if(count > 0) chg |= (sys_cfgs.roam_start != vals[0]);
    //if(count > 1) chg |= (sys_cfgs.roam_samefreq != vals[1]);
    if(count > 2 && vals[2]) chg |= (sys_cfgs.roam_rssi_th != (int8)vals[2]);
    if(count > 3 && vals[3]) chg |= (sys_cfgs.roam_rssi_diff != vals[3]);
    if(count > 4 && vals[4]) chg |= (sys_cfgs.roam_rssi_int != vals[4]);
    if(chg){
        sys_cfgs.roam_start = vals[0];
        //if(count > 1) sys_cfgs.roam_samefreq = vals[1];
        if(count > 2 && vals[2]) sys_cfgs.roam_rssi_th = (int8)vals[2];
        if(count > 3 && vals[3]) sys_cfgs.roam_rssi_diff = vals[3];
        if(count > 4 && vals[4]) sys_cfgs.roam_rssi_int = vals[4];
        ieee80211_conf_set_roaming(ifidx, vals[0]);
        ieee80211_conf_set_roam_config(ifidx, (int8)vals[2], vals[3], vals[4]);
        wificfg_save(0);
        //lmac_set_obss_annonce_interval(wnb->ops, wnb->cfg->roaming ? wnb->cfg->beacon_int : 2000);
        os_printf("set roaming %s\r\n", sys_cfgs.roam_start ? "enable" : "disable");        
    }

    return 0;
}

int32 wificfg_set_ap_hide(uint8 en)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (sys_cfgs.ap_hide != en) {
        sys_cfgs.ap_hide = en;
        if (ifidx < 0) {
            ieee80211_conf_set_aphide(WIFI_MODE_AP, en);
            ieee80211_conf_set_aphide(WIFI_MODE_WNBAP, en);
        } else {
            ieee80211_conf_set_aphide(ifidx, en);
        }
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_dual_ant(uint8 en)
{
    if(en != sys_cfgs.dual_ant){
        sys_cfgs.dual_ant = en;
        lmac_set_ant_dual_en(lmacops, en);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_max_txcnt(uint8 frm_max, uint8 rts_max)
{
    if(frm_max != sys_cfgs.frm_max || rts_max != sys_cfgs.rts_max){
        sys_cfgs.frm_max = frm_max;
        sys_cfgs.rts_max = rts_max;
        lmac_set_retry_cnt(lmacops, frm_max, rts_max);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_dup_filter_en(uint8 en)
{
    if(en != sys_cfgs.dupfilter){
        sys_cfgs.dupfilter = en;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_dis_1v1_m2u(uint8 dis)
{
    if(dis != sys_cfgs.dis_1v1_m2u){
        sys_cfgs.dis_1v1_m2u = dis;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_rtc(uint8 *data)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    return ieee80211_conf_set_rtc(ifidx, data);
}

int32 wificfg_set_dis_psconnect(uint8 dis)
{
    if(dis != sys_cfgs.dis_psconnect){
        sys_cfgs.dis_psconnect = dis;
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_cca_for_ce(uint8 en)
{
    if(en != sys_cfgs.cca_for_ce){
        sys_cfgs.cca_for_ce = en;
        lmac_set_cca_for_ce(lmacops, en);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_ap_psmode(uint8 en)
{
    if(en != sys_cfgs.ap_psmode){
        sys_cfgs.ap_psmode = en;
        lmac_set_ap_psmode_en(lmacops, en);
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_ap_chan_switch(uint8 chan, uint8 counter)
{
    uint8 cmd[12];
    if(MODE_IS_AP(sys_cfgs.wifi_mode) && chan > 0 && chan <= sys_cfgs.chan_cnt){    //unsupported dual ap
        os_sprintf(cmd, "AT+CS_NUM=%d", (sys_cfgs.chan_list[chan - 1] - 7000)/10);
        atcmd_recv(cmd, os_strlen(cmd));
        os_sprintf(cmd, "AT+CS_CNT=%d", counter);
        atcmd_recv(cmd, os_strlen(cmd));
        return RET_OK;
    }
    return RET_ERR;
}

int32 wificfg_set_radio_onoff(uint8 data)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    if (ifidx < 0) {
        ifidx = WIFI_MODE_AP;
    }
    return ieee80211_conf_set_radio_onoff(ifidx, data);
}

int32 wificfg_set_connect_paironly(uint8 en)
{
    if (sys_cfgs.pair_conn_only != en) {
        sys_cfgs.pair_conn_only = en;
        if (sys_cfgs.pair_conn_only == 1) {
            // 简单快捷的做法是重置断开，等重新连接时拦截
            ieee80211_iface_stop(sys_cfgs.wifi_mode);
            ieee80211_iface_start(sys_cfgs.wifi_mode);
        }
        wificfg_save(0);
    }
    return 0;
}

int32 wificfg_set_paired_stas(uint8 *mac_list, uint8 cnt)
{
#if SYS_SAVE_PAIRSTA
    uint8 i, j, find;
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);

    for (i = 0; i < SYS_STA_MAX; ++i) {
        if (IS_ZERO_ADDR(sys_cfgs.pair_stas[i])) {
            continue;
        }
        find = 0;
        for (j = 0; j < cnt && j < SYS_STA_MAX; ++j) {
            if (MAC_EQU(sys_cfgs.pair_stas[i], mac_list + j * 6)) {
                find = 1;
                break;
            }
        }
        if (find == 0) {
            if (ifidx < 0) {
                ieee80211_unpair(WIFI_MODE_AP, sys_cfgs.pair_stas[i]);
                ieee80211_unpair(WIFI_MODE_WNBAP, sys_cfgs.pair_stas[i]);
            } else {
                ieee80211_unpair(ifidx, sys_cfgs.pair_stas[i]);
            }
        }
        os_memset(sys_cfgs.pair_stas[i], 0, 6);
    }
    for (i = 0; i < cnt; ++i) {
        os_memcpy(sys_cfgs.pair_stas[i], mac_list + i * 6, 6);
    }
    sys_cfgs.pair_conn_only = 1; // 搭配使用
    // 简单快捷的做法是重置断开，等重新连接时拦截
    ieee80211_iface_stop(sys_cfgs.wifi_mode);
    ieee80211_iface_start(sys_cfgs.wifi_mode);
    wificfg_save(0);
    return 0;
#else
    return -ENOTSUPP;
#endif
}

int32 wificfg_set_mcast_key(uint8 *key)
{
    uint8 mode_sta = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);
    uint8 mode_ap = wificfg_get_ifidx(sys_cfgs.wifi_mode, 1);

    if (os_memcmp(sys_cfgs.mcast_key, key, 32)) {
        sys_cfgs.mkey_set = 1;
        os_memcpy(sys_cfgs.mcast_key, key, 32);
        ieee80211_conf_set_mcast_key(mode_sta, sys_cfgs.mkey_set, sys_cfgs.mcast_key);
        if (mode_sta != mode_ap) {
            ieee80211_conf_set_mcast_key(mode_ap, sys_cfgs.mkey_set, sys_cfgs.mcast_key);
        }
        return RET_OK;
    }
    return RET_ERR;
}

