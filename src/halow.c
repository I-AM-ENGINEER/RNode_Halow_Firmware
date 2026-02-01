#include "halow.h"

#include <string.h>

#include "lib/lmac/ieee802_11_defs.h"
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/hgic.h"
#include "lib/skb/skb.h"
#include "lib/skb/skbuff.h"
#include "osal/string.h"
#include "syscfg.h"

extern struct sys_config sys_cfgs;

/* ===== internal state ===== */

static struct lmac_ops *g_ops = NULL;
static halow_rx_cb      g_rx_cb;
static uint16_t         g_seq;

/* ===== helpers ===== */

static inline void mac_bcast(uint8_t mac[6]){
    memset(mac, 0xff, 6);
}

/* ===== RX/TX hooks ===== */

static int32_t halow_lmac_rx(struct lmac_ops *ops,
                             struct hgic_rx_info *info,
                             uint8_t *data,
                             int32_t len){
    (void)ops;

    if (!data || len < (int32_t)sizeof(struct ieee80211_hdr)) {
        return -1;
    }

    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)data;

    if ((hdr->frame_control & 0x000C) != WLAN_FTYPE_DATA) {
        return -1;
    }

    const uint8_t *payload = data + sizeof(*hdr);
    int32_t payload_len = len - (int32_t)sizeof(*hdr);

    if (payload_len <= 0 || !g_rx_cb) {
        return 0;
    }

    g_rx_cb(info, payload, payload_len);
    return 0;
}

static int32_t halow_lmac_tx_status(struct lmac_ops *ops,
                                   struct sk_buff *skb){
    (void)ops;
    if (skb) {
        kfree_skb(skb);
    }
    return 0;
}

/* ===== LMAC post-init ===== */

static void halow_post_init(struct lmac_ops *ops){
    static uint8 g_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ops->ioctl(ops, LMAC_IOCTL_SET_MAC_ADDR, (uint32)(uintptr_t)g_mac, 0);
    ops->ioctl(ops, LMAC_IOCTL_SET_ANT_DUAL_EN, 0, 0);
    ops->ioctl(ops, LMAC_IOCTL_SET_ANT_SEL, 0, 0);
    ops->ioctl(ops, LMAC_IOCTL_SET_RADIO_ONOFF, 1, 0);
    
    lmac_set_freq(ops, sys_cfgs.chan_list[0]);
    lmac_set_bss_bw(ops, sys_cfgs.bss_bw);
    lmac_set_tx_mcs(ops, sys_cfgs.tx_mcs);
    lmac_set_fallback_mcs(ops, sys_cfgs.tx_mcs);
    lmac_set_mcast_txmcs(ops, sys_cfgs.tx_mcs);
    lmac_set_txpower(ops, sys_cfgs.txpower);
    lmac_set_aggcnt(ops, sys_cfgs.agg_cnt);
    lmac_set_auto_chan_switch(ops, !sys_cfgs.auto_chsw);
    lmac_set_wakeup_io(ops, sys_cfgs.wkup_io, sys_cfgs.wkio_edge);
    lmac_set_super_pwr(ops, sys_cfgs.super_pwr_set ? sys_cfgs.super_pwr : 1);
    lmac_set_pa_pwr_ctrl(ops, !sys_cfgs.pa_pwrctrl_dis);
    lmac_set_vdd13(ops, sys_cfgs.dcdc13);
    lmac_set_ack_timeout_extra(ops, sys_cfgs.ack_tmo);

    if (sys_cfgs.dual_ant) {
        lmac_set_ant_auto_en(ops, !sys_cfgs.ant_auto_dis);
        lmac_set_ant_sel(ops, sys_cfgs.ant_sel);
    }

    lmac_set_ps_mode(ops, DSLEEP_MODE_NONE);
    lmac_set_wait_psmode(ops, DSLEEP_WAIT_MODE_PS_CONNECT);
    lmac_set_psconnect_period(ops, sys_cfgs.psconnect_period);
    lmac_set_ap_psmode_en(ops, sys_cfgs.ap_psmode);
    lmac_set_standby(ops, sys_cfgs.standby_channel - 1, sys_cfgs.standby_period_ms * 1000);
    lmac_set_dbg_levle(ops, 0);
    lmac_set_cca_for_ce(ops, sys_cfgs.cca_for_ce);
}

/* ===== public API ===== */

bool halow_init(uint32_t rxbuf, uint32_t rxbuf_size,
                uint32_t tdma_buf, uint32_t tdma_buf_size){
    struct lmac_init_param p;

    memset(&p, 0, sizeof(p));
    p.rxbuf          = rxbuf;
    p.rxbuf_size     = rxbuf_size;
    p.tdma_buff      = tdma_buf;
    p.tdma_buff_size = tdma_buf_size;

    g_ops = lmac_ah_init(&p);
    if (!g_ops) {
        return false;
    }

    g_ops->rx        = halow_lmac_rx;
    g_ops->tx_status = halow_lmac_tx_status;

    lmac_set_promisc_mode(g_ops, 1);

    static uint8_t bssid[6];
    mac_bcast(bssid);
    lmac_set_bssid(g_ops, bssid);

    if (lmac_open(g_ops) != 0) {
        return false;
    }

    halow_post_init(g_ops);
    return true;
}

void halow_set_rx_cb(halow_rx_cb cb){
    g_rx_cb = cb;
}

bool halow_tx(const uint8_t *data, int32_t len){
    if (!g_ops || !data || len <= 0) {
        return false;
    }

    struct ieee80211_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.frame_control = (uint16_t)(WLAN_FTYPE_DATA | WLAN_STYPE_DATA);
    mac_bcast(hdr.addr1);
    mac_bcast(hdr.addr2);
    mac_bcast(hdr.addr3);

    g_seq++;
    hdr.seq_ctrl = (uint16_t)((g_seq & 0x0fff) << 4);

    uint32_t hr = (uint32_t)g_ops->headroom;
    uint32_t tr = (uint32_t)g_ops->tailroom;
    uint32_t need = hr + sizeof(hdr) + (uint32_t)len + tr;

    struct sk_buff *skb = alloc_tx_skb(need);
    if (!skb) {
        return false;
    }

    skb_reserve(skb, (int)hr);
    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, len), data, (size_t)len);

    skb->priority = 0;
    skb->tx       = 1;

    return (lmac_tx(g_ops, skb) == 0);
}
