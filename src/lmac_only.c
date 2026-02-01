/*
 * Minimal LMAC‑only transmission path
 *
 * This file provides a self contained example of how to bring up the
 * low level MAC (LMAC) without the full 802.11/UMAC stack and how to
 * transmit and receive raw frames through it.  The goal is to expose
 * just the radio and queue handling provided by the liblmac library
 * so that higher layers can inject arbitrary bytes on the air or
 * consume raw receive data without any of the management overhead
 * normally performed by ieee80211_init(), wifi_mgr_init() and friends.
 *
 * The code below is deliberately simple: it initialises the skb
 * memory pool, boots the LMAC via lmac_ah_init(), overrides the
 * default rx/tx_status callbacks with ones defined in this file and
 * exposes two small helper functions, lmac_raw_tx() and
 * lmac_raw_register_rx_cb(), which can be used by application code
 * to push and pull raw frames.
 *
 * To use this module you must provide a sufficiently large RX buffer
 * and (optionally) a TDMA buffer at initialisation time.  These can
 * either come from fixed memory regions (e.g. the definitions of
 * SKB_POOL_ADDR/WIFI_RX_BUFF_ADDR/TDMA_BUFF_ADDR in your board
 * configuration) or be allocated from the heap.  The choice depends
 * on how your system memory map is laid out.  See lmac_only_init()
 * below for details.
 */

#include <stdint.h>
#include <string.h>
#include "lib/lmac/ieee802_11_defs.h"
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/hgic.h"
#include "lib/skb/skb.h"
#include "lib/skb/skbuff.h"
#include "osal/string.h"
#include "syscfg.h"



extern struct sys_config sys_cfgs;
static struct lmac_ops *g_lmac_ops = NULL;

typedef void (*lmac_raw_rx_cb)(struct hgic_rx_info *info, uint8_t *data, int32_t len);
static lmac_raw_rx_cb g_rx_cb = NULL;

void lmac_raw_register_rx_cb(lmac_raw_rx_cb cb){
    g_rx_cb = cb;
}

static int32_t lmac_only_rx(struct lmac_ops *ops,
                            struct hgic_rx_info *info,
                            uint8_t *data,
                            int32_t len){
    (void)ops;

    if (!data || len < (int32_t)sizeof(struct ieee80211_hdr)) {
        return -1;
    }

    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)data;

    /* принимаем только DATA */
    if ((hdr->frame_control & 0x000C) != WLAN_FTYPE_DATA) {
        return -1;
    }

    uint8_t *payload = data + sizeof(struct ieee80211_hdr);
    int32_t payload_len = len - (int32_t)sizeof(struct ieee80211_hdr);

    if (payload_len <= 0) {
        return -1;
    }

    if (g_rx_cb) {
        g_rx_cb(info, payload, payload_len);
    }

    return 0;
}

static int32_t lmac_only_tx_status(struct lmac_ops *ops, struct sk_buff *skb){
    (void)ops;
    if (skb) {
        kfree_skb(skb);
    }
    return 0;
}

static void lmac_only_post_init (struct lmac_ops *ops){
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

int32_t lmac_only_init(uint32_t rxbuf, uint32_t rxbuf_size,
                       uint32_t tdma_buf, uint32_t tdma_buf_size){
    struct lmac_init_param param;
    memset(&param, 0, sizeof(param));
    param.rxbuf          = rxbuf;
    param.rxbuf_size     = rxbuf_size;
    param.tdma_buff      = tdma_buf;
    param.tdma_buff_size = tdma_buf_size;
    param.uart_tx_io     = 0;
    param.dual_ant       = 0;

    g_lmac_ops = lmac_ah_init(&param);
    if (!g_lmac_ops) {
        return -1;
    }

    g_lmac_ops->rx        = lmac_only_rx;
    g_lmac_ops->tx_status = lmac_only_tx_status;

    lmac_set_promisc_mode(g_lmac_ops, 1);

    static uint8_t bssid[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    lmac_set_bssid(g_lmac_ops, bssid);

    if (lmac_open(g_lmac_ops) != 0) {
        return -2;
    }

    lmac_only_post_init(g_lmac_ops);
    return 0;
}

static uint16_t g_seq;

static void mac_bcast (uint8_t out[6]){
    out[0] = 0xff; out[1] = 0xff; out[2] = 0xff;
    out[3] = 0xff; out[4] = 0xff; out[5] = 0xff;
}

int32_t lmac_raw_tx_bcast(const uint8_t *payload, int32_t payload_len){
    if (!g_lmac_ops || !payload || payload_len <= 0) {
        return -1;
    }

    struct ieee80211_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));

    /* обычный DATA, без ToDS/FromDS (ты не в инфраструктуре) */
    hdr.frame_control = (uint16_t)(WLAN_FTYPE_DATA | WLAN_STYPE_DATA);

    /* duration = 0 норм */
    memset(hdr.addr1, 0xFF, sizeof(hdr.addr1));
    memset(hdr.addr2, 0xFF, sizeof(hdr.addr2));
    memset(hdr.addr3, 0xFF, sizeof(hdr.addr3));

    g_seq = (uint16_t)(g_seq + 1);
    hdr.seq_ctrl = (uint16_t)((g_seq & 0x0fff) << 4);

    uint32_t hr = (uint32_t)g_lmac_ops->headroom;
    uint32_t tr = (uint32_t)g_lmac_ops->tailroom;

    uint32_t need = hr + (uint32_t)sizeof(hdr) + (uint32_t)payload_len + tr;

    struct sk_buff *skb = alloc_tx_skb(need);
    if (skb == NULL) {
        return -2;
    }

    skb_reserve(skb, (int)hr);

    memcpy(skb_put(skb, (int)sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, payload_len), payload, (size_t)payload_len);

    skb->priority = 0;
    skb->tx       = 1;

    return lmac_tx(g_lmac_ops, skb);
}
