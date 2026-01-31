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
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/hgic.h"
#include "lib/skb/skb.h"
#include "lib/skb/skbuff.h"
#include "osal/string.h"
#include "syscfg.h"
//#include "lmac_pa_fix.h"
/* Forward declaration of memory pool initialiser.  The real
 * declaration lives in lib/skb/skbpool.h but we avoid including
 * it here to keep dependencies low. */
extern struct sys_config sys_cfgs;
extern int32 skbpool_init(uint32 addr, uint32 size, uint32 max, uint8 flags);

/* Optional: initialise additional collection routines if your port
 * requires them.  See lib/skb/skbpool.h for details. */
extern int32 skbpool_collect_init(void);

/* -------------------------------------------------------------------- */
/* Global state
 *
 * The LMAC returns a pointer to a structure of callbacks (struct
 * lmac_ops).  We keep a single global pointer here.  If you need to
 * support multiple radios at once you can extend this to an array.
 */
static struct lmac_ops *g_lmac_ops = NULL;

/* A user supplied callback invoked whenever a frame is received.  The
 * lmac layer hands us a pointer to the payload (without any hgic
 * header) and the length.  We simply forward this to the user. */
typedef void (*lmac_raw_rx_cb)(uint8_t *data, int32_t len);
static lmac_raw_rx_cb g_rx_cb = NULL;

/* Register a receive callback.  Pass a NULL pointer to disable
 * reception. */
void lmac_raw_register_rx_cb(lmac_raw_rx_cb cb)
{
    g_rx_cb = cb;
}

/* Default receive handler.  This is installed into the ops->rx slot
 * during lmac_only_init().  See lmac_def.h for prototype. */
static int32_t lmac_only_rx(struct lmac_ops *ops,
                            struct hgic_rx_info *info,
                            uint8_t *data,
                            int32_t len)
{
    (void)ops;
    (void)info;
    /* When a frame arrives the hgic wrapper removes the hgic header
     * before passing it into this callback, so the buffer pointed to
     * by `data` is the start of the MAC header of the received frame.
     * You can dump it or forward it to a higher layer here. */
    if (g_rx_cb) {
        g_rx_cb(data, len);
    }
    return 0;
}

/* Default TX status handler.  LMAC will call this once it is
 * finished with the skb passed into lmac_tx().  We must free the skb
 * here to avoid leaking memory.  Without this callback the default
 * implementation buried in libwifi would free the skb and propagate
 * the status up into the UMAC – exactly the behaviour we do not
 * require in a pure LMAC environment. */
static int32_t lmac_only_tx_status(struct lmac_ops *ops, struct sk_buff *skb)
{
    (void)ops;
    if (skb) {
        kfree_skb(skb);
    }
    return 0;
}



static void lmac_only_post_init (struct lmac_ops *ops){
    /* 1) MAC address (иначе может быть "zmac") */

    /* возьми откуда угодно: UUID->MAC, sys_cfgs, fixed, etc */
    uint8 mac[6];

    ops->ioctl(ops, LMAC_IOCTL_SET_MAC_ADDR, (uint32)(uintptr_t)mac, 0);
    ops->ioctl(ops, LMAC_IOCTL_SET_ANT_DUAL_EN, 0, 0);
    ops->ioctl(ops, LMAC_IOCTL_SET_ANT_SEL, 0, 0);
    ops->ioctl(ops, LMAC_IOCTL_SET_RADIO_ONOFF, 1, 0);
    //uint8 mac[6] = { 0x02,0x11,0x22,0x33,0x44,0x55 };
    //lmac_set_mac_addr(ops, 0, mac); 
    //lmac_set_mac_addr(ops, 1, mac); 
    
    lmac_set_freq(ops, sys_cfgs.chan_list[0]);
    lmac_set_bss_bw(ops, sys_cfgs.bss_bw);
    lmac_set_tx_mcs(ops, sys_cfgs.tx_mcs);
    lmac_set_txpower(ops, sys_cfgs.txpower);
    //lmac_set_pri_chan(ops, sys_cfgs.pri_chan);
    lmac_set_aggcnt(ops, sys_cfgs.agg_cnt);
    lmac_set_auto_chan_switch(ops, !sys_cfgs.auto_chsw);
    lmac_set_wakeup_io(ops, sys_cfgs.wkup_io, sys_cfgs.wkio_edge);
    lmac_set_super_pwr(ops, sys_cfgs.super_pwr_set?sys_cfgs.super_pwr:1);
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
    lmac_set_standby(ops, sys_cfgs.standby_channel-1, sys_cfgs.standby_period_ms*1000);
    lmac_set_dbg_levle(ops, 0);
    //lmac_set_rxg_offest(wnb->ops, wnb->cfg->rxg_offest);
    lmac_set_cca_for_ce(ops, sys_cfgs.cca_for_ce);
    //gpio_set_val(DSLEEP_STATE_IND, sys_cfgs.wkio_mode);
}

int32_t lmac_only_init(uint32_t rxbuf, uint32_t rxbuf_size,
                       uint32_t tdma_buf, uint32_t tdma_buf_size){
    struct lmac_init_param param;
    memset(&param, 0, sizeof(param));
    param.rxbuf         = rxbuf;
    param.rxbuf_size    = rxbuf_size;
    param.tdma_buff     = tdma_buf;
    param.tdma_buff_size= tdma_buf_size;
    param.uart_tx_io    = 0;
    param.dual_ant      = 0;

    g_lmac_ops = lmac_ah_init(&param);
    if (!g_lmac_ops) {
        return -1;
    }
    g_lmac_ops->rx        = lmac_only_rx;
    g_lmac_ops->tx_status = lmac_only_tx_status;

    lmac_set_promisc_mode(g_lmac_ops, 1);


    
    uint8 mac[6];
    mac[0] = 0x02; mac[1] = 0x11; mac[2] = 0x22; mac[3] = 0x33; mac[4] = 0x44; mac[5] = 0x55;

    
    static uint8 bssid[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    lmac_set_bssid(g_lmac_ops, bssid);

    if (lmac_open(g_lmac_ops) != 0) {
        return -2;
    }
    lmac_only_post_init(g_lmac_ops);
    return 0;
}




int32_t lmac_raw_tx(const uint8_t *buf, int32_t len)
{
    if (!g_lmac_ops || !buf || len <= 0) {
        return -1;
    }
    /* Compute the total number of bytes required to hold the packet
     * including any headroom/tailroom the LMAC needs. */
    uint32_t need = (uint32_t)g_lmac_ops->headroom + (uint32_t)len + (uint32_t)g_lmac_ops->tailroom;
    struct sk_buff *skb = alloc_tx_skb(need);
    if (!skb) {
        return -2;
    }
    /* Reserve the requested headroom so that the data pointer is
     * aligned properly for the LMAC. */
    skb_reserve(skb, g_lmac_ops->headroom);
    /* Copy the user payload into the sk_buff. */
    memcpy(skb_put(skb, len), buf, (size_t)len);
    /* Mark the skb as outgoing.  The tx flag is used internally by
     * liblmac to distinguish TX from RX buffers. */
    skb->tx = 1;
    /* Queue the packet.  lmac_tx() returns 0 on success.  It will
     * eventually call back into our lmac_only_tx_status() which is
     * responsible for freeing the skb. */
    return lmac_tx(g_lmac_ops, skb);
}
