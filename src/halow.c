#include "halow.h"

#include <string.h>

#include "lib/lmac/ieee802_11_defs.h"
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/hgic.h"
#include "lib/skb/skb.h"
#include "lib/skb/skbuff.h"
#include "osal/semaphore.h"
#include "osal/string.h"

/* ===== Wi-Fi HaLow fixed config ===== */

/* Channel / RF */
#define HALOW_FREQ_KHZ          8665        /* sys_cfgs.chan_list[0] */
#define HALOW_BSS_BW            1           /* 1 MHz */

/* PHY / rate */
#define HALOW_TX_MCS            LMAC_RATE_S1G_1_NSS_MCS0

/* Power */
#define HALOW_TX_POWER          20
#define HALOW_PA_PWRCTRL_EN     1
#define HALOW_VDD13_MODE        0

/* Antenna */
#define HALOW_DUAL_ANT_EN       0
#define HALOW_ANT_AUTO_EN       0
#define HALOW_ANT_SEL           0

/* Aggregation */
#define HALOW_TX_AGGCNT         1
#define HALOW_RX_AGGCNT         1

/* Power save / sleep */
#define HALOW_PS_MODE           DSLEEP_MODE_NONE
#define HALOW_WAIT_PSMODE       DSLEEP_WAIT_MODE_PS_CONNECT
#define HALOW_PSCONNECT_PERIOD  60

/* Standby */
#define HALOW_STANDBY_CH        1           /* channel index starts from 1 */
#define HALOW_STANDBY_PERIOD_MS 5000

/* ACK / retry */
#define HALOW_ACK_TMO_EXTRA     0
#define HALOW_RETRY_FRM_MAX     0
#define HALOW_RETRY_RTS_MAX     0
#define HALOW_RETRY_FB_CNT      0
#define HALOW_RTS_THRESH        0xFFFF

/* CCA */
#define HALOW_CCA_FOR_CE        0

/* Wakeup */
#define HALOW_WAKEUP_IO         0
#define HALOW_WAKEUP_EDGE       0

/* Debug */
#define HALOW_DBG_LEVEL         0
#define TX_BUFFER_SIZE          (4*1024)

/* ===== internal state ===== */

static struct lmac_ops *g_ops = NULL;
static halow_rx_cb g_rx_cb;
static uint16_t g_seq;

static uint32_t g_tx_vacated_bytes = TX_BUFFER_SIZE;
static struct os_semaphore g_tx_vacated_sem;

// Disable broadcast
int32_t __wrap_lmac_send_bss_announcement(void){
    return 0;
}

static inline void mac_bcast(uint8_t mac[6]) {
    memset(mac, 0xff, 6);
}

static int32_t halow_lmac_rx(struct lmac_ops *ops,
                             struct hgic_rx_info *info,
                             uint8_t *data,
                             int32_t len) {
    (void)ops;

    if (!data || len < (int32_t)sizeof(struct ieee80211_hdr)) {
        return -1;
    }

    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)data;

    if ((hdr->frame_control & 0x000C) != WLAN_FTYPE_DATA) {
        return -1;
    }

    const uint8_t *payload = data + sizeof(*hdr);
    int32_t payload_len    = len - (int32_t)sizeof(*hdr);

    if (payload_len <= 0 || !g_rx_cb) {
        return 0;
    }

    g_rx_cb(info, payload, payload_len);
    return 0;
}

static int32_t halow_lmac_tx_status_callback(struct lmac_ops *ops, struct sk_buff *skb) {
    (void)ops;
    if (skb) {
        g_tx_vacated_bytes += skb->len;
        os_sema_up(&g_tx_vacated_sem);
        kfree_skb(skb);
    }
    return 0;
}

/* ===== LMAC post-init ===== */
static void halow_post_init(struct lmac_ops *ops)
{
    static uint8 g_mac[6] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    /* ---- basic bring-up ---- */
    ops->ioctl(ops, LMAC_IOCTL_SET_MAC_ADDR,
               (uint32)(uintptr_t)g_mac, 0);

    //ops->ioctl(ops, LMAC_IOCTL_SET_ANT_DUAL_EN,
    //           HALOW_DUAL_ANT_EN, 0);

    //ops->ioctl(ops, LMAC_IOCTL_SET_ANT_SEL,
    //           HALOW_ANT_SEL, 0);

    //ops->ioctl(ops, LMAC_IOCTL_SET_RADIO_ONOFF, 1, 0);

    /* ---- RF / channel ---- */
    lmac_set_freq(ops, HALOW_FREQ_KHZ);
    lmac_set_bss_bw(ops, HALOW_BSS_BW);

    /* ---- PHY rate control ---- */
    lmac_set_tx_mcs(ops, HALOW_TX_MCS);
    lmac_set_fix_tx_rate(ops, HALOW_TX_MCS);
    lmac_set_fallback_mcs(ops, HALOW_TX_MCS);
    lmac_set_mcast_txmcs(ops, HALOW_TX_MCS);
	
    /* ---- power ---- */
    lmac_set_txpower(ops, HALOW_TX_POWER);
    //SUPER POWER (200 mA device consumption, 20-22 dBm expected)
    lmac_set_super_pwr(ops, 1);
    //lmac_set_pa_pwr_ctrl(ops, HALOW_PA_PWRCTRL_EN);

    /* ---- aggregation ---- */
    lmac_set_aggcnt(ops, HALOW_TX_AGGCNT);
    lmac_set_rx_aggcnt(ops, HALOW_RX_AGGCNT);

    /* ---- channel switching ---- */
    lmac_set_auto_chan_switch(ops, 0);

    /* ---- wakeup ---- */
    lmac_set_wakeup_io(ops, HALOW_WAKEUP_IO, HALOW_WAKEUP_EDGE);

    /* ---- power save ---- */
    lmac_set_ps_mode(ops, HALOW_PS_MODE);
    lmac_set_wait_psmode(ops, HALOW_WAIT_PSMODE);
    lmac_set_psconnect_period(ops, HALOW_PSCONNECT_PERIOD);
    lmac_set_ap_psmode_en(ops, 0);

    /* ---- standby ---- */
    lmac_set_standby(ops,
                     HALOW_STANDBY_CH - 1,
                     HALOW_STANDBY_PERIOD_MS * 1000);

    /* ---- CCA / retry / RTS ---- */
    lmac_set_cca_for_ce(ops, HALOW_CCA_FOR_CE);
    lmac_set_retry_cnt(ops,
                       HALOW_RETRY_FRM_MAX,
                       HALOW_RETRY_RTS_MAX);
    lmac_set_retry_fallback_cnt(ops, HALOW_RETRY_FB_CNT);
    lmac_set_rts(ops, HALOW_RTS_THRESH);

    /* ---- misc ---- */
    lmac_set_ack_timeout_extra(ops, HALOW_ACK_TMO_EXTRA);
    lmac_set_dbg_levle(ops, HALOW_DBG_LEVEL);
}

bool halow_init(uint32_t rxbuf, uint32_t rxbuf_size,
                uint32_t tdma_buf, uint32_t tdma_buf_size) {
    struct lmac_init_param p;

    os_sema_init(&g_tx_vacated_sem, 0);
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
    g_ops->tx_status = halow_lmac_tx_status_callback;

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

void halow_set_rx_cb(halow_rx_cb cb) {
    g_rx_cb = cb;
}

void halow_get_tx_vacanted_bytes(uint32_t bytes){
    while(1) {
        if (g_tx_vacated_bytes >= bytes) {
            g_tx_vacated_bytes -= bytes;
            return;
        }
        os_sema_down(&g_tx_vacated_sem, OS_MUTEX_WAIT_FOREVER);
    }
}

int32_t halow_tx(const uint8_t *data, uint32_t len) {
    if(g_ops == NULL){
        return -1;
    }
    if(data == NULL){
        return -2;
    }
    if(len == 0){
        return -3;
    }
    if(len > TX_BUFFER_SIZE){
        return -4;
    }

    struct ieee80211_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.frame_control = (uint16_t)(WLAN_FTYPE_DATA | WLAN_STYPE_DATA);
    mac_bcast(hdr.addr1);
    mac_bcast(hdr.addr2);
    mac_bcast(hdr.addr3);

    g_seq++;
    hdr.seq_ctrl = (uint16_t)((g_seq & 0x0fff) << 4);

    uint32_t hr   = (uint32_t)g_ops->headroom;
    uint32_t tr   = (uint32_t)g_ops->tailroom;
    uint32_t need = hr + sizeof(hdr) + (uint32_t)len + tr;

    struct sk_buff *skb = alloc_tx_skb(need);
    if (!skb) {
        return -5;
    }

    skb_reserve(skb, (int)hr);
    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, len), data, (size_t)len);

    skb->priority = 0;
    skb->tx       = 1;
    halow_get_tx_vacanted_bytes(skb->len);
    return lmac_tx(g_ops, skb);
}
