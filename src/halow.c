#include "halow.h"

#include <string.h>

#include "lib/lmac/ieee802_11_defs.h"
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/hgic.h"
#include "lib/skb/skb.h"
#include "lib/skb/skbuff.h"
#include "osal/semaphore.h"
#include "osal/string.h"
#include "halow_lbt.h"
#include "configdb.h"
#include "sys_config.h"

#define HALOW_CONFIG_PREFIX             CONFIGDB_ADD_MODULE("halow")
#define HALOW_CONFIG_ADD_CONFIG(name)   HALOW_CONFIG_PREFIX "." name

#define HALOW_CONFIG_CENTRAL_FREQ_NAME  HALOW_CONFIG_ADD_CONFIG("freq")
#define HALOW_CONFIG_POWER_NAME         HALOW_CONFIG_ADD_CONFIG("pwr")
#define HALOW_CONFIG_BANDWIDTH_NAME     HALOW_CONFIG_ADD_CONFIG("band")
#define HALOW_CONFIG_MCS_NAME           HALOW_CONFIG_ADD_CONFIG("mcs")
#define HALOW_CONFIG_SPOWER_EN_NAME     HALOW_CONFIG_ADD_CONFIG("spwr")

/* ===== Wi-Fi HaLow fixed config ===== */

/* Power */
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

//#define HALOW_DEBUG
#ifdef HALOW_DEBUG
#define halow_debug(fmt, ...)  os_printf("[HALW] " fmt "\r\n", ##__VA_ARGS__)
#else
#define halow_debug(fmt, ...)  do { } while (0)
#endif

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

    halow_debug("rx: len=%ld", (long)len);

    if (!data || len < (int32_t)sizeof(struct ieee80211_hdr)) {
        halow_debug("rx: drop (invalid data or too short)");
        return -1;
    }

    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)data;

    if ((hdr->frame_control & 0x000C) != WLAN_FTYPE_DATA) {
        halow_debug("rx: drop (not data frame)");
        return -1;
    }

    const uint8_t *payload = data + sizeof(*hdr);
    int32_t payload_len    = len - (int32_t)sizeof(*hdr);

    if (payload_len <= 0 || !g_rx_cb) {
        halow_debug("rx: no payload or cb=NULL");
        return 0;
    }

    g_rx_cb(info, payload, payload_len);

    return 0;
}

static int32_t halow_lmac_tx_status_callback(struct lmac_ops *ops, struct sk_buff *skb) {
    (void)ops;
    if (skb) {
        g_tx_vacated_bytes += skb->len;
        if(g_tx_vacated_bytes == TX_BUFFER_SIZE){
            halow_lbt_set_tx_as_deactive();
        }
        os_sema_up(&g_tx_vacated_sem);
        kfree_skb(skb);
    }
    return 0;
}

int32_t get_mcs_val(uint8_t mcs){
    if((mcs <= 7) || (mcs == 10)){
        return LMAC_RATE_DEF(LMAC_PHY_S1G, 1, mcs, 0);
    }
    return 0;
}

static void halow_cfg_sanitize(halow_config_t *cfg){
    if(cfg == NULL){
        return;
    }

    if (cfg->rf_power < 1)  cfg->rf_power = 1;
    if (cfg->rf_power > 20) cfg->rf_power = 20;

    if ((cfg->rf_super_power != 0) &&
        (cfg->rf_super_power != 1)) {
        cfg->rf_super_power = 0;
    }

    if ((cfg->mcs > 7) && (cfg->mcs != 10)) {
        cfg->mcs = 0;
    }

    if (cfg->central_freq < 7500) {
        cfg->central_freq = 7500;
    }
    if (cfg->central_freq > 9500) {
        cfg->central_freq = 9500;
    }

    if((cfg->bandwidth != 1) &&
       (cfg->bandwidth != 2) &&
       (cfg->bandwidth != 4) &&
       (cfg->bandwidth != 8)
    ){
        cfg->bandwidth = 1;
    }
}

void halow_config_save(const halow_config_t *cfg){
    if (cfg == NULL) { 
        return; 
    }
    halow_config_apply(cfg);
    configdb_set_i8(HALOW_CONFIG_BANDWIDTH_NAME, (int8_t*)&cfg->bandwidth);
    configdb_set_i8(HALOW_CONFIG_SPOWER_EN_NAME, (int8_t*)&cfg->rf_super_power);
    configdb_set_i8(HALOW_CONFIG_POWER_NAME, (int8_t*)&cfg->rf_power);
    configdb_set_i8(HALOW_CONFIG_MCS_NAME, (int8_t*)&cfg->mcs);
    configdb_set_i16(HALOW_CONFIG_CENTRAL_FREQ_NAME, (int16_t*)&cfg->central_freq);
}

static void halow_config_set_default(halow_config_t *cfg){
    if (cfg == NULL) {
        return;
    }

    cfg->bandwidth      = HALOW_CONFIG_BANDWIDTH_DEF;
    cfg->rf_super_power = HALOW_CONFIG_SPOWER_EN_DEF ? 1 : 0;
    cfg->rf_power       = HALOW_CONFIG_POWER_DEF;
    cfg->mcs            = HALOW_CONFIG_MCS_DEF;
    cfg->central_freq   = HALOW_CONFIG_CENTRAL_FREQ_DEF;
}

void halow_config_load(halow_config_t *cfg){
    if (cfg == NULL) { 
        return; 
    }
    configdb_get_i8(HALOW_CONFIG_BANDWIDTH_NAME, (int8_t*)&cfg->bandwidth);
    configdb_get_i8(HALOW_CONFIG_SPOWER_EN_NAME, (int8_t*)&cfg->rf_super_power);
    configdb_get_i8(HALOW_CONFIG_POWER_NAME, (int8_t*)&cfg->rf_power);
    configdb_get_i8(HALOW_CONFIG_MCS_NAME, (int8_t*)&cfg->mcs);
    configdb_get_i16(HALOW_CONFIG_CENTRAL_FREQ_NAME, (int16_t*)&cfg->central_freq);
}

void halow_config_apply(const halow_config_t *cfg){
    halow_config_t halow_cfg;
    if (cfg == NULL) { 
        return; 
    }
    if(g_ops == NULL){
        return;
    }
    
    halow_cfg = *cfg;
    halow_cfg_sanitize(&halow_cfg);
    lmac_set_freq(g_ops, halow_cfg.central_freq);
    lmac_set_bss_bw(g_ops, halow_cfg.bandwidth);

    /* ---- PHY rate control ---- */
    int32_t mcs_val = get_mcs_val(halow_cfg.mcs);
    lmac_set_tx_mcs(g_ops, mcs_val);
    lmac_set_fix_tx_rate(g_ops, mcs_val);
    lmac_set_fallback_mcs(g_ops, mcs_val);
    lmac_set_mcast_txmcs(g_ops, mcs_val);
	
    /* ---- power ---- */
    lmac_set_txpower(g_ops, halow_cfg.rf_power);
    //SUPER POWER (200 mA device consumption, 20-22 dBm expected)
    lmac_set_super_pwr(g_ops, halow_cfg.rf_super_power);
    
}

static void halow_modem_set_default(void){
    static uint8 g_mac[6] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    /* ---- basic bring-up ---- */
    g_ops->ioctl(g_ops, LMAC_IOCTL_SET_MAC_ADDR, (uint32)(uintptr_t)g_mac, 0);

    /* ---- RF / channel ---- */
    lmac_set_freq(g_ops, HALOW_CONFIG_CENTRAL_FREQ_DEF);
    lmac_set_bss_bw(g_ops, HALOW_CONFIG_BANDWIDTH_DEF);

    /* ---- PHY rate control ---- */
    int32_t mcs_val = get_mcs_val(HALOW_CONFIG_MCS_DEF);
    lmac_set_tx_mcs(g_ops, mcs_val);
    lmac_set_fix_tx_rate(g_ops, mcs_val);
    lmac_set_fallback_mcs(g_ops, mcs_val);
    lmac_set_mcast_txmcs(g_ops, mcs_val);
	
    /* ---- power ---- */
    lmac_set_txpower(g_ops, HALOW_CONFIG_POWER_DEF);
    //SUPER POWER (200 mA device consumption, 20-22 dBm expected)
    lmac_set_super_pwr(g_ops, HALOW_CONFIG_SPOWER_EN_DEF);
    //lmac_set_pa_pwr_ctrl(g_ops, HALOW_PA_PWRCTRL_EN);

    /* ---- aggregation ---- */
    lmac_set_aggcnt(g_ops, HALOW_TX_AGGCNT);
    lmac_set_rx_aggcnt(g_ops, HALOW_RX_AGGCNT);

    /* ---- channel switching ---- */
    lmac_set_auto_chan_switch(g_ops, 0);

    /* ---- wakeup ---- */
    lmac_set_wakeup_io(g_ops, HALOW_WAKEUP_IO, HALOW_WAKEUP_EDGE);

    /* ---- power save ---- */
    lmac_set_ps_mode(g_ops, HALOW_PS_MODE);
    lmac_set_wait_psmode(g_ops, HALOW_WAIT_PSMODE);
    lmac_set_psconnect_period(g_ops, HALOW_PSCONNECT_PERIOD);
    lmac_set_ap_psmode_en(g_ops, 0);

    /* ---- standby ---- */
    lmac_set_standby(g_ops,
                     HALOW_STANDBY_CH - 1,
                     HALOW_STANDBY_PERIOD_MS * 1000);

    /* ---- CCA / retry / RTS ---- */
    lmac_set_cca_for_ce(g_ops, HALOW_CCA_FOR_CE);
    lmac_set_retry_cnt(g_ops,
                       HALOW_RETRY_FRM_MAX,
                       HALOW_RETRY_RTS_MAX);
    lmac_set_retry_fallback_cnt(g_ops, HALOW_RETRY_FB_CNT);
    lmac_set_rts(g_ops, HALOW_RTS_THRESH);

    /* ---- misc ---- */
    lmac_set_ack_timeout_extra(g_ops, HALOW_ACK_TMO_EXTRA);
    lmac_set_dbg_levle(g_ops, HALOW_DBG_LEVEL);
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
    halow_modem_set_default();
    halow_config_t config;
    halow_config_set_default(&config);
    halow_config_load(&config);
    halow_cfg_sanitize(&config);
    halow_config_save(&config); // Incorrect values should be removed from DB
    halow_config_apply(&config);
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
        os_sema_down(&g_tx_vacated_sem, osWaitForever);
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
    //halow_lbt_wait();
    int32_t res = lmac_tx(g_ops, skb);
    halow_lbt_set_tx_as_active();
    return res;
}
