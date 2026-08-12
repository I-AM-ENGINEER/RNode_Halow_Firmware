#include "halow.h"

#include <string.h>

#include "lib/lmac/ieee802_11_defs.h"
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/hgic.h"
#include "lib/skb/skb.h"
#include "lib/skb/skbuff.h"
#include "lib/skb/skb_list.h"
#include "osal/semaphore.h"
#include "osal/string.h"
#include "osal/work.h"
#include "halow_lbt.h"
#include "lib/lmac/lmac_ctx.h"
#include "lib/lmac/lmac_regmap.h"
#include "lib/lmac/mars_lmac_tx.h"
#include "configdb.h"
#include "sys_config.h"
//#include "lmac_ctx.h"
#include "utils.h"
#include "mac_generator.h"

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
#define HALOW_TX_AGGCNT         16
#define HALOW_RX_AGGCNT         1

/* Power save / sleep */
#define HALOW_PS_MODE           DSLEEP_MODE_NONE
#define HALOW_WAIT_PSMODE       DSLEEP_WAIT_MODE_PS_CONNECT
#define HALOW_PSCONNECT_PERIOD  60

/* Standby */
#define HALOW_STANDBY_CH        1           /* channel index starts from 1 */
#define HALOW_STANDBY_PERIOD_MS 0

/* ACK / retry */
#define HALOW_ACK_TMO_EXTRA     0
#define HALOW_RETRY_FRM_MAX     0
#define HALOW_RETRY_RTS_MAX     0
#define HALOW_RETRY_FB_CNT      0
#define HALOW_RTS_THRESH        100

/* CCA */
#define HALOW_CCA_FOR_CE        0

/* Wakeup */
#define HALOW_WAKEUP_IO         0
#define HALOW_WAKEUP_EDGE       0

/* Debug */
#define HALOW_DBG_LEVEL         0
#define TX_BUFFER_SIZE          (1460*20)

#define HALOW_MCS10_MAX_MSDU    500
#define HALOW_FRAG_HDR_SIZE     2
#define HALOW_FRAG_MAX_PAYLOAD  250
#define HALOW_FRAG_TIMEOUT_MS   1000
#define HALOW_FRAG_MAX_TOTAL    16

//#define HALOW_DEBUG
#ifdef HALOW_DEBUG
#define halow_debug(fmt, ...)  os_printf("[HALW] " fmt "\r\n", ##__VA_ARGS__)
#else
#define halow_debug(fmt, ...)  do { } while (0)
#endif

/* ===== internal state ===== */

static struct os_work lmac_wdt_wk;

static struct lmac_ops *g_ops = NULL;
static halow_rx_cb g_rx_cb;
static uint16_t g_seq;

static uint32_t g_tx_vacated_bytes = TX_BUFFER_SIZE;
static struct os_semaphore g_tx_vacated_sem;

extern void lmac_kick_tx_task( void );
extern void lhw_abort_fsm(void);
extern void update_rx_buff_addr(void);
extern void lhw_start_rx(uint32 flags);

/* ===== MCS10 fragmentation =====
 *
 * MCS10 (OFDMA 26-tone) has ~450B PHY payload limit.
 * For packets exceeding this, we split into fragments with 2B header:
 *   [0] (total << 4) | seq    total>=1, seq<total
 *   [1] uuid                incremented per logical packet
 *
 * total=1: single fragment, strip header on RX
 * total>1: reassemble on RX, discard after 1 s timeout
 */
static uint8_t  frag_tx_uuid;
static uint8_t  frag_tx_buf[HALOW_FRAG_HDR_SIZE + HALOW_FRAG_MAX_PAYLOAD];

typedef struct {
    bool     active;
    uint8_t  uuid;
    uint8_t  total;
    uint8_t  received;
    uint32_t last_tick;
    uint16_t part_len[HALOW_FRAG_MAX_TOTAL];
    uint8_t  buf[HALOW_FRAG_MAX_PAYLOAD * HALOW_FRAG_MAX_TOTAL];
} frag_reassembly_t;

static frag_reassembly_t frag_reasm;

static const uint16_t halow_max_msdu[4][8] = {
    /* 1MHz */ {  700, 1450, 2200, 3000, 4500, 6050, 6800, 7600 },
    /* 2MHz */ { 1600, 3200, 4900, 6500, 8192, 8192, 8192, 8192 },
    /* 4MHz */ { 3400, 6800, 8192, 8192, 8192, 8192, 8192, 8192 },
    /* 8MHz */ { 7400, 8192, 8192, 8192, 8192, 8192, 8192, 8192 },
};

static uint8_t halow_bw_index( uint8_t bw ) {
    return (bw >= 8) ? 3 : (bw >= 4) ? 2 : (bw >= 2) ? 1 : 0;
}

static void halow_runtime_reconfig_barrier(void)
{
    if (g_ops == NULL) {
        return;
    }

    lmac_custom_cfg.defer_ac_pd = 1;
    LMAC_HW->AC_PD = 0u;

    uint32_t saved_irq = LMAC_HW->IRQ_EN;
    LMAC_HW->IRQ_EN = 0u;
    LMAC_HW->IRQ_PD = 0xffffffffu;

    lhw_abort_fsm();

    for (uint32_t ac = 0; ac < 4u; ac++) {
        lmac_tx_ctx_buff *aggr = &ah_lmac_tx.pTx_ac_aggr_data[ac];

        for (int32_t i = (int32_t)aggr->selected_count - 1; i >= 0; i--) {
            struct sk_buff *skb = aggr->skb_list[i];
            if (skb != NULL) {
                skb_list_queue_head(&ah_lmac_tx.pTx_ac_queues[ac], skb);
                aggr->skb_list[i] = NULL;
            }
        }

        aggr->total_len_bytes = 0u;
        aggr->symbol_len = 0u;
        aggr->first_seq = -1;
        aggr->last_seq = -1;
        aggr->selected_count = 0u;
        aggr->queued_count = 0u;
        aggr->tx_flags &= (uint8_t)~0x04u;
    }

    ah_lmac.bo_frame_type = 0u;
    ah_lmac.bo_tx_substate = 0u;
    ah_lmac_tx.pPv0_txvec = NULL;
    ah_lmac_tx.tx_pending_nav_dur = 0u;
    ah_lmac_tx.tx_cca_slot_count = 0u;

    LMAC_HW->BO_CNT0 = 0u;
    LMAC_HW->CCA_STAT = 0x0ff0u;
    update_rx_buff_addr();
    lhw_start_rx(0u);

    LMAC_HW->IRQ_EN = saved_irq;
    LMAC_HW->IRQ_PD = 0xffffffffu;

    lmac_custom_cfg.defer_ac_pd = 0;
    for (uint32_t ac = 0; ac < 4u; ac++) {
        if (skb_list_count(&ah_lmac_tx.pTx_ac_queues[ac]) != 0u) {
            LMAC_HW->AC_PD = 0u;
            LMAC_HW->AC_PD = 0xFu;
            break;
        }
    }
}


// Disable broadcast
int32_t __wrap_lmac_send_bss_announcement(void){
    return 0;
}

static inline void mac_bcast(uint8_t mac[6]) {
    memset(mac, 0xff, 6);
}

static int32_t halow_lmac_rx_mcs10(struct hgic_rx_info *info,
                                     struct ieee80211_hdr *hdr,
                                     uint8_t *payload, int32_t payload_len) {
    if (payload_len < HALOW_FRAG_HDR_SIZE) {
        g_rx_cb(info, hdr, payload, payload_len);
        return 0;
    }

    uint8_t total = payload[0] >> 4;

    if (total == 0) {
        g_rx_cb(info, hdr, payload, payload_len);
        return 0;
    }

    uint8_t seq  = payload[0] & 0x0F;
    uint8_t uuid = payload[1];
    uint8_t *fdata = payload + HALOW_FRAG_HDR_SIZE;
    int32_t flen   = payload_len - HALOW_FRAG_HDR_SIZE;

    if (total == 1) {
        g_rx_cb(info, hdr, fdata, flen);
        return 0;
    }

    uint32_t now = (uint32_t)get_time_ms();

    if (frag_reasm.active &&
        (now - frag_reasm.last_tick) > HALOW_FRAG_TIMEOUT_MS) {
        frag_reasm.active = false;
    }

    if (!frag_reasm.active || frag_reasm.uuid != uuid) {
        frag_reasm.active = false;
        frag_reasm.uuid = uuid;
        frag_reasm.total = total;
        frag_reasm.received = 0;
        memset(frag_reasm.part_len, 0, sizeof(frag_reasm.part_len));
        frag_reasm.active = true;
    }

    if (seq < frag_reasm.total) {
        uint32_t off = 0;
        for (uint8_t i = 0; i < seq; i++)
            off += frag_reasm.part_len[i];
        memcpy(frag_reasm.buf + off, fdata, (uint32_t)flen);
        frag_reasm.part_len[seq] = (uint16_t)flen;
        frag_reasm.received++;
    }

    frag_reasm.last_tick = now;

    if (frag_reasm.received == frag_reasm.total) {
        uint32_t rlen = 0;
        for (uint8_t i = 0; i < frag_reasm.total; i++)
            rlen += frag_reasm.part_len[i];
        g_rx_cb(info, hdr, frag_reasm.buf, (int32_t)rlen);
        frag_reasm.active = false;
    }

    return 0;
}

static int32_t halow_lmac_rx(struct lmac_ops *ops,
                             struct hgic_rx_info *info,
                             uint8_t *data,
                             int32_t len) {
    (void)ops;

    if (!data || len < (int32_t)sizeof(struct ieee80211_hdr))
        return -1;

    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)data;

    if ((hdr->frame_control & 0x000C) != WLAN_FTYPE_DATA)
        return -1;

    uint8_t *payload = data + sizeof(*hdr);
    int32_t payload_len = len - (int32_t)sizeof(*hdr);

    if (payload_len <= 0 || !g_rx_cb)
        return 0;

    if (info->mcs == 10)
        return halow_lmac_rx_mcs10(info, hdr, payload, payload_len);

    g_rx_cb(info, hdr, payload, payload_len);

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

static int32_t halow_lmac_notify(struct lmac_ops *ops, uint8 evt_id,
                                  uint8 *data, int32 len) {
    (void)ops;
    (void)evt_id;
    (void)data;
    (void)len;
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

    if (cfg->central_freq < 7300) {
        cfg->central_freq = 7300;
    }
    if (cfg->central_freq > 10800) {
        cfg->central_freq = 10800;
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

static void halow_config_set_mcs_raw(uint8_t mcs)
{
	lmac_set_fix_tx_rate(g_ops, mcs);
    lmac_set_tx_mcs(g_ops, mcs);
    lmac_set_fallback_mcs(g_ops, mcs);
    lmac_set_mcast_txmcs(g_ops, mcs);
    halow_debug("GET MCS: %d", lmac_get_tx_mcs(g_ops));
}

void halow_config_set_mcs(uint8_t mcs){
    halow_runtime_reconfig_barrier();
    halow_config_set_mcs_raw(mcs);
}

static void halow_config_set_bandwidth_raw(uint8_t bw)
{
    lmac_set_bss_bw(g_ops, bw);
    lmac_set_mcast_txbw(g_ops, bw);
    lmac_set_tx_bw(g_ops, bw);
}

void halow_config_set_bandwidth(uint8_t bw){
    halow_runtime_reconfig_barrier();
    halow_config_set_bandwidth_raw(bw);
}

static void halow_config_set_freq_raw(uint16_t freq)
{
    lmac_set_freq(g_ops, freq);
}

static void halow_config_set_freq_live(uint16_t freq)
{
    halow_runtime_reconfig_barrier();
    halow_config_set_freq_raw(freq);
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
    halow_runtime_reconfig_barrier();
    halow_config_set_freq_raw(halow_cfg.central_freq);

    /* ---- PHY rate control ---- */
    halow_config_set_mcs_raw(halow_cfg.mcs);
    halow_config_set_bandwidth_raw(halow_cfg.bandwidth);
	
    /* ---- power ---- */
    lmac_set_txpower(g_ops, halow_cfg.rf_power);
    //SUPER POWER (200 mA device consumption, 20-22 dBm expected)
    lmac_set_super_pwr(g_ops, halow_cfg.rf_super_power);
    
}

static void halow_modem_set_default(void){
    uint8_t g_mac[6];

    get_mac(g_mac);

    /* ---- basic bring-up ---- */
    lmac_set_mac_addr(g_ops, 0, g_mac);

    /* ---- RF / channel ---- */
    halow_runtime_reconfig_barrier();
    halow_config_set_freq_raw(HALOW_CONFIG_CENTRAL_FREQ_DEF);

    /* ---- PHY rate control ---- */
    halow_config_set_mcs_raw(HALOW_CONFIG_MCS_DEF);
    halow_config_set_bandwidth_raw(HALOW_CONFIG_BANDWIDTH_DEF);
	
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
    if (HALOW_STANDBY_PERIOD_MS != 0) {
        lmac_set_standby(g_ops,
                         HALOW_STANDBY_CH - 1,
                         HALOW_STANDBY_PERIOD_MS * 1000);
    }

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

static int32_t lmac_watchdog_feed_work( struct os_work *work ){
    //ah_lmac.phy_watchdog_flags &= ~0x01;
    os_run_work_delay(&lmac_wdt_wk, 100);
    return 0;
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
    g_ops->notify    = halow_lmac_notify;

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
    halow_lbt_set_tx_as_deactive();
    
    OS_WORK_INIT(&lmac_wdt_wk, lmac_watchdog_feed_work,0);
    os_run_work_delay(&lmac_wdt_wk, 10);
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

static int32_t halow_send_frame(const uint8_t *payload, uint32_t len,
                                 const uint8_t destination_mac[6], uint8_t mcs)
{
    struct ieee80211_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.frame_control = (uint16_t)(WLAN_FTYPE_DATA | WLAN_STYPE_DATA);
    mac_bcast(hdr.addr1);
    mac_generator_get(hdr.addr2);
    memcpy(hdr.addr3, destination_mac, 6);

    g_seq++;
    hdr.seq_ctrl = (uint16_t)((g_seq & 0x0fff) << 4);

    uint32_t hr   = (uint32_t)g_ops->headroom;
    uint32_t tr   = (uint32_t)g_ops->tailroom;
    uint32_t need = hr + sizeof(hdr) + len + tr;

    struct sk_buff *skb = alloc_tx_skb(need);
    if (!skb){
        return -5;
    }

    skb_reserve(skb, (int)hr);
    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, len), payload, len);

    skb->priority = 0;
    skb->tx       = 1;
    halow_get_tx_vacanted_bytes(skb->len);

    int32_t res;
    if (lmac_custom_cfg.fast_tx) {
        res = lmac_fast_tx(skb, mcs);
    } else {
        res = lmac_tx(g_ops, skb);
        lmac_kick_tx_task();
    }

    halow_lbt_set_tx_as_active();
    return res;
}

static int32_t halow_tx_mcs10_frag( const uint8_t *data, uint32_t len, const uint8_t destination_mac[6], uint8_t mcs ) {
    uint8_t uuid = ++frag_tx_uuid;

    if (len <= HALOW_FRAG_MAX_PAYLOAD) {
        frag_tx_buf[0] = (uint8_t)(1u << 4);
        frag_tx_buf[1] = uuid;
        memcpy(frag_tx_buf + HALOW_FRAG_HDR_SIZE, data, len);
        return halow_send_frame(frag_tx_buf, HALOW_FRAG_HDR_SIZE + len, destination_mac, mcs);
    }

    uint8_t n = (uint8_t)((len + HALOW_FRAG_MAX_PAYLOAD - 1) / HALOW_FRAG_MAX_PAYLOAD);
    uint32_t off = 0;

    for (uint8_t i = 0; i < n; i++) {
        uint32_t chunk = len - off;
        if (chunk > HALOW_FRAG_MAX_PAYLOAD){
            chunk = HALOW_FRAG_MAX_PAYLOAD;
        }

        frag_tx_buf[0] = (uint8_t)((n << 4) | i);
        frag_tx_buf[1] = uuid;
        memcpy(frag_tx_buf + HALOW_FRAG_HDR_SIZE, data + off, chunk);

        int32_t res = halow_send_frame(frag_tx_buf, HALOW_FRAG_HDR_SIZE + chunk, destination_mac, mcs);
        if (res != 0){
            return res;
        }

        off += chunk;
    }

    return 0;
}

int32_t halow_tx( const uint8_t *data, uint32_t len, const uint8_t destination_mac[6], uint8_t mcs ) {
    if (g_ops == NULL)  return -1;
    if (data == NULL)   return -2;
    if (len == 0)        return -3;
    if (len > TX_BUFFER_SIZE) return -4;

    /* Per-frame MCS override. Fall back to the globally configured (sanitized)
     * MCS for HALOW_MCS_DEFAULT or any value the LMAC TX rate tables cannot
     * index: only MCS0-7 and the special MCS10 are supported. Without this,
     * auto-rate-adaptation can drive the per-peer TX MCS up to 8/9 -> OOB in
     * the NDBPS/retry tables -> wrong symbol count -> truncated frame in air. */
    if (mcs == HALOW_MCS_DEFAULT || (mcs > 7 && mcs != 10)) {
        halow_config_t cfg;
        halow_config_load(&cfg);
        mcs = cfg.mcs;
    }

    if (mcs == 10) {
        return halow_tx_mcs10_frag(data, len, destination_mac, mcs);
    }

    return halow_send_frame(data, len, destination_mac, mcs);
}

uint32_t halow_get_mtu(uint8_t mcs) {
    halow_config_t cfg;
    halow_config_load(&cfg);

    if (mcs == 10) {
        return HALOW_MCS10_MAX_MSDU;
    }

    return (uint32_t)halow_max_msdu[halow_bw_index(cfg.bandwidth)][mcs];
}
