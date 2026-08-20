#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW
#include "lib/logc/log.h"
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
#include "device.h"
extern bool ota_wota_active( void );
extern bool ota_fw_active( void );

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
#define HALOW_RTS_THRESH        2400

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
#define HALOW_FRAG_MAX_PAYLOAD  300
#define HALOW_FRAG_TIMEOUT_MS   1000
#define HALOW_FRAG_MAX_TOTAL    8

#define HALOW_TX_BO_TMO_MS          500u
#define HALOW_TX_BO_TMO_GAP_MS      1000u
#define HALOW_TX_WEDGE_TMO_MS       5000u
#define HALOW_TX_WEDGE_CONTEND_MS   15000u
#define HALOW_TX_WEDGE_REBOOT_MS    30000u
#define HALOW_TX_WEDGE_STRIKES      3u
#define HALOW_TX_LEAK_TMO_MS        500u

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
static volatile uint32_t g_tx_complete_seq = 0u;

halow_tx_dbg_t g_tx_dbg;
static uint32_t g_tx_wedge_count = 0u;

extern volatile uint8_t lmac_tx_purge_request;
extern volatile uint32_t lmac_ac_pd_count;

void halow_tx_dbg_get( halow_tx_dbg_t *out ){
    if( out == NULL ) return;
    uint32_t flag = disable_irq();
    *out = g_tx_dbg;
    enable_irq(flag);
    out->complete_seq  = g_tx_complete_seq;
    out->wedge_count   = g_tx_wedge_count;
    out->ac_pd          = lmac_ac_pd_count;
    out->budget_live    = g_tx_vacated_bytes;
    out->bo_ftype_live  = ah_lmac.bo_frame_type;
    out->bo_sub_live    = ah_lmac.bo_tx_substate;
    for( uint32_t ac = 0u; ac < 4u; ac++ ){
        out->q_live[ac]   = skb_list_count(&ah_lmac_tx.pTx_ac_queues[ac]);
        out->sel_live[ac] = ah_lmac_tx.pTx_ac_aggr_data[ac].selected_count;
    }
    {
        extern float halow_lbt_ch_util_get(void);
        extern float halow_lbt_airtime_get(void);
        int32_t at = (int32_t)(halow_lbt_airtime_get() * 1000.0f);
        int32_t cu = (int32_t)(halow_lbt_ch_util_get() * 1000.0f);
        if( at > 2550 ) at = 2550;  if( at < 0 ) at = 0;
        if( cu > 2550 ) cu = 2550;  if( cu < 0 ) cu = 0;
        out->airtime_pct_x10 = (uint8_t)((at + 5) / 10);
        out->ch_util_pct_x10 = (uint8_t)((cu + 5) / 10);
    }
}

static void halow_tx_wedge_snapshot( void ){
    uint32_t flag = disable_irq();
    g_tx_dbg.snap_jiffies         = (uint32_t)os_jiffies();
    g_tx_dbg.snap_complete_seq    = g_tx_complete_seq;
    g_tx_dbg.snap_tx_end_count    = g_tx_dbg.tx_end_count;
    g_tx_dbg.snap_budget          = g_tx_vacated_bytes;
    g_tx_dbg.snap_tx_stat         = LMAC_HW->TX_STAT;
    g_tx_dbg.snap_fsm             = LMAC_HW->FSM_STAT;
    g_tx_dbg.snap_comn            = LMAC_HW->COMN_CTRL;
    g_tx_dbg.snap_irqpd           = LMAC_HW->IRQ_PD;
    g_tx_dbg.snap_bocnt           = LMAC_HW->BO_CNT0;
    g_tx_dbg.snap_ac              = ah_lmac.current_ac_flags & 0x0fu;
    g_tx_dbg.snap_sub             = (uint8_t)ah_lmac.bo_tx_substate;
    g_tx_dbg.snap_bo_ftype        = (uint8_t)ah_lmac.bo_frame_type;
    g_tx_dbg.snap_ctrl_flags      = (uint8_t)ah_lmac.tx_irq_ctrl_flags;
    for( uint32_t ac = 0u; ac < 4u; ac++ ){
        g_tx_dbg.snap_q_ac[ac] = skb_list_count(&ah_lmac_tx.pTx_ac_queues[ac]);
        g_tx_dbg.snap_sel[ac]  = ah_lmac_tx.pTx_ac_aggr_data[ac].selected_count;
    }
    g_tx_wedge_count++;
    enable_irq(flag);
}
static struct os_semaphore g_tx_vacated_sem;

extern void lmac_kick_tx_task( void );
extern void lhw_abort_fsm(void);
extern void lhw_enable_irq_ac(void);
extern void update_rx_buff_addr(void);
extern void lhw_start_rx(uint32 flags);

/* ===== MCS10 fragmentation =====
 *
 * MCS10 (S1G duplicate mode) single-PPDU limit is ~344-400B, boot-dependent (see HALOW_FRAG_MAX_PAYLOAD).
 * For packets exceeding this, we split into fragments with 2B header:
 *   [0] (total << 4) | seq    total>=1, seq<total
 *   [1] uuid                incremented per logical packet
 *
 * total=1: single fragment, strip header on RX
 * total>1: reassemble on RX, discard after 1 s timeout
 */
static uint8_t  frag_tx_uuid;

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

static void rescue_ac_aggregate( uint32_t ac ){
    lmac_tx_ctx_buff *aggr = &ah_lmac_tx.pTx_ac_aggr_data[ac];

    for (int32_t i = 63; i >= 0; i--) {
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

static void kick_ac_pd_if_queued( void ){
    for (uint32_t ac = 0u; ac < 4u; ac++) {
        if (skb_list_count(&ah_lmac_tx.pTx_ac_queues[ac]) != 0u) {
            LMAC_HW->AC_PD = 0u;
            LMAC_HW->AC_PD = 0xFu;
            return;
        }
    }
}

static void halow_runtime_reconfig_barrier(void)
{
    if (g_ops == NULL) {
        return;
    }

    lmac_custom_cfg.defer_ac_pd = 1;
    LMAC_HW->AC_PD = 0u;

    uint32_t cpsr = disable_irq();
    uint32_t saved_irq = LMAC_HW->IRQ_EN;
    LMAC_HW->IRQ_EN = 0u;
    LMAC_HW->IRQ_PD = 0xffffffffu;

    lhw_abort_fsm();

    for (uint32_t ac = 0; ac < 4u; ac++) {
        rescue_ac_aggregate( ac );
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
    enable_irq(cpsr);

    lmac_custom_cfg.defer_ac_pd = 0;
    kick_ac_pd_if_queued();
}


// Disable broadcast
int32_t __wrap_lmac_send_bss_announcement(void){
    return 0;
}

static inline void mac_bcast(uint8_t mac[6]) {
    memset(mac, 0xff, 6);
}

static void frag_reasm_reset( uint8_t uuid, uint8_t total ){
    frag_reasm.active   = false;
    frag_reasm.uuid     = uuid;
    frag_reasm.total    = total;
    frag_reasm.received = 0;
    memset(frag_reasm.part_len, 0, sizeof(frag_reasm.part_len));
    frag_reasm.active   = true;
}

static void frag_reasm_store( uint8_t seq, const uint8_t *fdata, int32_t flen ){
    bool malformed = (seq >= frag_reasm.total) ||
                     (flen <= 0) || (flen > HALOW_FRAG_MAX_PAYLOAD);
    if( malformed ){
        g_tx_dbg.rx_frag_drop++;
        return;
    }
    if( frag_reasm.part_len[seq] != 0 ){
        return;
    }

    uint32_t off = 0;
    for (uint8_t i = 0; i < seq; i++)
        off += frag_reasm.part_len[i];
    if (off + (uint32_t)flen <= sizeof(frag_reasm.buf)) {
        memcpy(frag_reasm.buf + off, fdata, (uint32_t)flen);
        frag_reasm.part_len[seq] = (uint16_t)flen;
        frag_reasm.received++;
    }else{
        g_tx_dbg.rx_frag_drop++;
    }
}

static bool frag_reasm_complete( void ){
    return frag_reasm.received == frag_reasm.total;
}

static uint32_t frag_reasm_length( void ){
    uint32_t rlen = 0;
    for (uint8_t i = 0; i < frag_reasm.total; i++)
        rlen += frag_reasm.part_len[i];
    return rlen;
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

    if (total > HALOW_FRAG_MAX_TOTAL) {
        g_tx_dbg.rx_frag_drop++;
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
        g_tx_dbg.rx_frag_drop++;
        frag_reasm.active = false;
    }

    if (!frag_reasm.active || frag_reasm.uuid != uuid) {
        frag_reasm_reset( uuid, total );
    }

    frag_reasm_store( seq, fdata, flen );
    frag_reasm.last_tick = now;

    if (frag_reasm_complete()) {
        g_rx_cb(info, hdr, frag_reasm.buf, (int32_t)frag_reasm_length());
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

static void halow_tx_skb_budget_refund( uint32_t len ){
    bool full;
    uint32_t flag = disable_irq();
    g_tx_vacated_bytes += len;
    full = (g_tx_vacated_bytes >= TX_BUFFER_SIZE);
    if( full ) g_tx_vacated_bytes = TX_BUFFER_SIZE;
    enable_irq(flag);
    if( full ){
        halow_lbt_set_tx_as_deactive();
    }
}

static bool tx_budget_take( uint32_t len ){
    uint32_t flag = disable_irq();
    bool ok = (g_tx_vacated_bytes >= len);
    if( ok ){
        g_tx_vacated_bytes -= len;
    }
    enable_irq(flag);
    return ok;
}

void halow_tx_skb_complete( struct sk_buff *skb ){
    if( skb == NULL ) return;
    bool full;
    uint32_t flag = disable_irq();
    g_tx_complete_seq++;
    {
        extern void halow_lbt_tx_done_notify( void );
        halow_lbt_tx_done_notify();
    }
    g_tx_vacated_bytes += skb->len;
    full = (g_tx_vacated_bytes >= TX_BUFFER_SIZE);
    if( full ) g_tx_vacated_bytes = TX_BUFFER_SIZE;
    enable_irq(flag);
    if( full ){
        halow_lbt_set_tx_as_deactive();
    }
    os_sema_up(&g_tx_vacated_sem);
    kfree_skb(skb);
}

static int32_t halow_lmac_tx_status_callback(struct lmac_ops *ops, struct sk_buff *skb) {
    (void)ops;
    if (skb) {
        halow_tx_skb_complete(skb);
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

uint32_t halow_get_tx_vacancy( void ){
    return g_tx_vacated_bytes;
}

static bool tx_work_pending( void ){
    if( g_tx_vacated_bytes < TX_BUFFER_SIZE ) return true;
    for( uint32_t ac = 0u; ac < 4u; ac++ ){
        if( skb_list_count(&ah_lmac_tx.pTx_ac_queues[ac]) != 0u ) return true;
        if( ah_lmac_tx.pTx_ac_aggr_data[ac].selected_count != 0u ) return true;
    }
    return false;
}

static void tx_request_purge( void ){
    lmac_tx_purge_request = 1u;
    os_sema_up(&ah_lmac_tx.tx_sem);
}

static void tx_watchdog_bo_timeout( uint64_t now ){
    static uint64_t bo_stuck_since = 0u;
    static uint64_t bo_last_abort  = 0u;
    static uint32_t bo_last_end_cnt = 0u, bo_last_acpd = 0u;

    if( ah_lmac.bo_frame_type == 0u ){
        bo_stuck_since = 0u;
    }else if( g_tx_dbg.tx_end_count != bo_last_end_cnt ||
              lmac_ac_pd_count        != bo_last_acpd ){
        bo_stuck_since = now;
    }else if( bo_stuck_since == 0u ){
        bo_stuck_since = now;
    }
    bo_last_end_cnt = g_tx_dbg.tx_end_count;
    bo_last_acpd    = lmac_ac_pd_count;

    if( ah_lmac.bo_frame_type != 0u &&
        lhw_tx_gate_blocked() && lhw_rf_gates_off() ){
        if( bo_stuck_since == 0u ) bo_stuck_since = now;
    }

    if( bo_stuck_since == 0u ||
        (now - bo_stuck_since) < os_msecs_to_jiffies(HALOW_TX_BO_TMO_MS) ||
        ( bo_last_abort != 0u &&
          (now - bo_last_abort) < os_msecs_to_jiffies(HALOW_TX_BO_TMO_GAP_MS) ) ){
        return;
    }

    uint32_t stuck_sub = ah_lmac.bo_tx_substate;
    if( lhw_abort_armed_tx() ){
        bo_last_abort = now;
        g_tx_dbg.bo_tmo_recov++;
    }
    bo_stuck_since = 0u;
    log_warn("halow: fast TX bo-timeout (sub=%u frozen >=%ums) -> FSM aborted, TX retried",
             (unsigned)stuck_sub, HALOW_TX_BO_TMO_MS);
}

static void tx_watchdog_hard_wedge( uint64_t now ){
    static uint64_t wedge_since = 0u;
    static uint64_t wedge_purge_jiff = 0u;
    static uint32_t wedge_last_seq = 0u;
    static uint32_t wedge_last_acpd = 0u;
    static uint32_t dead_strikes = 0u;

    if( !tx_work_pending() ){
        wedge_since = 0u;
        wedge_purge_jiff = 0u;
        dead_strikes = 0u;
        return;
    }
    if( g_tx_complete_seq != wedge_last_seq ){
        wedge_since = 0u;
        wedge_purge_jiff = 0u;
        wedge_last_seq  = g_tx_complete_seq;
        wedge_last_acpd = lmac_ac_pd_count;
        return;
    }

    if( wedge_since == 0u ) wedge_since = now;
    uint64_t stuck_ms = os_jiffies_to_msecs(now - wedge_since);
    uint32_t acpd_moved = (lmac_ac_pd_count != wedge_last_acpd) ? 1u : 0u;
    uint32_t wedge_thresh_ms = acpd_moved ? HALOW_TX_WEDGE_CONTEND_MS : HALOW_TX_WEDGE_TMO_MS;
    bool purge_due = ( stuck_ms >= wedge_thresh_ms &&
                       ( wedge_purge_jiff == 0u ||
                         (now - wedge_purge_jiff) >= os_msecs_to_jiffies(wedge_thresh_ms) ) );
    if( !purge_due ){
        if( stuck_ms >= HALOW_TX_WEDGE_REBOOT_MS && dead_strikes >= HALOW_TX_WEDGE_STRIKES &&
            !(ota_wota_active() || ota_fw_active()) ){
            log_error("halow: TX dead after %u purges -> reboot",
                      (unsigned)g_tx_wedge_count);
            os_sleep_ms(50);
            device_reboot();
        }
        return;
    }

    wedge_purge_jiff = now;
    wedge_last_acpd  = lmac_ac_pd_count;
    if( acpd_moved == 0u ) dead_strikes++;
    else                   dead_strikes = 0u;
    halow_tx_wedge_snapshot();
    log_warn("halow: TX hard wedge #%u (budget=%lu, no complete %lums, acpd_move=%u, dead=%u) -> purge",
             (unsigned)g_tx_wedge_count,
             (unsigned long)g_tx_vacated_bytes, (unsigned long)stuck_ms,
             (unsigned)acpd_moved, (unsigned)dead_strikes);
    tx_request_purge();
    if( dead_strikes >= HALOW_TX_WEDGE_STRIKES &&
        stuck_ms >= HALOW_TX_WEDGE_REBOOT_MS &&
        (ota_wota_active() || ota_fw_active()) ){
        log_warn("halow: TX still wedged after purges, OTA active - no reboot");
        tx_request_purge();
    }
}

static void tx_watchdog_budget_leak( uint64_t now ){
    static uint64_t leak_since = 0u;

    if( tx_work_pending() ){
        leak_since = 0u;
        return;
    }
    if( leak_since == 0u ){
        leak_since = now;
        return;
    }
    if( (now - leak_since) < os_msecs_to_jiffies(HALOW_TX_LEAK_TMO_MS) ) return;
    leak_since = 0u;
    log_warn("halow: TX vacancy leak (budget=%lu, queues idle) -> resync",
             (unsigned long)g_tx_vacated_bytes);
    g_tx_vacated_bytes = TX_BUFFER_SIZE;
    halow_lbt_set_tx_as_deactive();
    os_sema_up(&g_tx_vacated_sem);
}

void halow_tx_vacancy_watchdog( void ){
    uint64_t now = os_jiffies();
    tx_watchdog_bo_timeout( now );
    tx_watchdog_hard_wedge( now );
    tx_watchdog_budget_leak( now );
}

static int32_t halow_send_frame(const uint8_t *payload, uint32_t len,
                                 const uint8_t destination_mac[6], uint8_t mcs, uint8_t tid)
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
        g_tx_dbg.tx_drop_alloc++;
        return -5;
    }

    skb_reserve(skb, (int)hr);
    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, len), payload, len);

    skb->priority = tid & 7u;
    skb->tx       = 1;
    if( !tx_budget_take( skb->len ) ){
        kfree_skb(skb);
        g_tx_dbg.tx_drop_budget++;
        return -6;
    }

    int32_t res;
    uint32_t sent_len = skb->len;
    if (lmac_custom_cfg.fast_tx) {
        res = lmac_fast_tx(skb, mcs);
    } else {
        res = lmac_tx(g_ops, skb);
        lmac_kick_tx_task();
    }

    if( res != 0 ){
        halow_tx_skb_budget_refund(sent_len);
        g_tx_dbg.tx_drop_lmac++;
        return res;
    }

    halow_lbt_set_tx_as_active();
    return 0;
}

static int32_t halow_tx_mcs10_frag( const uint8_t *data, uint32_t len,
                                    const uint8_t destination_mac[6], uint8_t mcs, uint8_t tid ) {
    if( len > (uint32_t)HALOW_FRAG_MAX_PAYLOAD * HALOW_FRAG_MAX_TOTAL ){
        g_tx_dbg.tx_drop_alloc++;
        return -4;
    }

    static struct os_mutex g_frag_mu;
    static bool g_frag_mu_ok = false;
    static uint8_t frag[HALOW_FRAG_HDR_SIZE + HALOW_FRAG_MAX_PAYLOAD];
    uint8_t uuid;
    {
        uint32_t flag = disable_irq();
        uuid = ++frag_tx_uuid;
        if( !g_frag_mu_ok ){
            (void)os_mutex_init(&g_frag_mu);
            g_frag_mu_ok = true;
        }
        enable_irq(flag);
    }
    (void)os_mutex_lock(&g_frag_mu, -1);

    int32_t ret;
    if (len <= HALOW_FRAG_MAX_PAYLOAD) {
        frag[0] = (uint8_t)(1u << 4);
        frag[1] = uuid;
        memcpy(frag + HALOW_FRAG_HDR_SIZE, data, len);
        ret = halow_send_frame(frag, HALOW_FRAG_HDR_SIZE + len, destination_mac, mcs, tid);
        os_mutex_unlock(&g_frag_mu);
        return ret;
    }

    uint8_t n = (uint8_t)((len + HALOW_FRAG_MAX_PAYLOAD - 1) / HALOW_FRAG_MAX_PAYLOAD);
    uint32_t off = 0;

    for (uint8_t i = 0; i < n; i++) {
        uint32_t chunk = len - off;
        if (chunk > HALOW_FRAG_MAX_PAYLOAD){
            chunk = HALOW_FRAG_MAX_PAYLOAD;
        }

        frag[0] = (uint8_t)((n << 4) | i);
        frag[1] = uuid;
        memcpy(frag + HALOW_FRAG_HDR_SIZE, data + off, chunk);

        int32_t res = halow_send_frame(frag, HALOW_FRAG_HDR_SIZE + chunk, destination_mac, mcs, tid);
        if (res != 0){
            os_mutex_unlock(&g_frag_mu);
            return res;
        }

        off += chunk;
    }

    os_mutex_unlock(&g_frag_mu);
    return 0;
}

int32_t halow_tx( const uint8_t *data, uint32_t len, const uint8_t destination_mac[6], uint8_t mcs ) {
    return halow_tx_p( data, len, destination_mac, mcs, 0u );
}

static uint8_t  cfg_cache_mcs  = 0u;
static uint8_t  cfg_cache_bw   = 0u;
static bool     cfg_cache_ok   = false;

void halow_cfg_mcs_bw_refresh( void ){
    halow_config_t cfg;
    halow_config_load(&cfg);
    cfg_cache_mcs = cfg.mcs;
    cfg_cache_bw  = cfg.bandwidth;
    cfg_cache_ok  = true;
}

static void halow_cfg_mcs_bw_cached( uint8_t *mcs_out, uint8_t *bw_out ){
    if( !cfg_cache_ok ) halow_cfg_mcs_bw_refresh();
    *mcs_out = cfg_cache_mcs;
    *bw_out  = cfg_cache_bw;
}

static uint8_t mcs_fit_len( uint8_t mcs, uint32_t len ){
    uint8_t cfg_mcs, cfg_bw;
    halow_cfg_mcs_bw_cached(&cfg_mcs, &cfg_bw);
    uint8_t bw_idx = halow_bw_index(cfg_bw);

    if( len + 32u <= halow_max_msdu[bw_idx][mcs] ){
        return mcs;
    }
    for( uint8_t m = (uint8_t)(mcs + 1u); m <= 7u; m++ ){
        if( len + 32u <= halow_max_msdu[bw_idx][m] ){
            g_tx_dbg.tx_mcs_bump++;
            return m;
        }
    }
    return HALOW_MCS_DEFAULT;
}

int32_t halow_tx_p( const uint8_t *data, uint32_t len, const uint8_t destination_mac[6], uint8_t mcs, uint8_t tid ) {
    if (g_ops == NULL)  return -1;
    if (data == NULL)   return -2;
    if (len == 0)        return -3;
    if (len > TX_BUFFER_SIZE) return -4;

    if (mcs == HALOW_MCS_DEFAULT || (mcs > 7 && mcs != 10)) {
        uint8_t dflt_mcs, dflt_bw;
        halow_cfg_mcs_bw_cached(&dflt_mcs, &dflt_bw);
        mcs = dflt_mcs;
    }

    if (mcs == 10) {
        return halow_tx_mcs10_frag(data, len, destination_mac, mcs, tid);
    }

    mcs = mcs_fit_len( mcs, len );
    if( mcs == HALOW_MCS_DEFAULT ){
        g_tx_dbg.tx_drop_oversize++;
        return -4;
    }

    return halow_send_frame(data, len, destination_mac, mcs, tid);
}

uint8_t halow_cfg_mcs_get_cached(void) {
    uint8_t mcs, bw;
    halow_cfg_mcs_bw_cached(&mcs, &bw);
    return mcs;
}

uint32_t halow_get_mtu(uint8_t mcs) {
    uint8_t cm, cb;
    halow_cfg_mcs_bw_cached(&cm, &cb);
    if (mcs == 10) {
        return HALOW_MCS10_MAX_MSDU;
    }
    return (uint32_t)halow_max_msdu[halow_bw_index(cb)][mcs];
}
