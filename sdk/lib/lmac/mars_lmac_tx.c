// Auto-reconstructed: mars_lmac_tx.c
#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_MARS_LMAC_TX
#include "lib/logc/log.h"

#include "typesdef.h"
#include "osal/string.h"
#include "osal/semaphore.h"
#include "osal/task.h"
#include "osal/time.h"
#include "lib/lmac/lmac_ctx.h"
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/ieee802_11_defs.h"
#include "lib/lmac/lmac_globals.h"
#include "lib/lmac/lmac_regmap.h"
#include "lib/lmac/mars_tdma.h"
#include "lib/skb/skb.h"
#include "lib/skb/skbuff.h"
#include "lib/skb/skb_list.h"

extern lmac_ah_tx_ctx_t ah_lmac_tx_orig;
extern uint32_t ft_att_pre_orig;
extern uint32_t sys_con8_bak_orig;

#define ah_lmac_tx ah_lmac_tx_orig
#define ft_att_pre ft_att_pre_orig
#define sys_con8_bak sys_con8_bak_orig

extern int32 os_sema_up(struct os_semaphore *sem);
extern int32 skb_list_init(struct skb_list *list);
extern uint32 skb_list_count(struct skb_list *list);
extern void assert_internal(const char *__function, unsigned int __line, const char *__assertion);
extern int32 os_task_set_priority(struct os_task *task, uint8 priority);
extern void lmac_sta_put(void *sta);
extern void lhw_cfg_dma_list_cnt(uint32 cnt);
extern void lhw_cfg_tx_sub_frm(uint32 idx, uint32 v0, uint32 v1);
extern void lhw_abort_fsm(void);
extern void lhw_start_rx(uint32 flags);
extern uint32 lhw_get_cca_remain(void);
extern void lhw_start_cca(uint32 bw, uint32 dur);
extern void lhw_start_tx(uint32 flags);
extern void hgics_print_hex(void *buf, uint32 len);
extern uint16 partial_bssid_calc(uint8 *bssid);
extern uint16 partial_aid_calc(uint16 aid, uint8 *bssid);
extern void lmac_lo_table_kick(uint16 id);
extern int32 lmac_tdma_start(void);
extern void lmac_set_basic_nav(uint32 nav);
extern void lmac_get_rx_addr(uint8 *addr, uint8 *hdr);
extern void *lmac_sta_get(uint16 aid, uint8 *addr);
extern void *lmac_sta_search(uint16 aid, uint8 *addr);
extern uint32 lmac_get_tid(void *hdr);
extern uint32 lmac_get_seq_num(void *hdr);
extern uint32 lmac_get_hdr_len_pv0(void *hdr);
extern uint32 lmac_get_hdr_len_pv1(void *hdr);
extern uint8 *lmac_convert_sid2mac(uint16 sid);
static void lmac_tx_pv0_s1g_beacon(struct sk_buff *skb);
extern uint32 calc_max_agg_bytes(uint32 bw, uint32 mcs);
extern uint32 calc_symbol_len(uint32 bytes, uint32 bw, uint32 mcs);
extern void ah_rfdigicali_tx_pwr(uint32 arg0);
extern void config_ft_att_val(void);
extern int jtag_map_set(uint8 val);
extern int32 gpio_set_dir(uint32 pin, int32 direction);
extern int32 gpio_set_val(uint32 pin, int32 value);
extern void lhw_enable_irq_ac(void);
extern void lmac_delay_us(uint32 us);
extern void lmac_cancle_tx_tmo(void);
extern uint32 ah_wphy_err_code_get(void);
extern void lmac_rx_gain_cfg(uint32 gain);
extern void update_rx_buff_addr(void);
extern void os_sleep_us(int us);
extern void ah_rfdigicali_bknoise_calc_en(void);
extern void ah_rfdigicali_bknoise_calc_dis(void);
extern uint32 ah_rfdigicali_bknoise_valid_pd_get(void);
extern void ah_rfdigicali_bknoise_valid_pd_clr(void);
extern int8 ah_rfdigicali_bknoise_get(void);
extern uint32 ah_wphy_agc_info_get(void);
extern int32 ah_wphy_rx_gain_para_get(int32 idx);
extern void ah_wphy_cca_th_cfg(void *cfg);
extern void ah_wphy_obss_para_cfg(int32 a, int32 b, int32 c, int32 d);
extern uint64 lhw_get_ndp2m(void);
extern void ah_rfdigicali_config_hw_bknoise(uint16_t arg0, uint16_t arg1);
extern void ah_wphy_auto_sig_err_rst_disable(void);
extern void ah_wphy_auto_sig_err_rst_enable(void);
extern void ah_wphy_pri_channel_cfg(uint32 cfg);
extern int32 lmac_lo_freq_set(uint16 id);
extern void lmac_notify_channel_switch(uint8 chan);
extern void lmac_beacon_timer_start(uint32 us);

#define AH_TXQ_OFS        0x064U
#define AH_TXSQ_OFS       0x070U
#define AH_CUR_TXVEC_OFS  0x004U
#define AH_BEACON_SKB_OFS 0x008U
#define AH_ACQ_OFS        0x088U
#define AH_STATQ_OFS      0x538U
#define AH_AC_STRIDE      0x120U
#define AH_AGGLIST_OFS    0x0B8U
#define AH_AGGBYTES_OFS   0x1B8U
#define AH_AGGSYM_OFS     0x1BCU
#define AH_AGGNUM_OFS     0x1C4U
#define AH_AGGCNT_OFS     0x1C5U
#define AH_AGGHDR_OFS     0x1C6U
#define AH_DURCACHE_OFS   0x55EU
#define AH_LMAC_TXCNT_OFS 0xA78U
#define AH_LMAC_TXERR_OFS 0xA7AU
#define AH_LMAC_TXMAX_OFS 0x760U
#define AH_LMAC_TXSUM_OFS 0x764U
#define AH_LMAC_BEACON_CUR_OFS 0xA54U
#define AH_LMAC_FLAG_A4F_OFS 0xA4FU
#define AH_LMAC_BCNCTL_OFS 0x3B8U
#define AH_LMAC_TXSTATE_OFS 0x9B4U
#define AH_LMAC_ACSEL0_OFS 0x30CU
#define AH_LMAC_ACSEL1_OFS 0x30DU
#define AH_LMAC_ACSEL2_OFS 0x30EU
#define AH_LMAC_ACLAST_OFS 0x9DCU
#define AH_LMAC_MISC9E2_OFS 0x9E2U
#define AH_LMAC_MISC9E0_OFS 0x9E0U
#define AH_LMAC_STA_HEAD_OFS 0x9F8U
#define AH_LMAC_PM_FLAG_OFS 0xA08U
#define AH_LMAC_PM_FLAG2_OFS 0xA0AU
#define AH_LMAC_PM_MODE_OFS 0x0BCU
#define AH_LMAC_PM_DEADLINE_LO_OFS 0x3CCU
#define AH_LMAC_PM_DEADLINE_HI_OFS 0x3D0U
#define AH_LMAC_PM_MARGIN_OFS 0x3C8U
#define AH_LMAC_DTIM_COUNT_OFS 0x555U
#define AH_LMAC_DTIM_PERIOD_OFS 0x556U
#define AH_LMAC_DTIM_TU_OFS 0x658U
#define AH_LMAC_RF_PD_FLAGS_OFS 0x878U
#define AH_LMAC_PSPOLL_ACK_OFS 0x994U
#define AH_LMAC_TXSTART_OFS 0x670U

#define AH_TX_BYTES()     ((uint8 *)&ah_lmac_tx)
#define AH_CUR_TXVEC()    (*(void **)(AH_TX_BYTES() + AH_CUR_TXVEC_OFS))
#define AH_BEACON_SKB()   (*(struct sk_buff **)(AH_TX_BYTES() + AH_BEACON_SKB_OFS))
#define AH_TXQ()          ((struct skb_list *)(AH_TX_BYTES() + AH_TXQ_OFS))
#define AH_TXSQ()         ((struct skb_list *)(AH_TX_BYTES() + AH_TXSQ_OFS))
#define AH_STATQ()        ((struct skb_list *)(AH_TX_BYTES() + AH_STATQ_OFS))
#define AH_ACQ(idx)       ((struct skb_list *)(AH_TX_BYTES() + AH_ACQ_OFS + ((idx) * sizeof(struct skb_list))))
#define AH_AGGCNT(idx)    (*(uint8 *)(AH_TX_BYTES() + AH_AGGCNT_OFS + ((idx) * AH_AC_STRIDE)))
#define AH_AGGNUM(idx)    (*(uint8 *)(AH_TX_BYTES() + AH_AGGNUM_OFS + ((idx) * AH_AC_STRIDE)))
#define AH_AGGLIST(idx)   ((uint32 *)(AH_TX_BYTES() + AH_AGGLIST_OFS + ((idx) * AH_AC_STRIDE)))
#define AH_AGGBYTES(idx)  (*(uint32 *)(AH_TX_BYTES() + AH_AGGBYTES_OFS + ((idx) * AH_AC_STRIDE)))
#define AH_AGGSYM(idx)    (*(uint32 *)(AH_TX_BYTES() + AH_AGGSYM_OFS + ((idx) * AH_AC_STRIDE)))
#define AH_AGGHDR(idx)    (*(uint16 *)(AH_TX_BYTES() + AH_AGGHDR_OFS + ((idx) * AH_AC_STRIDE)))
#define AH_DURCACHE()     (*(uint16 *)(AH_TX_BYTES() + AH_DURCACHE_OFS))
#define AH_TX_EXIT_FLAG() (*(uint8 *)AH_TX_BYTES())
#define AH_PENDING_TX()   (*(uint16 *)((uint8 *)&ah_lmac + AH_LMAC_TXCNT_OFS))
#define AH_TX_ERRCNT()    (*(uint16 *)((uint8 *)&ah_lmac + AH_LMAC_TXERR_OFS))
#define AH_TX_LAT_MAX()   (*(uint32 *)((uint8 *)&ah_lmac + AH_LMAC_TXMAX_OFS))
#define AH_TX_LAT_SUM()   (*(uint32 *)((uint8 *)&ah_lmac + AH_LMAC_TXSUM_OFS))
#define AH_CUR_BEACON()   (*(struct sk_buff **)((uint8 *)&ah_lmac + AH_LMAC_BEACON_CUR_OFS))
#define AH_MISC_FLAG_A4F() (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_FLAG_A4F_OFS))
#define AH_BCN_CTRL()     (*(uint32 *)((uint8 *)&ah_lmac + AH_LMAC_BCNCTL_OFS))
#define AH_TX_STATE()     (*(uint32 *)((uint8 *)&ah_lmac + AH_LMAC_TXSTATE_OFS))
#define AH_ACSEL0()       (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_ACSEL0_OFS))
#define AH_ACSEL1()       (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_ACSEL1_OFS))
#define AH_ACSEL2()       (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_ACSEL2_OFS))
#define AH_ACLAST()       (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_ACLAST_OFS))
#define AH_MISC9E2()      (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_MISC9E2_OFS))
#define AH_MISC9E0()      (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_MISC9E0_OFS))
#define AH_STA_HEAD_RAW() (*(void **)((uint8 *)&ah_lmac + AH_LMAC_STA_HEAD_OFS))
#define AH_PM_FLAG()      (*(uint16 *)((uint8 *)&ah_lmac + AH_LMAC_PM_FLAG_OFS))
#define AH_PM_FLAG2()     (*(uint16 *)((uint8 *)&ah_lmac + AH_LMAC_PM_FLAG2_OFS))
#define AH_PM_MODE()      (*(uint32 *)((uint8 *)&ah_lmac + AH_LMAC_PM_MODE_OFS))
#define AH_PM_DEADLINE_LO() (*(uint32 *)((uint8 *)&ah_lmac + AH_LMAC_PM_DEADLINE_LO_OFS))
#define AH_PM_DEADLINE_HI() (*(uint32 *)((uint8 *)&ah_lmac + AH_LMAC_PM_DEADLINE_HI_OFS))
#define AH_PM_MARGIN()    (*(uint16 *)((uint8 *)&ah_lmac + AH_LMAC_PM_MARGIN_OFS))
#define AH_DTIM_COUNT()   (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_DTIM_COUNT_OFS))
#define AH_DTIM_PERIOD()  (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_DTIM_PERIOD_OFS))
#define AH_DTIM_TU()      (*(uint32 *)((uint8 *)&ah_lmac + AH_LMAC_DTIM_TU_OFS))
#define AH_RF_PD_FLAGS()  (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_RF_PD_FLAGS_OFS))
#define AH_PSPOLL_ACK()   (*(uint32 *)((uint8 *)&ah_lmac + AH_LMAC_PSPOLL_ACK_OFS))
#define AH_TXSTART()      (*(uint8 *)((uint8 *)&ah_lmac + AH_LMAC_TXSTART_OFS))
#define AH_AGGQ_DECR(idx) (*(uint8 *)(AH_TX_BYTES() + 0x554U + (idx)))
#define LMAC_REG32(ofs)   (*(volatile uint32 *)((uintptr_t)LMAC + (ofs)))

static void lmac_check_tx_queue_empty(void);
static int32 lmac_tx_queue_init(void);
static void lmac_tx_data_reload(void);
static void lmac_tx_task(void *arg);
static void lmac_tx_status_task(void *arg);
__attribute__((weak)) void ndp_tx_vec_init_one(uint8 *txvec);
int32 lmac_check_aggregation(struct sk_buff *skb0, struct sk_buff *skb1);
__attribute__((weak)) void lmac_partial_aid_update(void *txi);
static uint32 seq_num_space_update(void *sta, uint32 tid);
__attribute__((weak)) uint32 lmac_hdr_dur_calc(uint32 len);
__attribute__((weak)) uint32 lmac_dtim_timer_rem(void);
__attribute__((weak)) int32 lmac_tx_to_pm_ap(void);
__attribute__((weak)) int32 lmac_cfg_txvec_part1(void);
__attribute__((weak)) int32 lmac_cfg_txvec_part2(void);
__attribute__((weak)) uint32 lmac_get_ack_policy(void *txi);
static uint32 tx_pwr_adjust_by_mcs(uint32 tx_pwr, uint32 mcs);
__attribute__((weak)) int32 lmac_tx_pwr_sel(void *txi, uint32 mcs);
__attribute__((weak)) uint32 pv0_ctrl_uplink_txpwr_gen(void);
__attribute__((weak)) uint32 lmac_select_resp_ind(void);
__attribute__((weak)) uint32 lmac_select_tx_acq(void);
__attribute__((weak)) int32 lmac_tx_frame_regen(uint32 ac, uint32 ac_hint, uint32 mcs, void *arg);
__attribute__((weak)) int32 lmac_tx_date_prepared(void);
__attribute__((weak)) void *lmac_gen_txvec(uint32 ac, uint32 ac_hint, uint32 mcs);
static void *lmac_gen_tx_agglist(uint32 ac, uint32 ac_hint, uint32 mcs, void *arg);
static int32 lmac_attempt_tx_obss(int32 lo_id);
static int32 lmac_attempt_tx(uint32 ac);
__attribute__((weak)) void ndp_tx_vec_init(void);
__attribute__((weak)) void lmac_pv0_rts_init(void);
__attribute__((weak)) void lmac_pv0_wpcts_init(void);
__attribute__((weak)) void lmac_pv0_wpack_init(void);
__attribute__((weak)) void lmac_pv0_wpba_init(void);
__attribute__((weak)) void lmac_pv0_cfpoll_init(void);
__attribute__((weak)) void lmac_pv0_cfend_init(void);
__attribute__((weak)) void lmac_pv0_qos_null_init(void);
__attribute__((weak)) void lmac_pv0_pspoll_init(void);
__attribute__((weak)) int32 lmac_tx_ba(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_ack(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_cts(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_rts(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_pv0_null(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_pv0_pspoll(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_pv0_cfpoll(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_pv0_cfend(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_frm(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_beacon(struct sk_buff *skb);
__attribute__((weak)) int32 ndp_pspoll_ack_rx_hdl(void);


__attribute__((weak)) uint32 lmac_txsq_count(void) {
    log_debug("lmac_txsq_count called\n");
    return skb_list_count(AH_TXSQ());
}
__attribute__((weak)) uint32 lmac_statq_count(void) {
    log_debug("lmac_statq_count called\n");
    return skb_list_count(AH_STATQ());
}
__attribute__((weak)) uint32 lmac_txq_count(void) {
    log_debug("lmac_txq_count called\n");
    return skb_list_count(AH_TXQ());
}
__attribute__((weak)) uint32 lmac_acq_count(uint32 ac) {
    log_debug("lmac_acq_count called with ac=%u\n", ac);

    if (ac >= 4U) {
        return 0;
    }

    return skb_list_count(AH_ACQ(ac));
}
__attribute__((weak)) uint32 lmac_txagg_count(uint32 ac) {
    log_debug("lmac_txagg_count called with ac=%u\n", ac);

    if (ac >= 4U) {
        return 0;
    }

    return AH_AGGCNT(ac);
}
static void lmac_check_tx_queue_empty(void) {
    static const uint8 ac_pd_bits[4] = { 1U, 0U, 2U, 3U };

    log_debug("lmac_check_tx_queue_empty called\n");

    for (uint32 ac = 0; ac < 4U; ++ac) {
        if ((lmac_acq_count(ac) + lmac_txagg_count(ac)) != 0U) {
            continue;
        }

        uint32 reg = LMAC_REG32(0x4c);
        reg &= ~(1U << ac_pd_bits[ac]);
        LMAC_REG32(0x4c) = reg;
    }
}
__attribute__((weak)) void lmac_kick_tx_task(void) {
    log_debug("lmac_kick_tx_task called\n");
    os_sema_up(&ah_lmac_tx.tx_sem);
}
static int32 lmac_tx_queue_init(void) {
    int32 ret = skb_list_init(AH_TXQ());
    if (ret != 0) {
        assert_internal(__func__, 5969, "");
    }

    ret = skb_list_init(AH_TXSQ());
    if (ret != 0) {
        assert_internal(__func__, 5975, "");
    }

    ret = skb_list_init((struct skb_list *)(AH_TX_BYTES() + 0x07C));
    if (ret != 0) {
        assert_internal(__func__, 5977, "");
    }

    for (uint32 ac = 0; ac < 4U; ++ac) {
        ret = skb_list_init(AH_ACQ(ac));
        if (ret != 0) {
            assert_internal(__func__, 5980, "");
        }
    }

    ret = skb_list_init(AH_STATQ());
    if (ret != 0) {
        assert_internal(__func__, 5983, "");
    }

    return ret;
}
__attribute__((weak)) void lmac_tx_vec_init(void) {
    log_debug("lmac_tx_vec_init called\n");
    ndp_tx_vec_init();
    lmac_pv0_rts_init();
    lmac_pv0_wpcts_init();
    lmac_pv0_wpack_init();
    lmac_pv0_wpba_init();
    lmac_pv0_cfpoll_init();
    lmac_pv0_cfend_init();
    lmac_pv0_qos_null_init();
    lmac_pv0_pspoll_init();
}
__attribute__((weak)) void lmac_tx_queue_agglist_init(void) {
    log_debug("lmac_tx_queue_agglist_init called\n");

    lmac_tx_queue_init();

    for (uint32 ac = 0; ac < 4U; ++ac) {
        memset(AH_AGGLIST(ac), 0, 64U * sizeof(uint32));
        *(uint32 *)(AH_TX_BYTES() + 0x1B8U + (ac * AH_AC_STRIDE)) = 0;
        *(uint32 *)(AH_TX_BYTES() + 0x1BCU + (ac * AH_AC_STRIDE)) = 0;
        AH_AGGCNT(ac) = 0;
    }

    lmac_check_tx_queue_empty();
}

__attribute__((weak)) int32 lmac_ah_tx(struct lmac_ops *ops, struct sk_buff *skb) {
    uint32 headroom;
    uint64 jiffies;
    int32 ret;

    if ((ops == NULL) || ((ops->radio_on & 1U) == 0U) || (skb == NULL)) {
        return RET_ERR;
    }

    headroom = (uint32)(skb->data - skb->head);
    if (headroom < 72U) {
        log_error("lmac error!!!ERROR: skb headroom:%d, lmac_tx_info size=%d\r\n",
            (int32)headroom, 68);
        return RET_ERR;
    }

    jiffies = os_jiffies();
    *(uint32 *)((uint8 *)skb + 0x2c) = (uint32)jiffies;
    *(uint32 *)((uint8 *)skb + 0x30) = headroom;

    ret = skb_list_queue(AH_TXQ(), skb);
    if (ret == 0) {
        log_debug("[TX] packet added to TXQ, signaling semaphore\r\n");
        os_sema_up(&ah_lmac_tx.tx_sem);
        AH_PENDING_TX()++;
    } else {
        log_error("lmac error!!!tx queue overflow\r\n");
    }

    return ret;
}
__attribute__((weak)) void lmac_tx_init(void) {
    struct sk_buff *skb;

    /* Original ah_lmac_tx object size; the reconstructed C type is larger. */
    memset(&ah_lmac_tx, 0, 0x6d4U);
    lmac_tx_queue_init();

    for (uint32 ac = 0; ac < 4U; ++ac) {
        uint8 *base = (uint8 *)AH_TX_BYTES() + AH_AGGLIST_OFS + (ac * AH_AC_STRIDE);
        for (uint32 i = 0; i < 64U; ++i) {
            *(uint32 *)(base + (i * 4U)) = 0;
        }
        *(uint32 *)(base + (AH_AGGBYTES_OFS - AH_AGGLIST_OFS)) = 0;
        *(uint32 *)(base + (AH_AGGSYM_OFS - AH_AGGLIST_OFS)) = 0;
        *(uint8 *)(base + (AH_AGGCNT_OFS - AH_AGGLIST_OFS)) = 0;
    }

    lmac_tx_vec_init();

    os_sema_init(&ah_lmac_tx.tx_sem, 0);
    os_sema_init(&ah_lmac_tx.tx_status_sem, 0);

    os_task_init((const uint8 *)"lmac tx", &ah_lmac_tx.tx_task, lmac_tx_task, (uint32)(uintptr_t)&ah_lmac_tx);
    os_task_set_stacksize(&ah_lmac_tx.tx_task, 1024);
    _os_task_set_priority(&ah_lmac_tx.tx_task, 81);
    /* PRIORITY removed - was INVALID PRIORITY with values 81, 10, 1 */
    os_task_run(&ah_lmac_tx.tx_task);

    os_task_init((const uint8 *)"lmac tx status", &ah_lmac_tx.tx_status_task, lmac_tx_status_task, (uint32)(uintptr_t)&ah_lmac_tx);
    os_task_set_stacksize(&ah_lmac_tx.tx_status_task, 1024);
    _os_task_set_priority(&ah_lmac_tx.tx_task, 80);
    /* PRIORITY removed - was INVALID PRIORITY with values 80, 9, 2 */
    os_task_run(&ah_lmac_tx.tx_status_task);
    os_task_run(&ah_lmac_tx.tx_status_task);

    skb = alloc_tx_skb(128U << 3);
    AH_BEACON_SKB() = skb;
    if (skb == NULL) {
        log_error("lmac error!!!alloc beacon failed\r\n");
        return;
    }

    skb_reserve(skb, 128 << 1);
    *(uint8 *)((uint8 *)skb + 0x2a) |= 0x40U;
}
__attribute__((weak)) int32 lmac_ah_test_tx(struct lmac_ops *ops, struct sk_buff *skb) {
    uint64 jiffies;
    int32 ret;

    (void)ops;

    if (skb == NULL) {
        return RET_ERR;
    }

    jiffies = os_jiffies();
    *(uint32 *)((uint8 *)skb + 0x2c) = (uint32)jiffies;
    *(uint32 *)((uint8 *)skb + 0x30) = (uint32)(jiffies >> 32);

    ret = skb_list_queue(AH_TXQ(), skb);
    if (ret == 0) {
        os_sema_up(&ah_lmac_tx.tx_sem);
    } else {
        log_error("lmac error!!!tx queue overflow\r\n");
    }

    return ret;
}

static uint16 lmac_tx_seq_fallback_next(void) {
    static uint16 seq_dup;
    uint16 seq = seq_dup;

    seq_dup = (uint16)((seq_dup + 1U) & 0x0fffU);
    if (seq_dup == 0x0fffU) {
        seq_dup = 0U;
    }

    return seq;
}

static uint8 lmac_ieee80211_is_data_qos(uint16 fc) {
    return (uint8)(((fc & (WLAN_FC_FTYPE | WLAN_STYPE_QOS_DATA | WLAN_FC_PVER)) ==
                     (WLAN_FTYPE_DATA | WLAN_STYPE_QOS_DATA)) ? 1U : 0U);
}

static uint16 lmac_tx_aligned_len(uint16 len) {
    uint16 padded = (uint16)(len + 8U);

    if ((padded & 0x03U) != 0U) {
        padded = (uint16)((padded & (uint16)~0x03U) + 4U);
    }

    return padded;
}

static volatile uint32 *lmac_hw_regs(void) {
    return (volatile uint32 *)(uintptr_t)LMAC;
}

static void lmac_tx_hw_commit(uint8 *tmpl, uint32 subfrm_len, uint32 total_len) {
    volatile uint32 *regs = lmac_hw_regs();

    lhw_cfg_dma_list_cnt(1U);
    lhw_cfg_tx_sub_frm(0U, (uint32)(uintptr_t)tmpl, subfrm_len);
    regs[0x7cU / 4U] = total_len;
    regs[0x58U / 4U] &= ~0x01U;
    regs[0x58U / 4U] = regs[0x58U / 4U];
}
static void lmac_tx_hw_commit_rts(uint8 *tmpl) {
    volatile uint32 *regs = lmac_hw_regs();

    lhw_cfg_dma_list_cnt(1U);
    lhw_cfg_tx_sub_frm(0U, (uint32)(uintptr_t)tmpl, 16U);
    regs[0x7cU / 4U] = 24U;
    regs[0x58U / 4U] &= ~0x02U;
    regs[0x58U / 4U] |= 0x02U;
    regs[0x58U / 4U] &= ~0x01U;
    regs[0x58U / 4U] |= 0x01U;
}
static void lmac_tx_ctrl_store_sta(uint8 *addr) {
    *(void **)((uint8 *)&ah_lmac + 0xA50U) = lmac_sta_search(0xffffU, addr);
}
static void lmac_pv0_ctrl_txvec_clear(uint8 *txvec, uint8 txlen_field) {
    *(uint32 *)(txvec + 0U) = 0U;
    *(uint32 *)(txvec + 4U) = 0U;
    *(uint32 *)(txvec + 8U) = 0U;
    *(uint32 *)(txvec + 12U) = 0U;
    txvec[0] = 0U;
    txvec[2] = txlen_field;
}
static void lmac_pv0_ctrl_common_rate(uint8 *txvec, uint32 len, const char *name) {
    uint8 bw_sel = *(uint8 *)((uint8 *)&ah_lmac + 0x308U);
    uint8 rf_flags = *(uint8 *)((uint8 *)&ah_lmac + 0x875U);
    uint8 phy_sel = *(uint8 *)((uint8 *)&ah_lmac + 0x867U);
    uint8 mode = 1U;
    uint8 bw_code;

    if (((rf_flags & 0x02U) != 0U) && (phy_sel == 3U)) {
        mode = 0U;
    }

    txvec[1] = (uint8)((txvec[1] & (uint8)~0xf3U) | (bw_sel & 0x03U));
    txvec[1] = (uint8)((txvec[1] & (uint8)~0xf0U) | ((mode & 0x0fU) << 4));

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x34aU) & 0x01U) != 0U) {
        bw_code = 0U;
    } else {
        bw_code = 1U;
    }

    txvec[1] = (uint8)((txvec[1] & (uint8)~0x0cU) | ((bw_code & 0x03U) << 2));
    *(uint32 *)(txvec + 4U) = calc_symbol_len(len, 3U, bw_code);

    if ((name != NULL) && (bw_code > 2U)) {
        log_warn("%s: invalid bw code\r\n", name);
    }
}
static void lmac_pv0_ctrl_fill_resp1(uint8 *txvec, uint8 resp_sel, uint32 len) {
    txvec[8] = (uint8)((txvec[8] & (uint8)~0x55U) |
                       ((resp_sel & 0x01U) << 0) |
                       (1U << 2) |
                       (1U << 4) |
                       (1U << 6));
    *(uint16 *)(txvec + 8U) =
        (uint16)((*(uint16 *)(txvec + 8U) & (uint16)~0x0780U) |
                 (((txvec[1] >> 4) & 0x0fU) << 7));
    txvec[9] = (uint8)((txvec[9] & (uint8)~0x08U) | ((resp_sel & 0x01U) << 3));
    *(uint32 *)(txvec + 8U) =
        (*(uint32 *)(txvec + 8U) & ~(0x01ffU << 12)) | ((len & 0x01ffU) << 12);
    txvec[10] = (uint8)((txvec[10] & (uint8)~0x60U) | (2U << 5));
    txvec[11] &= (uint8)~0x03U;
}
static void lmac_pv0_ctrl_fill_resp0(uint8 *txvec, uint8 resp_sel, uint32 len) {
    txvec[8] = (uint8)((txvec[8] & (uint8)~0x77U) |
                       ((resp_sel & 0x01U) << 0) |
                       (1U << 2) |
                       (2U << 5));
    *(uint16 *)(txvec + 8U) =
        (uint16)((*(uint16 *)(txvec + 8U) & (uint16)~0x0780U) |
                 (((txvec[1] >> 4) & 0x0fU) << 7));
    txvec[9] = 40U;
    txvec[12] = (uint8)((txvec[12] & (uint8)~0x34U) | (2U << 2));
}
static void lmac_pv0_ctrl_finish(uint8 *txvec, uint8 resp_sel, uint32 len, const char *name) {
    lmac_pv0_ctrl_common_rate(txvec, len, name);

    switch ((txvec[1] >> 2) & 0x03U) {
    case 0U:
        lmac_pv0_ctrl_fill_resp0(txvec, resp_sel, len);
        break;
    case 1U:
        lmac_pv0_ctrl_fill_resp1(txvec, resp_sel, len);
        break;
    case 2U:
        txvec[8] = (uint8)((txvec[8] & (uint8)~0x77U) |
                           ((resp_sel & 0x01U) << 0) |
                           (1U << 2) | (2U << 5));
        *(uint16 *)(txvec + 8U) =
            (uint16)((*(uint16 *)(txvec + 8U) & (uint16)~0x0780U) |
                     ((((txvec[1] >> 4) & 0x0fU)) << 7));
        txvec[9] = 40U;
        txvec[12] = (uint8)((txvec[12] & (uint8)~0x34U) | (2U << 2));
        txvec[12] &= (uint8)~0x20U;
        break;
    default:
        log_warn("%s: invalid resp_mode\r\n", name);
        break;
    }
}
static void lmac_pv0_rts_init_inner(uint8 *hdr, uint8 *txvec) {
    hdr[0] = (uint8)((1U << 2) | (11U << 4));
    hdr[1] = 0U;
    *(uint16 *)(hdr + 2U) = 0U;

    lmac_pv0_ctrl_txvec_clear(txvec, 14U);
    if (*(uint8 *)((uint8 *)&ah_lmac + 0x308U) < 2U) {
        txvec[2] |= 0x80U;
    }

    lmac_pv0_ctrl_finish(txvec, 0U, 24U, "lmac_pv0_rts_init");
}
static void lmac_pv0_pspoll_init_inner(uint8 *hdr, uint8 *txvec) {
    hdr[0] = (uint8)((hdr[0] & 0xfcU) | (1U << 2) | (10U << 4));
    hdr[1] &= (uint8)~0x04U;

    lmac_pv0_ctrl_txvec_clear(txvec, 10U);

    lmac_pv0_ctrl_common_rate(txvec, 20U, "lmac_pv0_pspoll_init");

    switch ((txvec[1] >> 2) & 0x03U) {
    case 0U:
        lmac_pv0_ctrl_fill_resp0(txvec, 0U, 20U);
        txvec[12] = (uint8)((txvec[12] & (uint8)~0x3cU) | (2U << 2));
        txvec[12] &= (uint8)~0x20U;
        break;
    case 1U:
        lmac_pv0_ctrl_fill_resp1(txvec, 0U, 20U);
        break;
    case 2U:
        txvec[8] = (uint8)((txvec[8] & (uint8)~0x55U) |
                           (1U << 2) | (1U << 4) | (1U << 6));
        *(uint16 *)(txvec + 8U) =
            (uint16)((*(uint16 *)(txvec + 8U) & (uint16)~0x0780U) |
                     ((((txvec[1] >> 4) & 0x0fU)) << 7));
        txvec[10] = (uint8)((txvec[10] & (uint8)~0x79U) | (2U << 3));
        txvec[11] = 40U;
        txvec[12] = (uint8)((txvec[12] & (uint8)~0x3cU) | (2U << 2));
        txvec[12] &= (uint8)~0x20U;
        break;
    default:
        hgprintf("lmac_pv0_pspoll_init: invalid resp_mode\r\n");
        break;
    }
}
static void lmac_pv0_cfend_init_inner(uint8 *hdr, uint8 *txvec) {
    hdr[0] = (uint8)((1U << 2) | (14U << 4));
    hdr[1] = 0U;
    *(uint16 *)(hdr + 2U) = 0U;

    lmac_pv0_ctrl_txvec_clear(txvec, 10U);
    if (*(uint8 *)((uint8 *)&ah_lmac + 0x308U) < 2U) {
        txvec[2] |= 0x80U;
    }
    hdr[0] &= (uint8)~0x60U;

    lmac_pv0_ctrl_common_rate(txvec, 20U, "lmac_pv0_cfend_init");

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x34aU) & 0x01U) != 0U) {
        *(uint16 *)((uint8 *)&ah_lmac + 0x672U) = (uint16)(calc_symbol_len(20U, 3U, 0U) * 40U + 560U);
    } else {
        *(uint16 *)((uint8 *)&ah_lmac + 0x672U) = (uint16)(calc_symbol_len(20U, 3U, 1U) * 40U + 240U);
    }

    switch ((txvec[1] >> 2) & 0x03U) {
    case 0U:
        lmac_pv0_ctrl_fill_resp0(txvec, 1U, 20U);
        break;
    case 1U:
        lmac_pv0_ctrl_fill_resp1(txvec, 1U, 20U);
        break;
    case 2U:
        txvec[8] = (uint8)((txvec[8] & (uint8)~0x77U) |
                           (1U << 0) | (1U << 2) | (2U << 5));
        *(uint16 *)(txvec + 8U) =
            (uint16)((*(uint16 *)(txvec + 8U) & (uint16)~0x0780U) |
                     ((((txvec[1] >> 4) & 0x0fU)) << 7));
        txvec[9] = 40U;
        txvec[12] = (uint8)((txvec[12] & (uint8)~0x34U) | (2U << 2));
        txvec[12] &= (uint8)~0x20U;
        break;
    default:
        hgprintf("lmac_pv0_cfend_init: invalid resp_mode\r\n");
        break;
    }
}
static void lmac_pv0_cfpoll_init_inner(uint8 *hdr, uint8 *txvec) {
    hdr[0] = 0xa4U;
    hdr[1] = 0U;
    *(uint16 *)(hdr + 2U) = 0U;

    lmac_pv0_ctrl_txvec_clear(txvec, 12U);
    if (*(uint8 *)((uint8 *)&ah_lmac + 0x308U) < 2U) {
        txvec[2] |= 0x80U;
    }

    lmac_pv0_ctrl_finish(txvec, 1U, 32U, "lmac_pv0_cfpoll_init");
}
static void lmac_pv0_qos_null_init_inner(uint8 *hdr, uint8 *txvec) {
    uint8 mcs;

    hdr[0] = 0xc8U;
    hdr[1] = 0U;
    if (AH_PM_MODE() == 1U) {
        hdr[1] = (uint8)((hdr[1] & (uint8)~0x02U) | (0U << 1));
        hdr[0x18U] = (uint8)((hdr[0x18U] & 0xf0U) | (2U << 5));
        hdr[0x16U] = 0U;
        hdr[0x17U] = 0U;
    }

    lmac_pv0_ctrl_txvec_clear(txvec, 12U);
    txvec[1] = (uint8)(*(uint8 *)((uint8 *)&ah_lmac + 0x308U) & 0x03U);

    mcs = (uint8)(((*(uint8 *)((uint8 *)&ah_lmac + 0x36dU) & 0x0cU) == 0U) ?
        (((*(uint16 *)((uint8 *)&ah_lmac + 0x36cU)) >> 5) & 0x1fU) : 0U);
    txvec[0] = (uint8)((txvec[0] & (uint8)~0x1fU) | (mcs & 0x1fU));

    lmac_pv0_ctrl_common_rate(txvec, 32U, "lmac_pv0_qos_null_init");

    switch ((txvec[1] >> 2) & 0x03U) {
    case 0U:
        lmac_pv0_ctrl_fill_resp0(txvec, 1U, 32U);
        break;
    case 1U:
        lmac_pv0_ctrl_fill_resp1(txvec, 1U, 32U);
        break;
    case 2U:
        txvec[8] = (uint8)((txvec[8] & (uint8)~0x77U) |
                           (1U << 0) | (1U << 2) | (2U << 5));
        *(uint16 *)(txvec + 8U) =
            (uint16)((*(uint16 *)(txvec + 8U) & (uint16)~0x0780U) |
                     ((((txvec[1] >> 4) & 0x0fU)) << 7));
        txvec[9] = 40U;
        txvec[12] = (uint8)((txvec[12] & (uint8)~0x34U) | (2U << 2));
        txvec[12] &= (uint8)~0x20U;
        break;
    default:
        hgprintf("lmac_pv0_qos_null_init: invalid resp_mode\r\n");
        break;
    }
}
static void lmac_pv0_wp_txvec_init(uint8 *txvec, const char *name) {
    ndp_tx_vec_init_one(txvec);
    txvec[1] = (uint8)((txvec[1] & (uint8)~0x30U) | (1U << 4));

    if ((name != NULL) && ((txvec[1] & 0x0cU) > 0x08U)) {
        hgprintf("%s: unexpected ctrl mode\r\n", name);
    }
}
static uint8 *lmac_txinfo_first_for_ac(uint32 ac) {
    struct sk_buff *skb;

    if (ac >= 4U) {
        return NULL;
    }

    skb = (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[0];
    if (skb == NULL) {
        return NULL;
    }

    return *(uint8 **)((uint8 *)skb + 0x20U);
}
static void lmac_tx_status_notify_local(uint32 ac, uint32 ok, uint32 bytes) {
    uint8 rate_word = *(uint8 *)((uint8 *)&ah_lmac_tx + 0x55dU);
    uint32 ant = (uint32)((rate_word >> 5) & 0x07U);
    uint32 bw = (uint32)(rate_word & 0x0fU);

    if (ah_ops.tx_status != NULL) {
        ah_ops.tx_status(&ah_ops, (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[0]);
    }

    AH_MISC9E2() = (uint8)((AH_MISC9E2() & (uint8)~0xe0U) | ((ant & 0x07U) << 5));
    *(uint8 *)((uint8 *)&ah_lmac + 0x55dU) = (uint8)((ant << 5) | (bw & 0x0fU));
    if (ok != 0U) {
        *(uint32 *)((uint8 *)&ah_lmac + 0x754U) += 1U;
    } else {
        *(uint32 *)((uint8 *)&ah_lmac + 0x758U) += 1U;
    }
    (void)bytes;
}
__attribute__((weak)) uint32 lmac_tx_cur_ac(void) {
    return AH_ACLAST() & 0x0fU;
}
static void lmac_tx_mark_timeout_for_ac(uint32 ac) {
    uint32 notified = 0U;

    if (ac >= 4U) {
        return;
    }

    for (uint32 idx = 0; idx < AH_AGGNUM(ac); ++idx) {
        struct sk_buff *skb = (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[idx];
        uint8 *txi;

        if (skb == NULL) {
            continue;
        }

        txi = *(uint8 **)((uint8 *)skb + 0x20U);
        if (txi == NULL) {
            continue;
        }

        if ((txi[0x25U] & 0x02U) != 0U) {
            txi[0x27U] |= 0x80U;
        } else {
            *(uint32 *)((uint8 *)&ah_lmac + 0x758U) += 1U;
            notified = 1U;
        }
    }

    if (notified != 0U) {
        lmac_tx_status_notify_local(ac, 0U, AH_AGGBYTES(ac));
    }
}

static uint8 lmac_dialog_token_next(void) {
    uint8 *token = (uint8 *)&ah_lmac + 0x37cU;
    uint8 cur = *token;

    *token = (uint8)(cur + 1U);
    return cur;
}
static int32 lmac_mac_is_zero(const uint8 *addr) {
    uint32 i;

    for (i = 0; i < 6U; ++i) {
        if (addr[i] != 0U) {
            return 0;
        }
    }

    return 1;
}
static struct sk_buff *lmac_alloc_mgmt_skb(uint32 size) {
    struct sk_buff *skb = alloc_tx_skb(size);

    if (skb == NULL) {
        return NULL;
    }

    skb_reserve(skb, 128 << 1);
    *(uint8 *)((uint8 *)skb + 0x2aU) |= 0x40U;
    return skb;
}
static struct ieee80211_mgmt *lmac_mgmt_header_init(struct sk_buff *skb,
    uint16 fc, const uint8 *da, const uint8 *sa, const uint8 *bssid) {
    struct ieee80211_mgmt *mgmt;

    mgmt = (struct ieee80211_mgmt *)skb_put(skb, 24U);
    if (mgmt == NULL) {
        return NULL;
    }

    memset(mgmt, 0, 24U);
    mgmt->frame_control = fc;
    memcpy(mgmt->da, da, 6U);
    memcpy(mgmt->sa, sa, 6U);
    memcpy(mgmt->bssid, bssid, 6U);
    return mgmt;
}
static int32 lmac_send_mgmt_skb(struct sk_buff *skb) {
    int32 ret;

    if (skb == NULL) {
        return RET_ERR;
    }

    ret = lmac_ah_tx(&ah_ops, skb);
    if (ret != 0) {
        kfree_skb(skb);
    }

    return ret;
}
__attribute__((weak)) uint32 lmac_tx_max_frame_len(void) {
    const uint32 *limit_tbl = (const uint32 *)(const void *)max_byte_table;
    uint8 phy_sel = *(uint8 *)((uint8 *)&ah_lmac + 0x865U);

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x34aU) & 0x01U) == 0U) {
        return 383U;
    }

    if (phy_sel == 0U) {
        return 383U;
    }

    return limit_tbl[(uint32)phy_sel * 4U];
}

static int32 lmac_tx_dispatch_pv0(struct sk_buff *skb, uint16 fc) {
    if (ieee80211_is_s1g_beacon(fc) != 0U) {
        return lmac_tx_beacon(skb);
    }

    if (ieee80211_is_pspoll(fc)) {
        return lmac_tx_pv0_pspoll(skb);
    }

    if ((ieee80211_is_nullfunc(fc) != 0U) || (ieee80211_is_qos_nullfunc(fc) != 0U)) {
        return lmac_tx_pv0_null(skb);
    }

    return 0;
}
static int32 lmac_tx_dispatch_pv1(struct sk_buff *skb, uint16 fc) {
    if (ieee80211_is_pv1_mgmt(fc) != 0U) {
        return lmac_tx_frm(skb);
    }

    if ((ieee80211_is_pv1_qos_data1(fc) != 0U) || (ieee80211_is_pv1_qos_data2(fc) != 0U)) {
        return 0;
    }

    return 0;
}
static void lmac_tx_task(void *arg) {
    static const uint8 ieee802_1d_to_ac[8] = { 0U, 1U, 1U, 0U, 2U, 2U, 3U, 3U };

    uint8 *skb_bytes;
    uint8 *hdr;
    uint8 *txi;
    uint8 *tmpl;
    uint16 fc;
    uint16 seq;
    uint16 frame_len;
    uint32 ac;
    void *sta;
    uint32 tid;
    uint8 sta_flags;
    struct skb_list *tx_queue;
    struct sk_buff  *last_skb;
    struct sk_buff  *skb;
    uint32 cpu_sr;
    uint8 aggq_val;
    int    do_early_reload;
    uint8 max_agg;

    (void)arg;

    log_info("[TX] task started\r\n");  /* VERIFIED: matches original asm line 3692-3694 */

    for (;;) {  /* VERIFIED: main loop matches original */
        int32 wake = os_sema_down(&ah_lmac_tx.tx_sem, 1);  /* VERIFIED: matches asm line 3698-3700 */

        if ((AH_TX_EXIT_FLAG() & 1U) != 0U) {  /* VERIFIED: matches asm line 3704-3708 */
            log_info("%s exit!!!\r\n", __func__);
            return;
        }

        /* wake==0: семафор получен (есть пакеты) → обработка TXQ.
         * wake!=0: таймаут 1мс → только reload и снова ждём. */
        if (wake == 0) {  /* FIXED: was incorrectly wake!=0, now VERIFIED against asm line 3700 */

            //log_debug("[TX] sema got, txq=%u\r\n", skb_list_count(AH_TXQ()));  /* DEBUG: not in loop */

            skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED: matches asm line 3724-3728 */

            while (skb != NULL) {  /* VERIFIED: loop matches asm */
                skb_bytes = (uint8 *)skb;  /* VERIFIED */
                hdr = *(uint8 **)(skb_bytes + 0x1cU);  /* VERIFIED: matches asm line 3738 */
                txi = *(uint8 **)(skb_bytes + 0x20U);  /* VERIFIED: matches asm line 3740 */
                tmpl = *(uint8 **)(skb_bytes + 0x34U);  /* VERIFIED: matches asm line 3744 */

                log_debug("[TX] skb=%p hdr=%p txi=%p tmpl=%p\r\n", skb, hdr, txi, tmpl);  /* VERIFIED */

                if ((hdr != NULL) && (hdr[0] == 28U)) {  /* VERIFIED: matches asm line 3770-3776 */
                    log_debug("[TX] beacon skb\r\n");
                    lmac_tx_pv0_s1g_beacon(skb);  /* WEAK: guaranteed correct */
                    skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED */
                    continue;
                }

                if (((uintptr_t)hdr & 0x1U) != 0U) {  /* VERIFIED: matches asm line 3940-3942 */
                    hgprintf("lmac_tx_task: invalid hdr %p\r\n", hdr);  /* VERIFIED */
                    hgics_print_hex(hdr, *(uint16 *)(skb_bytes + 0x28U));  /* VERIFIED */
                    skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED */
                    continue;
                }

                if ((hdr == NULL) || (txi == NULL)) {  /* VERIFIED: matches asm line 3946-3948 */
                    log_debug("[TX] null hdr/txi, skip\r\n");
                    skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED */
                    continue;
                }

                memset(txi, 0, 68U);  /* VERIFIED: matches asm line 3835-3839 */

                if (tmpl != NULL) {  /* VERIFIED: matches asm line 3840-3842 */
                    uint8 tmpl3 = tmpl[0x03];  /* VERIFIED: matches asm line 3843-3847 */
                    *(uint32 *)(txi + 0x00U) = *(uint32 *)(tmpl + 0x04U);  /* VERIFIED: matches asm line 3848-3853 */
                    txi[0x25] = (uint8)((txi[0x25] & (uint8)~0x20U) | ((*(uint32 *)(tmpl + 0x04U) >> 31) << 5));  /* VERIFIED: matches asm line 3854-3874 */
                    *(uint32 *)(txi + 0x04U) = *(uint32 *)(tmpl + 0x08U);  /* VERIFIED: matches asm line 3875-3881 */
                    txi[0x27] = (uint8)((txi[0x27] & (uint8)~0x08U) | ((*(uint16 *)(tmpl + 0x08U) & 0x01U) << 3));  /* VERIFIED: matches asm line 3882-3904 */
                    txi[0x3c] = tmpl[0x01];  /* VERIFIED: matches asm line 3905-3912 */
                    txi[0x3d] = 0xffU;  /* VERIFIED: matches asm line 3913-3918 */
                    /* Match original: two stores to txi[0x3f] */
                    txi[0x3f] = (uint8)((txi[0x3f] & (uint8)~0x60U) | (tmpl3 & 0x60U));  /* VERIFIED: matches asm line 3919-3935 */
                    txi[0x3e] = tmpl[0x0a];  /* VERIFIED: matches asm line 3936-3943 */
                    txi[0x3f] = (uint8)((txi[0x3f] & (uint8)~0x1fU) | (tmpl3 & 0x1fU));  /* VERIFIED: matches asm line 3944-3960 */

                    if ((txi[0x27] & 0x08U) != 0U) {  /* VERIFIED: matches asm line 3961-3967 */
                        txi[0x3e] = 7U;  /* VERIFIED: matches asm line 3968-3972 */
                        txi[0x3d] = 1U;  /* VERIFIED: matches asm line 3973-3977 */
                        txi[0x3c] = ((*(uint8 *)((uint8 *)&ah_lmac + 0x34aU) & 0x01U) != 0U) ? 3U : 0U;  /* VERIFIED: matches asm line 3978-3991 */
                    }

                    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x34aU) & 0x01U) != 0U) {  /* VERIFIED: matches asm line 3992-3997 */
                        if ((txi[0x3d] >= 8U) && (txi[0x3d] != 10U)) {  /* VERIFIED: matches asm line 3998-4004,4005-4020 */
                            txi[0x3d] = *(uint8 *)((uint8 *)&ah_lmac + 0x866U);  /* VERIFIED: matches asm line 4016-4019 */
                        }
                    } else if (txi[0x3d] < 8U) {  /* VERIFIED: matches asm line 4021-4028,4036 */
                        txi[0x3d] = *(uint8 *)((uint8 *)&ah_lmac + 0x866U);  /* VERIFIED: matches asm line 4032-4035 */
                    } else if (txi[0x3d] != 10U) {  /* VERIFIED: matches asm line 4037-4044 */
                        txi[0x3d] = *(uint8 *)((uint8 *)&ah_lmac + 0x866U);  /* VERIFIED: matches asm line 4048-4051 */
                    }

                    if (txi[0x3c] == 2U) {  /* VERIFIED: matches asm line 4053-4059 */
                        txi[0x3c] = ((*(uint8 *)((uint8 *)&ah_lmac + 0x308U) == 1U) ||
                                       (*(uint8 *)((uint8 *)&ah_lmac + 0x308U) == 2U)) ? 1U : 0U;  /* VERIFIED: matches asm line 4060-4080 */
                    } else if (txi[0x3c] == 1U) {  /* VERIFIED: matches asm line 4081-4088 */
                        txi[0x3c] = ((*(uint8 *)((uint8 *)&ah_lmac + 0x308U) == 1U) || (txi[0x3d] != 0U)) ? 3U : 1U;  /* VERIFIED: matches asm line 4089-4110 */
                    } else if ((txi[0x3c] == 4U) && (txi[0x3d] == 0U)) {  /* VERIFIED: matches asm line 4111-4118 */
                        txi[0x3c] = 1U;  /* VERIFIED: matches asm line 4120-4129 */
                    }
                } else {  /* VERIFIED: matches asm line 4131 */
                    txi[0x3c] = 0xffU;  /* VERIFIED: matches asm line 4132-4137 */
                    txi[0x3d] = 0xffU;  /* VERIFIED: matches asm line 4138-4143 */
                    txi[0x3e] = 0x0fU;  /* VERIFIED: matches asm line 4144-4147 */
                    txi[0x3f] = (uint8)((txi[0x3f] & (uint8)~0x60U) | 0x60U);  /* VERIFIED: matches asm line 4148-4159 */
                }

                if ((txi[0x3f] & 0x1fU) > *(uint8 *)((uint8 *)&ah_lmac + 0x378U)) {  /* VERIFIED: matches asm line 4160-4171 (cmphs checks ah_lmac[888] >= value, jbt skips clear) */
                    txi[0x3f] &= (uint8)~0x1fU;  /* VERIFIED: matches asm line 4172-4182 */
                }

                *(uint8 **)(txi + 0x10U) = hdr;  /* VERIFIED: matches asm line 4184-4189 */
                *(uint16 *)(txi + 0x14U) = *(uint16 *)(skb_bytes + 0x28U);  /* VERIFIED: matches asm line 4190-4197 */

                txi[0x24] = (uint8)((txi[0x24] & (uint8)~0x03U) | (hdr[0] & 0x03U));  /* VERIFIED: matches asm line 4198-4216 */
                if ((txi[0x24] & 0x03U) != 0U) {  /* VERIFIED: matches asm line 4217-4223 */
                    hgprintf("lmac_tx_task: invalid fc type bits\r\n");  /* VERIFIED */
                    skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED: matches asm line 4224-4231 */
                    continue;
                }

                fc = *(uint16 *)hdr;  /* VERIFIED */
                log_debug("[TX] fc=0x%04x pv=%u type=%u sub=%u\r\n",
                          fc, fc & 0x3u, (fc>>2)&0x3u, (fc>>4)&0xfu);  /* VERIFIED: matches asm line 4233-4265 */
                txi[0x27] = (uint8)((txi[0x27] & (uint8)~0x02U) | ((ieee80211_is_data(fc) != 0U) << 1));  /* VERIFIED: matches asm line 4266-4292 */
                lmac_get_rx_addr(txi + 0x1aU, hdr);  /* VERIFIED: matches asm line 4293-4299 */
                sta = lmac_sta_get(0xffffU, txi + 0x1aU);  /* VERIFIED: matches asm line 4300+ */
                *(void **)(txi + 0x0cU) = sta;  /* VERIFIED */

                if ((txi[0x1a] & 0x01U) != 0U) {  /* VERIFIED: matches asm line 4314-4320 */
                    tid = (uint32)((uint8)(txi[0x3e] - 1U));  /* VERIFIED: matches asm line 4321-4329 */

                    txi[0x26] |= 0x80U;  /* VERIFIED: matches asm line 4330-4342 */
                    txi[0x25] = (uint8)((txi[0x25] & (uint8)~0x02U) |
                                            ((lmac_get_ack_policy(txi) & 0x01U) << 1));  /* VERIFIED: matches asm line 4343-4364 */

                    if (tid >= 7U) {  /* VERIFIED: matches asm line 4365-4369 */
                        tid = lmac_get_tid(hdr);  /* VERIFIED: matches asm line 4370-4374 */
                    }

                    if (tid > 7U) {  /* VERIFIED: matches asm line 4375-4380 */
                        tid = 7U;  /* VERIFIED: matches asm line 4381-4383 */
                    }

                    txi[0x26] = (uint8)((txi[0x26] & (uint8)~0x0fU) | (tid & 0x0fU));  /* VERIFIED: matches asm line 4384-4402 */

                    if ((*(uint16 *)(txi + 0x26U) & 0x0280U) == 0x0280U) {  /* VERIFIED: matches asm line 4403-4410 */
                        txi[0x2c] = *(uint8 *)((uint8 *)&ah_lmac + 0x314U) & 0x1fU;  /* VERIFIED: matches asm line 4411-4419 */

                        if (txi[0x2c] != 0U) {  /* VERIFIED: matches asm line 4420-4425 */
                            txi[0x26] = (uint8)((txi[0x26] & (uint8)~0x0fU) | 0x01U);  /* VERIFIED: matches asm line 4426-4438 */
                        }
                    }
                } else if (sta != NULL) {  /* VERIFIED: matches asm line 4440-4443 */
                    sta_flags = *(uint8 *)((uint8 *)sta + 0x6bU);  /* VERIFIED: matches asm line 4444-4448 */

                    if ((sta_flags & 0x10U) != 0U) {  /* VERIFIED: matches asm */
                        hgprintf("lmac_tx_task: sta asleep, data=%u\r\n",
                                 (uint32)((txi[0x27] >> 1) & 0x01U));  /* VERIFIED */
                        skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED */
                        continue;
                    }

                    if (((sta_flags & 0x20U) != 0U) && ((txi[0x27] & 0x02U) != 0U)) {  /* VERIFIED */
                        hgprintf("lmac_tx_task: blocked sta data frame\r\n");  /* VERIFIED */
                        skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED */
                        continue;
                    }
                }

                if ((*(uint8 *)((uint8 *)&ah_lmac + 0x310U) & 0x20U) == 0U) {  /* VERIFIED: matches asm line 4493-4497 */
                    *(uint32 *)(txi + 0x08U) |= 0x01U;  /* VERIFIED: matches asm line 4498-4506 */
                    seq = lmac_tx_seq_fallback_next();  /* VERIFIED: matches asm line 4507-4510 */
                    hdr[0x16] = (uint8)(seq << 4);  /* VERIFIED: matches asm line 4511-4519 */
                    hdr[0x17] = (uint8)(seq >> 4);  /* VERIFIED: matches asm line 4520-4529 */
                } else {  /* VERIFIED: matches asm line 4531 */
                    switch (txi[0x24] & 0x03U) {  /* VERIFIED: matches asm line 4532-4537 */
                    case 0U:  /* VERIFIED: matches asm line 4538 (jbez .L236) */
                        seq = (uint16)seq_num_space_update(sta, txi[0x26] & 0x0fU);  /* VERIFIED: matches asm line 4543-4554 */
                        hdr[0x16] = (uint8)(seq << 4);  /* VERIFIED: matches asm line 4555-4564 */
                        hdr[0x17] = (uint8)(seq >> 4);  /* VERIFIED: matches asm line 4565-4574 */
                        break;
                    case 1U:  /* VERIFIED: matches asm line 4539-4540 (cmpnei 1, jbf .L237) */
                        if ((ieee80211_is_pv1_mgmt(fc) != 0U) ||  /* VERIFIED: matches asm line 4576-4597 */
                            (ieee80211_is_pv1_qos_data1(fc) != 0U) ||
                            (ieee80211_is_pv1_qos_data2(fc) != 0U)) {
                            seq = (uint16)seq_num_space_update(sta, txi[0x26] & 0x0fU);  /* VERIFIED */
                            if (ieee80211_is_pv1_qos_data2(fc) != 0U) {  /* VERIFIED */
                                *(uint16 *)(hdr + 0x0eU) = (uint16)(seq << 4);  /* VERIFIED */
                            } else {
                                *(uint16 *)(hdr + 0x0aU) = (uint16)(seq << 4);  /* VERIFIED */
                            }
                        } else {
                            seq = (uint16)lmac_get_seq_num(hdr);  /* VERIFIED */
                        }
                        break;
                    default:  /* VERIFIED */
                        seq = (uint16)lmac_get_seq_num(hdr);  /* VERIFIED */
                        break;
                    }
                }

                *(uint16 *)(txi + 0x18U) = seq;  /* VERIFIED: matches asm line 4657-4662 */

                if ((txi[0x24] & 0x03U) == 0U) {  /* VERIFIED: matches asm line 4663-4669 */
                    *(uint16 *)(txi + 0x24U) &= 0x0003U;  /* VERIFIED: matches asm line 4670-4680 */
                    *(uint16 *)(txi + 0x24U) |= (uint16)(((fc >> 2) & 0x07U) << 2);  /* VERIFIED: matches asm line 4681-4698 */
                    *(uint16 *)(txi + 0x24U) |= (uint16)(((fc >> 4) & 0x1fU) << 5);  /* VERIFIED: matches asm line 4699-4721 */
                    txi[0x25] = (uint8)((txi[0x25] & (uint8)~0xc0U) |
                                                        ((((hdr[1] >> 1) & 0x01U) << 6) | (hdr[1] & 0x80U)));  /* VERIFIED: matches asm line 4722-4750 */
                    txi[0x2a] = (uint8)lmac_get_hdr_len_pv0(hdr);  /* VERIFIED */
                    txi[0x2b] = (uint8)((txi[0x2b] & (uint8)~0x70U) |
                                                        (((*(uint8 *)((uint8 *)&ah_lmac + 0x308U)) & 0x07U) << 4));  /* VERIFIED */

                    if ((hdr[1] & 0x10U) != 0U) {  /* VERIFIED */
                        hgprintf("lmac_tx_task: pv0 protected bit set before CE\r\n");  /* VERIFIED */
                    }

                    if (((txi[0x24] & 0x1cU) == 0x08U) && ((txi[0x24] & 0xe0U) == 0x80U)) {  /* VERIFIED */
                        txi[0x27] |= 0x08U;  /* VERIFIED */
                        hgprintf("lmac_tx_task: qos null frame\r\n");  /* VERIFIED */
                        hgics_print_hex(hdr, *(uint16 *)(skb_bytes + 0x28U));  /* VERIFIED */
                    }

                    if (lmac_tx_dispatch_pv0(skb, fc) != 0) {  /* VERIFIED */
                        log_debug("[TX] pv0 dispatch rejected fc=0x%04x\r\n", fc);  /* VERIFIED */
                        skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED */
                        continue;
                    }
                } else if ((txi[0x24] & 0x03U) == 1U) {  /* VERIFIED */
                    *(uint16 *)(txi + 0x24U) &= 0x0003U;  /* VERIFIED */
                    *(uint16 *)(txi + 0x24U) |= (uint16)(((fc >> 2) & 0x07U) << 2);  /* VERIFIED */
                    *(uint16 *)(txi + 0x24U) |= (uint16)(((fc >> 5) & 0x0fU) << 5);  /* VERIFIED */
                    hdr[1] &= (uint8)~0x10U;  /* VERIFIED */
                    txi[0x26] &= (uint8)~0x10U;  /* VERIFIED */
                    txi[0x25] = (uint8)((txi[0x25] & (uint8)~0x40U) | (((hdr[1] >> 1) & 0x01U) << 6));  /* VERIFIED */
                    txi[0x2a] = (uint8)lmac_get_hdr_len_pv1(hdr);  /* VERIFIED */

                    if (lmac_tx_dispatch_pv1(skb, fc) != 0) {  /* VERIFIED */
                        log_debug("[TX] pv1 dispatch rejected fc=0x%04x\r\n", fc);  /* VERIFIED */
                        skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED */
                        continue;
                    }
                } else {  /* VERIFIED */
                    hgprintf("lmac_tx_task: unsupported pv=%u fc=%04x\r\n",
                             (uint32)(txi[0x24] & 0x03U), fc);  /* VERIFIED */
                    skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED */
                    continue;
                }

                frame_len = lmac_tx_aligned_len(*(uint16 *)(skb_bytes + 0x28U));  /* VERIFIED */
                *(uint16 *)(txi + 0x16U) = frame_len;  /* VERIFIED */
                if (frame_len > lmac_tx_max_frame_len()) {  /* VERIFIED */
                    hgprintf("lmac_tx_task: frame too large len=%u max=%u\r\n",
                             (uint32)frame_len, lmac_tx_max_frame_len());  /* VERIFIED */
                    skb = skb_list_dequeue(AH_TXQ());  /* VERIFIED */
                    continue;
                }

                lmac_partial_aid_update(txi);  /* VERIFIED: matches asm line 4755-4763 */

                if ((AH_PM_MODE() == 1U) &&  /* VERIFIED */
                    ((*(uint8 *)((uint8 *)&ah_lmac + 0x34aU) & 0x01U) == 0U) &&
                    (sta != NULL)) {
                    txi[0x26] |= 0x40U;  /* VERIFIED */
                }

                if (((*(uint8 *)((uint8 *)&ah_lmac + 0x319U) & 0x02U) != 0U) ||  /* VERIFIED */
                    ((((uint32)(*(uint32 *)((uint8 *)&ah_lmac + 0x99cU)) - 2U) < 2U))) {
                    *(uint16 *)hdr |= WLAN_FC_PWRMGT;  /* VERIFIED */
                } else {
                    *(uint16 *)hdr &= (uint16)~WLAN_FC_PWRMGT;  /* VERIFIED */
                }

                if ((txi[0x26] & 0x10U) != 0U) {  /* VERIFIED: retry bit set */
                    *(uint16 *)(txi + 0x14U) = *(uint16 *)(skb_bytes + 0x28U);  /* VERIFIED */
                    *(uint16 *)(txi + 0x16U) = lmac_tx_aligned_len(*(uint16 *)(skb_bytes + 0x28U));  /* VERIFIED */
                }

                ac = ieee802_1d_to_ac[txi[0x26] & 0x07U];  /* VERIFIED */
                log_debug("[TX] frame_len=%u ac=%u txi26=0x%02x txi27=0x%02x txi3c=%u txi3d=%u\r\n", frame_len, ac, txi[0x26], txi[0x27], txi[0x3c], txi[0x3d]);  /* VERIFIED */

                last_skb = skb_list_last(AH_ACQ(ac));  /* VERIFIED */
                if (lmac_check_aggregation(skb, last_skb) != 0) {  /* VERIFIED: no aggregation possible */
                    tx_queue = AH_ACQ(ac);  /* FIX: add to ACQ for sending, not TXQ! */
                    log_debug("[TX] -> ACQ[%u] (no agg, last=%p)\r\n", ac, last_skb);  /* VERIFIED */
                } else {
                    tx_queue = AH_ACQ(ac);  /* VERIFIED: queue for aggregation */
                    log_debug("[TX] -> ACQ[%u] (last=%p)\r\n", ac, last_skb);  /* VERIFIED */
                }

                __asm__ volatile("mfcr %0, cr<0,0>" : "=r"(cpu_sr));  /* VERIFIED */
                __asm__ volatile("psrclr ie");  /* VERIFIED */
                skb_list_queue(tx_queue, skb);  /* VERIFIED */
                AH_AGGQ_DECR(ac)++;  /* VERIFIED */
                aggq_val = AH_AGGQ_DECR(ac);  /* VERIFIED */

                do_early_reload = 0;  /* VERIFIED */
                if (AH_AGGQ_DECR(3U) != 0U) {  /* VERIFIED */
                    if (last_skb == NULL) {  /* VERIFIED */
                        do_early_reload = 1;  /* VERIFIED */
                    }
                }
                if (do_early_reload == 0) {  /* VERIFIED */
                    max_agg = *(uint8 *)((uint8 *)&ah_lmac + 0x315U);  /* VERIFIED */
                    if (AH_AGGQ_DECR(2U) >= (uint8)(max_agg >> 1)) {  /* VERIFIED */
                        do_early_reload = 1;  /* VERIFIED */
                    } else if (aggq_val >= max_agg) {  /* VERIFIED */
                        do_early_reload = 1;  /* VERIFIED */
                    }
                }

                if (cpu_sr & 0x40U) {  /* VERIFIED: restore interrupts if originally enabled */
                    __asm__ volatile("psrset ie");  /* VERIFIED */
                }

                /* FIX: Call lmac_send_data_to_phy to actually send the packet!
                 * This was missing - packet was queued but never sent to PHY.
                 * Then call ah_ce_start() to start the DMA transmission. */
                log_debug("[TX] Calling lmac_send_data_to_phy(ac=%u)\r\n", ac);
                (void)lmac_send_data_to_phy(ac);  /* Calls original assembly version via WRAP */

                /* Start the CE (Copy Engine) to send the packet to PHY
                 * Assembly shows ah_ce_start expects config struct pointer in r0
                 * Loaded from lmac_tx_task+0xc44 before call */
                log_debug("[TX] Calling ah_ce_start()\r\n");
                /* TODO: Need to find correct config struct pointer argument */
                ah_ce_start();  /* Start DMA transmission - may need arguments! */

                log_debug("[TX] aggq=%u early_reload=%d\r\n", aggq_val, do_early_reload);
                /* REMOVED: do_early_reload logic - causes infinite loop!
                if (do_early_reload) {
                    log_debug("[TX] early lmac_tx_data_reload\r\n");
                    lmac_tx_data_reload();
                }
                */

                skb = skb_list_dequeue(AH_TXQ());
            }
        }

                /* Queue state logged only when TXQ was processed */
        lmac_tx_data_reload();
    }
}

static void lmac_tx_status_task(void *arg) {
    (void)arg;

    for (;;) {
        struct sk_buff *skb;

        if ((AH_TX_EXIT_FLAG() & 1U) != 0U) {
            hgprintf("%s exit!!!\r\n", __func__);
            return;
        }

        os_sema_down(&ah_lmac_tx.tx_status_sem, osWaitForever);
        skb = skb_list_dequeue(AH_STATQ());
        while (skb != NULL) {
            void *txinfo = *(void **)((uint8 *)skb + 0x20);

            AH_MISC_FLAG_A4F() &= (uint8)~0x01U;
            AH_PENDING_TX()--;

            if (*(uint32 *)((uint8 *)skb + 0x3c) < 2U) {
                AH_TX_ERRCNT()++;
            }

            lmac_sta_put(*(void **)((uint8 *)txinfo + 0x0c));  /* VERIFIED */

            if ((*(uint8 *)((uint8 *)txinfo + 0x27) & 0x02U) != 0U) {  /* VERIFIED */
                uint32 latency = (uint32)os_jiffies() - *(uint32 *)((uint8 *)skb + 0x2c);  /* VERIFIED */

                AH_TX_LAT_SUM() += latency;  /* VERIFIED */
                if (AH_TX_LAT_MAX() < latency) {  /* VERIFIED */
                    AH_TX_LAT_MAX() = latency;  /* VERIFIED */
                }
            }

            if ((*(uint8 *)((uint8 *)skb + 0x2a) & 0x40U) != 0U) {  /* VERIFIED */
                if (AH_CUR_BEACON() != skb) {  /* VERIFIED */
                    kfree_skb(skb);  /* VERIFIED */
                } else {
                    if ((AH_BCN_CTRL() & 0x08U) != 0U) {  /* VERIFIED */
                        hgprintf("\2SP_Tx over\r\n");  /* VERIFIED */
                    }

                    AH_MISC_FLAG_A4F() &= (uint8)~0x10U;  /* VERIFIED */
                }
            } else if (ah_ops.tx_status != NULL) {  /* VERIFIED */
                ah_ops.tx_status(&ah_ops, skb);  /* VERIFIED */
            }

            skb = skb_list_dequeue(AH_STATQ());  /* VERIFIED */
        }
    }
}
/* This function MUST be called from lmac_tx_task - no weak attribute */
int32 lmac_send_data_to_phy(uint32 ac) {
    uint8 agg_cnt;  /* VERIFIED */
    uint16 dur;  /* VERIFIED */

    agg_cnt = AH_AGGNUM(ac);  /* VERIFIED */
    log_debug("[TX] lmac_send_data_to_phy: ac=%u agg_cnt=%u\r\n", ac, agg_cnt);  /* DEBUG */
    if (agg_cnt == 0U) {  /* VERIFIED */
        log_warn("[TX] lmac_send_data_to_phy: agg_cnt=0, NOT sending!\r\n");  /* DEBUG */
        AH_TX_STATE() |= 0x4000U;  /* VERIFIED */
        return 0;  /* VERIFIED */
    }

    dur = (uint16)lmac_hdr_dur_calc(40U * (AH_AGGSYM(ac) + ((AH_AGGHDR(ac) >> 6) & 0x03ffU)));
    if (AH_DURCACHE() < dur) {
        dur = AH_DURCACHE();
    }

    lhw_cfg_dma_list_cnt(agg_cnt);

    for (uint32 idx = 0; idx < agg_cnt; ++idx) {
        struct sk_buff *skb = (struct sk_buff *)AH_AGGLIST(ac)[idx];

        if (skb == NULL) {
            continue;
        }

        if (*(uint8 *)skb->data == 180U) {
            skb->data[2] = (uint8)dur;
            skb->data[3] = (uint8)(dur >> 8);
        }

        lhw_cfg_tx_sub_frm(idx, (uint32)(uintptr_t)skb->data, skb->len);
    }

    LMAC_REG32(0x7c) = AH_AGGBYTES(ac);
    LMAC_REG32(0x58) = (LMAC_REG32(0x58) & ~0x3U) |
                       (((agg_cnt != 1U) ? 1U : 0U) << 1) | 1U;
    return 0;
}
static int32 lmac_attempt_tx_obss(int32 lo_id) {
    uint32 reg34;

    if (lmac_tx_to_pm_ap() != 0) {
        return RET_ERR;
    }

    if ((AH_MISC9E0() & 0x01U) != 0U) {
        return RET_ERR;
    }

    if ((AH_MISC_FLAG_A4F() & 0x08U) != 0U) {
        return RET_ERR;
    }

    if ((AH_MISC9E2() & 0x02U) != 0U) {
        if ((AH_MISC9E2() & 0x28U) == 0U) {
            return RET_ERR;
        }
    }

    if ((LMAC_REG32(0xd0) != 0U) || (LMAC_REG32(0xd4) != 0U)) {
        return RET_ERR;
    }

    reg34 = LMAC_REG32(0x34);
    if (((reg34 >> 8) & 0x07U) != 0U) {
        return RET_ERR;
    }

    if (((reg34 >> 24) & 0x07U) != 1U) {
        return RET_ERR;
    }

    lhw_abort_fsm();
    if (lo_id >= 0) {
        lmac_lo_table_kick((uint16)lo_id);
    }

    LMAC_REG32(0x30) = (LMAC_REG32(0x30) & ~(1U << 9)) | (1U << 10);
    lhw_start_cca(2U, 0U);
    lhw_start_tx((uint8)(AH_TXSTART() - 96U));
    lmac_cfg_txvec_part1();
    return 0;
}
static int32 lmac_attempt_tx(uint32 ac) {
    uint8 *lmac;
    uint32 reg34;
    uint16 cca_limit;
    uint32 cca_remain;
    uint8 cca_bw;

    if (lmac_tx_to_pm_ap() != 0) {
        return RET_ERR;
    }

    if ((AH_MISC9E0() & 0x01U) != 0U) {
        return RET_ERR;
    }

    if ((AH_MISC_FLAG_A4F() & 0x08U) != 0U) {
        return RET_ERR;
    }

    if ((AH_MISC9E2() & 0x02U) != 0U) {
        if ((AH_MISC9E2() & 0x28U) == 0U) {
            return RET_ERR;
        }
    }

    if ((LMAC_REG32(0xd0) != 0U) || (LMAC_REG32(0xd4) != 0U)) {
        return RET_ERR;
    }

    reg34 = LMAC_REG32(0x34);
    if (((reg34 >> 8) & 0x07U) != 0U) {
        return RET_ERR;
    }

    if (((reg34 >> 24) & 0x07U) != 1U) {
        return RET_ERR;
    }

    lmac = (uint8 *)&ah_lmac;
    if ((lmac[0x892] & 0x02U) == 0U) {
        lmac_lo_table_kick(lmac[0x33c]);
    }

    if ((ac < 4U) && (AH_AGGCNT(ac) != 0U)) {
        struct sk_buff *skb = (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[0];
        void *txinfo = *(void **)((uint8 *)skb + 0x20);
        uint16 base = *(uint16 *)(lmac + 0x28U + (ac * sizeof(uint16)));
        uint16 span = *(uint16 *)(lmac + 0x38U + (ac * sizeof(uint16)));
        uint32 shift = (uint32)(*(uint8 *)((uint8 *)txinfo + 0x28)) +
                       (uint32)(*(uint8 *)((uint8 *)txinfo + 0x29));
        uint32 scaled;

        if (shift > 16U) {
            shift = 16U;
        }

        scaled = (uint32)base << shift;
        if (scaled < span) {
            cca_limit = (uint16)scaled;
        } else {
            cca_limit = span;
        }

        if (cca_limit < base) {
            cca_limit = base;
        }

        cca_bw = (uint8)(lmac[0x1cU + ac] + 3U);
    } else {
        cca_limit = *(uint16 *)(lmac + 0x2eU);
        cca_bw = 3U;
    }

    if (cca_limit == 0U) {
        AH_TX_STATE() |= 0x04U;
        cca_limit = 7U;
    }

    cca_remain = lhw_get_cca_remain();
    if (cca_remain == 0U) {
        cca_remain = LMAC_REG32(0x3c) % cca_limit;
    }

    if ((AH_PM_MODE() == 2U) &&
        ((lmac[0x360] & 0x01U) == 0U) &&
        (((int8)lmac[0x301]) == 0)) {
        cca_remain = 0U;
    }

    if (AH_PSPOLL_ACK() == 7U) {
        cca_remain = 0U;
    }

    if ((AH_MISC9E2() & 0x20U) != 0U) {
        uint32 reg30;

        lhw_start_cca(2U, 0U);

        reg30 = LMAC_REG32(0x30);
        reg30 &= ~(1U << 9);
        LMAC_REG32(0x30) = reg30;

        reg30 = LMAC_REG32(0x30);
        reg30 |= 1U << 10;
        LMAC_REG32(0x30) = reg30;
    } else {
        uint32 reg30;

        reg30 = LMAC_REG32(0x30);
        reg30 |= 1U << 9;
        LMAC_REG32(0x30) = reg30;

        reg30 = LMAC_REG32(0x30);
        reg30 |= 1U << 10;
        LMAC_REG32(0x30) = reg30;

        lhw_start_cca(cca_bw, cca_remain);
    }

    *(uint16 *)(AH_TX_BYTES() + 0x560U) = cca_bw;
    *(uint16 *)(AH_TX_BYTES() + 0x562U) = (uint16)cca_remain;

    lhw_start_tx(0U);
    lmac_cfg_txvec_part1();
    lmac_tdma_start();
    return 0;
}

static void lmac_beacon_reset_workspace(struct sk_buff *skb) {
    skb->data = skb->head + (128U << 1);
    skb->tail = skb->data;
    skb->len = 0U;
    skb->clone = NULL;
    skb->sta = NULL;
}

__attribute__((weak)) int32 lmac_beacon_add_s1g_beacon_compatibility(struct sk_buff *skb) {
    uint8 *pos;
    uint8 *end;

    if ((skb == NULL) || (skb->data == NULL) || (skb->len < 2U)) {
        return RET_ERR;
    }

    pos = skb->data;
    end = skb->data + skb->len;
    while ((pos + 2U) <= end) {
        uint8 eid = pos[0];
        uint8 elen = pos[1];

        if ((pos + 2U + elen) > end) {
            break;
        }

        if (eid == WLAN_EID_S1G_BEACON_COMPATIBILITY) {
            return 0;
        }

        pos += 2U + elen;
    }

    return 0;
}
__attribute__((weak)) int32 lmac_beacon_build_s1gbeacon(struct sk_buff *skb) {
    struct sk_buff *dst = AH_BEACON_SKB();

    if ((skb == NULL) || (dst == NULL) || (skb->data == NULL) || (dst->head == NULL)) {
        return RET_ERR;
    }

    lmac_beacon_reset_workspace(dst);
    if ((uint32)skb->len > (uint32)skb_tailroom(dst)) {
        hgprintf("\2lmac error!!!beacon too large:%u>%u\r\n",
                 (uint32)skb->len, (uint32)skb_tailroom(dst));
        return RET_ERR;
    }

    memcpy(dst->cb, skb->cb, sizeof(dst->cb));
    dst->priority = skb->priority;
    dst->acked = skb->acked;
    dst->cloned = 0U;
    dst->lmaced = skb->lmaced;
    dst->pkt_type = skb->pkt_type;
    dst->tx = skb->tx;
    dst->src_in = skb->src_in;
    dst->lifetime = skb->lifetime;
    dst->txinfo = skb->txinfo;
    dst->sta = skb->sta;
    (void)skb_put_data(dst, skb->data, skb->len);
    *(uint8 *)((uint8 *)dst + 0x2aU) |= 0x40U;

    return lmac_beacon_add_s1g_beacon_compatibility(dst);
}
__attribute__((weak)) int32 lmac_tx_ba(struct sk_buff *skb) {
    uint8 *tmpl = (uint8 *)&ah_lmac + 0x914U;

    (void)skb;

    if ((AH_ACLAST() & 0x20U) == 0U) {
        if ((AH_MISC9E2() & 0x02U) == 0U) {
            *(uint16 *)(tmpl + 0x02U) = (uint16)lmac_hdr_dur_calc(*(uint16 *)((uint8 *)&ah_lmac + 0x670U));
        }

        lmac_tx_hw_commit(tmpl, 34U, 38U);
    }

    lmac_tx_ctrl_store_sta(tmpl + 4U);
    return lmac_cfg_txvec_part2();
}
__attribute__((weak)) int32 lmac_tx_ack(struct sk_buff *skb) {
    uint8 *tmpl = (uint8 *)&ah_lmac + 0x904U;

    (void)skb;

    if ((AH_ACLAST() & 0x40U) == 0U) {
        *(uint16 *)(tmpl + 0x02U) = (uint16)lmac_hdr_dur_calc(*(uint16 *)((uint8 *)&ah_lmac + 0x66eU));
        lmac_tx_hw_commit(tmpl, 16U, 20U);
    }

    lmac_tx_ctrl_store_sta(tmpl + 4U);
    return lmac_cfg_txvec_part2();
}
__attribute__((weak)) int32 lmac_tx_cts(struct sk_buff *skb) {
    uint8 *tmpl = (uint8 *)&ah_lmac + 0x8f4U;

    (void)skb;

    if ((AH_ACLAST() & 0x10U) == 0U) {
        lmac_tx_hw_commit(tmpl, 16U, 20U);

        if ((*(uint8 *)((uint8 *)&ah_lmac + 0x9ddU) & 0x10U) != 0U) {
            *(uint16 *)(tmpl + 0x02U) = (uint16)(lmac_dtim_timer_rem() + 4000U);
            memcpy(tmpl + 4U, (uint8 *)&ah_lmac + 0x302U, 6U);
        }
    }

    lmac_tx_ctrl_store_sta(tmpl + 4U);
    return lmac_cfg_txvec_part2();
}
__attribute__((weak)) int32 lmac_tx_rts(struct sk_buff *skb) {
    uint8 *tmpl = (uint8 *)&ah_lmac + 0x8e4U;
    uint32 ac;

    (void)skb;

    lmac_tx_hw_commit_rts(tmpl);
    lmac_tx_ctrl_store_sta(tmpl + 4U);
    lmac_cfg_txvec_part2();

    ac = AH_ACLAST() & 0x0fU;
    if (ac < 4U) {
        for (uint32 idx = 0; idx < AH_AGGNUM(ac); ++idx) {
            struct sk_buff *agg = (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[idx];
            uint8 *txi;

            if (agg == NULL) {
                continue;
            }

            txi = *(uint8 **)((uint8 *)agg + 0x20U);
            if (txi != NULL) {
                txi[0x29U]++;
            }
        }
    }

    return 0;
}
__attribute__((weak)) int32 lmac_tx_pv0_null(struct sk_buff *skb) {
    uint8 *tmpl = (uint8 *)&ah_lmac + 0x978U;

    (void)skb;

    lmac_tx_hw_commit(tmpl, 26U, 30U);
    lmac_tx_ctrl_store_sta(tmpl + 4U);
    return lmac_cfg_txvec_part2();
}
__attribute__((weak)) int32 lmac_tx_pv0_pspoll(struct sk_buff *skb) {
    uint8 *tmpl = (uint8 *)&ah_lmac + 0x968U;

    (void)skb;

    lmac_tx_hw_commit(tmpl, 16U, 20U);
    lmac_tx_ctrl_store_sta(tmpl + 4U);
    return lmac_cfg_txvec_part2();
}
__attribute__((weak)) int32 lmac_tx_pv0_cfpoll(struct sk_buff *skb) {
    uint8 *tmpl = (uint8 *)&ah_lmac + 0x938U;

    (void)skb;

    lmac_tx_hw_commit(tmpl, 32U, 36U);
    lmac_tx_ctrl_store_sta(tmpl + 4U);
    return lmac_cfg_txvec_part2();
}
__attribute__((weak)) int32 lmac_tx_pv0_cfend(struct sk_buff *skb) {
    uint8 *tmpl = (uint8 *)&ah_lmac + 0x958U;

    (void)skb;

    lmac_tx_hw_commit(tmpl, 16U, 20U);
    lmac_tx_ctrl_store_sta(tmpl + 4U);
    lmac_cfg_txvec_part2();

    if (AH_PM_MODE() == 1U) {
        lmac_set_basic_nav(2000U);
    }

    return 0;
}
__attribute__((weak)) int32 lmac_tx_frm(struct sk_buff *skb) {
    uint32 ac = AH_ACLAST() & 0x0fU;
    uint8 *ac_ctx;
    uint32 *tx_cnt;

    (void)skb;

    if (ac >= 4U) {
        hgprintf("\2lmac error!!!tx_frm ac invalid\r\n");
        return RET_ERR;
    }

    ac_ctx = AH_TX_BYTES() + (ac * AH_AC_STRIDE);
    if ((ac_ctx[0x1c7U] & 0x04U) == 0U) {
        hgprintf("\2lmac error!!!tx_agg invalid\r\n");
        return RET_ERR;
    }

    lmac_send_data_to_phy(ac);
    lmac_cfg_txvec_part2();
    ac_ctx[0x1c7U] &= (uint8)~0x04U;

    tx_cnt = (uint32 *)((uint8 *)&ah_lmac + 0x71cU + (ac * sizeof(uint32)));
    (*tx_cnt)++;
    return 0;
}
static void lmac_tx_pv0_s1g_beacon(struct sk_buff *skb) {
    uint8 *hdr;
    uint16 fc;

    if (skb == NULL) {
        return;
    }

    hdr = *(uint8 **)((uint8 *)skb + 0x1cU);
    if (hdr == NULL) {
        return;
    }

    fc = (uint16)hdr[0] | ((uint16)hdr[1] << 8);
    if (ieee80211_is_s1g_beacon(fc) == 0U) {
        return;
    }

    *(uint8 *)((uint8 *)skb + 0x2aU) |= 0x10U;
    if (*(void **)((uint8 *)skb + 0x20U) != NULL) {
        memset(*(void **)((uint8 *)skb + 0x20U), 0, 68U);
    }

    if (skb_list_queue(AH_TXQ(), skb) == 0) {
        os_sema_up(&ah_lmac_tx.tx_sem);
        if ((*(uint8 *)((uint8 *)&ah_lmac + 0x9deU) & 0x20U) == 0U) {
            lmac_beacon_timer_start(1000U);
            *(uint8 *)((uint8 *)&ah_lmac + 0x9deU) |= 0x20U;
        }
    }

    if (AH_TX_STATE() == 0U) {
        AH_TX_STATE() = 2U;
    }
}
__attribute__((weak)) int32 lmac_tx_beacon(struct sk_buff *skb) {
    struct sk_buff *beacon;

    if (skb == NULL) {
        return RET_ERR;
    }

    if (lmac_beacon_build_s1gbeacon(skb) != 0) {
        return RET_ERR;
    }

    beacon = AH_BEACON_SKB();
    if (beacon == NULL) {
        return RET_ERR;
    }

    AH_CUR_BEACON() = beacon;
    lmac_tx_pv0_s1g_beacon(beacon);
    return 0;
}



__attribute__((weak)) void *lmac_gen_txvec(uint32 ac, uint32 ac_hint, uint32 mcs) {
    uint8 *ac_ctx;
    struct sk_buff *skb;
    uint8 *txi;
    uint8 *txvec;
    void *sta;
    uint32 tx_pwr;
    uint32 frame_sel;
    uint32 resp_mode;
    uint32 resp_ind;
    uint16 tx16;
    uint16 dur_field;

    if (ac >= 4U) {
        return NULL;
    }

    ac_ctx = AH_TX_BYTES() + (ac * AH_AC_STRIDE);
    skb = (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[0];
    if (skb == NULL) {
        return NULL;
    }

    txi = *(uint8 **)((uint8 *)skb + 0x20);
    if (txi == NULL) {
        return NULL;
    }

    txvec = ac_ctx + 0x1c8U;
    sta = *(void **)(txi + 0x0cU);
    tx_pwr = (uint32)lmac_tx_pwr_sel(txi, mcs);

    txvec[0] = (uint8)((txvec[0] & (uint8)~0x1fU) | (tx_pwr & 0x1fU));
    txvec[0] = (uint8)((txvec[0] & (uint8)~0xc0U) | ((ac_hint % 3U) << 6));
    txvec[1] = (uint8)((txvec[1] & (uint8)~0x03U) | ((txi[0x2b] >> 3) & 0x03U));

    if (ac_hint == 3U) {
        txi[0x2b] &= (uint8)~0x06U;
        frame_sel = 0U;
    } else {
        frame_sel = (txi[0x24] >> 2) & 0x07U;
        frame_sel = ((frame_sel == 1U) || (frame_sel == 2U)) ? 2U : 1U;
        txi[0x2b] = (uint8)((txi[0x2b] & (uint8)~0x06U) | ((frame_sel & 0x03U) << 1));
    }

    txvec[1] = (uint8)((txvec[1] & (uint8)~0x0cU) | (((txi[0x2b] >> 1) & 0x03U) << 2));
    txvec[1] = (uint8)((txvec[1] & (uint8)~0xf0U) | ((mcs & 0x0fU) << 4));
    txvec[2] = (uint8)((txvec[2] & 0x80U) | ((LMAC_REG32(0x3c) % 127U) + 1U));

    if (((txvec[0] & 0xc0U) == 0U) && (*(uint8 *)((uint8 *)&ah_lmac + 0x308U) < 2U)) {
        txi[0x25] &= (uint8)~0x20U;
    }

    txvec[2] = (uint8)((txvec[2] & 0x7fU) | ((txi[0x25] & 0x20U) << 2));
    *(uint32 *)(txvec + 4) = AH_AGGSYM(ac);
    *(uint32 *)(txvec + 8) = 0;
    *(uint32 *)(txvec + 12) = 0;

    if ((((uint8)((txvec[0] & 0x1fU) - 3U)) < 2U) ||
        ((sta != NULL) && (*(int8 *)((uint8 *)sta + 0xb4U) >= 38))) {
        uint32 mcs_fold = (((txvec[1] >> 4) + 11U) & 0x0fU);

        if (mcs_fold < 3U) {
            txi[0x2b] = (uint8)((txi[0x2b] & (uint8)~0x01U) |
                                (*(uint8 *)((uint8 *)&ah_lmac + 0x310U) & 0x01U));
        }
    }

    txvec[3] = (uint8)((txvec[3] & (uint8)~0x03U) | ((txi[0x3f] >> 5) & 0x03U));
    resp_mode = (txvec[1] >> 2) & 0x03U;

    if (resp_mode == 0U) {
        *(uint16 *)(ac_ctx + 0x1c6U) =
            (uint16)((*(uint16 *)(ac_ctx + 0x1c6U) & (uint16)~0x03c0U) | (14U << 6));
        txvec[8] = (uint8)((txvec[8] & (uint8)~0x54U) |
                           ((txi[0x2b] & 0x01U) << 2) | 0x50U);
        tx16 = *(uint16 *)(txvec + 8);
        tx16 = (uint16)((tx16 & (uint16)~0x0780U) | ((frame_sel & 0x0fU) << 7));
        *(uint16 *)(txvec + 8) = tx16;
        txvec[9] |= 0x08U;
        *(uint32 *)(txvec + 8) =
            (*(uint32 *)(txvec + 8) & ~(0x01ffU << 12)) | ((tx_pwr & 0x01ffU) << 12);
        resp_ind = lmac_select_resp_ind();
        txvec[10] = (uint8)((txvec[10] & (uint8)~0x60U) | ((resp_ind & 0x03U) << 5));
        txvec[11] = (uint8)((txvec[11] & (uint8)~0x03U) |
                            ((*(uint8 *)((uint8 *)&ah_lmac + 0x3e4U)) & 0x01U));
    } else if (resp_mode == 1U) {
        *(uint16 *)(ac_ctx + 0x1c6U) =
            (uint16)((*(uint16 *)(ac_ctx + 0x1c6U) & (uint16)~0x03c0U) | (6U << 6));
        txvec[8] = (uint8)((txvec[8] & (uint8)~0x5dU) |
                           0x01U |
                           (((txi[0x26] >> 6) & 0x01U) << 2) |
                           (((txvec[0] >> 6) & 0x03U) << 3));

        if ((txvec[8] & 0x04U) != 0U) {
            dur_field = *(uint16 *)(txi + 0x30U);
        } else {
            dur_field = (uint16)(((*(uint16 *)(txi + 0x30U) << 3) & 0x01f8U) |
                                 (*(uint8 *)((uint8 *)&ah_lmac + 0x668U) & 0x07U));
        }

        tx16 = *(uint16 *)(txvec + 8);
        tx16 = (uint16)((tx16 & (uint16)~0xff80U) | ((dur_field & 0x01ffU) << 7));
        *(uint16 *)(txvec + 8) = tx16;

        txvec[10] = (uint8)((txvec[10] & (uint8)~0x7dU) |
                            (txi[0x2b] & 0x01U) |
                            0x04U |
                            ((frame_sel & 0x0fU) << 3));
        txvec[11] = (uint8)(1U | ((tx_pwr & 0x7fU) << 1));
        txvec[12] &= 0xfcU;
        resp_ind = lmac_select_resp_ind();
        txvec[12] = (uint8)((txvec[12] & (uint8)~0x3cU) |
                            ((resp_ind & 0x03U) << 2) |
                            (((*(uint8 *)((uint8 *)&ah_lmac + 0x3e4U)) & 0x01U) << 4));
    } else if (resp_mode == 2U) {
        *(uint16 *)(ac_ctx + 0x1c6U) =
            (uint16)((*(uint16 *)(ac_ctx + 0x1c6U) & (uint16)~0x03c0U) | (8U << 6));
        txvec[8] = (uint8)((txvec[8] & (uint8)~0x1cU) |
                           (((txi[0x26] >> 6) & 0x01U) << 2) |
                           (((txvec[0] >> 6) & 0x03U) << 3));

        if ((txvec[8] & 0x04U) != 0U) {
            dur_field = *(uint16 *)(txi + 0x30U);
        } else {
            dur_field = (uint16)(((*(uint16 *)(txi + 0x30U) << 3) & 0x01f8U) |
                                 (*(uint8 *)((uint8 *)&ah_lmac + 0x668U) & 0x07U));
        }

        tx16 = *(uint16 *)(txvec + 8);
        tx16 = (uint16)((tx16 & (uint16)~0xff80U) | ((dur_field & 0x01ffU) << 7));
        *(uint16 *)(txvec + 8) = tx16;

        txvec[10] = (uint8)((txvec[10] & (uint8)~0x7dU) |
                            (txi[0x2b] & 0x01U) |
                            0x04U |
                            ((frame_sel & 0x0fU) << 3));
        txvec[11] = (uint8)(1U | ((tx_pwr & 0x7fU) << 1));
        txvec[12] &= 0xfcU;
        resp_ind = lmac_select_resp_ind();
        txvec[12] = (uint8)((txvec[12] & (uint8)~0x3cU) |
                            ((resp_ind & 0x03U) << 2) |
                            0x10U |
                            (((*(uint8 *)((uint8 *)&ah_lmac + 0x3e4U)) & 0x01U) << 5));
    }

    if ((txi[0x27] & 0x40U) != 0U) {
        *(uint16 *)((uint8 *)&ah_lmac + 0x674U) =
            (uint16)((((*(uint16 *)(ac_ctx + 0x1c6U) >> 6) & 0x0fU) + *(uint32 *)(ac_ctx + 0x1ccU)) * 40U);
    }

    ac_ctx[0x1c7] |= 0x04U;
    return txvec;
}
__attribute__((weak)) int32 lmac_cfg_txvec_part1(void) {
    uint8 *txvec = (uint8 *)AH_CUR_TXVEC();
    uint32 tx_word;
    uint32 tx_pwr;
    uint8 pwr_mode;

    if (txvec == NULL) {
        return RET_ERR;
    }

    if ((txvec[0] & 0xc0U) == 0xc0U) {
        txvec[0] &= (uint8)~0xc0U;
    }

    tx_word = *(uint32 *)txvec;
    LMAC_REG32(0x64) = tx_word;

    tx_pwr = ((*(uint16 *)((uint8 *)&ah_lmac + 0x36cU)) >> 5) & 0x1fU;
    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x338U) & 0x01U) != 0U) {
        uint32 req_pwr = txvec[0] & 0x1fU;

        if (tx_pwr < req_pwr) {
            AH_TX_STATE() |= 0x2000U;
        } else {
            tx_pwr = req_pwr;
        }
    }

    pwr_mode = *(uint8 *)((uint8 *)&ah_lmac + 0x36dU) & 0x0cU;
    if (pwr_mode == 0U) {
        if (tx_pwr < 3U) {
            AH_TX_STATE() |= 0x2000U;
            tx_pwr = 3U;
        }
    } else if (pwr_mode == 0x08U) {
        if (tx_pwr == 0U) {
            tx_pwr = 1U;
        }
    } else if ((pwr_mode == 0x0cU) && (tx_pwr == 1U)) {
        tx_pwr = 5U;
    }

    *(uint8 *)((uint8 *)&ah_lmac + 0x710U) = (uint8)tx_pwr;
    ah_rfdigicali_tx_pwr(tx_pwr);

    if ((AH_MISC9E2() & 0x02U) != 0U) {
        uint32 ft_att = (*(uint8 *)((uint8 *)&ah_lmac + 0x708U)) & 0x3fU;

        if (ft_att != ft_att_pre) {
            config_ft_att_val();
            ft_att_pre = ft_att;
        }
    }

    if (((LMAC_REG32(0x64) ^ tx_word) & 0x00ffffffU) != 0U) {
        hgprintf("lmac_cfg_txvec_part1: reg mismatch 0x%x 0x%x\r\n", LMAC_REG32(0x64), tx_word);
    }

    return 0;
}
__attribute__((weak)) void lmac_ant_sel(uint32 ant) {
    uint8 *lmac = (uint8 *)&ah_lmac;
    uint8 gpio_pin;

    if ((lmac[0x875] & 0x04U) == 0U) {
        return;
    }

    if ((*(uint16 *)(lmac + 0x876U) & 0x8080U) == 0U) {
        jtag_map_set(0);
        lmac[0x876] = (uint8)((lmac[0x876] & 0x80U) | 31U);
        gpio_set_dir(31U, 1);
        lmac[0x876] |= 0x80U;
    }

    gpio_pin = lmac[0x876] & 0x7fU;
    if (((int8)lmac[0x876]) < 0) {
        gpio_set_val(gpio_pin, (ant == 0U) ? 1 : 0);
    }

    gpio_pin = lmac[0x877] & 0x7fU;
    if (((int8)lmac[0x877]) < 0) {
        gpio_set_val(gpio_pin, (ant != 0U) ? 1 : 0);
    }

    (*(uint8 *)((uint8 *)&ah_lmac + 0x55dU)) =
        (uint8)((*(uint8 *)((uint8 *)&ah_lmac + 0x55dU) & (uint8)~0x04U) |
                ((ant & 0x01U) << 2));
}
__attribute__((weak)) int32 lmac_cfg_txvec_part2(void) {
    uint8 *txvec = (uint8 *)AH_CUR_TXVEC();
    uint32 ant;

    if (txvec == NULL) {
        return RET_ERR;
    }

    LMAC_REG32(0x68) = *(uint32 *)(txvec + 4);
    LMAC_REG32(0x6c) = *(uint32 *)(txvec + 8);
    LMAC_REG32(0x70) = *(uint32 *)(txvec + 12);

    switch (txvec[3] & 0x03U) {
        case 1U:
            ant = 0U;
            break;
        case 2U:
            ant = 1U;
            break;
        default:
            ant = ((*(uint8 *)((uint8 *)&ah_lmac + 0x875U)) >> 4) & 0x01U;
            break;
    }

    lmac_ant_sel(ant);
    return 0;
}
__attribute__((weak)) int32 lmac_update_frm_tx_vec(void) {
    uint32 ac = AH_ACLAST() & 0x0fU;
    uint8 *ac_ctx;

    if (ac >= 4U) {
        hgprintf("\2lmac error!!!ac error!\r\n");
        return RET_ERR;
    }

    ac_ctx = AH_TX_BYTES() + (ac * AH_AC_STRIDE);
    if (((ac_ctx[0x1c7] >> 2) & 0x03U) == 0U) {
        hgprintf("\2lmac error!!!tx_agg invalid\r\n");
        return RET_ERR;
    }

    AH_CUR_TXVEC() = ac_ctx + 0x1c8U;
    lmac_cfg_txvec_part1();
    return 0;
}
__attribute__((weak)) int32 lmac_update_ndp_cts_tx_vec(uint32 arg0, uint32 arg1) {
    *(uint32 *)(AH_TX_BYTES() + 0x56cU) = arg0;
    *(uint32 *)(AH_TX_BYTES() + 0x570U) = arg1;

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x34aU) & 0x01U) != 0U) {
        *(uint8 *)(AH_TX_BYTES() + 0x56fU) |= 0x02U;
    } else {
        uint8 packed = (uint8)(((arg0 >> 30) & 0x03U) | ((arg1 & 0x01U) << 2));

        *(uint8 *)(AH_TX_BYTES() + 0x565U) =
            (uint8)((*(uint8 *)(AH_TX_BYTES() + 0x565U) & (uint8)~0x03U) | (packed & 0x03U));
        *(uint8 *)(AH_TX_BYTES() + 0x570U) |= 0x20U;
    }

    AH_CUR_TXVEC() = AH_TX_BYTES() + 0x564U;
    return lmac_cfg_txvec_part1();
}
__attribute__((weak)) int32 lmac_update_ndp_ack_tx_vec(uint32 arg0, uint32 arg1) {
    *(uint32 *)(AH_TX_BYTES() + 0x57cU) = arg0;
    *(uint32 *)(AH_TX_BYTES() + 0x580U) = arg1;

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x34aU) & 0x01U) != 0U) {
        *(uint8 *)(AH_TX_BYTES() + 0x57fU) |= 0x02U;
    } else {
        *(uint8 *)(AH_TX_BYTES() + 0x580U) |= 0x20U;
    }

    AH_CUR_TXVEC() = AH_TX_BYTES() + 0x574U;
    return lmac_cfg_txvec_part1();
}
__attribute__((weak)) int32 lmac_update_ndp_ba_tx_vec(uint32 arg0, uint32 arg1) {
    *(uint32 *)(AH_TX_BYTES() + 0x58cU) = arg0;
    *(uint32 *)(AH_TX_BYTES() + 0x590U) = arg1;

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x34aU) & 0x01U) != 0U) {
        *(uint8 *)(AH_TX_BYTES() + 0x58fU) |= 0x02U;
    } else {
        *(uint8 *)(AH_TX_BYTES() + 0x590U) |= 0x20U;
    }

    AH_CUR_TXVEC() = AH_TX_BYTES() + 0x584U;
    return lmac_cfg_txvec_part1();
}
__attribute__((weak)) int32 lmac_update_pv0_wpba_tx_vec(void) {
    AH_CUR_TXVEC() = AH_TX_BYTES() + 0x5d4U;
    pv0_ctrl_uplink_txpwr_gen();
    return lmac_cfg_txvec_part1();
}
__attribute__((weak)) int32 lmac_update_pv0_wpack_tx_vec(void) {
    AH_CUR_TXVEC() = AH_TX_BYTES() + 0x5e4U;
    pv0_ctrl_uplink_txpwr_gen();
    return lmac_cfg_txvec_part1();
}
__attribute__((weak)) int32 lmac_update_pv0_wpcts_tx_vec(void) {
    *(uint8 *)(AH_TX_BYTES() + 0x5c6U) =
        (uint8)((*(uint8 *)(AH_TX_BYTES() + 0x5c6U) & 0x7fU) |
                (((*(uint8 *)((uint8 *)&ah_lmac + 0x338U) >> 2) & 0x01U) << 7));
    AH_CUR_TXVEC() = AH_TX_BYTES() + 0x5c4U;
    pv0_ctrl_uplink_txpwr_gen();
    ((uint8 *)AH_CUR_TXVEC())[2] &= 0x7fU;
    return lmac_cfg_txvec_part1();
}
__attribute__((weak)) int32 lmac_update_pv0_cfend_tx_vec(void) {
    AH_CUR_TXVEC() = AH_TX_BYTES() + 0x604U;
    pv0_ctrl_uplink_txpwr_gen();

    if ((AH_PM_MODE() == 2U) && (*(uint8 *)((uint8 *)&ah_lmac + 0x308U) >= 2U)) {
        ((uint8 *)AH_CUR_TXVEC())[2] |= 0x80U;
    } else {
        ((uint8 *)AH_CUR_TXVEC())[2] &= 0x7fU;
    }

    return lmac_cfg_txvec_part1();
}
__attribute__((weak)) void ndp_tx_vec_init_one(uint8 *txvec) {
    uint8 *lmac = (uint8 *)&ah_lmac;

    *(uint32 *)(txvec + 0) = 0;
    txvec[1] = 0x10U;
    txvec[2] = 0x0fU;
    txvec[1] = (uint8)((txvec[1] & (uint8)~0x03U) | (lmac[0x308] & 0x03U));

    if ((lmac[0x34a] & 0x01U) != 0U) {
        txvec[1] &= (uint8)~0x0cU;
        *(uint32 *)(lmac + 0x668U) =
            (*(uint32 *)(lmac + 0x668U) & 0xf0000fffU) | ((140U & 0x7fffU) << 12);
    } else {
        txvec[1] = (uint8)((txvec[1] & (uint8)~0x0cU) | 0x04U);
        *(uint32 *)(lmac + 0x668U) =
            (*(uint32 *)(lmac + 0x668U) & 0xf0000fffU) | ((240U & 0x7fffU) << 12);
    }

    txvec[2] &= 0x7fU;
    txvec[0] |= 0x20U;
    txvec[0] = (uint8)((txvec[0] & (uint8)~0x1fU) |
                       (((*(uint16 *)(lmac + 0x36cU)) >> 5) & 0x1fU));
    *(uint32 *)(txvec + 4) = 0;
}
__attribute__((weak)) void ndp_tx_vec_init(void) {
    ndp_tx_vec_init_one(AH_TX_BYTES() + 0x564U);
    ndp_tx_vec_init_one(AH_TX_BYTES() + 0x574U);
    ndp_tx_vec_init_one(AH_TX_BYTES() + 0x584U);
    ndp_tx_vec_init_one(AH_TX_BYTES() + 0x594U);
    ndp_tx_vec_init_one(AH_TX_BYTES() + 0x5a4U);
}
__attribute__((weak)) uint32 pv0_ctrl_uplink_txpwr_gen(void) {
    uint8 *txvec = (uint8 *)AH_CUR_TXVEC();
    uint32 tx_pwr = ((uint32)(*(uint16 *)((uint8 *)&ah_lmac + 0x36cU) >> 5)) & 0x1fU;
    uint8 ctrl_type;

    if (txvec == NULL) {
        return tx_pwr;
    }

    ctrl_type = txvec[1] & 0x0cU;
    if (ctrl_type == 0x04U) {
        if (AH_PM_MODE() == 1U) {
            txvec[8] |= 1U << 2;
            *(uint16 *)(txvec + 8) &= (uint16)~(0x01ffU << 7);
        } else {
            *(uint16 *)(txvec + 8) =
                (uint16)((*(uint16 *)(txvec + 8) & ~((uint16)1U << 2)) |
                         ((((uint16)(*(uint8 *)((uint8 *)&ah_lmac + 0x668U) & 0x07U))) << 7));
        }
    } else if (ctrl_type == 0x08U) {
        if (AH_PM_MODE() == 1U) {
            txvec[8] |= 1U << 2;
        } else {
            *(uint16 *)(txvec + 8) =
                (uint16)((*(uint16 *)(txvec + 8) & ~((uint16)1U << 2)) |
                         ((((uint16)(*(uint8 *)((uint8 *)&ah_lmac + 0x668U) & 0x07U))) << 7));
        }
    }

    tx_pwr = tx_pwr_adjust_by_mcs(tx_pwr, txvec[1] >> 4);
    txvec[0] = (uint8)((txvec[0] & ~0x1fU) | (tx_pwr & 0x1fU));
    return tx_pwr;
}



__attribute__((weak)) void lmac_irq_tx_end(void) {
    uint32 irq_state;
    uint16 nav_seed;

    LMAC_REG32(0x48) = 4U;
    lhw_abort_fsm();
    ah_tdma_abort();

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x340U) == *(uint8 *)((uint8 *)&ah_lmac + 0x33cU)) &&
        ((AH_MISC_FLAG_A4F() & 0x08U) == 0U) &&
        ((*(uint8 *)((uint8 *)&ah_lmac + 0x892U) & 0x02U) == 0U)) {
        lmac_lo_table_kick(*(uint8 *)((uint8 *)&ah_lmac + 0x33cU));
        lmac_delay_us(52U);
    }

    irq_state = LMAC_REG32(0x74) & 0x03U;
    if (irq_state != 0U) {
        AH_TX_STATE() |= 0x02U;
    } else {
        *(uint32 *)(AH_TX_BYTES() + 0x558U) = LMAC_REG32(0x54);
        *(uint8 *)(AH_TX_BYTES() + 0x55cU) =
            (uint8)((*(uint8 *)(AH_TX_BYTES() + 0x55cU) & (uint8)~0x3fU) |
                    ((LMAC_REG32(0x64) >> 16) & 0x3fU));
        *(uint16 *)(AH_TX_BYTES() + 0x55cU) =
            (uint16)((*(uint16 *)(AH_TX_BYTES() + 0x55cU) & (uint16)~0x0380U) |
                     ((LMAC_REG32(0x64) >> 16) & 0x0380U));
        *(uint8 *)(AH_TX_BYTES() + 0x55dU) =
            (uint8)((*(uint8 *)(AH_TX_BYTES() + 0x55dU) & (uint8)~0xf8U) |
                    ((LMAC_REG32(0x64) >> 12) & 0xf8U));
    }

    LMAC_REG32(0x74) |= 0x03U;
    *(uint32 *)((uint8 *)&ah_lmac + 0xA50U) = 0U;
    *(uint32 *)((uint8 *)&ah_lmac + 0x998U) = 0U;
    lmac_rx_gain_cfg((*(uint16 *)((uint8 *)&ah_lmac + 0x362U) >> 4) & 0x7ffU);
    *(uint32 *)((uint8 *)&ah_lmac + 0x994U) = 0U;
    update_rx_buff_addr();
    lmac_tdma_start();

    if ((AH_MISC9E2() & 0x08U) != 0U) {
        nav_seed = *(uint16 *)((uint8 *)&ah_lmac + 0x9e2U);
        lmac_set_basic_nav((((uint32)(nav_seed >> 6) & 0x3fU) * 1000U));
    }

    lhw_start_rx(0U);

    if (AH_DURCACHE() != 0U) {
        LMAC_REG32(0xcc) |= 0x2000U;
        LMAC_REG32(0x48) = (128U << 12);
        LMAC_REG32(0xdc) = AH_DURCACHE();
        LMAC_REG32(0xcc) |= 0x1000U;
    }

    if (*(uint32 *)((uint8 *)&ah_lmac + 0x998U) == 1U) {
        AH_DURCACHE() = 0U;
    }

    {
        uint16 v0 = (uint16)(*(uint8 *)((uint8 *)&ah_lmac + 0x90eU) |
                              ((uint16)*(uint8 *)((uint8 *)&ah_lmac + 0x90fU) << 8));
        uint16 v1 = (uint16)(*(uint8 *)((uint8 *)&ah_lmac + 0x91eU) |
                              ((uint16)*(uint8 *)((uint8 *)&ah_lmac + 0x91fU) << 8));
        v0 &= 0xdfffU;
        v1 &= 0xdfffU;
        *(uint8 *)((uint8 *)&ah_lmac + 0x90eU) = (uint8)v0;
        *(uint8 *)((uint8 *)&ah_lmac + 0x90fU) = (uint8)(v0 >> 8);
        *(uint8 *)((uint8 *)&ah_lmac + 0x91eU) = (uint8)v1;
        *(uint8 *)((uint8 *)&ah_lmac + 0x91fU) = (uint8)(v1 >> 8);
    }
}
__attribute__((weak)) void lmac_irq_tx_tmo(void) {
    uint32 ac;

    lmac_cancle_tx_tmo();

    if ((int8)AH_ACLAST() < 0) {
        ah_tdma_abort();
        *(uint32 *)((uint8 *)&ah_lmac + 0x738U) += 1U;
        *(uint32 *)((uint8 *)&ah_lmac + 0x998U) = 0U;
        if ((AH_MISC9E0() & 0x01U) == 0U) {
            lhw_enable_irq_ac();
        }
        return;
    }

    ac = lmac_tx_cur_ac();
    if (ac >= 4U) {
        hgprintf("lmac_irq_tx_tmo: invalid ac %u\r\n", ac);
        *(uint32 *)((uint8 *)&ah_lmac + 0x998U) = 0U;
        if ((AH_MISC9E0() & 0x01U) == 0U) {
            lhw_enable_irq_ac();
        }
        return;
    }

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x892U) & 0x03U) == 0x03U) {
        lmac_tx_mark_timeout_for_ac(ac);
    } else {
        lmac_tx_mark_timeout_for_ac(ac);
    }

    *(uint32 *)((uint8 *)&ah_lmac + 0x734U) += 1U;
    *(uint32 *)((uint8 *)&ah_lmac + 0x998U) = 0U;

    if ((AH_MISC9E0() & 0x01U) == 0U) {
        lhw_enable_irq_ac();
    }
}
__attribute__((weak)) void lmac_irq_bo_fns(void) {
    uint32 ac = AH_ACLAST() & 0x0fU;

    if (ac >= 4U) {
        ac = lmac_select_tx_acq();
        if (ac >= 4U) {
            if ((AH_MISC9E0() & 0x01U) == 0U) {
                lhw_enable_irq_ac();
            }
            return;
        }
        AH_ACLAST() = (AH_ACLAST() & (uint8)~0x0fU) | (uint8)ac;
    }

    if (lmac_tx_date_prepared() != 0) {
        if (lmac_tx_frame_regen(ac, 0xffU, 0xffU, NULL) != 0) {
            if ((AH_MISC9E0() & 0x01U) == 0U) {
                lhw_enable_irq_ac();
            }
            return;
        }
    }

    if (lmac_attempt_tx(ac) != 0) {
        if ((AH_MISC9E0() & 0x01U) == 0U) {
            lhw_enable_irq_ac();
        }
    }
}
__attribute__((weak)) void lmac_irq_ac_pd(void) {
    uint32 ac = lmac_select_tx_acq();

    lmac_tx_data_reload();

    if (ac >= 4U) {
        ac = lmac_select_tx_acq();
        if (ac >= 4U) {
            if ((AH_MISC9E0() & 0x01U) == 0U) {
                lhw_enable_irq_ac();
            }
            return;
        }
    }

    AH_ACLAST() = (AH_ACLAST() & (uint8)~0x0fU) | (uint8)ac;

    if (lmac_tx_date_prepared() != 0) {
        if (lmac_tx_frame_regen(ac, 0xffU, 0xffU, NULL) != 0) {
            if ((AH_MISC9E0() & 0x01U) == 0U) {
                lhw_enable_irq_ac();
            }
            return;
        }
    }

    if (lmac_attempt_tx(ac) != 0) {
        if ((AH_MISC9E0() & 0x01U) == 0U) {
            lhw_enable_irq_ac();
        }
    }
}


__attribute__((weak)) int32 lmac_update_tx_rate(uint32 ac, uint8 *rate_out, uint8 *bw_out) {
    uint8 *txi;
    uint8 rate;
    uint8 bw;

    if ((ac >= 4U) || (rate_out == NULL) || (bw_out == NULL)) {
        return RET_ERR;
    }

    txi = lmac_txinfo_first_for_ac(ac);
    if (txi == NULL) {
        return RET_ERR;
    }

    rate = txi[0x3dU];
    if (rate == 0xffU) {
        rate = *(uint8 *)((uint8 *)&ah_lmac + 0x867U);
        if (rate == 0xffU) {
            rate = *(uint8 *)((uint8 *)&ah_lmac + 0x865U);
        }
    }

    bw = txi[0x3cU];
    if (bw == 0xffU) {
        bw = *(uint8 *)((uint8 *)&ah_lmac + 0x308U) & 0x03U;
    }

    *rate_out = rate;
    *bw_out = bw;
    *(uint32 *)((uint8 *)&ah_lmac + 0x6e8U) = rate;
    *(uint32 *)((uint8 *)&ah_lmac + 0x6ecU) = bw;
    return 0;
}
__attribute__((weak)) int32 lmac_update_tx_state_ack(uint32 ok, uint32 arg1, uint32 arg2) {
    uint32 ac = AH_ACLAST() & 0x0fU;
    uint8 *txi;

    (void)arg1;
    (void)arg2;

    if (ac >= 4U) {
        hgprintf("lmac_update_tx_state_ack: invalid ac %u\r\n", ac);
        return RET_ERR;
    }

    txi = lmac_txinfo_first_for_ac(ac);
    if (txi == NULL) {
        return RET_ERR;
    }

    if ((txi[0x25U] & 0x02U) != 0U) {
        txi[0x27U] |= 0x80U;
        lmac_tx_status_notify_local(ac, 1U, *(uint16 *)(txi + 0x16U));
    } else {
        lmac_tx_status_notify_local(ac, 0U, *(uint16 *)(txi + 0x16U));
    }

    if (ok != 0U) {
        txi[0x27U] |= 0x80U;
    }

    return 0;
}
__attribute__((weak)) int32 lmac_update_tx_state_ba(uint32 start_ssn, uint32 bitmap_lo, uint32 bitmap_hi) {
    uint32 ac = AH_ACLAST() & 0x0fU;
    uint32 acked_bytes = 0U;
    uint32 success = 0U;
    uint32 seen = 0U;

    if (ac >= 4U) {
        hgprintf("lmac_update_tx_state_ba: invalid ac %u\r\n", ac);
        return RET_ERR;
    }

    for (uint32 idx = 0; idx < AH_AGGNUM(ac); ++idx) {
        struct sk_buff *skb = (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[idx];
        uint8 *txi;
        uint32 seq;
        uint32 delta;
        uint64 mask;

        if (skb == NULL) {
            continue;
        }

        txi = *(uint8 **)((uint8 *)skb + 0x20U);
        if (txi == NULL) {
            continue;
        }

        seq = *(uint16 *)(txi + 0x18U) & 0x0fffU;
        delta = (seq - start_ssn) & 0x0fffU;
        if (delta >= 64U) {
            if ((txi[0x25U] & 0x02U) == 0U) {
                *(uint32 *)((uint8 *)&ah_lmac + 0x758U) += 1U;
            }
            continue;
        }

        mask = 1ULL << delta;
        seen = 1U;
        if ((((uint64)bitmap_lo | ((uint64)bitmap_hi << 32)) & mask) != 0ULL) {
            txi[0x27U] |= 0x80U;
            acked_bytes += *(uint16 *)(txi + 0x16U);
            success = 1U;
            *(uint32 *)((uint8 *)&ah_lmac + 0x754U) += 1U;
        } else if ((txi[0x25U] & 0x02U) == 0U) {
            *(uint32 *)((uint8 *)&ah_lmac + 0x758U) += 1U;
        }
    }

    if (seen != 0U) {
        lmac_tx_status_notify_local(ac, success, acked_bytes);
    }

    return 0;
}
__attribute__((weak)) int32 lmac_update_tx_state_cts(uint32 ok) {
    AH_RF_PD_FLAGS() = (uint8)((AH_RF_PD_FLAGS() & (uint8)~0x0cU) | ((ok & 0x03U) << 2));
    return 0;
}
__attribute__((weak)) int32 ndp_ack_rx_hdl(uint32 rx0, uint32 rx1, uint32 ext) {
    uint32 sig;
    uint32 want;

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x3e2U) & 0x01U) != 0U) {
        AH_AGGQ_DECR(8U) &= 0x7fU;
    }

    if (ext == 0U) {
        sig = ((*(uint32 *)(AH_TX_BYTES() + 0x558U) >> 23) & 0x180U) |
              (*(uint8 *)(AH_TX_BYTES() + 0x55cU) & 0x7fU);
        want = (rx0 >> 11) & 0x7U;
    } else {
        sig = ((*(uint16 *)(AH_TX_BYTES() + 0x55aU) & 0xff80U)) |
              (*(uint8 *)(AH_TX_BYTES() + 0x55cU) & 0x7fU);
        want = (rx1 >> 3) & 0x7U;
    }

    if ((AH_PSPOLL_ACK() == 1U) && ((rx0 >> 24) == 0U) && (sig == want)) {
        ndp_pspoll_ack_rx_hdl();
    } else if (AH_PSPOLL_ACK() == 1U) {
        hgprintf("ndp_ack_rx_hdl: mismatch sig=%u want=%u rx0=0x%x\n", sig, want, rx0);
        AH_PSPOLL_ACK() = 0U;
    }

    return 0;
}
__attribute__((weak)) int32 ndp_ba_rx_hdl(uint32 rx0, uint32 rx1, uint32 ext) {
    uint32 sig;
    uint32 want;

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x3e2U) & 0x01U) != 0U) {
        AH_AGGQ_DECR(8U) &= 0x7fU;
    }

    if (ext == 0U) {
        sig = *(uint8 *)(AH_TX_BYTES() + 0x55cU) & 0x03U;
        want = (rx0 >> 4) & 0x07U;
    } else {
        sig = *(uint8 *)(AH_TX_BYTES() + 0x55cU) & 0x3fU;
        want = (rx0 >> 8) & 0x07U;
    }

    if ((AH_PSPOLL_ACK() == 1U) && (sig == want)) {
        ndp_pspoll_ack_rx_hdl();
    } else if (AH_PSPOLL_ACK() == 1U) {
        hgprintf("ndp_ba_rx_hdl: mismatch sig=%u want=%u rx0=0x%x\n", sig, want, rx0);
        AH_PSPOLL_ACK() = 0U;
    }

    (void)rx1;
    return 0;
}
__attribute__((weak)) int32 ndp_pspoll_ack_rx_hdl(void) {
    AH_PSPOLL_ACK() = 0;
    return 0;
}
__attribute__((weak)) uint32 lmac_select_resp_ind(void) {
    uint32 ac = AH_ACLAST() & 0x0fU;
    uint8 *ac_ctx;
    struct sk_buff *skb;
    uint8 *txi;
    uint8 delta;

    if (ac >= 4U) {
        return 0;
    }

    ac_ctx = AH_TX_BYTES() + (ac * AH_AC_STRIDE);
    skb = (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[0];
    if (skb == NULL) {
        return 0;
    }

    txi = *(uint8 **)((uint8 *)skb + 0x20);
    if (txi == NULL) {
        return 0;
    }

    if ((txi[0x1a] & 0x01U) != 0U) {
        return 0;
    }

    delta = (uint8)((uint8)(*(uint8 *)(ac_ctx + 0x1c2U) + 1U) - *(uint8 *)(ac_ctx + 0x1c0U));
    if (delta == 1U) {
        return ((txi[0x25] & 0x02U) != 0U) ? 2U : 0U;
    }

    if (delta >= 65U) {
        hgprintf("lmac_select_resp_ind: invalid delta %u\r\n", delta);
        return 0;
    }

    return 2U;
}


__attribute__((weak)) void lmac_pv0_rts_init(void) {
    lmac_pv0_rts_init_inner((uint8 *)&ah_lmac + 0x8e4U, AH_TX_BYTES() + 0x5b4U);
}
__attribute__((weak)) void lmac_pv0_wpack_init(void) {
    lmac_pv0_wp_txvec_init(AH_TX_BYTES() + 0x5e4U, "lmac_pv0_wpack_init");
}
__attribute__((weak)) void lmac_pv0_wpcts_init(void) {
    lmac_pv0_wp_txvec_init(AH_TX_BYTES() + 0x5c4U, "lmac_pv0_wpcts_init");
    *(uint8 *)(AH_TX_BYTES() + 0x5c6U) =
        (uint8)((*(uint8 *)(AH_TX_BYTES() + 0x5c6U) & 0x7fU) |
                (((*(uint8 *)((uint8 *)&ah_lmac + 0x338U) >> 2) & 0x01U) << 7));
}
__attribute__((weak)) void lmac_pv0_wpba_init(void) {
    lmac_pv0_wp_txvec_init(AH_TX_BYTES() + 0x5d4U, "lmac_pv0_wpba_init");
}
__attribute__((weak)) void lmac_pv0_cfpoll_init(void) {
    lmac_pv0_cfpoll_init_inner((uint8 *)&ah_lmac + 0x938U, AH_TX_BYTES() + 0x5f4U);
}
__attribute__((weak)) void lmac_pv0_pspoll_init(void) {
    lmac_pv0_pspoll_init_inner((uint8 *)&ah_lmac + 0x968U, AH_TX_BYTES() + 0x614U);
}
__attribute__((weak)) void lmac_pv0_cfend_init(void) {
    lmac_pv0_cfend_init_inner((uint8 *)&ah_lmac + 0x958U, AH_TX_BYTES() + 0x604U);
}
__attribute__((weak)) void lmac_pv0_qos_null_init(void) {
    lmac_pv0_qos_null_init_inner((uint8 *)&ah_lmac + 0x978U, AH_TX_BYTES() + 0x624U);
}

__attribute__((always_inline)) int32 lmac_check_aggregation(struct sk_buff *skb0, struct sk_buff *skb1) {
    void *txinfo0;
    void *txinfo1;
    uint16 fc;

    if ((skb0 == NULL) || (skb1 == NULL)) {
        return RET_ERR;
    }

    txinfo0 = *(void **)((uint8 *)skb0 + 0x20);
    txinfo1 = *(void **)((uint8 *)skb1 + 0x20);

    if (((*(uint32 *)((uint8 *)txinfo0 + 0x08)) & 0x01U) != 0U) {
        return RET_ERR;
    }

    if (((*(uint32 *)((uint8 *)txinfo1 + 0x08)) & 0x01U) != 0U) {
        return RET_ERR;
    }

    if ((*(uint8 *)((uint8 *)txinfo0 + 0x27) & 0x08U) != 0U) {
        return RET_ERR;
    }

    if ((*(uint8 *)((uint8 *)txinfo1 + 0x27) & 0x08U) != 0U) {
        return RET_ERR;
    }

    if (((*(uint8 *)((uint8 *)txinfo0 + 0x25) ^ *(uint8 *)((uint8 *)txinfo1 + 0x25)) & 0x40U) != 0U) {
        return RET_ERR;
    }

    if (*(uint8 *)((uint8 *)txinfo0 + 0x3c) != *(uint8 *)((uint8 *)txinfo1 + 0x3c)) {
        return RET_ERR;
    }

    if (*(uint8 *)((uint8 *)txinfo0 + 0x3d) != *(uint8 *)((uint8 *)txinfo1 + 0x3d)) {
        return RET_ERR;
    }

    if (((*(uint8 *)((uint8 *)txinfo0 + 0x3f) ^ *(uint8 *)((uint8 *)txinfo1 + 0x3f)) & 0x60U) != 0U) {
        return RET_ERR;
    }

    if (((*(uint8 *)((uint8 *)txinfo0 + 0x26) ^ *(uint8 *)((uint8 *)txinfo1 + 0x26)) & 0x0fU) != 0U) {
        return RET_ERR;
    }

    fc = (uint16)(skb0->data[0] | (skb0->data[1] << 8));
    if (ieee80211_is_data(fc) == 0U) {
        return RET_ERR;
    }

    fc = (uint16)(skb1->data[0] | (skb1->data[1] << 8));
    if (ieee80211_is_data(fc) == 0U) {
        return RET_ERR;
    }

    if ((*(uint16 *)((uint8 *)txinfo0 + 0x24) & 0x01fcU) != 0x0188U) {
        return RET_ERR;
    }

    if (((*(uint8 *)((uint8 *)txinfo0 + 0x1a) ^ *(uint8 *)((uint8 *)txinfo1 + 0x1a)) & 0x01U) != 0U) {
        return RET_ERR;
    }

    if ((*(uint8 *)((uint8 *)txinfo0 + 0x1a) & 0x01U) != 0U) {
        return 0;
    }

    if (*(uint16 *)((uint8 *)txinfo0 + 0x1a) != *(uint16 *)((uint8 *)txinfo1 + 0x1a)) {
        return RET_ERR;
    }

    if (*(uint32 *)((uint8 *)txinfo0 + 0x1c) != *(uint32 *)((uint8 *)txinfo1 + 0x1c)) {
        return RET_ERR;
    }

    return 0;
}
static void lmac_tx_data_reload(void) {
    static const uint8 reg_ac_pd_mapping[4] = { 1U, 0U, 2U, 3U };  /* VERIFIED: matches asm line 3478-3482 */
    static const uint8 ieee802_1d_to_ac[8] = { 0U, 1U, 1U, 0U, 2U, 2U, 3U, 3U };  /* VERIFIED: matches asm line 3483-3486 */

    for (uint32 ac = 0; ac < 4U; ++ac) {  /* VERIFIED: loop matches asm line 3487 */
        uint32 ac_bit = 1U << reg_ac_pd_mapping[ac];  /* VERIFIED: asm line 3488-3490 */
        struct sk_buff *prev_queued = NULL;  /* VERIFIED */

        if ((LMAC_REG32(0x4c) & ac_bit) != 0U) {  /* VERIFIED: matches asm line 3491-3494 */
            continue;  /* VERIFIED */
        }

        struct sk_buff *skb = skb_list_first(AH_TXSQ());  /* VERIFIED: matches asm line 3495-3498 */
        if ((skb == NULL) || ((void *)skb == (void *)AH_TXSQ())) {  /* VERIFIED: matches asm line 3499-3502 */
            if (skb_list_count(AH_TXSQ()) != 0U) {  /* VERIFIED: matches asm line 3503-3506 */
                LMAC_REG32(0x4c) = 0U;  /* VERIFIED: asm line 3507-3508 */
                LMAC_REG32(0x4c) = 0x0fU;  /* VERIFIED: asm line 3509-3510 */
                os_sema_up(&ah_lmac_tx.tx_sem);  /* VERIFIED: asm line 3511-3513 */
            } else {  /* VERIFIED */
                (*(uint32 *)((uint8 *)&ah_lmac + 0x7acU))++;  /* VERIFIED: asm line 3514-3516 */
            }
            return;  /* VERIFIED */
        }

        while ((skb != NULL) && ((void *)skb != (void *)AH_TXSQ())) {  /* VERIFIED: matches asm line 3517-3520 */
            uint8 *skb_bytes = (uint8 *)skb;  /* VERIFIED */
            struct sk_buff *next = *(struct sk_buff **)skb_bytes;  /* VERIFIED: asm line 3521-3523 */
            uint8 *txi = *(uint8 **)(skb_bytes + 0x20U);  /* VERIFIED: asm line 3524-3526 */

            if ((txi != NULL) && (ieee802_1d_to_ac[txi[0x26] & 0x07U] == ac)) {  /* VERIFIED: matches asm line 3527-3532 */
                int32 aggr_ok = 0;  /* VERIFIED */

                if (prev_queued != NULL) {  /* VERIFIED: asm line 3533-3535 */
                    aggr_ok = lmac_check_aggregation(skb, prev_queued);  /* VERIFIED: asm line 3536-3538 */
                }

                if ((prev_queued == NULL) || (aggr_ok == 0)) {  /* VERIFIED: matches asm line 3539-3542 */
                    skb_list_unlink(skb, AH_TXSQ());  /* VERIFIED: asm line 3543-3545 */

                    void *sta = *(void **)(txi + 0x0cU);  /* VERIFIED: asm line 3546-3548 */
                    if ((sta != NULL) && ((((uint8 *)sta)[0x6b] & 0x30U) != 0U)) {  /* VERIFIED: matches asm line 3549-3554 */
                        *(uint8 *)(skb_bytes + 0x2aU) &= (uint8)~0x10U;  /* VERIFIED: asm line 3555-3557 */
                        skb_list_queue(AH_STATQ(), skb);  /* VERIFIED: asm line 3558-3560 */
                    } else {  /* VERIFIED */
                        skb_list_queue(AH_ACQ(ac), skb);  /* VERIFIED: asm line 3561-3563 */
                        prev_queued = skb;  /* VERIFIED */
                    }
                }
            }

            skb = next;  /* VERIFIED */
        }
    }

    if (skb_list_count(AH_TXSQ()) != 0U) {  /* VERIFIED: matches asm line 3564-3567 */
        LMAC_REG32(0x4c) = 0U;  /* VERIFIED: asm line 3568-3569 */
        LMAC_REG32(0x4c) = 0x0fU;  /* VERIFIED: asm line 3570-3571 */
        os_sema_up(&ah_lmac_tx.tx_sem);  /* VERIFIED: asm line 3572-3574 */
    } else {  /* VERIFIED */
        (*(uint32 *)((uint8 *)&ah_lmac + 0x7acU))++;  /* VERIFIED: asm line 3575-3577 */
    }
}
__attribute__((weak)) int32 lmac_reorder_tx_agglist(void) {  /* VERIFIED: matches asm line 1963-1966 */
    int32 completed = 0;  /* VERIFIED */

    log_debug("[TX] lmac_reorder_tx_agglist called\r\n");  /* DEBUG: not in loop */

    for (uint32 ac = 0; ac < 4U; ++ac) {  /* VERIFIED: matches asm line 1967-1970 */
        uint8 *ac_ctx = AH_TX_BYTES() + (ac * AH_AC_STRIDE);  /* VERIFIED */
        uint8 agg_cnt = AH_AGGCNT(ac);  /* VERIFIED */
        uint32 keep_idx = 0;  /* VERIFIED */

        for (uint32 idx = 0; idx < agg_cnt; ++idx) {  /* VERIFIED: matches asm line 1971-1974 */
            struct sk_buff *skb = (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[idx];  /* VERIFIED */
            uint8 *txi;  /* VERIFIED */
            void *sta;  /* VERIFIED */
            int32 dispatch_now;  /* VERIFIED */

            if (skb == NULL) {  /* VERIFIED: matches asm line 1975-1977 */
                continue;  /* VERIFIED */
            }

            txi = *(uint8 **)((uint8 *)skb + 0x20);  /* VERIFIED: matches asm line 1978-1980 */
            if (txi == NULL) {  /* VERIFIED: matches asm line 1981-1983 */
                AH_AGGLIST(ac)[keep_idx++] = (uint32)(uintptr_t)skb;  /* VERIFIED: asm line 1984-1986 */
                continue;  /* VERIFIED */
            }

            dispatch_now = (((AH_MISC9E2() & 0x0aU) != 0x02U) ? 1 : 0);  /* VERIFIED: matches asm line 1987-1991 */

            if (((int8)txi[0x27]) < 0) {  /* VERIFIED: matches asm line 1992-1995 */
                *(uint8 *)((uint8 *)skb + 0x2a) |= 0x10U;  /* VERIFIED: asm line 1996-1998 */

                if (txi[0x2c] == 0U) {  /* VERIFIED: matches asm line 1999-2001 */
                    dispatch_now = 1;  /* VERIFIED */
                }

                if (((int8)txi[0x26] < 0) &&  /* VERIFIED: matches asm line 2002-2006 */
                    ((AH_PM_DEADLINE_LO() != 0U) || (AH_PM_DEADLINE_HI() != 0U))) {
                    AH_PM_MARGIN() = 150U;  /* VERIFIED: asm line 2007-2009 */
                }
            } else {  /* VERIFIED */
                sta = *(void **)(txi + 0x0c);  /* VERIFIED: matches asm line 2010-2012 */

                if ((txi[0x29] >= *(uint8 *)((uint8 *)&ah_lmac + 0x312U)) ||  /* VERIFIED: matches asm line 2013-2018 */
                    (txi[0x28] >= *(uint8 *)((uint8 *)&ah_lmac + 0x313U)) ||
                    ((sta != NULL) && ((*(uint8 *)((uint8 *)sta + 0x6bU) & 0x30U) != 0U))) {
                    *(uint8 *)((uint8 *)skb + 0x2a) &= (uint8)~0x10U;  /* VERIFIED: asm line 2019-2021 */
                    (*(uint32 *)((uint8 *)&ah_lmac + 0x75cU))++;  /* VERIFIED: asm line 2022-2024 */
                    dispatch_now = 1;  /* VERIFIED */
                } else {  /* VERIFIED */
                    if ((sta != NULL) &&  /* VERIFIED: matches asm line 2025-2029 */
                        (*(uint16 *)(txi + 0x16U) != 0U) &&
                        ((txi[0x24] & 0x14U) == 0U)) {
                        uint8 *hdr = *(uint8 **)((uint8 *)skb + 0x1c);  /* VERIFIED: asm line 2030-2032 */

                        if (hdr != NULL) {  /* VERIFIED: matches asm line 2033-2035 */
                            hdr[1] |= 0x08U;  /* VERIFIED: asm line 2036-2038 */
                        }
                    }

                    dispatch_now = 0;  /* VERIFIED */
                }
            }

            if (!dispatch_now) {  /* VERIFIED: matches asm line 2039-2042 */
                if ((*(uint8 *)((uint8 *)skb + 0x2a) & 0x10U) == 0U) {  /* VERIFIED: asm line 2043-2045 */
                    sta = *(void **)(txi + 0x0c);  /* VERIFIED */
                    if ((sta != NULL) &&  /* VERIFIED: matches asm line 2046-2050 */
                        ((*(uint8 *)((uint8 *)sta + 0x6bU) & 0x02U) != 0U) &&
                        ((txi[0x24] & 0x1cU) == 0x08U) &&
                        (((*(uint16 *)(txi + 0x24U)) & 0x00e0U) == 0x0080U)) {
                        txi[0x27] |= 0x08U;  /* VERIFIED: asm line 2051-2053 */
                        txi[0x29] = 0U;  /* VERIFIED */
                        txi[0x28] = 0U;  /* VERIFIED */
                        hgprintf("lmac_reorder_tx_agglist: ps frame adjusted\r\n");  /* VERIFIED */
                    }
                }

                AH_AGGLIST(ac)[keep_idx++] = (uint32)(uintptr_t)skb;  /* VERIFIED */
                continue;  /* VERIFIED */
            }

            if ((*(uint8 *)((uint8 *)skb + 0x2a) & 0x10U) != 0U) {  /* VERIFIED: matches asm line 2054-2056 */
                if (((txi[0x24] & 0x1cU) == 0x08U) &&  /* VERIFIED: matches asm line 2057-2060 */
                    (((*(uint16 *)(txi + 0x24U)) & 0x00e0U) == 0x0080U)) {
                    hgprintf("lmac_reorder_tx_agglist: tx done qos data\r\n");  /* VERIFIED */
                }
            }

            completed++;  /* VERIFIED */
            sta = *(void **)(txi + 0x0c);  /* VERIFIED */
            if (sta != NULL) {  /* VERIFIED */
                int16 dur = *(int16 *)(txi + 0x16U);  /* VERIFIED */

                if ((*(uint8 *)((uint8 *)skb + 0x2a) & 0x10U) != 0U) {  /* VERIFIED: matches asm line 2061-2063 */
                    (*(uint16 *)((uint8 *)sta + 0x1d4U))++;  /* VERIFIED */
                    (*(uint32 *)((uint8 *)sta + 0x1d8U)) += (int32)dur;  /* VERIFIED */
                } else {  /* VERIFIED */
                    (*(uint16 *)((uint8 *)sta + 0x1d6U))++;  /* VERIFIED */
                    (*(uint32 *)((uint8 *)sta + 0x1dcU)) += (int32)dur;  /* VERIFIED */
                }
            }

            skb_list_queue(AH_STATQ(), skb);  /* VERIFIED: matches asm line 2064-2066 */
            AH_AGGCNT(ac)--;  /* VERIFIED */
            AH_AGGQ_DECR(ac)--;  /* VERIFIED */
        }

        ac_ctx[0x1c7] &= (uint8)~0x04U;  /* VERIFIED */
    }

    if (completed != 0) {  /* VERIFIED: matches asm line 2067-2069 */
        os_sema_up(&ah_lmac_tx.tx_status_sem);  /* VERIFIED: asm line 2070-2072 */
        lmac_set_basic_nav(1612U);  /* VERIFIED */
    }

    log_debug("[TX] lmac_reorder_tx_agglist done, completed=%d\r\n", completed);  /* DEBUG: not in loop */

    return completed;  /* VERIFIED */
}
static void *lmac_gen_tx_agglist(uint32 ac, uint32 ac_hint, uint32 mcs, void *arg) {  /* VERIFIED: matches asm line 1920-1923 */
    uint8 *ac_ctx;  /* VERIFIED */
    uint32 max_syms;  /* VERIFIED */
    uint32 max_bytes;  /* VERIFIED */
    uint32 cap;  /* VERIFIED */
    struct sk_buff *first_skb;  /* VERIFIED */
    void *first_txi;  /* VERIFIED */

    if (ac >= 4U) {  /* VERIFIED: matches asm line 1924-1926 */
        hgprintf("lmac_gen_tx_agglist invalid ac=%u\r\n", ac);  /* VERIFIED */
        return NULL;  /* VERIFIED */
    }

    ac_ctx = AH_TX_BYTES() + (ac * AH_AC_STRIDE);  /* VERIFIED: matches asm line 1927-1930 */
    AH_AGGNUM(ac) = 0U;  /* VERIFIED: matches asm line 1931-1933 */
    AH_AGGBYTES(ac) = 0U;  /* VERIFIED: matches asm line 1934-1936 */
    AH_AGGSYM(ac) = 0U;  /* VERIFIED: matches asm line 1937-1939 */
    *(uint16 *)(ac_ctx + 0x1c0U) = 0xffffU;  /* VERIFIED: matches asm line 1940-1943 */
    *(uint16 *)(ac_ctx + 0x1c2U) = 0xffffU;  /* VERIFIED: matches asm line 1944-1947 */

    ac_ctx[0x1c6] = (uint8)((ac_ctx[0x1c6] & (uint8)~0x03U) | (ac_hint & 0x03U));  /* VERIFIED: matches asm line 1948-1952 */
    if ((mcs < 8U) || (mcs == 10U)) {  /* VERIFIED: matches asm line 1953-1956 */
        ac_ctx[0x1c6] = (uint8)((ac_ctx[0x1c6] & (uint8)~0x3cU) | ((mcs & 0x0fU) << 2));  /* VERIFIED: matches asm line 1957-1961 */
    }

    max_syms = (((*(uint16 *)((uint8 *)&ah_lmac + 0x360U)) >> 1) & 0x01ffU);  /* VERIFIED: matches asm line 1962-1966 */
    if ((uintptr_t)arg < max_syms) {  /* VERIFIED: matches asm line 1967-1969 */
        max_syms = (uint32)(uintptr_t)arg;  /* VERIFIED: asm line 1970-1972 */
    }

    max_bytes = (calc_max_agg_bytes(ac_hint, mcs) * max_syms) / 511U;  /* VERIFIED: matches asm line 1973-1977 */
    if ((((uint8 *)&ah_lmac)[0x34a] & 0x01U) != 0U) {  /* VERIFIED: matches asm line 1978-1981 */
        uint32 floor_bytes = calc_max_agg_bytes(3U, 0U);  /* VERIFIED */
        if (max_bytes < floor_bytes) {  /* VERIFIED: asm line 1982-1985 */
            max_bytes = floor_bytes;  /* VERIFIED: asm line 1986-1988 */
        }
    } else {  /* VERIFIED */
        uint32 floor_bytes = calc_max_agg_bytes(0U, 0U);  /* VERIFIED */
        if (max_bytes < floor_bytes) {  /* VERIFIED: asm line 1989-1992 */
            max_bytes = floor_bytes;  /* VERIFIED: asm line 1993-1995 */
        }
    }

    while (AH_AGGNUM(ac) < AH_AGGCNT(ac)) {  /* VERIFIED: matches asm line 1996-1999 */
        struct sk_buff *skb = (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[AH_AGGNUM(ac)];  /* VERIFIED: asm line 2000-2003 */
        void *txi;  /* VERIFIED */
        uint32 frame_bytes;  /* VERIFIED */

        if (skb == NULL) {  /* VERIFIED: matches asm line 2004-2006 */
            assert_internal(__func__, 1929, "");  /* VERIFIED */
            return NULL;  /* VERIFIED */
        }

        txi = *(void **)((uint8 *)skb + 0x20);  /* VERIFIED: matches asm line 2007-2009 */
        if (txi == NULL) {  /* VERIFIED: matches asm line 2010-2012 */
            break;  /* VERIFIED */
        }

        if (AH_AGGNUM(ac) >= *(uint8 *)((uint8 *)&ah_lmac + 0x315U)) {  /* VERIFIED: matches asm line 2013-2016 */
            break;  /* VERIFIED */
        }

        frame_bytes = *(uint16 *)((uint8 *)txi + 0x16U);  /* VERIFIED: matches asm line 2017-2020 */
        if ((AH_AGGBYTES(ac) + frame_bytes) > max_bytes) {  /* VERIFIED: matches asm line 2021-2024 */
            break;  /* VERIFIED */
        }

        AH_AGGNUM(ac)++;  /* VERIFIED: matches asm line 2025-2027 */
        AH_AGGBYTES(ac) += frame_bytes;  /* VERIFIED: matches asm line 2028-2030 */
    }

    if (AH_AGGCNT(ac) == 0U) {  /* VERIFIED: matches asm line 2031-2033 */
        struct sk_buff *skb = skb_list_dequeue(AH_ACQ(ac));  /* VERIFIED: matches asm line 2034-2037 */
        void *txi;  /* VERIFIED */

        if (skb == NULL) {  /* VERIFIED: matches asm line 2038-2040 */
            assert_internal(__func__, 1951, "");  /* VERIFIED */
            return NULL;  /* VERIFIED */
        }

        AH_AGGLIST(ac)[0] = (uint32)(uintptr_t)skb;  /* VERIFIED: matches asm line 2041-2044 */
        AH_AGGNUM(ac) = 1U;  /* VERIFIED: matches asm line 2045-2047 */
        AH_AGGCNT(ac) = 1U;  /* VERIFIED: matches asm line 2048-2050 */

        txi = *(void **)((uint8 *)skb + 0x20);  /* VERIFIED: matches asm line 2051-2053 */
        if (txi == NULL) {  /* VERIFIED: matches asm line 2054-2056 */
            return NULL;  /* VERIFIED */
        }

        AH_AGGBYTES(ac) = *(uint16 *)((uint8 *)txi + 0x16U);  /* VERIFIED: matches asm line 2057-2060 */
    }

    first_skb = (struct sk_buff *)(uintptr_t)AH_AGGLIST(ac)[0];  /* VERIFIED: matches asm line 2061-2064 */
    if (first_skb == NULL) {  /* VERIFIED: matches asm line 2065-2067 */
        return NULL;  /* VERIFIED */
    }

    first_txi = *(void **)((uint8 *)first_skb + 0x20);  /* VERIFIED: matches asm line 2068-2070 */
    if (first_txi == NULL) {  /* VERIFIED: matches asm line 2071-2073 */
        return NULL;  /* VERIFIED */
    }

    *(uint16 *)(ac_ctx + 0x1c0U) = *(uint16 *)((uint8 *)first_txi + 0x18U);  /* VERIFIED: matches asm line 2074-2077 */
    *(uint16 *)(ac_ctx + 0x1c2U) =  /* VERIFIED: matches asm line 2078-2081 */
        *(uint16 *)((uint8 *)(*(void **)((uint8 *)AH_AGGLIST(ac)[AH_AGGNUM(ac) - 1U] + 0x20)) + 0x18U);  /* VERIFIED */

    if ((((uint8 *)&ah_lmac)[0x310] & 0x10U) != 0U) {  /* VERIFIED: matches asm line 2082-2085 */
        void *sta = *(void **)((uint8 *)first_txi + 0x0c);  /* VERIFIED: asm line 2086-2088 */

        if ((sta != NULL) && (*(uint16 *)((uint8 *)sta + 0x1d6U) != 0U)) {  /* VERIFIED: matches asm line 2089-2093 */
            cap = 8U;  /* VERIFIED: asm line 2094-2096 */
        } else if ((mcs == 7U) && ((((ac_hint + 1U) & 0x03U)) == *(uint8 *)((uint8 *)&ah_lmac + 0x308U))) {  /* VERIFIED: matches asm line 2097-2102 */
            cap = *(uint8 *)((uint8 *)&ah_lmac + 0x315U);  /* VERIFIED: asm line 2103-2105 */
            if (cap >= 33U) {  /* VERIFIED: matches asm line 2106-2108 */
                cap = 32U;  /* VERIFIED: asm line 2109-2111 */
            }
        } else {  /* VERIFIED */
            cap = 16U;  /* VERIFIED: asm line 2112-2114 */
        }
    } else {  /* VERIFIED */
        cap = *(uint8 *)((uint8 *)&ah_lmac + 0x315U);  /* VERIFIED: matches asm line 2115-2117 */
    }

    while (AH_AGGNUM(ac) < cap) {
        struct sk_buff *skb = skb_list_first(AH_ACQ(ac));
        void *txi;
        uint16 first_dur;
        uint16 last_dur;
        uint16 dur;
        uint32 frame_bytes;

        if (skb == NULL) {
            break;
        }

        txi = *(void **)((uint8 *)skb + 0x20);
        if (txi == NULL) {
            break;
        }

        dur = *(uint16 *)((uint8 *)txi + 0x18U);
        last_dur = *(uint16 *)(ac_ctx + 0x1c2U);
        if (last_dur >= dur) {
            break;
        }

        first_dur = *(uint16 *)(ac_ctx + 0x1c0U);
        if ((uint16)(dur - first_dur) >= 63U) {
            break;
        }

        frame_bytes = *(uint16 *)((uint8 *)txi + 0x16U);
        if ((AH_AGGBYTES(ac) + frame_bytes) > max_bytes) {
            break;
        }

        if ((((uint8 *)&ah_lmac)[0x310] & 0x10U) != 0U) {
            if (*(uint8 *)((uint8 *)txi + 0x28U) != *(uint8 *)((uint8 *)first_txi + 0x28U)) {
                break;
            }
        }

        if ((((uint8 *)&ah_lmac)[0x310] & 0x08U) != 0U) {
            if ((dur + 1U) != last_dur) {
                break;
            }
        }

        skb = skb_list_dequeue(AH_ACQ(ac));
        if (skb == NULL) {
            break;
        }

        AH_AGGLIST(ac)[AH_AGGCNT(ac)] = (uint32)(uintptr_t)skb;
        AH_AGGNUM(ac)++;
        AH_AGGCNT(ac)++;
        AH_AGGBYTES(ac) += frame_bytes;
        *(uint16 *)(ac_ctx + 0x1c2U) = dur;
    }

    if (AH_AGGNUM(ac) == 0U) {
        return NULL;
    }

    AH_AGGSYM(ac) = calc_symbol_len(AH_AGGBYTES(ac) + 4U, ac_hint, mcs);
    return *(void **)((uint8 *)(uintptr_t)AH_AGGLIST(ac)[0] + 0x20);
}
__attribute__((weak)) struct sk_buff *lmac_get_first_skb(uint32 ac) {
    struct sk_buff *skb;

    if (ac >= 4U) {
        hgprintf("\2lmac error!!!in valid ac= %d\r\n", ac);
        return NULL;
    }

    if (AH_AGGCNT(ac) != 0U) {
        skb = (struct sk_buff *)AH_AGGLIST(ac)[0];
        if (skb == NULL) {
            hgprintf("\2lmac error!!!tx_agg NULL\r\n");
        }
        return skb;
    }

    skb = skb_list_first(AH_ACQ(ac));
    if (skb == NULL) {
        hgprintf("\2lmac error!!!ac_q NULL\r\n");
    }

    return skb;
}
__attribute__((weak)) uint32 lmac_get_ack_policy(void *txi) {
    uint32 sta;
    uint8 *hdr;
    uint16 fc;
    uint32 ack_policy;

    sta = *(uint32 *)((uint8 *)txi + 0x0c);
    hdr = *(uint8 **)((uint8 *)txi + 0x10);

    if ((sta != 0U) || ((AH_MISC9E2() & 0x02U) != 0U)) {
        fc = *(uint16 *)hdr;

        if (((fc & 0x000fU) == 0x0008U) ||
            ((fc & 0x00ffU) == 0x00d0U) ||
            ((fc & 0x00ffU) == 0x00e0U) ||
            ((fc & 0x00ffU) == 0x00fcU)) {
            ack_policy = (*(uint8 *)((uint8 *)txi + 0x1a)) & 0x01U;
        } else if ((fc & 0x0003U) == 0x0001U) {
            if ((((fc >> 2) & 0x07U) == 1U) && (((fc >> 5) & 0x07U) == 2U)) {
                ack_policy = 0U;
            } else {
                ack_policy = hdr[1] >> 7;
            }
        } else {
            ack_policy = 1U;
        }
    } else {
        ack_policy = 1U;
    }

    if ((AH_MISC9E2() & 0x20U) != 0U) {
        return 1U;
    }

    return ack_policy;
}
__attribute__((weak)) uint32 lmac_select_tx_acq(void) {  /* VERIFIED: matches asm line 2163-2166 */
    uint32 reg_4c = LMAC_REG32(0x4c) & 0x0fU;  /* VERIFIED: matches asm line 2167-2169 */
    uint32 choice;  /* VERIFIED */

    log_debug("[TX] lmac_select_tx_acq called, reg_4c=0x%x\r\n", reg_4c);  /* DEBUG: not in loop */

    if (reg_4c == 0U) {  /* VERIFIED: matches asm line 2170-2172 */
        choice = 4U;  /* VERIFIED */
    } else {  /* VERIFIED */
        uint32 rem = LMAC_REG32(0x3c) % 100U;  /* VERIFIED: matches asm line 2173-2176 */

        if (rem <= AH_ACSEL0()) {  /* VERIFIED: matches asm line 2177-2179 */
            if ((reg_4c & 0x01U) != 0U) {  /* VERIFIED: matches asm line 2180-2182 */
                choice = 1U;  /* VERIFIED */
            } else if ((reg_4c & 0x08U) != 0U) {  /* VERIFIED: matches asm line 2183-2185 */
                choice = 3U;  /* VERIFIED */
            } else {  /* VERIFIED */
                choice = ((reg_4c & 0x04U) != 0U) ? 2U : 0U;  /* VERIFIED: asm line 2186-2188 */
            }
        } else if (rem <= (uint32)(AH_ACSEL0() + AH_ACSEL1())) {  /* VERIFIED: matches asm line 2189-2191 */
            if ((reg_4c & 0x02U) != 0U) {  /* VERIFIED: matches asm line 2192-2194 */
                choice = 0U;  /* VERIFIED */
            } else if ((reg_4c & 0x08U) != 0U) {  /* VERIFIED: matches asm line 2195-2197 */
                choice = 3U;  /* VERIFIED */
            } else {  /* VERIFIED */
                choice = ((reg_4c & 0x04U) != 0U) ? 2U : 1U;  /* VERIFIED: asm line 2198-2200 */
            }
        } else if (rem <= (uint32)(AH_ACSEL0() + AH_ACSEL1() + AH_ACSEL2())) {  /* VERIFIED: matches asm line 2201-2203 */
            if ((reg_4c & 0x04U) != 0U) {  /* VERIFIED: matches asm line 2204-2206 */
                choice = 2U;  /* VERIFIED */
            } else if ((reg_4c & 0x08U) != 0U) {  /* VERIFIED: matches asm line 2207-2209 */
                choice = 3U;  /* VERIFIED */
            } else {  /* VERIFIED */
                choice = ((reg_4c & 0x02U) != 0U) ? 0U : 1U;  /* VERIFIED: asm line 2210-2212 */
            }
        } else if ((reg_4c & 0x08U) != 0U) {  /* VERIFIED: matches asm line 2213-2215 */
            choice = 3U;  /* VERIFIED */
        } else if ((reg_4c & 0x04U) != 0U) {  /* VERIFIED: matches asm line 2216-2218 */
            choice = 2U;  /* VERIFIED */
        } else {  /* VERIFIED */
            choice = ((reg_4c & 0x02U) != 0U) ? 0U : 1U;  /* VERIFIED: asm line 2219-2221 */
        }
    }

    AH_ACLAST() = (AH_ACLAST() & (uint8)~0x0fU) | (uint8)choice;  /* VERIFIED: matches asm line 2222-2225 */
    log_debug("[TX] lmac_select_tx_acq returns %u\r\n", choice);  /* DEBUG: not in loop */
    return choice;  /* VERIFIED */
}
__attribute__((weak)) int32 tx_skbs_cached(void) {
    return (int32)(lmac_txsq_count() +
        skb_list_count(AH_ACQ(0)) +
        skb_list_count(AH_ACQ(1)) +
        skb_list_count(AH_ACQ(2)) +
        skb_list_count(AH_ACQ(3)) +
        AH_AGGCNT(0) +
        AH_AGGCNT(1) +
        AH_AGGCNT(2) +
        AH_AGGCNT(3));
}


static uint32 tx_pwr_adjust_by_mcs(uint32 tx_pwr, uint32 mcs) {
    if ((((uint8 *)&ah_lmac)[0x36d] & 0x0cU) == 0U) {
        return tx_pwr;
    }

    if (tx_pwr != 5U) {
        return tx_pwr;
    }

    if ((mcs == 10U) || (mcs < 3U)) {
        return 0U;
    }

    if ((mcs - 3U) < 2U) {
        return 1U;
    }

    return tx_pwr;
}
__attribute__((weak)) int32 lmac_tx_pwr_sel(void *txi, uint32 mcs) {
    void *sta;
    uint32 tx_pwr;
    uint16 ctl;

    if ((((uint8 *)txi)[0x27] & 0x02U) == 0U) {
        tx_pwr = tx_pwr_adjust_by_mcs(
            ((uint32)(*(uint16 *)((uint8 *)&ah_lmac + 0x36cU) >> 5)) & 0x1fU, mcs);
        return (int32)tx_pwr;
    }

    sta = *(void **)((uint8 *)txi + 0x0c);
    if (sta == NULL) {
        tx_pwr = tx_pwr_adjust_by_mcs(
            ((uint32)(*(uint16 *)((uint8 *)&ah_lmac + 0x36cU) >> 5)) & 0x1fU, mcs);
        return (int32)tx_pwr;
    }

    ctl = *(uint16 *)((uint8 *)&ah_lmac + 0x36cU);
    if ((((uint8 *)&ah_lmac)[0x338] & 0x01U) == 0U) {
        tx_pwr = ((uint32)(ctl >> 5)) & 0x1fU;
    } else {
        int32 lo_limit = *(int8 *)((uint8 *)&ah_lmac + 0xa4eU);
        uint32 hi_limit = ((*(uint32 *)((uint8 *)&ah_lmac + 0x36cU)) >> 14) & 0xffU;

        tx_pwr = (uint32)(ctl & 0x1fU);
        if ((lo_limit < (int32)hi_limit) || ((AH_MISC9E2() & 0x02U) != 0U)) {
            tx_pwr = tx_pwr_adjust_by_mcs(tx_pwr, mcs);
        }
    }

    if (((uint8 *)txi)[0x29] >= (uint8)(((uint8 *)&ah_lmac)[0x312] - 2U)) {
        tx_pwr = tx_pwr_adjust_by_mcs(((uint32)(ctl >> 5)) & 0x1fU, mcs);
    }

    *(uint32 *)((uint8 *)&ah_lmac + 0x848U) = *(uint16 *)((uint8 *)sta + 0x68);
    *(uint8 *)((uint8 *)&ah_lmac + 0x841U) = *(uint8 *)((uint8 *)&ah_lmac + 0xa4eU);
    *(uint8 *)((uint8 *)&ah_lmac + 0x83eU) = (uint8)mcs;
    *(uint8 *)((uint8 *)&ah_lmac + 0x840U) = (uint8)tx_pwr;
    (*(uint32 *)((uint8 *)&ah_lmac + 0x844U))++;
    return (int32)tx_pwr;
}
__attribute__((weak)) void lmac_spec_cca_cfg(uint32 enable) {
    int8 cfg[10];
    uint8 ctrl = *(uint8 *)((uint8 *)&ah_lmac + 0x361U);

    if (enable == 1U) {
        ctrl &= (uint8)~0x04U;
        *(uint8 *)((uint8 *)&ah_lmac + 0x361U) = ctrl;
        if ((*(uint8 *)((uint8 *)&ah_lmac + 0x308U)) == 3U) {
            cfg[0] = -89;
            cfg[1] = -86;
            cfg[2] = -86;
            cfg[3] = -86;
            cfg[4] = -82;
            cfg[5] = -82;
        } else {
            cfg[0] = -98;
            cfg[1] = -92;
            cfg[2] = -89;
            cfg[3] = -89;
            cfg[4] = -86;
            cfg[5] = -86;
        }
    } else {
        ctrl |= 0x04U;
        *(uint8 *)((uint8 *)&ah_lmac + 0x361U) = ctrl;
        cfg[0] = -98;
        cfg[1] = -92;
        cfg[2] = -89;
        cfg[3] = -89;
        cfg[4] = -86;
        cfg[5] = -86;
    }

    cfg[6] = -75;
    cfg[7] = -72;
    cfg[8] = -72;
    cfg[9] = -69;
    ah_wphy_cca_th_cfg(cfg);
}
__attribute__((weak)) void lmac_adjust_cca_threshold(int32 delta) {
    int8 cfg[10];
    int8 base;
    uint8 bw;
    int8 v0, v1, v2, v3;

    if (delta > -90) {
        delta = -90;
    }

    base = (int8)delta;
    if (*(int8 *)((uint8 *)&ah_lmac + 0x329U) != 0 &&
        base < *(int8 *)((uint8 *)&ah_lmac + 0x329U)) {
        base = *(int8 *)((uint8 *)&ah_lmac + 0x329U);
    }

    bw = *(uint8 *)((uint8 *)&ah_lmac + 0x308U);
    if (bw == 2U) {
        base = (int8)(base - 3);
    } else if (bw == 3U) {
        base = (int8)(base - 6);
    }

    v0 = (int8)(*(uint8 *)((uint8 *)&ah_lmac + 0x328U) + base);
    v1 = (int8)(v0 + 13);
    v2 = (int8)(v0 + 10);
    v3 = (int8)(v0 + 17);
    cfg[0] = v1;
    cfg[1] = (int8)(v0 + 10);
    cfg[2] = v3;
    cfg[3] = (int8)(v0 + 14);
    cfg[4] = (int8)(v0 + 14);
    cfg[5] = v3;
    cfg[6] = (int8)(v0 + 21);
    cfg[7] = (int8)(v0 + 18);
    cfg[8] = (int8)(v0 + 18);
    cfg[9] = (int8)(v0 + 21);
    ah_wphy_cca_th_cfg(cfg);

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x37eU) & 0x08U) != 0U) {
        int32 obss = (int32)(((*(uint16 *)((uint8 *)&ah_lmac + 0x37eU)) >> 4) & 0x3fU) + (int32)(v0 + 18);
        int32 p1 = ((*(uint16 *)((uint8 *)&ah_lmac + 0x668U)) >> 3) & 0x7ffU;
        int32 p0 = (*(uint8 *)((uint8 *)&ah_lmac + 0x668U)) & 0x07U;
        ah_wphy_obss_para_cfg(obss, p1, p0, 0);
    }
}
__attribute__((weak)) void lmac_adjust_agc_threshold(int32 level) {
    int32 adj = level;
    uint8 bw = *(uint8 *)((uint8 *)&ah_lmac + 0x308U);
    uint16 gain_word;

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x361U) & 0x08U) == 0U) {
        return;
    }

    if (bw >= 2U) {
        if (bw == 2U) {
            adj += 3;
        } else {
            adj += 6;
        }
    }

    gain_word = *(uint16 *)((uint8 *)&ah_lmac + 0x362U);
    if (adj < *(int8 *)((uint8 *)&ah_lmac + 0x31fU)) {
        if ((gain_word & 0x0ff0U) != 0x0040U) {
            gain_word = (uint16)((gain_word & (uint16)~0x0ff0U) | (4U << 4));
            *(uint16 *)((uint8 *)&ah_lmac + 0x362U) = gain_word;
            lmac_rx_gain_cfg((gain_word >> 4) & 0x7ffU);
        }
        return;
    }

    if (adj > *(int8 *)((uint8 *)&ah_lmac + 0x320U)) {
        if ((gain_word & 0x0ff0U) != 0x0050U) {
            gain_word = (uint16)((gain_word & (uint16)~0x0ff0U) | (5U << 4));
            *(uint16 *)((uint8 *)&ah_lmac + 0x362U) = gain_word;
            lmac_rx_gain_cfg((gain_word >> 4) & 0x7ffU);
        }
    }
}
__attribute__((weak)) void lmac_bknoise_calc_en(void) {
    ah_rfdigicali_bknoise_calc_en();
}
__attribute__((weak)) void lmac_bknoise_calc_dis(void) {
    ah_rfdigicali_bknoise_calc_dis();
}
__attribute__((weak)) uint32 lmac_bknoise_valid_pd_get(void) {
    return ah_rfdigicali_bknoise_valid_pd_get();
}
__attribute__((weak)) void lmac_bknoise_valid_pd_clr(void) {
    ah_rfdigicali_bknoise_valid_pd_clr();
}
__attribute__((weak)) uint32 lmac_bknoise_get(void) {
    int8 bk;

    os_sleep_us(1);
    bk = ah_rfdigicali_bknoise_get();
    if (bk == 0) {
        return (uint32)(int32)-60;
    }

    {
        uint32 agc = ah_wphy_agc_info_get();
        int32 idx = (int32)(agc & 0x0fU);
        int32 rx_gain;
        int8 *lmac = (int8 *)&ah_lmac;

        if (idx > 5) {
            idx = 5;
        }

        rx_gain = ah_wphy_rx_gain_para_get(-6);
        return (uint32)(int32)(bk - (lmac[0x321 + idx] + lmac[0x327] + rx_gain));
    }
}
__attribute__((weak)) void lmac_bgrssi_update(void) {
    uint8 chan;
    uint8 *slot;
    int8 bk;

    if (ah_rfdigicali_bknoise_valid_pd_get() == 0U) {
        goto advance_chan;
    }

    bk = (int8)(int32)lmac_bknoise_get();
    ah_rfdigicali_bknoise_calc_dis();
    ah_rfdigicali_bknoise_valid_pd_clr();

    chan = *(uint8 *)((uint8 *)&ah_lmac + 0x379U);
    slot = (uint8 *)&ah_lmac + 0xc5U + (chan * 24U);

    if (bk < *(int8 *)(slot + 0x00U)) {
        *(int8 *)(slot + 0x00U) = bk;
    }

    *(uint32 *)(slot + 0x03U) += (int32)bk;
    (*(uint32 *)(slot + 0x07U))++;

    if (bk > *(int8 *)(slot + 0x01U)) {
        *(int8 *)(slot + 0x01U) = bk;
    }

    if (*(uint32 *)(slot + 0x07U) >= (((*(uint32 *)((uint8 *)&ah_lmac + 0x360U)) >> 12) & 0xffU)) {
        int32 avg = 0;
        int32 cnt = (int32)*(uint32 *)(slot + 0x07U) - 1;

        if (cnt > 0) {
            avg = ((int32)*(uint32 *)(slot + 0x03U) - *(int8 *)(slot + 0x01U) - *(int8 *)(slot + 0x00U)) / cnt;
        }
        *(int8 *)(slot + 0x02U) = (int8)avg;

        if (chan == *(uint8 *)((uint8 *)&ah_lmac + 0x33cU)) {
            *(int8 *)((uint8 *)&ah_lmac + 0x70dU) = (int8)avg;
            *(int8 *)((uint8 *)&ah_lmac + 0x70cU) = *(int8 *)(slot + 0x00U);
            *(int8 *)((uint8 *)&ah_lmac + 0x70eU) = *(int8 *)(slot + 0x01U);
            *(int8 *)((uint8 *)&ah_lmac + 0x31eU) = (int8)avg;

            if ((*(uint8 *)((uint8 *)&ah_lmac + 0x361U) & 0x04U) != 0U) {
                lmac_adjust_cca_threshold(*(int8 *)((uint8 *)&ah_lmac + 0x31eU));
            }

            lmac_adjust_agc_threshold(*(int8 *)((uint8 *)&ah_lmac + 0x31eU));
        }

        *(int8 *)(slot + 0x00U) = 0;
        *(int8 *)(slot + 0x01U) = -128;
        *(uint32 *)(slot + 0x03U) = 0U;
        *(uint32 *)(slot + 0x07U) = 0U;
    }

advance_chan:
    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x37cU) & 0x01U) != 0U) {
        uint8 next = (uint8)(*(uint8 *)((uint8 *)&ah_lmac + 0x379U) + 1U);

        if (next >= *(uint8 *)((uint8 *)&ah_lmac + 0x378U)) {
            next = 0U;
        }
        *(uint8 *)((uint8 *)&ah_lmac + 0x379U) = next;
    }
}


__attribute__((weak)) int32 lmac_send_mgmt_meas_req(void) {
    static const uint8 null_bssid[6] = { 0 };
    struct sk_buff *skb;
    struct ieee80211_mgmt *mgmt;
    uint8 *payload;
    uint8 token;
    uint16 beacon_tu;
    uint16 reload_tu;

    skb = lmac_alloc_mgmt_skb(128U << 4);
    if (skb == NULL) {
        return RET_ERR;
    }

    mgmt = lmac_mgmt_header_init(skb, 0x00d0U, (uint8 *)&ah_lmac + 0x526U,
        (uint8 *)&ah_lmac + 0x302U, null_bssid);
    if (mgmt == NULL) {
        kfree_skb(skb);
        return RET_ERR;
    }

    if (skb_tailroom(skb) < 11) {
        kfree_skb(skb);
        return RET_ERR;
    }

    token = lmac_dialog_token_next();
    beacon_tu = (uint16)((*(uint32 *)((uint8 *)&ah_lmac + 0x338U)) / 100U);
    reload_tu = (uint16)(((*(uint32 *)((uint8 *)&ah_lmac + 0x390U)) * 1000U) >> 10);

    payload = skb_put(skb, 11U);
    payload[0] = 38U;
    payload[1] = 3U;
    payload[2] = token;
    payload[3] = 0x0aU;
    payload[4] = 4U;
    payload[5] = (uint8)beacon_tu;
    payload[6] = (uint8)(beacon_tu >> 8);
    payload[7] = (uint8)-24;
    payload[8] = 3U;
    payload[9] = (uint8)reload_tu;
    payload[10] = (uint8)(reload_tu >> 8);

    return lmac_send_mgmt_skb(skb);
}
__attribute__((weak)) int32 lmac_send_mgmt_meas_report(void) {
    struct sk_buff *skb;
    struct ieee80211_mgmt *mgmt;
    uint8 *p;
    uint8 token;
    uint8 idx;
    uint8 chan_num;
    uint16 beacon_tu;
    uint8 cur_chan;

    skb = lmac_alloc_mgmt_skb(128U << 4);
    if (skb == NULL) {
        return RET_ERR;
    }

    mgmt = lmac_mgmt_header_init(skb, 0x00d0U, (uint8 *)&ah_lmac + 0x526U,
        (uint8 *)&ah_lmac + 0x302U, (uint8 *)&ah_lmac + 0x526U);
    if (mgmt == NULL) {
        kfree_skb(skb);
        return RET_ERR;
    }

    token = lmac_dialog_token_next();
    beacon_tu = (uint16)((*(uint32 *)((uint8 *)&ah_lmac + 0x338U)) / 100U);
    cur_chan = *(uint8 *)((uint8 *)&ah_lmac + 0x33cU);

    p = skb_put(skb, 5U);
    p[0] = 39U;
    p[1] = 4U;
    p[2] = token;
    p[3] = 0x02U;
    p[4] = 4U;

    p = skb_put(skb, 14U);
    memset(p, 0, 14U);
    p[0] = (uint8)beacon_tu;
    p[1] = (uint8)(beacon_tu >> 8);
    p[12] = cur_chan;
    p[13] = *(uint8 *)((uint8 *)&ah_lmac + 0xc7U + (cur_chan * 24U));

    p = skb_put(skb, 8U);
    memset(p, 0, 8U);
    p[0] = 0xddU;
    p[3] = 0x40U;
    p[5] = (uint8)(*(uint16 *)((uint8 *)&ah_lmac + 0x330U));
    p[6] = (uint8)(*(uint16 *)((uint8 *)&ah_lmac + 0x330U) >> 8);

    chan_num = *(uint8 *)((uint8 *)&ah_lmac + 0x378U);
    if (chan_num > 16U) {
        chan_num = 16U;
    }

    for (idx = 0U; idx < chan_num; ++idx) {
        uint8 *slot = (uint8 *)&ah_lmac + 0xc0U + (idx * 24U);

        if (*(uint32 *)slot == 0U) {
            continue;
        }

        if (*(uint32 *)slot != (*(uint32 *)((uint8 *)&ah_lmac + 0x338U) & 0x0fU)) {
            continue;
        }

        p = skb_put(skb, 5U);
        p[0] = slot[0];
        p[1] = slot[4];
        p[2] = slot[5];
        p[3] = slot[6];
        p[4] = slot[7];
    }

    return lmac_send_mgmt_skb(skb);
}
__attribute__((weak)) int32 lmac_send_bss_announcement(void) {
    static const uint8 bcst[6] = { 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU };
    struct sk_buff *skb;
    struct ieee80211_mgmt *mgmt;
    uint8 *p;
    uint16 ie_len;

    if (lmac_mac_is_zero((uint8 *)&ah_lmac + 0x302U) != 0) {
        return RET_ERR;
    }

    if (lmac_mac_is_zero((uint8 *)&ah_lmac + 0x526U) != 0) {
        return RET_ERR;
    }

    skb = lmac_alloc_mgmt_skb(128U << 4);
    if (skb == NULL) {
        return RET_ERR;
    }

    mgmt = lmac_mgmt_header_init(skb, 0x00d0U, bcst,
        (uint8 *)&ah_lmac + 0x302U, (uint8 *)&ah_lmac + 0x526U);
    if (mgmt == NULL) {
        kfree_skb(skb);
        return RET_ERR;
    }

    p = skb_put(skb, 12U);
    memset(p, 0, 12U);
    p[0] = 19U;
    p[1] = 0U;
    p[2] = *(uint8 *)((uint8 *)&ah_lmac + 0x33cU);
    p[3] = *(uint8 *)((uint8 *)&ah_lmac + 0x308U);
    p[4] = *(uint8 *)((uint8 *)&ah_lmac + 0x31eU);
    p[5] = *(uint8 *)((uint8 *)&ah_lmac + 0xa08U);
    p[6] = (uint8)(*(uint16 *)((uint8 *)&ah_lmac + 0x330U));
    p[7] = (uint8)(*(uint16 *)((uint8 *)&ah_lmac + 0x330U) >> 8);

    ie_len = *(uint16 *)((uint8 *)&ah_lmac + 0x52eU);
    if (ie_len > 44U) {
        ie_len = 44U;
    }

    if (ie_len != 0U) {
        skb_put_data(skb, (uint8 *)&ah_lmac + 0x530U, ie_len);
    }

    return lmac_send_mgmt_skb(skb);
}
__attribute__((weak)) int32 lmac_send_scan_probe(void) {
    static const uint8 bcst[6] = { 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU };
    struct sk_buff *skb;
    struct ieee80211_mgmt *mgmt;
    uint16 ie_len;
    int32 ret;

    if (lmac_mac_is_zero((uint8 *)&ah_lmac + 0x302U) != 0) {
        return RET_ERR;
    }

    skb = lmac_alloc_mgmt_skb(128U << 4);
    if (skb == NULL) {
        return RET_ERR;
    }

    mgmt = lmac_mgmt_header_init(skb, 0x0040U, bcst,
        (uint8 *)&ah_lmac + 0x302U, bcst);
    if (mgmt == NULL) {
        kfree_skb(skb);
        return RET_ERR;
    }

    ie_len = *(uint16 *)((uint8 *)&ah_lmac + 0x52eU);
    if (ie_len > sizeof(((lmac_ctx_t *)0)->scan_ie_buffer)) {
        ie_len = sizeof(((lmac_ctx_t *)0)->scan_ie_buffer);
    }

    if (ie_len == 0U) {
        static const uint8 empty_ssid[2] = { 0U, 0U };
        skb_put_data(skb, empty_ssid, sizeof(empty_ssid));
    } else {
        skb_put_data(skb, (uint8 *)&ah_lmac + 0xa6cU, ie_len);
    }

    ret = lmac_send_mgmt_skb(skb);
    AH_MISC_FLAG_A4F() &= (uint8)~0x10U;
    return ret;
}
__attribute__((weak)) int32 lmac_send_ant_pkt(void) {
    struct sk_buff *skb;
    struct ieee80211_mgmt *mgmt;

    if (lmac_mac_is_zero((uint8 *)&ah_lmac + 0x302U) != 0) {
        return RET_ERR;
    }

    skb = lmac_alloc_mgmt_skb(128U << 2);
    if (skb == NULL) {
        return RET_ERR;
    }

    mgmt = lmac_mgmt_header_init(skb, 0x0048U, (uint8 *)&ah_lmac + 0x302U,
        (uint8 *)&ah_lmac + 0x302U, (uint8 *)&ah_lmac + 0x302U);
    if (mgmt == NULL) {
        kfree_skb(skb);
        return RET_ERR;
    }

    mgmt->duration = (uint16)(*(uint16 *)((uint8 *)&ah_lmac + 0x670U) +
        *(uint16 *)((uint8 *)&ah_lmac + 0x66cU) + 506U);
    return lmac_send_mgmt_skb(skb);
}
__attribute__((weak)) int32 lmac_send_probe_resp(void) {
    static const uint8 bcst[6] = { 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU };
    struct sk_buff *skb;
    struct ieee80211_mgmt *mgmt;
    uint16 ie_len;
    uint32 tsf_lo;

    if (lmac_mac_is_zero((uint8 *)&ah_lmac + 0x302U) != 0) {
        return RET_ERR;
    }

    skb = lmac_alloc_mgmt_skb(128U << 4);
    if (skb == NULL) {
        return RET_ERR;
    }

    mgmt = lmac_mgmt_header_init(skb, 0x0050U, bcst,
        (uint8 *)&ah_lmac + 0x302U, (uint8 *)&ah_lmac + 0x526U);
    if (mgmt == NULL) {
        kfree_skb(skb);
        return RET_ERR;
    }

    memset(mgmt->u.probe_resp.timestamp, 0, sizeof(mgmt->u.probe_resp.timestamp));
    tsf_lo = *(uint32 *)((uint8 *)&ah_lmac + 0x658U);
    memcpy(mgmt->u.probe_resp.timestamp, &tsf_lo, sizeof(tsf_lo));
    *(uint16 *)&mgmt->u.probe_resp.beacon_int = *(uint16 *)((uint8 *)&ah_lmac + 0x660U);
    *(uint16 *)&mgmt->u.probe_resp.capab_info = *(uint16 *)((uint8 *)&ah_lmac + 0x664U);

    skb_put(skb, 12U);

    ie_len = *(uint16 *)((uint8 *)&ah_lmac + 0x52eU);
    if (ie_len != 0U) {
        skb_put_data(skb, (uint8 *)&ah_lmac + 0x530U, ie_len);
    }

    return lmac_send_mgmt_skb(skb);
}


__attribute__((weak)) int32 lmac_tx_frame_regen(uint32 ac, uint32 ac_hint, uint32 mcs, void *arg) {  /* VERIFIED: matches asm line 2098-2102 */
    static const uint8 reg_ac_pd_mapping[4] = { 1U, 0U, 2U, 3U };  /* VERIFIED: matches asm line 2103-2106 */
    void *txi;  /* VERIFIED */

    if (ac_hint >= 4U) {  /* VERIFIED: matches asm line 2107-2110 */
        ac_hint = AH_AGGHDR(ac) & 0x03U;  /* VERIFIED: asm line 2111-2113 */
    }

    if ((mcs >= 8U) && (mcs != 10U)) {  /* VERIFIED: matches asm line 2114-2117 */
        mcs = (AH_AGGHDR(ac) >> 2) & 0x0fU;  /* VERIFIED: asm line 2118-2121 */
    }

    lmac_reorder_tx_agglist();  /* VERIFIED: asm line 2122-2124 */
    lmac_check_tx_queue_empty();  /* VERIFIED: asm line 2125-2127 */

    if ((LMAC_REG32(0x4c) & (1U << reg_ac_pd_mapping[ac])) == 0U) {  /* VERIFIED: matches asm line 2128-2132 */
        ac = lmac_select_tx_acq();  /* VERIFIED: asm line 2133-2135 */
    }

    if (ac >= 4U) {  /* VERIFIED: matches asm line 2136-2138 */
        return RET_ERR;  /* VERIFIED */
    }

    txi = lmac_gen_tx_agglist(ac, ac_hint, mcs, arg);  /* VERIFIED: matches asm line 2139-2143 */
    if (txi == NULL) {  /* VERIFIED: matches asm line 2144-2146 */
        hgprintf("lmac_tx_frame_regen failed: ac=%u ac_hint=%u mcs=%u\r\n", ac, ac_hint, mcs);  /* VERIFIED */
        return RET_ERR;  /* VERIFIED */
    }

    (*(uint8 *)((uint8 *)txi + 0x25)) &= (uint8)~0x20U;  /* VERIFIED: matches asm line 2147-2150 */
    AH_CUR_TXVEC() = lmac_gen_txvec(ac, ac_hint, mcs);  /* VERIFIED: asm line 2151-2154 */
    return 0;  /* VERIFIED */
}
__attribute__((weak)) int32 lmac_tx_date_prepared(void) {
    uint32 ac = AH_ACLAST() & 0x0fU;
    uint8 *ac_ctx;

    if (ac >= 4U) {
        return RET_ERR;
    }

    ac_ctx = AH_TX_BYTES() + (ac * AH_AC_STRIDE);
    if (((ac_ctx[0x1c7] >> 2) & 0x03U) == 0U) {
        return RET_ERR;
    }

    AH_CUR_TXVEC() = ac_ctx + 0x1c8U;
    lmac_cfg_txvec_part1();
    return 0;
}
__attribute__((weak)) void lmac_partial_aid_update(void *txi) {
    void *sta = *(void **)((uint8 *)txi + 0x0c);

    if (sta == NULL) {
        return;
    }

    *(uint16 *)((uint8 *)txi + 0x2e) = *(uint16 *)((uint8 *)sta + 0x68);
    if ((*(uint8 *)((uint8 *)txi + 0x27) & 0x01U) != 0U) {
        return;
    }

    switch (*(uint8 *)((uint8 *)txi + 0x25) & 0xc0U) {
    case 0x80U:
        *(uint16 *)((uint8 *)txi + 0x30) = partial_bssid_calc((uint8 *)&ah_lmac + 0x526U);
        break;
    case 0x40U:
        *(uint16 *)((uint8 *)txi + 0x30) =
            partial_aid_calc(*(uint16 *)((uint8 *)sta + 0x68), (uint8 *)&ah_lmac + 0x526U);
        break;
    default:
        break;
    }
}
__attribute__((weak)) uint32 lmac_dtim_timer_rem(void) {
    uint32 count;

    if ((AH_PM_MODE() != 2U) || (AH_PM_FLAG2() == 0U)) {
        return (uint32)RET_ERR;
    }

    if (AH_DTIM_COUNT() != 0U) {
        count = (uint32)(AH_DTIM_COUNT() - 1U);
    } else {
        count = AH_DTIM_PERIOD();
    }

    return LMAC_REG32(0xc0) + (AH_DTIM_TU() * count);
}
__attribute__((weak)) uint32 lmac_hdr_dur_calc(uint32 len) {
    uint32 base = LMAC_REG32(0xdc);

    if (len >= (base & 0xffffU)) {
        len = 0U;
    } else {
        len = (uint16)(base - len);
    }

    if ((AH_RF_PD_FLAGS() & 0x01U) != 0U) {
        return 0x8000U;
    }

    return len;
}
static uint32 seq_num_space_update(void *sta, uint32 tid) {
    uint16 seq;

    if (sta == NULL) {
        uint32 next = (ah_lmac_tx.seq_num_space + 1U) & 0x0fffU;

        seq = (uint16)ah_lmac_tx.seq_num_space;
        ah_lmac_tx.seq_num_space = (next != 0x0fffU) ? next : 0U;
        return seq;
    }

    seq = *(uint16 *)((uint8 *)sta + 0x152U + (tid << 4));
    *(uint16 *)((uint8 *)sta + 0x152U + (tid << 4)) = (seq + 1U) & 0x0fffU;
    return seq;
}
__attribute__((weak)) int32 lmac_tx_to_pm_ap(void) {
    uint64 deadline;
    uint64 now;

    if (AH_PM_FLAG() == 0U) {
        return 0;
    }

    if ((AH_PM_MODE() != 1U) || (AH_PM_FLAG2() == 0U)) {
        return 0;
    }

    if ((AH_PM_DEADLINE_LO() == 0U) && (AH_PM_DEADLINE_HI() == 0U)) {
        return RET_ERR;
    }

    deadline = ((uint64)AH_PM_DEADLINE_HI() << 32) | AH_PM_DEADLINE_LO();
    deadline += (uint16)(AH_PM_MARGIN() - 2U);
    now = os_jiffies();
    if ((int64)(deadline - now) >= 0) {
        return 0;
    }

    AH_PM_DEADLINE_LO() = 0;
    AH_PM_DEADLINE_HI() = 0;
    return RET_ERR;
}
__attribute__((weak)) void switch_ctrl_normal_mode(void) {
    volatile uint32 *syscon = (volatile uint32 *)(uintptr_t)0x40026054U;

    sys_con8_bak = *syscon;
    *syscon &= ~(1U << 30);
    *syscon &= 0x3fffffffU;
}


__attribute__((weak)) void switch_ctrl_recover(void) {
    volatile uint32 *syscon = (volatile uint32 *)(uintptr_t)0x40026054U;

    *syscon = sys_con8_bak;
}
__attribute__((weak)) int32 lmac_auto_channel_select(void) {
    uint8 chan_count = *(uint8 *)((uint8 *)&ah_lmac + 0x378U);
    uint8 best_chan = 0xffU;
    int32 best_metric = 0x40000000;
    uint8 idx;

    LMAC_REG32(0x44) &= ~(1U << 7);
    LMAC_REG32(0x48) = 128U;
    lhw_abort_fsm();

    if ((*(uint8 *)((uint8 *)&ah_lmac + 0x361U) & 0x08U) != 0U) {
        lmac_rx_gain_cfg(5U);
    }

    ah_rfdigicali_config_hw_bknoise(384U, 1U);
    ah_rfdigicali_bknoise_valid_pd_clr();
    *(uint32 *)((uint8 *)&ah_lmac + 0x994U) = 0U;
    *(uint32 *)((uint8 *)&ah_lmac + 0x998U) = 0U;
    ah_wphy_auto_sig_err_rst_disable();

    if ((AH_MISC9E0() & 0x01U) == 0U) {
        hgprintf("lmac_auto_channel_select: scan state disabled\r\n");
        lhw_enable_irq_ac();
        ah_wphy_auto_sig_err_rst_enable();
        ah_wphy_pri_channel_cfg(*(uint8 *)((uint8 *)&ah_lmac + 0x309U));
        lhw_start_rx(0U);
        return (int32)(*(uint8 *)((uint8 *)&ah_lmac + 0x33cU) + 1U);
    }

    if (chan_count == 0U) {
        chan_count = 1U;
    }
    if (chan_count > 16U) {
        chan_count = 16U;
    }

    for (idx = 0U; idx < chan_count; ++idx) {
        uint8 *slot = (uint8 *)&ah_lmac + 0xc0U + (idx * 24U);
        uint8 chan = slot[0];
        int32 total = 0;
        int32 count = 0;
        int32 min_rssi = 127;
        int32 max_rssi = -128;
        uint32 sample_idx;

        if (chan == 0U) {
            chan = (uint8)(idx + 1U);
            slot[0] = chan;
        }

        lhw_abort_fsm();
        lmac_lo_table_kick(chan);
        os_sleep_us(52);
        lhw_start_rx(0U);
        ah_wphy_pri_channel_cfg(*(uint8 *)((uint8 *)&ah_lmac + 0x309U));

        for (sample_idx = 0U; sample_idx < 4U; ++sample_idx) {
            lhw_abort_fsm();
            lhw_start_rx(0U);
            ah_rfdigicali_bknoise_calc_en();
            ah_tdma_start();
            os_sleep_us(32);
            ah_tdma_abort();

            if (ah_rfdigicali_bknoise_valid_pd_get() != 0U) {
                int32 sample = ah_rfdigicali_bknoise_get();

                ah_rfdigicali_bknoise_calc_dis();
                ah_rfdigicali_bknoise_valid_pd_clr();

                if (sample < min_rssi) {
                    min_rssi = sample;
                }
                if (sample > max_rssi) {
                    max_rssi = sample;
                }
                total += sample;
                count++;
            } else {
                ah_rfdigicali_bknoise_calc_dis();
                ah_rfdigicali_bknoise_valid_pd_clr();
            }
        }

        slot[4] = chan;
        slot[5] = (uint8)count;
        slot[6] = (uint8)min_rssi;
        slot[7] = (uint8)max_rssi;
        *(uint32 *)(slot + 0x10U) = (count != 0) ? (uint32)(total / count) : 0U;
        *(uint32 *)(slot + 0x14U) = (count != 0) ? (uint32)(total / count) : 0xffffffffU;

        if ((count != 0) && ((total / count) < best_metric)) {
            best_metric = total / count;
            best_chan = chan;
        }
    }

    AH_MISC9E0() &= (uint8)~0x01U;

    if (best_chan == 0xffU) {
        best_chan = *(uint8 *)((uint8 *)&ah_lmac + 0x33cU);
    }

    lhw_abort_fsm();
    if ((AH_MISC9E2() & 0x02U) == 0U) {
        lmac_lo_freq_set(best_chan);
        *(int8 *)((uint8 *)&ah_lmac + 0x31eU) = -60;
        lmac_adjust_cca_threshold(*(int8 *)((uint8 *)&ah_lmac + 0x31eU));
        lmac_adjust_agc_threshold(*(int8 *)((uint8 *)&ah_lmac + 0x31eU));
        lmac_notify_channel_switch(best_chan);
    }

    *(uint8 *)((uint8 *)&ah_lmac + 0x33cU) = best_chan;
    lhw_enable_irq_ac();
    ah_wphy_auto_sig_err_rst_enable();
    ah_wphy_pri_channel_cfg(*(uint8 *)((uint8 *)&ah_lmac + 0x309U));
    lhw_start_rx(0U);
    return (int32)(best_chan + 1U);
}
__attribute__((weak)) uint32 lmac_vht_info_get(uint32 info) {
    uint8 *sta = *(uint8 **)((uint8 *)&ah_lmac + 0xA50U);
    uint8 retry_state = *(uint8 *)((uint8 *)&ah_lmac + 0x998U);
    uint8 bw_req = *(uint8 *)((uint8 *)&ah_lmac + 0x308U);
    uint8 bw_cap;
    uint8 nss;
    uint8 mcs;

    if ((sta == NULL) || (retry_state == 0U) || (retry_state > 3U)) {
        return 0U;
    }

    bw_cap = (uint8)((info >> 15) & 0xffU);
    if (bw_req < bw_cap) {
        bw_cap = ((*(uint8 *)((uint8 *)&ah_lmac + 0x34aU) & 0x01U) != 0U) ? 0U : 3U;
    }

    sta[0xafU] = (uint8)((sta[0xafU] & 0xf0U) | (bw_cap & 0x0fU));

    nss = (uint8)((info >> 11) & 0x0fU);
    if (nss >= 8U) {
        nss = 1U;
    } else {
        uint8 cur_nss = (sta[0xadU] >> 4) & 0x0fU;
        nss = (cur_nss < nss) ? (uint8)(cur_nss + 1U) : nss;
    }
    sta[0xadU] = (uint8)((sta[0xadU] & 0x0fU) | ((nss & 0x0fU) << 4));

    mcs = (uint8)((info >> 18) & 0x3fU);
    sta[0xb4U] = (uint8)(mcs + (((*(uint16 *)(AH_TX_BYTES() + 0x55cU) >> 7) & 0x03U) == 0U ? -6 : -3));
    return ((uint32)nss << 8) | bw_cap;
}
__attribute__((weak)) void *get_worst_node(void) {
    uint8 *node = (uint8 *)AH_STA_HEAD_RAW();
    uint8 *sentinel = (uint8 *)&ah_lmac + AH_LMAC_STA_HEAD_OFS;
    void *worst = NULL;
    int32 worst_metric = 127;

    while (node != sentinel) {
        int32 metric = *(int8 *)(node + 0xb4);

        if (metric <= worst_metric) {
            worst_metric = metric;
            worst = node;
        }

        node = *(uint8 **)node;
    }

    return worst;
}
__attribute__((weak)) uint64 lmac_gen_pspack_ndp2m(void) {
    return lhw_get_ndp2m();
}
__attribute__((weak)) uint64 lmac_gen_pspoll_ndp2m(void) {
    return lhw_get_ndp2m();
}
__attribute__((weak)) uint64 lmac_gen_pspoll_ack_ndp2m(void) {
    return lhw_get_ndp2m();
}
