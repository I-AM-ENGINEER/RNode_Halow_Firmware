/*
 * C reconstruction of the outgoing HW TX path.
 *
 * This file intentionally defines normal lmac_* symbols.  The matching WRAP
 * entries in mars_lmac_tx_orig.c must stay disabled so callers reach these
 * functions through the existing lmac_tx_orig.c override mechanism.
 */
#include "sys_config.h"

#define LOG_LOCAL_LEVEL LOG_LEVEL_MARS_LMAC_TX
#include "lib/logc/log.h"
#include "typesdef.h"

#include "lib/lmac/lmac_ctx.h"
#include "lib/lmac/lmac_regmap.h"
#include "lib/lmac/mars_lmac_tx.h"
#include "lib/skb/skbuff.h"
#include "osal/time.h"

#define LMAC_AGGR_CTRL_START   (1u << 0)
#define LMAC_AGGR_CTRL_AMPDU   (1u << 1)

#define LMAC_U8(off)        (*(volatile uint8_t  *)((uint8_t *)&ah_lmac + (off)))
#define LMAC_U16(off)       (*(volatile uint16_t *)((uint8_t *)&ah_lmac + (off)))
#define LMAC_U32(off)       (*(volatile uint32_t *)((uint8_t *)&ah_lmac + (off)))
#define LMAC_U64(off)       (*(volatile uint64_t *)((uint8_t *)&ah_lmac + (off)))
#define LMAC_I8(off)        (*(volatile int8_t   *)((uint8_t *)&ah_lmac + (off)))
#define LMAC_PTR(off)       (*(void **)((uint8_t *)&ah_lmac + (off)))

#define TXCTX_U8(off)       (*(volatile uint8_t  *)((uint8_t *)&ah_lmac_tx_orig + (off)))
#define TXCTX_U16(off)      (*(volatile uint16_t *)((uint8_t *)&ah_lmac_tx_orig + (off)))

#define LMAC_IRQ_CLR_BO     0x20u
#define LMAC_CCA_STAT_CLR   0x0ff0u
#define LMAC_IRQ_CLR_TX_END 0x04u

extern lmac_tx_ctx_t ah_lmac_tx_orig;
extern lmac_ops_t    ah_ops;
extern void lmac_ant_sel_orig(uint32 ant);

/* lmac_irq_tx_end helpers not already declared in mars_lmac_tx.h */
extern void   lhw_abort_fsm(void);
extern void   ah_tdma_abort(void);
extern void   lmac_delay_us(uint32 us);
extern uint32 lmac_wait_sync(uint32 timeout);
extern void   ah_rfdigicali_config_rx_gain(uint32 stage, uint32 idx);
extern void   ah_wphy_rx_gain_stage_cfg(uint32 stage);
extern void   ah_rfdigicali_bknoise_valid_pd_clr(void);
extern void   ah_rfdigicali_bknoise_calc_en(void);
extern void   lmac_wait_bgscan(uint32 timeout);
extern uint32 ah_wphy_err_code_get(void);
extern void   lmac_rx_gain_cfg(uint32 gain);
extern void   update_rx_buff_addr(void);
extern void   lmac_set_basic_nav(uint32 nav_us);
extern void   lhw_start_rx(uint32 flags);

static inline uint8_t lmac_current_ac(void)
{
    return LMAC_U8(0x9dcu) & 0x0fu;
}

static inline void lmac_common_bo_irq_finish(void)
{
    uint32_t *txvec = (uint32_t *)ah_lmac_tx_orig.pPv0_txvec;

    ah_lmac.bo_nav_ctrl &= (uint16_t)~0x20u;
    if (txvec != NULL)
        ah_lmac.tx_queue_state_74c += txvec[1];

    if (ah_lmac.ap_sleep_timer != 0u) {
        ah_lmac.ap_sleep_timer = os_jiffies();
    }

    if (ah_lmac.bss_rx_activity != 0u) {
        ah_lmac.bss_rx_activity = os_jiffies();
    }
}

int32 lmac_cfg_txvec_part2(void)
{
    uint32_t *txvec = (uint32_t *)ah_lmac_tx_orig.pPv0_txvec;
    uint8_t ant_fmt;
    uint8_t ant;

    if (txvec == NULL) {
        log_warn("txvec_part2: pPv0_txvec is NULL");
        return -1;
    }

    LMAC_HW->TXVEC2 = txvec[1];
    LMAC_HW->TXVEC3 = txvec[2];
    LMAC_HW->TXVEC4 = txvec[3];

    ant_fmt = ((uint8_t *)txvec)[3] & 3u;
    if (ant_fmt == 1u)
        ant = 0u;
    else if (ant_fmt == 2u)
        ant = 1u;
    else
        ant = (LMAC_U8(0x875u) >> 4u) & 1u;

    lmac_ant_sel_orig(ant);
    return 0;
}

uint32 lmac_hdr_dur_calc(uint32 len)
{
    uint32_t timer6 = LMAC_HW->HF_TIMER6;
    uint32_t limit  = timer6 & 0x7fffu;
    uint32_t result;

    if (len < limit)
        result = (timer6 - len) & 0xffffu;
    else
        result = 0u;

    if (LMAC_U8(0x878u) & 1u)
        result = 0x8000u;

    return result;
}

int32 lmac_send_data_to_phy(uint32 ac)
{
    lmac_tx_ctx_buff *aggr;
    uint32_t duration;
    uint16_t tx_duration;
    uint16_t rate_flags;

    if (ac >= 4u) {
        log_warn("send_data_to_phy: ac=%u out of range", ac);
        return -1;
    }

    aggr = &ah_lmac_tx_orig.pTx_ac_aggr_data[ac];
    if (aggr->selected_count == 0u) {
        ah_lmac.tx_irq_error_flags |= 0x4000u;
        log_warn("send_data_to_phy: ac=%u selected_count=0", ac);
        return -1;
    }

    rate_flags = *(uint16_t *)((uint8_t *)aggr + 0x10eu);
    duration = lmac_hdr_dur_calc((aggr->symbol_len + ((rate_flags & 0x01ffu) >> 6)) * 40u);
    tx_duration = ah_lmac_tx_orig.tx_pending_nav_dur;
    if (tx_duration < duration)
        tx_duration = (uint16_t)duration;

    /* DMA scatter-gather: set frame count in TXDMACTL[6:0] */
    LMAC_HW->TXDMACTL = (LMAC_HW->TXDMACTL & ~0x7fu) | (aggr->selected_count & 0x7fu);

    for (uint32 i = 0; i < aggr->selected_count; i++) {
        struct sk_buff *skb = aggr->skb_list[i];
        uint8_t *data;

        if (skb == NULL) {
            log_warn("send_data_to_phy: ac=%u skb[%u]=NULL", ac, i);
            continue;
        }

        data = skb->data;
        if (data != NULL && data[0] != 0xb4u) {
            data[2] = (uint8_t)tx_duration;
            data[3] = (uint8_t)(tx_duration >> 8);
        }

        /* TX_SUB_FRM[i*2] = data ptr, TX_SUB_FRM[i*2+1] = length */
        LMAC_HW->TX_SUB_FRM[i * 2u]      = (uint32_t)data;
        LMAC_HW->TX_SUB_FRM[i * 2u + 1u] = (uint32_t)skb->len;
    }

    LMAC_HW->TX_BYTCNT = aggr->total_len_bytes;

    LMAC_HW->AGGR_CTRL &= ~LMAC_AGGR_CTRL_AMPDU;
    if (aggr->selected_count == 1u)
        LMAC_HW->AGGR_CTRL |= LMAC_AGGR_CTRL_AMPDU;

    LMAC_HW->AGGR_CTRL &= ~LMAC_AGGR_CTRL_START;
    LMAC_HW->AGGR_CTRL |= LMAC_AGGR_CTRL_START;

    return 0;
}

int32 lmac_tx_frm(struct sk_buff *skb)
{
    uint8_t ac = lmac_current_ac();
    lmac_tx_ctx_buff *aggr;

    (void)skb;

    if (ac >= 4u) {
        log_warn("tx_frm: ac=%u out of range", ac);
        return -1;
    }

    aggr = &ah_lmac_tx_orig.pTx_ac_aggr_data[ac];
    if (((aggr->reserved_10f >> 2u) & 1u) == 0u) {
        log_warn("tx_frm: ac=%u not ready flags=0x%02x", ac, aggr->reserved_10f);
        return -1;
    }

    lmac_send_data_to_phy(ac);
    lmac_cfg_txvec_part2();

    aggr->reserved_10f &= (uint8_t)~0x04u;
    ((volatile uint32_t *)&ah_lmac)[(uint32_t)ac + 0x1c7u] += 1u;
    return 0;
}

static void lmac_irq_bo_fns_tx_data_state(void)
{
    uint8_t ac;
    lmac_tx_ctx_buff *aggr;
    struct sk_buff *first_skb;
    uint8_t *txi;
    uint8_t *sta;
    uint32_t txvec1;
    uint32_t tx_airtime;
    uint64_t now;

    lmac_tx_frm(NULL);

    ac = lmac_current_ac();
    if (ac >= 4u) {
        log_warn("bo_state_data: ac=%u out of range after tx_frm", ac);
        return;
    }

    aggr = &ah_lmac_tx_orig.pTx_ac_aggr_data[ac];
    first_skb = aggr->skb_list[0];

    ah_lmac.tx_attempt_count++;
    ah_lmac.tx_mpdu_count       += aggr->selected_count;
    ah_lmac.tx_byte_count_total += aggr->total_len_bytes;
    ah_lmac.tx_sym_time_acc     += (uint16_t)TXCTX_U16(0x560u) + (uint16_t)TXCTX_U16(0x562u);

    if (first_skb == NULL || first_skb->head == NULL) {
        log_warn("bo_state_data: missing first skb/head first=%p", first_skb);
        goto finish_state;
    }

    txi = first_skb->head;
    sta = *(uint8_t **)(txi + 0x0c);

    if (sta != NULL) {
        uint16_t cnt = *(uint16_t *)(sta + 0x1c4) + 1u;
        ah_lmac.pTx_current_sta = sta;
        *(uint16_t *)(sta + 0x1c4) = cnt;
        *(uint16_t *)(sta + 0x1c6) += aggr->selected_count;
        *(uint32_t *)(sta + 0x1c8) += aggr->total_len_bytes;
        *(uint32_t *)(sta + 0x1cc) += aggr->symbol_len;
        *(uint32_t *)(sta + 0x1d0) += (uint16_t)TXCTX_U16(0x560u) + (uint16_t)TXCTX_U16(0x562u);

        txvec1 = *(volatile uint32_t *)((uint8_t *)(LMAC_HW) + 0x064u);
        sta[0xb1] = (uint8_t)((sta[0xb1] & ~0x07u) | (txvec1 & 0x07u));
        sta[0xaf] = (uint8_t)((sta[0xaf] & ~0xf0u) | (((txvec1 >> 6) & 0x0fu) << 4));
        sta[0xae] = (uint8_t)((sta[0xae] & ~0x0fu) | ((txvec1 >> 12) & 0x0fu));
    }

    if ((*(uint16_t *)(txi + 0x26) & 0x0280u) == 0x0280u) {
        txvec1 = *(volatile uint32_t *)((uint8_t *)(LMAC_HW) + 0x064u);
        ah_lmac.tx_last_mcs_bw = (uint8_t)((ah_lmac.tx_last_mcs_bw & ~0x0fu) | ((txvec1 >> 6) & 0x0fu));
        ah_lmac.tx_last_mcs_bw = (uint8_t)((ah_lmac.tx_last_mcs_bw & ~0xf0u) | ((txvec1 >> 8) & 0xf0u));
    }

    txvec1 = *(volatile uint32_t *)((uint8_t *)(LMAC_HW) + 0x064u);
    {
        uint32_t mcs_hi = (txvec1 >> 10) & 0x3u;
        uint32_t rate_idx;
        int32_t scale = 100 - ah_lmac.tx_airtime_scale_offset;
        uint16_t *rate_half = (uint16_t *)rate_tbl;

        if (mcs_hi != 0u)
            mcs_hi = ((txvec1 >> 6) + 1u) & 0x3u;
        rate_idx = (mcs_hi << 3) + ((txvec1 >> 12) & 0x7u);
        tx_airtime = ((uint32_t)rate_half[rate_idx] * (uint32_t)scale) / 100u;
    }

    {
        uint64_t a = ((uint64_t)ah_lmac.tx_airtime_acc_hi << 32) | ah_lmac.tx_airtime_acc_lo;
        a += tx_airtime;
        ah_lmac.tx_airtime_acc_lo = (uint32_t)a;
        ah_lmac.tx_airtime_acc_hi = (uint32_t)(a >> 32);
    }
    now = os_jiffies();
    {
        uint64_t lat = ((uint64_t)ah_lmac.tx_latency_acc_hi << 32) | ah_lmac.tx_latency_acc_lo;
        lat = lat - *(uint64_t *)(txi + 0x34) + now;
        ah_lmac.tx_latency_acc_lo = (uint32_t)lat;
        ah_lmac.tx_latency_acc_hi = (uint32_t)(lat >> 32);
    }

    if ((*(uint32_t *)(txi + 0x08) & 0x02u) != 0u) {
        for (uint32_t off = 0; off != 0xc0u; off += 0x0cu)
            *((volatile int8_t *)((uint8_t *)&ah_lmac + off + 0x247u)) = -128;
    }

    if ((*(uint32_t *)(txi + 0x08) & 0x08u) != 0u) {
        ah_lmac.tx_irq_ctrl_flags |= 0x08u;
    }

    for (uint32_t i = 0; i < aggr->selected_count; i++) {
        struct sk_buff *sub = aggr->skb_list[i];
        uint8_t *sub_txi;

        if (sub == NULL || sub->head == NULL)
            continue;

        sub_txi = sub->head;
        if ((sub_txi[0x25] & 0x02u) != 0u)
            sub_txi[0x27] |= 0x80u;
        sub_txi[0x28]++;
        if (sub_txi[0x2c] != 0u)
            sub_txi[0x2c]--;
    }

    for (uint8_t *node = ah_lmac.pSta_list_head;
         node != (uint8_t *)&ah_lmac.pSta_list_head;
         node = *(uint8_t **)node) {
        node[0x6b] &= (uint8_t)~0x08u;
    }

    ah_lmac.ps_data_delivery_ctrl = 0u;
    ah_lmac.bo_tx_substate = 1u;

finish_state:
    lmac_common_bo_irq_finish();
}

void lmac_irq_bo_fns(void)
{
    LMAC_HW->IRQ_PD = LMAC_IRQ_CLR_BO;
    LMAC_HW->BO_CNT0 = 0u;
    LMAC_HW->CCA_STAT = LMAC_CCA_STAT_CLR;
    ah_lmac.bo_tx_substate = 0u;

    switch (ah_lmac.bo_frame_type) {
    case 1:
        lmac_irq_bo_fns_tx_data_state();
        return;
    case 2:                                     /* send ACK */
        lmac_tx_ack(NULL);
        ah_lmac.bo_tx_substate = 4u;
        break;
    case 3:                                     /* send Block-ACK */
        lmac_tx_ba(NULL);
        if (!(ah_lmac.ba_ctrl_flags & 0x08u))
            ah_lmac.bo_tx_substate = 4u;
        break;
    case 4:                                     /* send RTS */
        lmac_tx_rts(NULL);
        ah_lmac.tx_queue_state_72c++;
        ah_lmac.bo_tx_substate = 2u;
        break;
    case 5:                                     /* send CTS */
        lmac_tx_cts(NULL);
        break;
    case 6:                                     /* send CF-Poll */
        lmac_tx_pv0_cfpoll(NULL);
        ah_lmac.bo_tx_substate = 3u;
        break;
    case 7:                                     /* send CF-End */
        lmac_tx_pv0_cfend(NULL);
        break;
    case 8:                                     /* send Beacon */
        lmac_tx_beacon(NULL);
        if (!(ah_lmac.ps_tim_state & 0x0fu) && !ah_lmac.ps_beacon_sta_cnt)
            ah_lmac.bo_tx_substate = 4u;
        ah_lmac.tx_attempt_count++;
        ah_lmac.tx_queue_state_730++;
        break;
    case 9:                                     /* send Null frame */
        lmac_tx_pv0_null(NULL);
        ah_lmac.bo_tx_substate = 5u;
        break;
    case 10:                                    /* send PS-Poll */
        lmac_tx_pv0_pspoll(NULL);
        ah_lmac.bo_tx_substate = 6u;
        break;
    default:
        ah_lmac.tx_irq_error_flags |= 1u;
        break;
    }
    lmac_common_bo_irq_finish();
}

void lmac_irq_tx_end(void)
{
    uint32_t flags = 0u;

    LMAC_HW->IRQ_PD = LMAC_IRQ_CLR_TX_END;
    lhw_abort_fsm();
    ah_tdma_abort();

    /* LO recalibration if operating channel changed during TX */
    if (LMAC_U8(0x340u) != LMAC_U8(0x33cu) &&
        !(ah_lmac.tx_irq_ctrl_flags & 0x08u) &&
        !(LMAC_U8(0x892u) & 0x02u)) {
        lmac_lo_table_kick(LMAC_U8(0x33cu));
        lmac_delay_us(0x34u);
    }

    if ((LMAC_HW->TX_STAT & 3u) == 0u) {
        /* TX success: capture FCS result and pack TXVEC1 rate/AID info */
        uint32_t txvec1 = LMAC_HW->TXVEC1;
        ah_lmac_tx_orig.tx_last_fcs = LMAC_HW->FCS_RES;
        /* tx_last_rate_packed bit layout:
         * byte[0] [6:0] = TXVEC1[22:16] (partial AID / scrambler seed)
         * byte[0]   [7] = preserved
         * [9:7]         = TXVEC1[2:0]   (MCS low)
         * byte[1] [4:3] = TXVEC1[7:6]   (BW / format)
         * byte[1] [7:5] = TXVEC1[14:12] (MCS high)
         */
        volatile uint8_t *rp = (uint8_t *)&ah_lmac_tx_orig.tx_last_rate_packed;
        rp[0] = (rp[0] & 0x80u) | ((uint8_t)(txvec1 >> 16) & 0x7fu);
        ah_lmac_tx_orig.tx_last_rate_packed =
            (ah_lmac_tx_orig.tx_last_rate_packed & 0xfc7fu) | (uint16_t)((txvec1 & 7u) << 7);
        rp[1] = (rp[1] & 0xe7u) | (uint8_t)(((txvec1 >>  6u) & 3u) << 3);
        rp[1] = (rp[1] & 0x1fu) | (uint8_t)(((txvec1 >> 12u) & 7u) << 5);

        uint32_t sub_state = ah_lmac.bo_tx_substate;
        if (sub_state < 7u) {
            uint32_t mask = 1u << sub_state;
            if (mask & 0x6eu) {
                /* data/ACK/BA path: wait for sync window */
                flags = lmac_wait_sync(0x1c0u);
            } else if (mask & 0x10u) {
                /* RTS path: restore RX gain and background scan */
                if (LMAC_U8(0x37cu) & 0x01u) {
                    lmac_lo_table_kick(LMAC_U8(0x379u));
                    LMAC_U16(0x9d8u)++;
                }
                switch_ctrl_normal_mode();
                if (LMAC_U8(0x361u) & 0x08u) {
                    ah_rfdigicali_config_rx_gain(5u, (uint32_t)LMAC_U8(0x308u));
                    ah_wphy_rx_gain_stage_cfg(5u);
                }
                ah_rfdigicali_config_hw_bknoise(0x640u, 1u);
                ah_rfdigicali_bknoise_valid_pd_clr();
                ah_rfdigicali_bknoise_calc_en();
                lmac_wait_bgscan(0x50u);
            }
        }
    } else {
        /* TX error */
        ah_lmac.tx_irq_error_flags |= 2u;
        if (LMAC_U32(0x3b8u) & 0x10u) {
            uint32_t sub = ah_lmac.bo_frame_type;
            uint32_t err = ah_wphy_err_code_get();
            log_warn("tx_end err: sub=%u wphy=0x%x stat=0x%x tv1=0x%x",
                     sub, err, LMAC_HW->TX_STAT, LMAC_HW->TXVEC1);
        }
        uint16_t gain_reg = LMAC_U16(0x362u);
        LMAC_HW->TX_STAT |= 3u;
        flags = 0u;
        ah_lmac.pTx_current_sta = NULL;
        ah_lmac.bo_tx_substate = 0u;
        lmac_rx_gain_cfg((gain_reg & 0x7ffu) >> 4);
    }

    /* Common tail: reset TX state, restart RX */
    ah_lmac.bo_frame_type = 0u;
    update_rx_buff_addr();
    lmac_tdma_start();
    if (ah_lmac.bo_nav_ctrl & 0x08u)
        lmac_set_basic_nav(((ah_lmac.bo_nav_ctrl & 0x1fffu) >> 6) * 1000u);
    lhw_start_rx(flags);

    /* Duration timer setup if a follow-on frame is pending */
    uint16_t dur = ah_lmac_tx_orig.tx_pending_nav_dur;
    if (dur != 0u) {
        LMAC_HW->TIMER_CTL |= 0x2000u;
        LMAC_HW->IRQ_PD     = 0x80000u;
        LMAC_HW->HF_TIMER6  = (uint32_t)dur;
        LMAC_HW->TIMER_CTL |= 0x1000u;
    }
    if (ah_lmac.bo_tx_substate == 1u)
        ah_lmac_tx_orig.tx_pending_nav_dur = 0u;

    /* Clear NAV continuation bits */
    LMAC_U16(0x90eu) &= (uint16_t)~0x2000u;
    LMAC_U16(0x91eu) &= (uint16_t)~0x2000u;
}
