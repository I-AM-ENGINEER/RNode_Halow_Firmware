/*
 * C reconstruction of the outgoing HW TX path.
 *
 * This file intentionally defines normal lmac_* symbols.  The matching WRAP
 * entries in mars_lmac_tx_orig.c must stay disabled so callers reach these
 * functions through the existing lmac_tx_orig.c override mechanism.
 */
#include "sys_config.h"

#define LOG_LOCAL_LEVEL LOG_DEBUG
#include "lib/logc/log.h"
#include "typesdef.h"

#include "lib/lmac/lmac_ctx.h"
#include "lib/lmac/lmac_regmap.h"
#include "lib/lmac/mars_lmac_tx.h"
#include "lib/skb/skbuff.h"
#include "lib/skb/skb_list.h"
#include "osal/time.h"
#include "osal/semaphore.h"

void lmac_check_tx_queue_empty(void);
extern void lmac_cfg_end_to_limit(uint32_t value);

#define LMAC_AGGR_CTRL_START   (1u << 0)
#define LMAC_AGGR_CTRL_AMPDU   (1u << 1)

#define LMAC_IRQ_CLR_BO     0x20u
#define LMAC_CCA_STAT_CLR   0x0ff0u
#define LMAC_IRQ_CLR_TX_END 0x04u

/* EDCA CW parameters in ah_lmac.ce_ctx (set per-AC before lmac_attempt_tx_orig reads them) */

/* ah_lmac_tx defined in mars_lmac_tx.c */
extern struct lmac_ops *g_pAhLmacOps;

/* Per-AC TX extension: aggregation metadata + inline TX vector */
static inline lmac_tx_ctx_buff *ac_aggr(uint32_t ac)
{
    return &ah_lmac_tx.pTx_ac_aggr_data[ac];
}

extern void   lhw_start_cca(uint32 bw, uint32 dur);
extern void   lhw_start_tx(uint32 flags);
extern uint32  lhw_get_cca_remain(void);
extern void   lmac_lo_table_kick(uint16 id);

/* Forward declarations for functions defined below */
struct sk_buff *lmac_gen_tx_agglist(uint32_t ac, uint32_t rate,
                                   uint32_t bw, uint32_t max_frames);
int32 lmac_attempt_tx(uint32_t ac);

lmac_custom_cfg_t lmac_custom_cfg = {
    .bypass_backoff = 0,    /* standard CSMA/CA for mesh — normal EDCA CW */
    .ignore_cca = HALOW_LBT_IGNORE_CCA_DEF ? 1u : 0u,
    .fast_tx = 1,           /* direct AC queue injection, skip tx_task */
    .cca_margin_db = HALOW_LBT_CCA_MARGIN_DB_DEF,
    .cca_mode = HALOW_LBT_CCA_MODE_DEF,
};

/* lmac_irq_tx_end helpers */
extern void   lhw_abort_fsm(void);
extern void   ah_tdma_abort(void);
extern uint32 lmac_wait_sync(uint32 timeout);
extern uint32 ah_wphy_err_code_get(void);
extern void   lmac_rx_gain_cfg(uint32 gain);
extern void   update_rx_buff_addr(void);
extern void   lhw_start_rx(uint32 flags);
extern uint32 lmac_select_resp_ind(void);
extern void   lmac_delay_us(uint32 us);

static inline uint8_t lmac_current_ac(void)
{
    return ah_lmac.current_ac_flags & 0x0fu;
}

static inline void lmac_common_bo_irq_finish(void)
{
    ah_lmac.bo_nav_ctrl &= (uint16_t)~0x20u;
}

int32 lmac_cfg_txvec_part2(void)
{
    uint32_t *txvec = (uint32_t *)ah_lmac_tx.pPv0_txvec;
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
        ant = (ah_lmac.tx_bw_ctrl_flags >> 4u) & 1u;

    lmac_ant_sel(ant);
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

    if (ah_lmac.force_nav_flags & 1u)
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

    aggr = &ah_lmac_tx.pTx_ac_aggr_data[ac];
    if (aggr->selected_count == 0u) {
        ah_lmac.tx_irq_error_flags |= 0x4000u;
        log_warn("send_data_to_phy: ac=%u selected_count=0", ac);
        return -1;
    }

    rate_flags = *(uint16_t *)&aggr->rate_cfg;
    duration = lmac_hdr_dur_calc((aggr->symbol_len + ((rate_flags & 0x01ffu) >> 6)) * 40u);
    tx_duration = ah_lmac_tx.tx_pending_nav_dur;
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

    aggr = &ah_lmac_tx.pTx_ac_aggr_data[ac];
    if (((aggr->tx_flags >> 2u) & 1u) == 0u) {
        log_warn("tx_frm: ac=%u not ready flags=0x%02x", ac, aggr->tx_flags);
        return -1;
    }

    ah_lmac.mcs_floor = 0u;   /* belt-and-suspenders: keep floor clear for next ac_pd */

    lmac_send_data_to_phy(ac);
    lmac_cfg_txvec_part2();

    aggr->tx_flags &= (uint8_t)~0x04u;
    ah_lmac.ac_tx_attempt_count[ac] += 1u;
    return 0;
}

/*
 * Full CCA/TX pipeline: select AC, rate, build agg list, generate txvec, start CCA.
 * Replaces lmac_irq_ac_pd_orig entirely — bypasses MCS floor and retry table OOB bugs.
 * See AGENTS.md "Architecture note: full lmac_irq_ac_pd rewrite" for call chain.
 */
void lmac_irq_ac_pd(void)
{
    /* 1. Clear AC_PD interrupt status */
    LMAC_HW->IRQ_PD = 0x80u;

    /* 2. Clear MCS floor (fix for MCS0/MCS10) */
    ah_lmac.mcs_floor = 0u;

    /* 3. Bypass backoff: CW=1 for zero-delay CSMA/CA */
    if (lmac_custom_cfg.bypass_backoff) {
        for (uint32_t i = 0u; i < 4u; i++) {
            ah_lmac.ce_ctx.cw_min[i] = 1u;
            ah_lmac.ce_ctx.cw_max[i] = 1u;
        }
    }

    /* 4. Reorder agg lists (complete finished frames) */
    lmac_reorder_tx_agglist();

    /* 5. Clear AC_PD bits for empty queues */
    lmac_check_tx_queue_empty();

    /* 6. Clear state variables */
    ah_lmac.beacon_cur_timer = 0;
    ah_lmac.bo_frame_type = 0;
    ah_lmac.tx_time_part2 = 0;
    ah_lmac.tx_time_ctrl = 0;

    /* 7. Skip beacon/DTIM/AP paths (modem mode only) */

    /* 8. Select AC that has data */
    uint32_t ac = lmac_select_tx_acq();
    if (ac >= 4u)
        return;

    /* 9. Update TX rate for selected AC.
     * Our function outputs: param2=mcs, param3=bw_hint */
    uint8_t mcs, bw_hint;
    if (lmac_update_tx_rate(ac, &mcs, &bw_hint) != 0)
        return;

    /* 10. Generate aggregation list with real MCS.
     * Original code also passes actual MCS directly (MCS10 max 685 symbols
     * vs MCS0-7 max 512). Only truncates if > 9-bit field. */
    struct sk_buff *first_skb = lmac_gen_tx_agglist(ac, bw_hint, mcs, 0x1ffu);
    if (first_skb == NULL)
        return;

    /* 11. Generate TX vector (uses actual MCS for modulation fields) */
    lmac_gen_txvec(ac, bw_hint, mcs);

    /* 12. Update frame TX vector pointer */
    lmac_update_frm_tx_vec();

    /* 13. Adjust END_TO_LIMIT for MCS10 (OFDMA 26-tone needs longer TX window) */
    if (mcs == 10u)
        lmac_cfg_end_to_limit(65000u);
    else
        lmac_cfg_end_to_limit(25000u);

    /* 14. Attempt TX.  BO IRQ dispatches by bo_frame_type; data must be state 1. */
    ah_lmac.bo_frame_type = 1u;
    ah_lmac.bo_tx_substate = 0u;
    int32_t result = lmac_attempt_tx(ac);
    if (result == -1)
        return;

    /* 14. Update stats */
    ah_lmac_tx.tx_pending_nav_dur = 0;
    ah_lmac.ac_tx_attempt_count[ac] += 1u;
}


/*
 * Single-packet agglist: dequeue exactly one skb from the AC queue.
 * Modem mode — no aggregation, each TX is one frame.
 */
struct sk_buff *lmac_gen_tx_agglist(uint32_t ac, uint32_t rate,
                                   uint32_t bw, uint32_t max_frames)
{
    lmac_tx_ctx_buff *aggr;
    lmac_txd_t *txd;
    struct sk_buff *skb;
    uint32_t next_bytes, next_sym;

    (void)max_frames;

    if (ac >= 4u)
        return NULL;

    aggr = &ah_lmac_tx.pTx_ac_aggr_data[ac];

    /* rate_cfg: bits [1:0] = bw_hint, bits [5:2] = mcs */
    aggr->rate_cfg = (uint8_t)(rate & 3u);
    if ((bw <= 7u) || (bw == 10u))
        aggr->rate_cfg = (aggr->rate_cfg & 0xc3u) | (uint8_t)((bw & 0xfu) << 2u);

    /* If aggr already has a queued skb from a previous failed CCA attempt
     * (kept by lmac_reorder_tx_agglist), re-use it.  The memset below
     * would zero skb_list[0] and leak the skb — after ~90 abort cycles
     * the pool is exhausted and the device freezes. */
    if (aggr->queued_count > 0 && aggr->skb_list[0] != NULL) {
        skb = aggr->skb_list[0];
        txd = (lmac_txd_t *)skb->head;
        if (txd != NULL) {
            next_bytes = (uint32_t)txd->aligned_len;
            next_sym = calc_symbol_len(next_bytes + 4u, rate, bw);
            aggr->total_len_bytes = next_bytes;
            aggr->symbol_len = (uint16_t)next_sym;
            aggr->selected_count = 1u;
            aggr->tx_flags &= ~0x04u;
            return skb;
        }
    }

    memset(aggr->skb_list, 0, sizeof(aggr->skb_list));
    aggr->total_len_bytes = 0u;
    aggr->symbol_len      = 0u;
    aggr->selected_count   = 0u;
    aggr->first_seq        = -1;
    aggr->last_seq         = -1;

    skb = skb_list_dequeue(&ah_lmac_tx.pTx_ac_queues[ac]);
    if (skb == NULL)
        return NULL;

    txd = (lmac_txd_t *)skb->head;
    if (txd == NULL)
        return NULL;

    next_bytes = (uint32_t)txd->aligned_len;
    next_sym = calc_symbol_len(next_bytes + 4u, rate, bw);

    aggr->skb_list[0] = skb;
    aggr->selected_count = 1u;
    aggr->queued_count = 1u;
    aggr->total_len_bytes = next_bytes;
    aggr->symbol_len = (uint16_t)next_sym;
    aggr->first_seq = txd->seq_num;
    aggr->last_seq = txd->seq_num;

    aggr->tx_flags &= ~0x04u;

    return aggr->skb_list[0];
}


/*
 * Minimal lmac_attempt_tx: start CCA timer for one AC.
 * Replicates the essential orig logic: check conditions, compute
 * random backoff from CW, call lhw_start_cca + lhw_start_tx.
 */
int32 lmac_attempt_tx(uint32_t ac)
{
    uint32_t cw_min, cw_max, cw, backoff, cca_dur, cca_mode;
    lmac_txd_t *txd;

    if (ac > 3u)
        ac = 3u;

    if (ah_lmac_tx.pTx_ac_aggr_data[ac].queued_count == 0u)
        return -1;

    /* FSM idle check — exact match with original lmac_attempt_tx_orig.
     * Bits [9:8] of FSM_STAT must be zero (FSM sub-state idle).
     * Bits [25:24] of FSM_STAT must be 0b01 (FSM in RX idle mode).
     * Without this check, CCA is started on a non-idle FSM after
     * interference aborts the previous TX, causing a hardware freeze. */
    {
        uint32_t fsm = LMAC_HW->FSM_STAT;
        if (((fsm >> 8) & 3u) != 0u || ((fsm >> 24) & 3u) != 1u)
            return -1;
    }

    /* NAV timer check — original also gates on HF_TIMER3/4 inside attempt_tx */
    if (LMAC_HW->HF_TIMER3 != 0 || LMAC_HW->HF_TIMER4 != 0)
        return -1;

    cw_min = ah_lmac.ce_ctx.cw_min[ac];
    cw_max = ah_lmac.ce_ctx.cw_max[ac];

    cca_dur = lhw_get_cca_remain();
    if (lmac_custom_cfg.ignore_cca || lmac_custom_cfg.bypass_backoff) {
        backoff = 0u;
    } else if (cca_dur == 0u) {
        txd = (lmac_txd_t *)ah_lmac_tx.pTx_ac_aggr_data[ac].skb_list[0]->head;
        uint32_t retry_exp = (uint32_t)txd->retry_count + (uint32_t)txd->_reserved_29;
        if (retry_exp > 0x0fu)
            retry_exp = 0x10u;

        cw = cw_min << retry_exp;
        if (cw_max < cw)
            cw = cw_max;
        if (cw == 0u) {
            ah_lmac.tx_irq_error_flags |= 4u;
            cw = 7u;
        }

        backoff = LMAC_HW->RAND_GEN % cw;
    } else {
        backoff = cca_dur;
    }

    if ((ah_lmac.qa_freq_hop_flags & 2u) == 0u) {
        /* lmac_lo_table_kick() takes a channel-table index, not packed LO frequency bits. */
        lmac_lo_table_kick(ah_lmac.lo_table_index);
    }

    cca_mode = (uint32_t)ah_lmac.ce_ctx.cca_mode_per_ac[ac] + 3u;

    if (lmac_custom_cfg.ignore_cca) {
        lhw_start_cca(2u, 0u);
        LMAC_HW->FSM_CFG &= ~0x200u;
        LMAC_HW->FSM_CFG |= 0x400u;
        ah_lmac_tx.tx_cca_slot_count = (uint16_t)cca_mode;
        ah_lmac_tx.tx_cca_remain = 0;
        lhw_start_tx(0u);
        lmac_cfg_txvec_part1();
        lmac_tdma_start();
    } else {
        LMAC_HW->FSM_CFG |= 0x200u;
        LMAC_HW->FSM_CFG |= 0x400u;
        lhw_start_cca(cca_mode, backoff);
        ah_lmac_tx.tx_cca_slot_count = (uint16_t)cca_mode;
        ah_lmac_tx.tx_cca_remain = (uint16_t)backoff;
        lhw_start_tx(0u);
        lmac_cfg_txvec_part1();
        lmac_tdma_start();
    }

    return 0;
}

static void lmac_irq_bo_fns_tx_data_state(void)
{
    lmac_tx_frm(NULL);
    ah_lmac.bo_tx_substate = 1u;
    lmac_common_bo_irq_finish();
}

void lmac_irq_bo_fns(void)
{
    LMAC_HW->IRQ_PD = LMAC_IRQ_CLR_BO;
    LMAC_HW->BO_CNT0 = 0u;
    LMAC_HW->CCA_STAT = LMAC_CCA_STAT_CLR;
    ah_lmac.bo_tx_substate = 0u;

    switch (ah_lmac.bo_frame_type) {
    case 1:  /* data frame */
        lmac_irq_bo_fns_tx_data_state();
        return;
    case 2:  /* ACK */
        lmac_tx_ack(NULL);
        ah_lmac.bo_tx_substate = 4u;
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
    uint8_t ac = lmac_current_ac();
    lmac_tx_ctx_buff *aggr = (ac < 4u) ? &ah_lmac_tx.pTx_ac_aggr_data[ac] : NULL;

    LMAC_HW->IRQ_PD = LMAC_IRQ_CLR_TX_END;
    lhw_abort_fsm();
    ah_tdma_abort();

    if ((ah_lmac.lo_table_index != ah_lmac.lo_active_index) &&
        !(ah_lmac.tx_irq_ctrl_flags & 0x08u) &&
        !(ah_lmac.qa_freq_hop_flags & 0x02u)) {
        lmac_lo_table_kick(ah_lmac.lo_table_index);
        lmac_delay_us(52u);
    }

    if ((LMAC_HW->TX_STAT & 3u) == 0u) {
        uint32_t sub_state = ah_lmac.bo_tx_substate;
        if (sub_state < 7u && ((1u << sub_state) & 0x6eu)) {
            struct sk_buff *first = aggr ? aggr->skb_list[0] : NULL;
            lmac_txd_t *first_txd = (first && first->head) ? (lmac_txd_t *)first->head : NULL;
            int no_ack = first_txd ? ((first_txd->frame_type_hi & 0x02u) != 0u) : 0;
            if (no_ack)
                lmac_update_tx_state_ack(1u, 0u, 0u);
            else
                flags = lmac_wait_sync(0x1c0u);
        }
    } else {
        ah_lmac.tx_irq_error_flags |= 2u;
        if (ah_lmac.debug_flags & 0x10u) {
            uint32_t err = ah_wphy_err_code_get();
            log_warn("tx_end err: sub=%u wphy=0x%x stat=0x%x tv1=0x%x",
                     ah_lmac.bo_frame_type, err, LMAC_HW->TX_STAT, LMAC_HW->TXVEC1);
        }
        uint16_t gain_reg = ah_lmac.rx_gain_cfg_bits;
        LMAC_HW->TX_STAT |= 3u;
        ah_lmac.bo_tx_substate = 0u;
        lmac_rx_gain_cfg((gain_reg & 0x7ffu) >> 4);
    }

    /* Move completed skbs from aggregate to status queue so the status task
     * calls halow_lmac_tx_status_callback → frees skb → ups g_tx_vacated_sem.
     * Without this, halow_tx blocks forever after TX_BUFFER_SIZE bytes. */
    if (aggr) {
        uint32_t moved = 0;
        for (uint32_t i = 0; i < aggr->selected_count && i < 64; i++) {
            struct sk_buff *skb = aggr->skb_list[i];
            if (skb != NULL) {
                lmac_txd_t *txd = (lmac_txd_t *)skb->head;
                txd->tx_flags |= 0x80u;
                skb_list_queue(&ah_lmac_tx.tx_frames_pending_queue, skb);
                aggr->skb_list[i] = NULL;
                moved++;
            }
        }
        aggr->selected_count = 0u;
        aggr->queued_count   = 0u;
        if (aggr->skb_list[0] != NULL || aggr->selected_count > 0)
            os_sema_up(&ah_lmac_tx.tx_status_sem);
        else
            os_sema_up(&ah_lmac_tx.tx_status_sem);
    }

    ah_lmac.bo_frame_type = 0u;
    update_rx_buff_addr();
    lmac_tdma_start();

    if (ah_lmac.bo_nav_ctrl & 0x08u) {
        lmac_set_basic_nav(((ah_lmac.bo_nav_ctrl & 0x1FFFu) >> 6) * 1000u);
    }

    lhw_start_rx(flags);

    if (ah_lmac_tx.tx_pending_nav_dur != 0u) {
        LMAC_HW->TIMER_CTL |= 0x2000u;
        LMAC_HW->IRQ_PD = 0x80000u;
        LMAC_HW->HF_TIMER6 = ah_lmac_tx.tx_pending_nav_dur;
        LMAC_HW->TIMER_CTL |= 0x1000u;
    }
    if (ah_lmac.bo_tx_substate == 1u) {
        ah_lmac_tx.tx_pending_nav_dur = 0u;
    }

    ah_lmac.bo_nav_ctrl &= (uint16_t)~0x2000u;
}

/* Mark the first frame in the current AC aggregate as done.
 * Modem mode: fire-and-forget — mark done regardless of ACK outcome. */
int32 lmac_update_tx_state_ack(uint32 ok, uint32 arg1, uint32 arg2)
{
    (void)ok; (void)arg1; (void)arg2;
    uint8_t ac = lmac_current_ac();
    if (ac >= 4u)
        return -1;
    struct sk_buff *skb = ah_lmac_tx.pTx_ac_aggr_data[ac].skb_list[0];
    if (skb != NULL && skb->head != NULL) {
        lmac_txd_t *txd = (lmac_txd_t *)skb->head;
        txd->tx_flags |= 0x80u;
    }
    return 0;
}

/* Mark all frames in the current AC aggregate as done after BA. */
int32 lmac_update_tx_state_ba(uint32 start_ssn, uint32 bitmap_lo, uint32 bitmap_hi)
{
    (void)start_ssn; (void)bitmap_lo; (void)bitmap_hi;
    uint8_t ac = lmac_current_ac();
    if (ac >= 4u)
        return -1;
    lmac_tx_ctx_buff *aggr = &ah_lmac_tx.pTx_ac_aggr_data[ac];
    for (uint32_t i = 0u; i < aggr->selected_count; i++) {
        struct sk_buff *skb = aggr->skb_list[i];
        if (skb != NULL && skb->head != NULL) {
            lmac_txd_t *txd = (lmac_txd_t *)skb->head;
            txd->tx_flags |= 0x80u;
        }
    }
    return 0;
}

/* No-op in modem mode: Partial AID requires a STA table entry, which we don't use. */
void lmac_partial_aid_update(void *txi)
{
    (void)txi;
}

void lmac_ant_sel(uint32 ant)
{
    if (!(ah_lmac.tx_bw_ctrl_flags & 4u))
        return;

    if (!((ah_lmac.gpio0_pin_flags | ah_lmac.gpio1_pin_flags) & 0x80u)) {
        jtag_map_set(0);
        ah_lmac.gpio0_pin_flags = (ah_lmac.gpio0_pin_flags & 0x80u) | 0x1fu;
        gpio_set_dir(0x1fu, 1);
        ah_lmac.gpio0_pin_flags = (ah_lmac.gpio0_pin_flags & 0x7fu) | 0x80u;
    }

    if ((int8_t)ah_lmac.gpio0_pin_flags < 0)
        gpio_set_val(ah_lmac.gpio0_pin_flags & 0x7fu, ant != 0);

    if ((int8_t)ah_lmac.gpio1_pin_flags < 0)
        gpio_set_val(ah_lmac.gpio1_pin_flags & 0x7fu, !(ant != 0));

    /* Store antenna bit in TX status area (high byte of tx_last_rate_packed) */
    ((uint8_t *)&ah_lmac_tx.tx_last_rate_packed)[1] =
        (((uint8_t *)&ah_lmac_tx.tx_last_rate_packed)[1] & 0xfbu) | (uint8_t)((ant & 1u) << 2u);
}

uint32 lmac_get_ack_policy(void *txi)
{
    lmac_txd_t *txd = (lmac_txd_t *)txi;
    bool needs_ack;

    if (txd->sta != NULL || (ah_lmac.bo_nav_ctrl & 2u)) {
        uint16_t fc = *(uint16_t *)txd->frame;
        uint32_t type_lo = fc & 0xfu;

        if (type_lo == 8u) {
            /* Management frame — ACK based on multicast bit */
            needs_ack = (bool)(txd->dest_mac[0] & 1u);
            goto done;
        }

        uint32_t type_full = fc & 0xffu;
        if (type_full == 0xd0u || type_full == 0xe0u || type_full == 0xfcu) {
            needs_ack = (bool)(txd->dest_mac[0] & 1u);
            goto done;
        }

        if ((fc & 3u) == 1u) {
            /* Control frame */
            if (((fc & 0xfu) >> 2u) == 1u && ((fc & 0x7fu) >> 5u) == 2u) {
                needs_ack = false;
            } else {
                needs_ack = (bool)(txd->frame[1] >> 7u);
            }
            goto done;
        }
    }

    needs_ack = true;

done:
    if (ah_lmac.bo_nav_ctrl & 0x20u)
        return 1u;
    return needs_ack ? 1u : 0u;
}

uint32 lmac_select_tx_acq(void)
{
    uint32_t ac_pending = LMAC_HW->AC_PD;
    uint32_t rand_val;
    uint8_t sel;

    if ((ac_pending & 0xfu) == 0u)
        return 4u;

    rand_val = LMAC_HW->RAND_GEN % 100u;

    if (ah_lmac.chan_busy_threshold_0 < rand_val) {
        uint32_t sum = ah_lmac.chan_busy_threshold_0 + ah_lmac.chan_busy_threshold_1;
        if (sum < rand_val) {
            if (sum + ah_lmac.chan_busy_threshold_2 < rand_val) {
                if (!(ac_pending & 8u)) {
                    if (!(ac_pending & 4u)) {
                        sel = ((ac_pending ^ 2u) >> 1u) & 1u;
                        goto out;
                    }
                    sel = 2u;
                    goto out;
                }
                /* fall through to AC3 */
            } else {
                if (ac_pending & 4u) {
                    sel = 2u;
                    goto out;
                }
                if (!(ac_pending & 8u)) {
                    sel = ((ac_pending ^ 2u) >> 1u) & 1u;
                    goto out;
                }
                /* fall through to AC3 */
            }
        } else {
            if (ac_pending & 2u) {
                sel = 0u;
                goto out;
            }
            if (!(ac_pending & 8u)) {
                sel = ((ac_pending & 4u) != 0) << 1u;
                goto out;
            }
            /* fall through to AC3 */
        }
    } else {
        if (ac_pending & 1u) {
            sel = 1u;
            goto out;
        }
        if (!(ac_pending & 8u)) {
            sel = ((ac_pending & 4u) != 0) << 1u;
            goto out;
        }
        /* fall through to AC3 */
    }

    sel = 3u;

out:
    ah_lmac.current_ac_flags = (ah_lmac.current_ac_flags & 0xf0u) | sel;
    return sel;
}

int32 lmac_cfg_txvec_part1(void)
{
    uint8_t *txvec = (uint8_t *)ah_lmac_tx.pPv0_txvec;
    uint32_t pwr_arg;
    static uint32_t ft_att_pre = 0;

    if (txvec == NULL)
        return -1;

    if ((*txvec & 0xc0u) == 0xc0u)
        *txvec &= 0x3fu;

    LMAC_HW->TXVEC1 = *(uint32_t *)txvec;

    if (!((uint8_t)ah_lmac.lo_freq_or_channel_bits & 1u)) {
        pwr_arg = (ah_lmac.tx_power_config & 0x1ffu) >> 5u;
    } else {
        pwr_arg = *txvec & 0x1fu;
        uint32_t pwr_cap = (ah_lmac.tx_power_config & 0x1ffu) >> 5u;
        if (pwr_cap < pwr_arg) {
            ah_lmac.tx_irq_error_flags |= 0x2000u;
            pwr_arg = pwr_cap;
        }
        if ((ah_lmac.tx_rate_ctrl_flags & 0xcu) == 0u && pwr_arg < 3u) {
            ah_lmac.tx_irq_error_flags |= 0x2000u;
            pwr_arg = 3u;
        }
    }

    uint8_t bw_pwr_bits = ah_lmac.tx_rate_ctrl_flags & 0xcu;
    if (bw_pwr_bits != 0u) {
        uint32_t pwr_fallback;
        if (bw_pwr_bits == 8u) {
            if (pwr_arg != 0u)
                pwr_fallback = 1u;
            else
                pwr_arg = 1u;
        } else if (bw_pwr_bits == 0xcu) {
            if (pwr_arg != 1u)
                pwr_fallback = 5u;
            else
                pwr_arg = 5u;
        } else {
            goto done_pwr;
        }
        if (pwr_arg == pwr_fallback)
            pwr_arg = pwr_fallback;
    }
done_pwr:
    ah_lmac.pwr_sel_result = (uint8_t)pwr_arg;
    ah_rfdigicali_tx_pwr(pwr_arg);

    if ((ah_lmac.bo_nav_ctrl & 2u) &&
        ((ah_lmac.pwr_ft_att_flags & 0x3fu) != ft_att_pre)) {
        config_ft_att_val();
        ft_att_pre = ah_lmac.pwr_ft_att_flags & 0x3fu;
    }

    return 0;
}

/* BW signal <-> BSS BW lookup tables (from mars_lmac_util.o) */
extern const uint8_t bw_map_sig2bss[4];

struct sk_buff *lmac_get_first_skb(uint32 ac)
{
    if (ac >= 4)
        return NULL;

    uint8_t agg_cnt = ac_aggr(ac)->queued_count;
    if (agg_cnt != 0) {
        return ah_lmac_tx.pTx_ac_aggr_data[ac].skb_list[0];
    }

    return (struct sk_buff *)skb_list_first(
        &ah_lmac_tx.pTx_ac_queues[ac]);
}

int32 lmac_update_tx_rate(uint32 ac, uint8_t *mcs_out, uint8_t *bw_out)
{
    uint32_t mcs, bw_hint;
    struct sk_buff *skb;
    lmac_txd_t *txd;

    if (ac >= 4)
        return -1;

    skb = lmac_get_first_skb(ac);
    if (skb == NULL)
        return -1;

    txd = (lmac_txd_t *)skb->head;

    /* Modem mode: use MCS from TXD directly, fallback to global config */
    mcs = txd->tx_rate_mcs;
    if (mcs > 7u && mcs != 10u)
        mcs = ah_lmac.tx_mcs;
    if (mcs > 7u && mcs != 10u)
        mcs = 1u;

    /* BW from TXD, fallback to global S1G default */
    bw_hint = txd->tx_bw_hint;
    if (bw_hint == 0xffu) {
        bw_hint = 3u;
        if (!(ah_lmac.beacon_s1g_format_flags & 1u))
            bw_hint = 0u;
    }

    /* MCS10 only valid at 1 MHz (bw_hint==3) */
    if (bw_hint != 3u && mcs == 10u)
        mcs = 1u;

    /* Clamp to max MCS limit */
    if (mcs < ah_lmac.tx_mcs_max_limit)
        ; /* mcs is fine */
    else
        mcs = ah_lmac.tx_mcs_max_limit;

    /* BW must not exceed BSS capacity */
    if (ah_lmac.bss_bw < bw_map_sig2bss[bw_hint]) {
        bw_hint = 3u;
        if (!(ah_lmac.beacon_s1g_format_flags & 1u))
            bw_hint = 0u;
    }

    *mcs_out = (uint8_t)mcs;
    *bw_out = (uint8_t)bw_hint;
    ah_lmac.diag_last_tx_mcs = mcs;
    ah_lmac.diag_last_tx_bw_hint = bw_hint;
    return 0;
}

/* ------------------------------------------------------------------ */
/* lmac_reorder_tx_agglist — reorder TX aggregation lists across 4 ACs */
/*                                                                      */
/* Iterates every queued sub-frame.  Completed frames (txd->tx_flags   */
/* bit 7) are acked and queued to tx_frames_pending_queue for the      */
/* status task.  Frames that exceeded their retry/rate budget are      */
/* failed.  Still-live frames are compacted to the front of the list.  */
/* ------------------------------------------------------------------ */
int32 lmac_reorder_tx_agglist(void)
{
    struct sk_buff *skb;
    lmac_txd_t *txd;
    uint8_t *skb_bf;
    uint8_t *sta_p;
    int16_t aligned_len;
    uint32_t ac;
    int32_t i, keep;
    int32_t completed = 0;
    uint8_t agg_cnt;
    uint8_t can_complete;
    uint8_t acked;

    for (ac = 0; ac < 4; ac++) {
        agg_cnt = ac_aggr(ac)->queued_count;
        keep = 0;

        for (i = 0; i < (int32_t)agg_cnt; i++) {
            skb = ac_aggr(ac)->skb_list[i];
            txd = (lmac_txd_t *)skb->head;
            skb_bf = (uint8_t *)skb + 0x2A; /* priority/acked/cloned bitfield byte */

            /* Allow immediate completion when RTS needed but no NAV pending */
            can_complete = ((ah_lmac.bo_nav_ctrl & 0x000Au) == 0x0002u) ? 1u : 0u;

            if ((int8_t)txd->tx_flags < 0) {
                /* ---- completed frame (bit 7 set) ---- */
                *skb_bf = (*skb_bf & 0xEFu) | 0x10u; /* set acked */

                if (txd->_reserved_2c[0] == 0)
                    can_complete = 1;

                /* PM deadline: if frame is not mcast and deadline is set, write margin */
                if ((int8_t)txd->tx_ctrl >= 0 &&
                    ah_lmac.bss_rx_activity != 0)
                    ah_lmac.ap_sleep_timeout_active = 0x96u;

                if (can_complete) goto do_complete;

keep_in_list:
                ac_aggr(ac)->skb_list[keep] = skb;
                keep++;
                continue;
            }

            /* ---- not completed — check rate validity ---- */
            if (txd->_reserved_29 < ah_lmac.rate_budget_threshold && txd->retry_count < ah_lmac.retry_count_threshold &&
                (txd->sta == NULL ||
                 (*(uint8_t *)((uint8_t *)txd->sta + 0x6B) & 0x30) == 0)) {
                /* Rate still within budget — mark power-save in frame header */
                if (txd->retry_count != 0 && (txd->frame_type_lo & 0x14) == 0)
                    skb->data[1] = (skb->data[1] & 0xF7u) | 0x08u;
                if (can_complete) goto do_complete;
                goto keep_in_list;
            }

            /* Rate exceeded — mark not acked, count failure */
            *skb_bf &= 0xEFu; /* clear acked */
            ah_lmac.diag_tx_rate_updates += 1;

do_complete:
            acked = *skb_bf & 0x10;

            if (acked == 0) {
                /* NDP retry: if sta supports it and frame type matches, re-queue */
                sta_p = (uint8_t *)txd->sta;
                if (sta_p != NULL &&
                    (*(sta_p + 0x6B) & 0x02) &&
                    (txd->frame_type_lo & 0x1C) == 0x08 &&
                    (*(uint16_t *)&txd->frame_type_lo & 0xE0) == 0x80) {
                    txd->tx_flags = (txd->tx_flags & 0xF7u) | 0x08u;
                    txd->_reserved_29 = acked; /* 0 */
                    txd->retry_count = acked;  /* 0 */
                    log_debug("retry.null");
                    goto keep_in_list;
                }
            } else {
                if ((txd->frame_type_lo & 0x1C) == 0x08 &&
                    (*(uint16_t *)&txd->frame_type_lo & 0xE0) == 0x80)
                    log_debug("acked.null");
            }

            /* STA statistics update */
            sta_p = (uint8_t *)txd->sta;
            completed++;
            if (sta_p != NULL) {
                aligned_len = txd->aligned_len;
                if (acked == 0) {
                    *(int16_t *)(sta_p + 0x1D6) += 1;            /* tx_fail count */
                    *(int32_t *)(sta_p + 0x1DC) += (int32_t)aligned_len; /* tx_fail bytes */
                } else {
                    *(int16_t *)(sta_p + 0x1D4) += 1;            /* tx_ok count */
                    *(int32_t *)(sta_p + 0x1D8) += (int32_t)aligned_len; /* tx_ok bytes */
                }
            }

            /* Queue to completion list */
            skb_list_queue(&ah_lmac_tx.tx_frames_pending_queue, skb);
            ac_aggr(ac)->queued_count -= 1;
            ah_lmac_tx.pTx_agg_count_per_ac[ac] -= 1;
        }

        /* Clear aggr flags bit 2 (AGGR_CTRL_START) */
        *(uint16_t *)&ac_aggr(ac)->rate_cfg &= ~0x0400u;
    }

    if (completed != 0) {
        os_sema_up(&ah_lmac_tx.tx_status_sem);
        lmac_set_basic_nav(0x64Cu);
    }

    return completed;
}

/* --------------------------------------------------------------------------
 * lmac_gen_txvec  —  build the HW TX vector from the first skb in the aggr
 * list for the given AC.  Returns a pointer to the 13-byte TXVEC buffer
 * inside the aggr data block (offset 0x1C8).
 *
 * Original binary: 0x20039448 (lmac_gen_txvec_orig)
 * -------------------------------------------------------------------------- */
void *lmac_gen_txvec(uint32_t ac, uint32_t bw_hint, uint32_t mcs)
{
    lmac_tx_ctx_buff *aggr = ac_aggr(ac);

    /* First skb in the aggregation list -> TXD at skb->head */
    struct sk_buff *skb = ah_lmac_tx.pTx_ac_aggr_data[ac].skb_list[0];
    uint8_t *txi = (uint8_t *)skb->head;
    lmac_txd_t *txd = (lmac_txd_t *)txi;

    /* --- TX power selection --- */
    uint8_t pwr = (uint8_t)lmac_tx_pwr_sel(txi, mcs);

    /* TXVEC.flags0: power [4:0] | bw_mode [7:6] */
    aggr->txvec.flags0 = (pwr & 0x1F) | (uint8_t)((bw_hint % 3u) << 6);

    /* TXVEC.bw_fmt bits [1:0] <- bw_cfg bit 3 */
    aggr->txvec.bw_fmt = (aggr->txvec.bw_fmt & 0xFC) | ((txd->bw_cfg & 0x0F) >> 3);

    /* --- Preamble mode selection (sets bw_cfg bits [2:1]) --- */
    if (bw_hint == 3) {
        txd->bw_cfg = (txd->bw_cfg & 0xF9) | (0u << 1);
    } else {
        uint32_t fmt = (txd->frame_type_lo & 0x0F) >> 2;
        if (fmt == 1) {
            txd->bw_cfg = (txd->bw_cfg & 0xF9) | (2u << 1);
        } else if (fmt == 0 || fmt == 3) {
            txd->bw_cfg = (txd->bw_cfg & 0xF9) | (1u << 1);
        } else if (fmt == 2) {
            txd->bw_cfg = (txd->bw_cfg & 0xF9) | 0x04;
        }
    }

    /* TXVEC.bw_fmt: preamble [3:2] | MCS [7:4] */
    uint32_t mcs_nib = mcs & 0x0F;
    aggr->txvec.bw_fmt = (aggr->txvec.bw_fmt & 0x03) |
                         (uint8_t)(((txd->bw_cfg & 0x06) >> 1) << 2) |
                         (uint8_t)(mcs_nib << 4);

    /* TXVEC.fmt_byte: scramble code [6:0] from hardware RAND_GEN */
    uint32_t rand_val = LMAC_HW->RAND_GEN;
    uint8_t scramble = (uint8_t)((rand_val % 127u) + 1u) & 0x7F;
    aggr->txvec.fmt_byte = (aggr->txvec.fmt_byte & 0x80) | scramble;

    /* Clear LDPC flag when bw > 1 MHz or bss_bw < 2 */
    if ((aggr->txvec.flags0 & 0xC0) != 0 || ah_lmac.bss_bw < 2)
        txd->frame_type_hi &= 0xDF;

    /* TXVEC.fmt_byte bit 7 <- frame_type_hi bit 5 */
    aggr->txvec.fmt_byte = (aggr->txvec.fmt_byte & 0x7F) |
                           (uint8_t)((txd->frame_type_hi >> 5) << 7);

    /* Copy agg symbol length -> TXVEC.tx_symbol_len */
    uint32_t agg_sym = aggr->symbol_len;
    aggr->txvec.tx_symbol_len = agg_sym;

    /* Zero ctrl words */
    aggr->txvec.ctrl_word_lo = 0;
    aggr->txvec.ctrl_word_hi = 0;

    /* GI flag: only for MCS 5/6/7 under certain power or sta conditions */
    if ((((uint8_t)((aggr->txvec.flags0 & 0x1F) - 3) < 2 ||
          (txd->sta != NULL &&
           *(int8_t *)((uint8_t *)txd->sta + 0xB4) > 0x25)) &&
         ((mcs_nib + 0x0B) & 0x0F) < 3)) {
        txd->bw_cfg = (txd->bw_cfg & 0xFE) | (ah_lmac.chan_busy_threshold_0 & 0x01);
    }

    /* TX vector format type (from preamble bits) */
    uint32_t txvec_type = (aggr->txvec.bw_fmt & 0x0C) >> 2;
    uint8_t *cw_lo = (uint8_t *)&aggr->txvec.ctrl_word_lo;
    uint8_t *cw_hi = (uint8_t *)&aggr->txvec.ctrl_word_hi;

    /* TXVEC.rsvd03 bits [1:0] <- rts_cfg bit 5 */
    aggr->txvec.rsvd03 = (aggr->txvec.rsvd03 & 0xFC) |
                         ((txd->rts_cfg & 0x3F) >> 5);

    /* ---- Format-specific TXVEC fields ---- */
    if (txvec_type == 1) {
        /* S1G Short format */
        cw_lo[0] |= 0x01;
        *(uint16_t *)&aggr->rate_cfg = (*(uint16_t *)&aggr->rate_cfg & 0xFC3F) | 0x0180;

        cw_lo[0] = (cw_lo[0] & 0xE3) |
                    (uint8_t)((txd->tx_ctrl >> 6) & 1) << 2 |
                    (uint8_t)((aggr->txvec.flags0 >> 6) & 1) << 3;

        uint16_t dur_val = *(uint16_t *)&txi[0x30];
        if ((cw_lo[0] & 0x04) == 0)
            dur_val = (uint16_t)((dur_val & 0x3F) << 3) | (ah_lmac.s1g_operation_bits & 0x07);

        *(uint16_t *)&cw_lo[0] =
            (*(uint16_t *)&cw_lo[0] & 0x007F) | (uint16_t)(dur_val << 7);

        cw_lo[2] = (cw_lo[2] & 0x82) |
                    (txd->bw_cfg & 0x01) | 0x04 |
                    (uint8_t)(mcs_nib << 3);
        cw_lo[3] = (uint8_t)((int8_t)(uint8_t)agg_sym * 2) | 0x01;
        cw_hi[0] = (cw_hi[0] & 0xFC) |
                    (uint8_t)((agg_sym & 0xFF) >> 7);

        uint32_t resp = lmac_select_resp_ind();
        uint8_t tmp = (cw_hi[0] & 0xE3) |
                      (uint8_t)((resp & 0x03) << 2) |
                      (uint8_t)((ah_lmac.resp_ind_ctrl & 0x01) << 4);
        cw_hi[0] = (tmp & 0xDF);
    } else if (txvec_type == 0) {
        /* S1G 1 MHz format */
        *(uint16_t *)&aggr->rate_cfg = (*(uint16_t *)&aggr->rate_cfg & 0xFC3F) | 0x0380;

        cw_lo[0] = (cw_lo[0] & 0xAB) |
                    (uint8_t)((txd->bw_cfg & 0x01) << 2) | 0x50;

        *(uint16_t *)&cw_lo[0] =
            (*(uint16_t *)&cw_lo[0] & 0xF87F) |
            (uint16_t)(mcs_nib << 7);

        cw_lo[1] = (cw_lo[1] & 0xF7) | 0x08;

        aggr->txvec.ctrl_word_lo =
            (aggr->txvec.ctrl_word_lo & 0xFFE00FFF) |
            ((agg_sym & 0x1FF) << 12);

        uint32_t resp = lmac_select_resp_ind();
        cw_lo[2] = (cw_lo[2] & 0x9F) |
                    (uint8_t)((resp & 0x03) << 5);
        cw_lo[3] = (cw_lo[3] & 0xFC) |
                    (ah_lmac.resp_ind_ctrl & 0x01);
    } else if (txvec_type == 2) {
        /* S1G >=2 MHz format */
        *(uint16_t *)&aggr->rate_cfg = (*(uint16_t *)&aggr->rate_cfg & 0xFC3F) | 0x0200;

        cw_lo[0] = (cw_lo[0] & 0xE3) |
                    (uint8_t)((txd->tx_ctrl >> 6) & 1) << 2 |
                    (uint8_t)((aggr->txvec.flags0 >> 6) & 1) << 3;

        uint16_t dur_val = *(uint16_t *)&txi[0x30];
        if ((cw_lo[0] & 0x04) == 0)
            dur_val = (uint16_t)((dur_val & 0x3F) << 3) | (ah_lmac.s1g_operation_bits & 0x07);

        *(uint16_t *)&cw_lo[0] =
            (*(uint16_t *)&cw_lo[0] & 0x007F) | (uint16_t)(dur_val << 7);

        cw_lo[2] = (cw_lo[2] & 0x82) |
                    (txd->bw_cfg & 0x01) | 0x04 |
                    (uint8_t)(mcs_nib << 3);
        cw_lo[3] = (uint8_t)((int8_t)(uint8_t)agg_sym * 2) | 0x01;
        cw_hi[0] = (cw_hi[0] & 0xFC) |
                    (uint8_t)((agg_sym & 0xFF) >> 7);

        uint32_t resp = lmac_select_resp_ind();
        uint8_t tmp = (cw_hi[0] & 0xE3) |
                      (uint8_t)((resp & 0x03) << 2) | 0x10;
        cw_hi[0] = (tmp & 0xDF) |
                    (uint8_t)((ah_lmac.resp_ind_ctrl & 0x01) << 5);
    }

    /* Duration estimate for TIM frames */
    if ((txd->tx_flags & 0x40) != 0) {
        ah_lmac.beacon_airtime = (int16_t)(
            (aggr->txvec.tx_symbol_len +
             ((*(uint16_t *)&aggr->rate_cfg & 0x01FF) >> 6)) * 0x28);
    }

    /* Mark TXVEC valid (aggr_hdr_ctrl bit 10) */
    *(uint16_t *)&aggr->rate_cfg = (*(uint16_t *)&aggr->rate_cfg & 0xFBFF) | 0x0400;

    return &aggr->txvec;
}

/* --------------------------------------------------------------------------
 * lmac_select_resp_ind  —  determine response indication for the current
 * aggregation window.  Returns 0 (no response), 2 (ACK/BA expected).
 *
 * Original binary: 0x200393E0 (lmac_select_resp_ind_orig)
 * -------------------------------------------------------------------------- */
uint32_t lmac_select_resp_ind(void)
{
    uint8_t  ac  = ah_lmac.current_ac_flags & 0x0F;
    lmac_tx_ctx_buff *aggr = ac_aggr(ac);

    struct sk_buff *skb = ah_lmac_tx.pTx_ac_aggr_data[ac].skb_list[0];
    lmac_txd_t *txd = (lmac_txd_t *)skb->head;

    /* Multicast / broadcast -> no response */
    if (txd->dest_mac[0] & 0x01)
        return 0;

    /* Frame count in the current aggregation window */
    uint32_t cnt = ((uint32_t)(uint8_t)aggr->last_seq + 1u - (uint8_t)aggr->first_seq) & 0xFFu;

    if (cnt == 1) {
        /* Single frame: check no-ack bit in frame_type_hi */
        return (txd->frame_type_hi & 0x02) ? 0u : 2u;
    }

    if (cnt >= 0x41u) {
        log_error("bad agg count %u", cnt);
        return 0;
    }

    /* Multi-frame (2-64): Block ACK expected */
    return 2;
}

/* --------------------------------------------------------------------------
 * tx_pwr_adjust_by_mcs  —  power backoff for specific MCS values.
 * When power control flags (tx_power_config byte[1] bits [3:2]) are set and base power is
 * 5, reduce power for low-MCS or MCS10 transmissions.
 *
 * Original binary: 0x20036BDC (tx_pwr_adjust_by_mcs_orig)
 * -------------------------------------------------------------------------- */
static int tx_pwr_adjust_by_mcs(int pwr, uint32_t mcs)
{
    if ((((uint8_t *)&ah_lmac.tx_power_config)[1] & 0x0C) != 0 && pwr == 5) {
        if (mcs == 10 || mcs < 3)
            pwr = 0;
        else if ((mcs - 3u) < 2u)   /* MCS 3 or 4 */
            pwr = 1;
    }
    return pwr;
}

/* --------------------------------------------------------------------------
 * lmac_tx_pwr_sel  —  select TX power level for the given MCS and TXD.
 * Returns the power level (0–31).  When the frame has already been started
 * and a station is associated, also stores power tracking context at
 * diag_pwr_sel_* diagnostic fields.
 *
 * Original binary: 0x20037350 (lmac_tx_pwr_sel_orig)
 * -------------------------------------------------------------------------- */
int32_t lmac_tx_pwr_sel(void *txi_ptr, uint32_t mcs)
{
    lmac_txd_t *txd = (lmac_txd_t *)txi_ptr;
    int pwr;

    /* Simple path: frame not started or no station */
    if (!(txd->tx_flags & 0x02) || txd->sta == NULL) {
        return tx_pwr_adjust_by_mcs((ah_lmac.tx_power_config & 0x1FF) >> 5, mcs);
    }

    /* Power control enabled? */
    if (!((uint8_t)ah_lmac.lo_freq_or_channel_bits & 0x01)) {
        pwr = (ah_lmac.tx_power_config & 0x1FF) >> 5;
    } else {
        int8_t rssi = (int8_t)((uint8_t *)&ah_lmac.last_rx_pv0_ctrl_info)[3];
        int threshold = (int)((ah_lmac.tx_power_config & 0x1FFFFFu) >> 14);

        if (rssi < threshold || (ah_lmac.bo_nav_ctrl & 0x02)) {
            pwr = tx_pwr_adjust_by_mcs(ah_lmac.tx_power_config & 0x1F, mcs);
        } else {
            pwr = ah_lmac.tx_power_config & 0x1F;
        }

        /* Retry floor: high retry count -> use fallback (conservative) power */
        if ((int)(int8_t)txd->_reserved_29 >= (int)(int8_t)(ah_lmac.rate_budget_threshold - 2)) {
            pwr = tx_pwr_adjust_by_mcs((ah_lmac.tx_power_config & 0x1FF) >> 5, mcs);
        }
    }

    /* Store power tracking context */
    ah_lmac.diag_pwr_sel_sta_word = *(uint16_t *)((uint8_t *)txd->sta + 0x68);
    ah_lmac.diag_pwr_sel_rx_ctrl = ((uint8_t *)&ah_lmac.last_rx_pv0_ctrl_info)[3];
    ah_lmac.diag_pwr_sel_mcs = (uint8_t)mcs;
    ah_lmac.diag_pwr_sel_power = (uint8_t)pwr;
    ah_lmac.diag_pwr_sel_count += 1;

    return pwr;
}

/* --------------------------------------------------------------------------
 * lmac_update_frm_tx_vec  —  set the PV0 TXVEC pointer from the last AC's
 * aggr data block and kick cfg_txvec_part1 (copy TXVEC → HW registers).
 *
 * Original binary: 0x20037850 (lmac_update_frm_tx_vec_orig)
 * -------------------------------------------------------------------------- */
int32_t lmac_update_frm_tx_vec(void)
{
    uint32_t ac  = ah_lmac.current_ac_flags & 0x0F;

    if (ac >= 4) {
        log_error("bad ac %u", ac);
        return 0;
    }

    lmac_tx_ctx_buff *aggr = ac_aggr(ac);
    if (!(*(uint16_t *)&aggr->rate_cfg & 0x0400u))
        log_debug("txvec not valid");

    ah_lmac_tx.pPv0_txvec = (uint8_t *)&aggr->txvec;
    lmac_cfg_txvec_part1();

    return 0;
}

/* --------------------------------------------------------------------------
 * pv0_ctrl_uplink_txpwr_gen  —  patch power and format fields in the PV0
 * control uplink TX vector (for response frames: PS-Poll, CF-End, etc.).
 *
 * Original binary: 0x20037404 (pv0_ctrl_uplink_txpwr_gen_orig)
 * -------------------------------------------------------------------------- */
uint32_t pv0_ctrl_uplink_txpwr_gen(void)
{
    uint8_t *tv = (uint8_t *)ah_lmac_tx.pPv0_txvec;
    uint16_t pwr_cfg = ah_lmac.tx_power_config;
    uint8_t fmt = tv[1] & 0x0C;

    if (fmt == 0x04) {
        /* S1G Short format */
        uint8_t b = tv[8];
        if (ah_lmac.sta0_added_or_assoc_flag == 1) {   /* STA mode */
            tv[8] = (b & 0xFB) | 0x04;
            *(uint16_t *)&tv[8] &= 0x7F;
        } else {
            tv[8] &= 0xFB;
            *(uint16_t *)&tv[8] = (*(uint16_t *)&tv[8] & 0x7F) | (uint16_t)((ah_lmac.s1g_operation_bits & 0x07) << 7);
        }
    } else if (fmt == 0x08) {
        /* S1G >=2 MHz format */
        uint8_t b = tv[8];
        if (ah_lmac.sta0_added_or_assoc_flag == 1) {
            tv[8] = (b & 0xFB) | 0x04;
        } else {
            tv[8] &= 0xFB;
            *(uint16_t *)&tv[8] = (*(uint16_t *)&tv[8] & 0x7F) | (uint16_t)((ah_lmac.s1g_operation_bits & 0x07) << 7);
        }
    }

    /* Common: adjust power in TXVEC byte 0 */
    int pwr = tx_pwr_adjust_by_mcs((pwr_cfg & 0x1FF) >> 5, tv[1] >> 4);
    tv[0] = (tv[0] & 0xE0) | (uint8_t)(pwr & 0x1F);

    return 0;
}

/* --------------------------------------------------------------------------
 * lmac_tx_ack  —  build and transmit an ACK frame (PV0 response).
 *
 * Original binary: 0x2003A118 (lmac_tx_ack_orig)
 * -------------------------------------------------------------------------- */
int32_t lmac_tx_ack(struct sk_buff *skb)
{
    (void)skb;

    if (!(ah_lmac.tx_ac_state_flags & 0x40)) {
        uint16_t dur = lmac_hdr_dur_calc(ah_lmac.tx_symbol_duration);
        *(uint16_t *)&ah_lmac.ack_resp_frame[2] = dur;
        lhw_cfg_dma_list_cnt(1);
        lhw_cfg_tx_sub_frm(ah_lmac.tx_ac_state_flags & 0x40, (uint32_t)ah_lmac.ack_resp_frame, 0x10);
        LMAC_HW->TX_BYTCNT = 0x14;
        LMAC_HW->AGGR_CTRL &= ~0x01u;
        LMAC_HW->AGGR_CTRL = LMAC_HW->AGGR_CTRL;
    }

    void *sta = lmac_sta_search(0xFFFF, &ah_lmac.ack_resp_frame[4]);
    ah_lmac.pTx_current_sta = sta;

    lmac_cfg_txvec_part2();

    return 0;
}

/* ======================================================================
 * C re-implementations of _orig functions.
 * Each replaces a WRAP entry in mars_lmac_tx_orig.c (comment it out there).
 * ====================================================================== */

/* Trivial forwarders to RF digital calibration */
void lmac_bknoise_calc_en(void)  { ah_rfdigicali_bknoise_calc_en(); }
void lmac_bknoise_calc_dis(void) { ah_rfdigicali_bknoise_calc_dis(); }

/* Get background noise measurement with AGC gain compensation */
uint32 lmac_bknoise_get(void)
{
    os_sleep_us(1);
    int8_t noise = ah_rfdigicali_bknoise_get();
    if (noise == 0)
        return (uint32)(-60);

    uint32 agc_info = ah_wphy_agc_info_get();
    /* Refresh gain ref + base offset from PHY registers.
     * Actual signature: void ah_wphy_rx_gain_para_get(void *dst6, void *dst1)
     * Header declares wrong prototype, cast to fix. */
    ((void(*)(void *, void *))ah_wphy_rx_gain_para_get)(
        ah_lmac.bknoise_gain_ref, &ah_lmac.bknoise_base_offset);

    uint32 gain_idx = agc_info & 0xFu;
    if (gain_idx > 5u)
        gain_idx = 5u;

    int8_t gain_ref = ah_lmac.bknoise_gain_ref[gain_idx];
    int8_t base_off = ah_lmac.bknoise_base_offset;

    return (uint32)(int32_t)(noise - gain_ref - base_off);
}

/* CCA threshold configuration */
void lmac_spec_cca_cfg(uint32_t enable)
{
    uint8_t margin = lmac_custom_cfg.cca_margin_db;

    uint8_t cfg[10];
    if (enable == 1) {
        cfg[0] = 0x9e + margin; cfg[1] = 0xa4 + margin; cfg[2] = 0xa7 + margin; cfg[3] = 0xa7 + margin;
        cfg[4] = 0xaa + margin; cfg[5] = 0xaa + margin;
    } else {
        uint8_t v = (ah_lmac.bss_bw == 3) ? 0xaa : 0xa7;
        cfg[0] = v + margin; cfg[1] = v + margin; cfg[2] = 0xaa + margin; cfg[3] = 0xaa + margin;
        cfg[4] = 0xae + margin; cfg[5] = 0xae + margin;
    }
    cfg[6] = 0xb5 + margin; cfg[7] = 0xb8 + margin; cfg[8] = 0xb8 + margin; cfg[9] = 0xbb + margin;
    ah_wphy_cca_th_cfg(cfg);
}

/* Adjust CCA thresholds based on background RSSI.
 * Adds cca_margin_db (from lmac_custom_cfg) to raise ED threshold
 * above the noise floor so ambient noise doesn't trigger CCA busy. */
void lmac_adjust_cca_threshold(int32_t rssi)
{
    if (rssi < -90) rssi = -90;

    int8_t adj = (int8_t)rssi;
    int8_t cca_max = ah_lmac.cca_threshold_max;
    if (cca_max != 0 && cca_max <= adj)
        adj = cca_max;

    if (ah_lmac.bss_bw == 2)      adj += -3;
    else if (ah_lmac.bss_bw == 3) adj += -6;

    int8_t base = ah_lmac.cca_threshold_offset + adj + lmac_custom_cfg.cca_margin_db;

    uint8_t cfg[10];
    cfg[0] = (uint8_t)(base + 13);
    cfg[1] = (uint8_t)(base + 10);
    cfg[2] = (uint8_t)(base + 18);
    cfg[3] = (uint8_t)(base + 17);
    cfg[4] = (uint8_t)(base + 14);
    cfg[5] = (uint8_t)(base + 14);
    cfg[6] = (uint8_t)(base + 17);
    cfg[7] = (uint8_t)(base + 18);
    cfg[8] = (uint8_t)(base + 18);
    cfg[9] = (uint8_t)(base + 21);
    ah_wphy_cca_th_cfg(cfg);

    if (ah_lmac.obss_cca_param_bits & 0x08) {
        ah_wphy_obss_para_cfg(
            ah_lmac.s1g_operation_bits & 7,
            (ah_lmac.s1g_operation_bits & 0x7ff) >> 3,
            0,
            (int32_t)(int8_t)((uint8_t)((ah_lmac.obss_cca_param_bits & 0x1ff) >> 4)
                              + (int8_t)(base + 18))
        );
    }
}

/* Adjust AGC gain based on background RSSI */
void lmac_adjust_agc_threshold(int32_t rssi)
{
    if (!(ah_lmac.cca_agc_ctrl_flags & 0x08))
        return;

    if (ah_lmac.bss_bw < 2)      rssi += 6;
    else if (ah_lmac.bss_bw == 2) rssi += 3;

    uint16_t gain_bits = ah_lmac.rx_gain_cfg_bits;
    uint16_t new_gain_field;

    if (rssi < (int8_t)ah_lmac.agc_threshold_high) {
        if ((int8_t)ah_lmac.agc_threshold_low < rssi) {
            /* Within acceptable range — keep current gain */
            goto set_gain;
        }
        /* Below low threshold — increase gain */
        if ((gain_bits & 0xff0) != 0x50)
            hgprintf("agc +%d\n", rssi);
        new_gain_field = 5 << 4;
    } else {
        /* Above high threshold — decrease gain */
        if ((gain_bits & 0xff0) != 0x40)
            hgprintf("agc -%d\n", rssi);
        new_gain_field = 4 << 4;
    }

    ah_lmac.rx_gain_cfg_bits = (gain_bits & 0xf00f) | new_gain_field;

set_gain:
    lmac_rx_gain_cfg((ah_lmac.rx_gain_cfg_bits & 0x7ff) >> 4);
}

/* Check if current AC has prepared data and configure its TX vector.
 * Original binary: 0x2003730C (lmac_tx_date_prepared_orig) */
int32 lmac_tx_date_prepared(void)
{
    uint32_t ac = ah_lmac.current_ac_flags & 0xf;
    if (ac < 4 && ((ah_lmac_tx.pTx_ac_aggr_data[ac].tx_flags >> 2) & 1)) {
        ah_lmac_tx.pPv0_txvec = (uint8_t *)&ah_lmac_tx.pTx_ac_aggr_data[ac].txvec;
        lmac_cfg_txvec_part1();
        return 0;
    }
    return -1;
}

/* NDP ACK reception handler.
 * Original binary: 0x20039344 (ndp_ack_rx_hdl_orig) */
extern void data_scrambler(uint32_t seed);

int32 ndp_ack_rx_hdl(uint32 rx0, uint32 rx1, uint32 ext)
{
    if (ah_lmac.ndp_scramble_enable & 1)
        data_scrambler(((uint8_t *)&ah_lmac_tx.tx_last_rate_packed)[0] & 0x7f);

    uint32_t scrambler, ssn, mask;
    if (ext == 0) {
        scrambler = (((uint8_t *)&ah_lmac_tx.tx_last_rate_packed)[0] & 0x7f) | ((ah_lmac_tx.tx_last_fcs >> 23) & 0x180);
        ssn = rx0 >> 24;
        mask = 0x7ff;
    } else {
        scrambler = (((uint8_t *)&ah_lmac_tx.tx_last_rate_packed)[0] & 0x7f) | (((uint16_t *)&ah_lmac_tx.tx_last_fcs)[1] & 0xffffff80);
        ssn = rx1 >> 3;
        mask = 0x3ffff;
    }

    if ((int32_t)ah_lmac.bo_tx_substate == 1) {
        if (((ssn & 1) == 0) && (scrambler == (rx0 & mask) >> 3))
            lmac_update_tx_state_ack(1, 0, 0);
        else
            lmac_update_tx_state_ack(0, 0, 0);
        ah_lmac.bo_tx_substate = 0;
    }
    return 0;
}

/* NDP BA reception handler.
 * Original binary: 0x20039218 (ndp_ba_rx_hdl_orig) */
int32 ndp_ba_rx_hdl(uint32 rx0, uint32 rx1, uint32 ext)
{
    if (ah_lmac.ndp_scramble_enable & 1)
        data_scrambler(((uint8_t *)&ah_lmac_tx.tx_last_rate_packed)[0] & 0x7f);

    uint32_t ba_ssn, ba_bitmap, ba_scrambler, mask;
    if (ext == 0) {
        ba_scrambler = ((uint8_t *)&ah_lmac_tx.tx_last_rate_packed)[0] & 3;
        mask = 0xf;
        ba_ssn = (rx0 & 0xffff) >> 5;
        ba_bitmap = (rx0 & 0xffffff) >> 17;
    } else {
        mask = 0xff;
        ba_ssn = (rx0 & 0xfffff) >> 9;
        ba_scrambler = ((uint8_t *)&ah_lmac_tx.tx_last_rate_packed)[0] & 0x3f;
        ba_bitmap = ((rx1 & 0x1f) << 11) | (rx0 >> 21);
    }

    if ((int32_t)ah_lmac.bo_tx_substate == 1) {
        if ((rx0 & mask) >> 3 == ba_scrambler)
            lmac_update_tx_state_ba(ba_ssn, ba_bitmap, 0);
        ah_lmac.bo_tx_substate = 0;
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * lmac_update_tx_state_cts  —  inform antenna subsystem of CTS outcome.
 * Original binary: 0x20038FE8 (lmac_update_tx_state_cts_orig)
 * -------------------------------------------------------------------------- */
extern void ah_ant_status(uint8_t ant_sel, uint32_t ok);

int32 lmac_update_tx_state_cts(uint32 ok)
{
    ah_ant_status((ah_lmac.tx_antenna_byte >> 2) & 1, ok);
    return 0;
}

/* --------------------------------------------------------------------------
 * PV0 response TX vector update functions.
 * Set the active TX vector pointer to the cached PV0 vector, then run
 * power generation and HW configuration.
 * Original binaries: 0x200379A4 / 0x200379BC / 0x200379D4
 * -------------------------------------------------------------------------- */
int32 lmac_update_pv0_wpba_tx_vec(void)
{
    ah_lmac_tx.pPv0_txvec = (uint8_t *)&ah_lmac_tx.resp_ba_txvec;
    pv0_ctrl_uplink_txpwr_gen();
    lmac_cfg_txvec_part1();
    return 0;
}

int32 lmac_update_pv0_wpack_tx_vec(void)
{
    ah_lmac_tx.pPv0_txvec = (uint8_t *)&ah_lmac_tx.resp_ack_txvec;
    pv0_ctrl_uplink_txpwr_gen();
    lmac_cfg_txvec_part1();
    return 0;
}

int32 lmac_update_pv0_wpcts_tx_vec(void)
{
    ((uint8_t *)&ah_lmac_tx.resp_cts_txvec)[2] = (((uint8_t *)&ah_lmac_tx.resp_cts_txvec)[2] & 0x7f) | (((uint8_t)ah_lmac.lo_freq_or_channel_bits >> 2) << 7);
    ah_lmac_tx.pPv0_txvec = (uint8_t *)&ah_lmac_tx.resp_cts_txvec;
    pv0_ctrl_uplink_txpwr_gen();
    uint8_t *vec = ah_lmac_tx.pPv0_txvec;
    vec[2] &= 0x7f;
    lmac_cfg_txvec_part1();
    return 0;
}

/* --------------------------------------------------------------------------
 * NDP response TX vector update functions.
 * Store response parameters into the cached NDP TX vector, patch format
 * bits based on S1G mode, then configure HW.
 * Original binaries: 0x200378A8 / 0x2003790C / 0x20037958
 * -------------------------------------------------------------------------- */
int32 lmac_update_ndp_cts_tx_vec(uint32 arg0, uint32 arg1)
{
    *(uint32_t *)&ah_lmac_tx.pTx_vector_cache[10] = arg0;
    *(uint32_t *)&ah_lmac_tx.pTx_vector_cache[14] = arg1;
    if (!(ah_lmac.beacon_s1g_format_flags & 1)) {
        ah_lmac_tx.pTx_vector_cache[3] = (ah_lmac_tx.pTx_vector_cache[3] & 0xfc) | (uint8_t)(arg0 >> 30);
        ah_lmac_tx.pTx_vector_cache[14] = (ah_lmac_tx.pTx_vector_cache[14] & 0xdf) | 0x20;
    } else {
        ah_lmac_tx.pTx_vector_cache[13] = (ah_lmac_tx.pTx_vector_cache[13] & 0xfd) | 0x02;
    }
    ah_lmac_tx.pPv0_txvec = &ah_lmac_tx.pTx_vector_cache[10];
    lmac_cfg_txvec_part1();
    return 0;
}

int32 lmac_update_ndp_ack_tx_vec(uint32 arg0, uint32 arg1)
{
    *(uint32_t *)&ah_lmac_tx.pTx_vector_cache[26] = arg0;
    *(uint32_t *)&ah_lmac_tx.pTx_vector_cache[30] = arg1;
    if (!(ah_lmac.beacon_s1g_format_flags & 1)) {
        ah_lmac_tx.pTx_vector_cache[30] = (ah_lmac_tx.pTx_vector_cache[30] & 0xdf) | 0x20;
    } else {
        ah_lmac_tx.pTx_vector_cache[29] = (ah_lmac_tx.pTx_vector_cache[29] & 0xfd) | 0x02;
    }
    ah_lmac_tx.pPv0_txvec = &ah_lmac_tx.pTx_vector_cache[26];
    lmac_cfg_txvec_part1();
    return 0;
}

int32 lmac_update_ndp_ba_tx_vec(uint32 arg0, uint32 arg1)
{
    memcpy(&ah_lmac_tx.pTx_vector_cache[42], &arg0, 4);
    memcpy(&ah_lmac_tx.pTx_vector_cache[46], &arg1, 4);
    if (!(ah_lmac.beacon_s1g_format_flags & 1)) {
        ah_lmac_tx.pTx_vector_cache[46] = (ah_lmac_tx.pTx_vector_cache[46] & 0xdf) | 0x20;
    } else {
        ah_lmac_tx.pTx_vector_cache[45] = (ah_lmac_tx.pTx_vector_cache[45] & 0xfd) | 0x02;
    }
    ah_lmac_tx.pPv0_txvec = &ah_lmac_tx.pTx_vector_cache[42];
    lmac_cfg_txvec_part1();
    return 0;
}

/* ======================================================================
 * Functions called from mars_lmac_tx.c or other files.
 * ====================================================================== */

void lmac_check_tx_queue_empty(void)
{
    static const uint8_t ac_bit[4] = {1, 0, 2, 3};

    for (uint32_t ac = 0; ac < 4; ac++) {
        uint32_t q_cnt = skb_list_count(&ah_lmac_tx.pTx_ac_queues[ac]);
        uint32_t a_cnt = ah_lmac_tx.pTx_ac_aggr_data[ac].queued_count;
        if (q_cnt + a_cnt == 0)
            LMAC_HW->AC_PD &= ~(1u << ac_bit[ac]);
    }
}

void ndp_tx_vec_init_one(uint8_t *tv)
{
    for (int i = 0; i < 8; i++) tv[i] = 0;
    tv[2] = 0x0f;
    tv[1] = 0x10;
}

void lmac_tx_vec_init(void)
{
    for (uint32_t i = 0; i < 5; i++)
        ndp_tx_vec_init_one(&ah_lmac_tx.pTx_vector_cache[i * 16]);
}

/* ======================================================================
 * Stubs required by precompiled mars_lmac.o (liblmac.a).
 * These are called from the binary library but unused in modem mode.
 * ====================================================================== */
int32_t lmac_update_pv0_cfend_tx_vec(void) { return 0; }
int32_t ndp_pspoll_ack_rx_hdl(void) { return 0; }
int32_t lmac_send_mgmt_meas_req(void)    { return 0; }
int32_t lmac_send_mgmt_meas_report(void) { return 0; }
int32_t lmac_send_scan_probe(void)       { return 0; }
int32_t lmac_send_ant_pkt(void)          { return 0; }
int32_t lmac_send_probe_resp(void)       { return 0; }
int32_t lmac_auto_channel_select(void) { return 0; }
uint32_t lmac_vht_info_get(uint32_t info) { (void)info; return 0; }
int32_t lmac_ah_test_tx(struct lmac_ops *ops, struct sk_buff *skb)
{ (void)ops; (void)skb; return 0; }
void lmac_irq_tx_tmo(void)
{
    //hgprintf("\n\nTIMEOUT!!!\n\n");
    lmac_cancle_tx_tmo();
    ah_lmac.bo_frame_type = 0u;
    ah_lmac.bo_tx_substate = 0u;
    lhw_abort_fsm();
    lhw_enable_irq_ac();
}

