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
#include "lib/skb/skb_list.h"
#include "osal/time.h"
#include "osal/semaphore.h"

void lmac_check_tx_queue_empty(void);

#define LMAC_AGGR_CTRL_START   (1u << 0)
#define LMAC_AGGR_CTRL_AMPDU   (1u << 1)

#define LMAC_IRQ_CLR_BO     0x20u
#define LMAC_CCA_STAT_CLR   0x0ff0u
#define LMAC_IRQ_CLR_TX_END 0x04u

/* EDCA CW parameters in ah_lmac.ce_ctx (set per-AC before lmac_attempt_tx_orig reads them) */

extern lmac_tx_ctx_t ah_lmac_tx_orig;
extern struct lmac_ops *g_pAhLmacOps;

/* Raw byte access to LMAC context structs */
#define _LM ((uint8_t *)&ah_lmac)
#define _LMX ((uint8_t *)&ah_lmac_tx_orig)

/* Per-AC TX extension: aggregation metadata + inline TX vector (0x1B8-0x1D7) */
static inline lmac_ac_tx_ext_t *ac_tx_ext(uint32_t ac)
{
    return (lmac_ac_tx_ext_t *)&_LMX[ac * AH_AC_STRIDE + 0x1B8];
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
    .bypass_backoff = 1,   /* skip random CW backoff — safe for point-to-point */
    .ignore_cca = HALOW_LBT_IGNORE_CCA_DEF ? 1u : 0u,
    .fast_tx = 1,          /* direct AC queue injection, skip tx_task */
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

    ah_lmac.mcs_floor = 0u;   /* belt-and-suspenders: keep floor clear for next ac_pd */

    lmac_send_data_to_phy(ac);
    lmac_cfg_txvec_part2();

    aggr->reserved_10f &= (uint8_t)~0x04u;
    ah_lmac.ac_tx_attempt_count[ac] += 1u;
    return 0;
}

/*
 * Two bugs prevent MCS0 and MCS10 from working at 1 MHz:
 *
 * Bug 1 — MCS floor (lmac[0x865]):
 *   lmac_cfg_set_bss_bw() sets lmac[0x865] = 1 on every MCS/channel change.
 *   lmac_update_tx_rate_orig reads this floor via a compound condition whose
 *   comma-operator side-effect forces mcs = floor for MCS0 and MCS10, even
 *   when bw_hint==3 (the otherwise-correct 1 MHz path).
 *   Fix: clear lmac[0x865] = 0 immediately before lmac_irq_ac_pd_orig so
 *   lmac_update_tx_rate_orig always sees floor = 0.
 *
 * Bug 2 — MCS10 retry rate table (rc_tb*_orig):
 *   When txi[0x28] (retry count) != 0, lmac_update_tx_rate_orig looks up the
 *   retry rate table with index = mcs*4 + (bw_hint+1)&3.  For MCS10 with
 *   bw_hint=3: index = 40.  The table was designed for MCS0-7 (32 entries),
 *   so rc_tb1_orig[40] = 0x01 → mcs=1.  lmac_gen_txvec_orig then builds the
 *   txvec with MCS=1 in two places:
 *     buf[1]    bits[7:4]  → TXVEC1 bits[15:12]  (primary MCS field)
 *     buf[8..9] bits[10:7] → TXVEC3 bits[10:7]   (MCS via param_3<<7)
 *   Fix: after lmac_irq_ac_pd_orig, if MCS10 is configured but the txvec
 *   buffer has MCS≠10, patch both fields and rewrite TXVEC1.  lmac_cfg_txvec_
 *   part2 (called later from lmac_tx_frm) reads the same patched buffer and
 *   writes the corrected value to TXVEC2-4.
 *
 *   The aggregate was already sized by lmac_gen_tx_agglist_orig for MCS=1
 *   (conservative: fewer frames than MCS10 would allow), but the payload is
 *   transmitted at the correct MCS=10 air rate.
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
    *(uint32_t *)&_LM[AH_LMAC_BEACON_CUR_OFS] = 0;
    *(uint32_t *)&_LM[AH_LMAC_PSPOLL_ACK_OFS] = 0;
    *(uint32_t *)&_LM[AH_LMAC_TXSTART_OFS] = 0;

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

    /* 10. Generate aggregation list.
     * _orig signature: (ac, bw_hint, mcs, max_frames) */
    struct sk_buff *first_skb = lmac_gen_tx_agglist(ac, bw_hint, mcs, 0x1ffu);
    if (first_skb == NULL)
        return;

    /* 11. Generate TX vector */
    lmac_gen_txvec(ac, bw_hint, mcs);

    /* 12. Update frame TX vector pointer */
    lmac_update_frm_tx_vec();

    /* 13. Attempt TX.  BO IRQ dispatches by bo_frame_type; data must be state 1. */
    ah_lmac.bo_frame_type = 1u;
    ah_lmac.bo_tx_substate = 0u;
    int32_t result = lmac_attempt_tx(ac);
    if (result == -1)
        return;

    /* 14. Update stats */
    *(uint16_t *)&_LMX[AH_DURCACHE_OFS] = 0;
    ah_lmac.ac_tx_attempt_count[ac] += 1u;
}


/*
 * Minimal lmac_gen_tx_agglist: dequeue a bounded run from the AC queue,
 * place it in the aggregate list, compute total symbol length.
 * Returns pointer to first skb on success, NULL on empty queue.
 */
struct sk_buff *lmac_gen_tx_agglist(uint32_t ac, uint32_t rate,
                                   uint32_t bw, uint32_t max_frames)
{
    lmac_tx_ctx_buff *aggr;
    lmac_txd_t *txd;
    struct sk_buff *skb;
    uint32_t limit;

    (void)max_frames;

    if (ac >= 4u)
        return NULL;

    aggr = &ah_lmac_tx_orig.pTx_ac_aggr_data[ac];

    memset(aggr->skb_list, 0, sizeof(aggr->skb_list));
    aggr->total_len_bytes = 0u;
    aggr->symbol_len      = 0u;
    aggr->selected_count   = 0u;
    aggr->first_seq        = -1;
    aggr->last_seq         = -1;

    /* rate_cfg: bits [1:0] = bw_hint, bits [5:2] = mcs (matches _orig binary) */
    aggr->rate_cfg = (uint8_t)(rate & 3u);
    if ((bw <= 7u) || (bw == 10u))
        aggr->rate_cfg = (aggr->rate_cfg & 0xc3u) | (uint8_t)((bw & 0xfu) << 2u);

    limit = ah_lmac.aggcnt;
    if (limit == 0u || limit > 64u)
        limit = 64u;
    if (limit > 16u)
        limit = 16u;

    while (aggr->selected_count < limit) {
        uint32_t next_bytes;
        uint32_t next_sym;
        uint32_t max_bytes;

        skb = (struct sk_buff *)skb_list_first(&ah_lmac_tx_orig.pTx_ac_queues[ac]);
        if (skb == NULL)
            break;

        txd = (lmac_txd_t *)skb->head;
        if (txd == NULL)
            break;

        if (aggr->selected_count != 0u) {
            int16_t expected_seq = (int16_t)(aggr->last_seq + 1);
            if (txd->seq_num != expected_seq)
                break;
        }

        next_bytes = aggr->total_len_bytes + (uint32_t)txd->aligned_len;
        max_bytes = calc_max_agg_bytes(rate, bw);
        if (aggr->selected_count != 0u && next_bytes > max_bytes)
            break;
        next_sym = calc_symbol_len(next_bytes + 4u, rate, bw);

        /* TXVEC3 carries the PPDU symbol count in 9 bits for normal MCS0-7.
         * Keep one MPDU even if the caller supplies an oversized test frame. */
        if (aggr->selected_count != 0u && bw <= 7u && next_sym >= 0x200u)
            break;
        if (aggr->selected_count != 0u && bw == 10u && next_sym >= 0x2adu)
            break;

        skb = skb_list_dequeue(&ah_lmac_tx_orig.pTx_ac_queues[ac]);
        if (skb == NULL)
            break;

        aggr->skb_list[aggr->selected_count] = skb;
        aggr->selected_count++;
        aggr->queued_count++;
        aggr->total_len_bytes = next_bytes;
        aggr->symbol_len = (uint16_t)next_sym;

        if (aggr->first_seq < 0)
            aggr->first_seq = txd->seq_num;
        aggr->last_seq = txd->seq_num;
    }

    if (aggr->selected_count == 0u)
        return NULL;

    aggr->reserved_10f &= ~0x04u;

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

    if (ah_lmac_tx_orig.pTx_ac_aggr_data[ac].queued_count == 0u)
        return -1;

    cw_min = ah_lmac.ce_ctx.cw_min[ac];
    cw_max = ah_lmac.ce_ctx.cw_max[ac];

    cca_dur = lhw_get_cca_remain();
    if (lmac_custom_cfg.ignore_cca) {
        backoff = 0u;
    } else if (lmac_custom_cfg.bypass_backoff) {
        backoff = 0u;
    } else if (cca_dur == 0u) {
        txd = (lmac_txd_t *)ah_lmac_tx_orig.pTx_ac_aggr_data[ac].skb_list[0]->head;
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
        backoff = 0u;
    }

    if ((ah_lmac.qa_freq_hop_flags & 2u) == 0u) {
        /* lmac_lo_table_kick() takes a channel-table index, not packed LO frequency bits. */
        lmac_lo_table_kick(ah_lmac.lo_table_index);
    }

    cca_mode = (uint32_t)_LM[0x1cu + ac] + 3u;
    log_debug("attempt_tx: ac=%u cw=%u/%u backoff=%u cca=%u", ac, cw_min, cw_max, backoff, cca_mode);

    LMAC_HW->FSM_CFG |= 0x200u;
    LMAC_HW->FSM_CFG |= 0x400u;
    if (lmac_custom_cfg.ignore_cca) {
        /* Match the original special path: start a synthetic CCA that
         * completes immediately, then let the normal BO IRQ handler call
         * lmac_tx_frm(). This keeps the expected FSM/IRQ ordering intact. */
        lhw_start_cca(2u, 0u);
        LMAC_HW->FSM_CFG &= ~0x200u;
        LMAC_HW->FSM_CFG |= 0x400u;
        *(uint16_t *)&_LMX[0x560u] = 2u;
        *(uint16_t *)&_LMX[0x562u] = 0u;
        lhw_start_tx(0u);
        lmac_cfg_txvec_part1();
        lmac_tdma_start();
    } else {
        lhw_start_cca(cca_mode, backoff);
        *(uint16_t *)&_LMX[0x560u] = (uint16_t)cca_mode;
        *(uint16_t *)&_LMX[0x562u] = (uint16_t)backoff;
        lhw_start_tx(0u);
        lmac_cfg_txvec_part1();
        lmac_tdma_start();
    }

    log_debug("attempt_tx: done");
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
    case 1:
        lmac_irq_bo_fns_tx_data_state();
        return;
    case 2:                                     /* send ACK */
        lmac_tx_ack(NULL);
        ah_lmac.bo_tx_substate = 4u;
        break;
    case 3:                                     /* send Block-ACK */
        lmac_tx_ba(NULL);
        if (!(ah_lmac.ba_resp_frame[0x16] & 0x08u))
            ah_lmac.bo_tx_substate = 4u;
        break;
    case 4:                                     /* send RTS */
        lmac_tx_rts(NULL);
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
        ah_lmac.bo_tx_substate = 4u;
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
    uint8_t ac = lmac_current_ac();
    lmac_tx_ctx_buff *aggr = (ac < 4u) ? &ah_lmac_tx_orig.pTx_ac_aggr_data[ac] : NULL;

    LMAC_HW->IRQ_PD = LMAC_IRQ_CLR_TX_END;
    lhw_abort_fsm();
    ah_tdma_abort();

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
        for (uint32_t i = 0; i < aggr->selected_count && i < 64; i++) {
            struct sk_buff *skb = aggr->skb_list[i];
            if (skb != NULL) {
                lmac_txd_t *txd = (lmac_txd_t *)skb->head;
                txd->tx_flags |= 0x80u;
                skb_list_queue(&ah_lmac_tx_orig.tx_frames_pending_queue, skb);
                aggr->skb_list[i] = NULL;
            }
        }
        aggr->selected_count = 0u;
        aggr->queued_count   = 0u;
        if (aggr->skb_list[0] != NULL || aggr->selected_count > 0)
            os_sema_up(&ah_lmac_tx_orig.tx_status_sem);
        else
            os_sema_up(&ah_lmac_tx_orig.tx_status_sem);
    }

    ah_lmac.bo_frame_type = 0u;
    update_rx_buff_addr();
    lmac_tdma_start();
    lhw_start_rx(flags);
    if (ac < 4u && skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[ac]) > 0u) {
        LMAC_HW->AC_PD = 0u;
        LMAC_HW->AC_PD = 0xfu;
    }

    /* Re-kick AC_PD if AC queue has more packets — keeps the pipeline full. */
}

/* Mark the first frame in the current AC aggregate as done.
 * Modem mode: fire-and-forget — mark done regardless of ACK outcome. */
int32 lmac_update_tx_state_ack(uint32 ok, uint32 arg1, uint32 arg2)
{
    (void)ok; (void)arg1; (void)arg2;
    uint8_t ac = lmac_current_ac();
    if (ac >= 4u)
        return -1;
    struct sk_buff *skb = ah_lmac_tx_orig.pTx_ac_aggr_data[ac].skb_list[0];
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
    lmac_tx_ctx_buff *aggr = &ah_lmac_tx_orig.pTx_ac_aggr_data[ac];
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
    ((uint8_t *)&ah_lmac_tx_orig.tx_last_rate_packed)[1] =
        (((uint8_t *)&ah_lmac_tx_orig.tx_last_rate_packed)[1] & 0xfbu) | (uint8_t)((ant & 1u) << 2u);
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
    uint8_t *txvec = (uint8_t *)ah_lmac_tx_orig.pPv0_txvec;
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
    ah_lmac.tx_write_only_710 = (uint8_t)pwr_arg;
    ah_rfdigicali_tx_pwr(pwr_arg);

    if ((ah_lmac.bo_nav_ctrl & 2u) &&
        ((ah_lmac.tx_flags_708 & 0x3fu) != ft_att_pre)) {
        config_ft_att_val();
        ft_att_pre = ah_lmac.tx_flags_708 & 0x3fu;
    }

    return 0;
}

/* BW signal <-> BSS BW lookup tables (from mars_lmac_util.o) */
extern const uint8_t bw_map_sig2bss[4];
extern const uint8_t bw_map_bss2sig[4];

/* Retry rate fallback tables (from mars_lmac_tx_origfuncs.o) */
/* Retry rate fallback tables — 10 MCS × 4 BW entries, each byte: [3:0]=new_mcs, [7:4]=bw_index.
 * Extracted from liblmac binary at 0x2004c32b. */
static const uint8_t rc_tb1_data[40] = {
    0x00,0x10,0x20,0x30, 0x01,0x11,0x21,0x31,
    0x01,0x11,0x21,0x31, 0x02,0x12,0x22,0x32,
    0x03,0x13,0x23,0x33, 0x04,0x14,0x24,0x34,
    0x05,0x15,0x25,0x35, 0x06,0x16,0x26,0x36,
    0x00,0x10,0x10,0x20, 0x00,0x11,0x11,0x21
};
static const uint8_t rc_tb3_data[40] = {
    0x0a,0x10,0x10,0x20, 0x00,0x11,0x11,0x11,
    0x00,0x11,0x11,0x12, 0x01,0x11,0x12,0x13,
    0x01,0x11,0x13,0x14, 0x02,0x12,0x14,0x15,
    0x03,0x13,0x15,0x16, 0x04,0x14,0x16,0x17
};
static const uint8_t rc_tb4_data[40] = {
    0x0a,0x10,0x10,0x10, 0x0a,0x11,0x11,0x11,
    0x00,0x11,0x11,0x11, 0x00,0x11,0x11,0x12,
    0x01,0x11,0x12,0x13, 0x01,0x11,0x13,0x14,
    0x02,0x12,0x14,0x15, 0x03,0x13,0x15,0x16
};
static const uint8_t rc_tb5_data[2] = { 0x0a, 0x10 };

extern uint32 ah_get_rate(void *txd);

struct sk_buff *lmac_get_first_skb(uint32 ac)
{
    if (ac >= 4)
        return NULL;

    uint8_t agg_cnt = ac_tx_ext(ac)->agg_cnt;
    if (agg_cnt != 0) {
        return *(struct sk_buff **)(
            &_LMX[ac * AH_AC_STRIDE + AH_AGGLIST_OFS]);
    }

    return (struct sk_buff *)skb_list_first(
        &ah_lmac_tx_orig.pTx_ac_queues[ac]);
}

int32 lmac_update_tx_rate(uint32 ac, uint8_t *mcs_out, uint8_t *bw_out)
{
    uint32_t mcs, bw_hint, floor_mcs, mcs_clamped;
    struct sk_buff *skb;
    lmac_txd_t *txd;
    void *sta;

    if (ac >= 4)
        return -1;

    skb = lmac_get_first_skb(ac);
    if (skb == NULL)
        return -1;

    txd = (lmac_txd_t *)skb->head;

    /* RTS path */
    if (ah_lmac.bo_nav_ctrl & 2u) {
        mcs = txd->tx_rate_mcs;
        if (mcs > 7u) {
            mcs = ah_lmac.tx_mcs;
            if (mcs > 7u && mcs != 10u)
                mcs = 7u;
        }
        if (ah_lmac.qa_freq_hop_flags & 2u) {
            txd->frame_type_hi = (txd->frame_type_hi & 0xdfu) |
                ((1u < ah_lmac.bss_bw) << 5u);
            uint8_t bw_1mhz = 3u;
            if (!(ah_lmac.beacon_s1g_format_flags & 1u))
                bw_1mhz = 0u;
            txd->tx_bw_hint = bw_1mhz;
        }
        bw_hint = txd->tx_bw_hint;
        if (bw_hint == 0xffu)
            bw_hint = ah_lmac.tx_bw_sig;
        goto check_mcast;
    }

    /* Rate control path */
    if ((uint8_t)ah_lmac.lo_freq_or_channel_bits & 8u) {
        mcs = ah_get_rate(txd);
        *(int16_t *)&txd->_reserved_40[2] = (int16_t)mcs;
        mcs_clamped = (mcs & 7u) | ((int32_t)mcs >> 3 & 8u);
        if (!(ah_lmac.tx_bw_ctrl_flags & 2u)) {
            bw_hint = txd->tx_bw_hint;
            if (bw_hint == 0xffu)
                bw_hint = ((int32_t)mcs >> 3) + 3u & 3u;
        } else {
            bw_hint = ah_lmac.tx_bw_sig;
        }
        if (ah_lmac.bss_bw < bw_map_sig2bss[bw_hint]) {
            bw_hint = 3u;
            if (!(ah_lmac.beacon_s1g_format_flags & 1u))
                bw_hint = 0u;
        }
        mcs = mcs_clamped;
        if ((txd->tx_flags & 2u) && (mcs = ah_lmac.tx_mcs, mcs > 7u) &&
            (mcs != 10u && (mcs = txd->tx_rate_mcs, txd->tx_rate_mcs > 7u))) {
            mcs = mcs_clamped;
        }
        goto check_mcast;
    }

    /* Normal path */
    sta = txd->sta;
    if (sta != NULL && (txd->frame_type_lo & 0x200u) == 0x2000000u &&
        (txd->frame_type_lo & 3u) != 1u) {
        mcs = txd->tx_rate_mcs;
        if (mcs > 7u) {
            mcs = ah_lmac.tx_mcs;
            if (mcs > 7u && mcs != 10u)
                mcs = *(uint8_t *)((uint8_t *)sta + 0xad) >> 4u;
        }
        bw_hint = txd->tx_bw_hint;
        if (bw_hint == 0xffu) {
            if (((uint8_t *)&ah_lmac.obss_cca_param_bits)[1] & 4u) {
                bw_hint = *(uint8_t *)((uint8_t *)sta + 0xaf) & 0xfu;
                uint8_t bss_bw = ah_lmac.bss_bw;
                if (bw_map_sig2bss[bw_hint] != bss_bw) {
                    uint8_t fail_cnt = *(uint8_t *)((uint8_t *)sta + 0xb0) + 1u;
                    *(uint8_t *)((uint8_t *)sta + 0xb0) = fail_cnt;
                    if (ah_lmac.bw_restore_count_threshold != fail_cnt)
                        goto check_mcast;
                    bw_hint = bw_map_bss2sig[bss_bw];
                }
                *(uint8_t *)((uint8_t *)sta + 0xb0) = 0;
            } else {
                bw_hint = ah_lmac.tx_bw_sig;
            }
        }
    } else {
        mcs = txd->tx_rate_mcs;
        if (mcs > 7u) {
            mcs = ah_lmac.tx_mcs;
            if (mcs > 7u && mcs != 10u) {
                if (!(ah_lmac.tx_bw_ctrl_flags & 2u))
                    mcs = 1u;
                else
                    mcs = (ah_lmac.tx_bw_sig != 3u) ? 1u : 0u;
            }
        }
        bw_hint = txd->tx_bw_hint;
        if (bw_hint == 0xffu) {
            bw_hint = 3u;
            if (!(ah_lmac.beacon_s1g_format_flags & 1u))
                bw_hint = 0u;
        }
    }

check_mcast:
    /* Multicast rate override */
    if ((*(uint16_t *)&txd->tx_ctrl & 0x280u) == 0x280u) {
        mcs = ah_lmac.mcast_tx_rate;
        bw_hint = 1u;
        uint8_t mcast_bw = ah_lmac.mcast_txbw;
        if (mcs > 7u)
            mcs = 1u;
        if (mcast_bw == 4u) goto apply_limits;
        if (mcast_bw == 8u) { bw_hint = 2u; goto apply_limits; }
        if (mcast_bw == 2u) { bw_hint = 0u; goto apply_limits; }
        bw_hint = ah_lmac.beacon_s1g_format_flags & 1u;
        if (ah_lmac.beacon_s1g_format_flags & 1u) { bw_hint = 3u; }
        goto apply_limits;
    }

    /* Retry rate fallback */
    if (!((uint8_t)ah_lmac.lo_freq_or_channel_bits & 8u) && !(ah_lmac.tx_rate_ctrl_flags & 0x40u) &&
        !(ah_lmac.bo_nav_ctrl & 2u) && txd->retry_count != 0) {
        const uint8_t *tbl;
        int retry = txd->retry_count;
        uint32_t bw_idx = (bw_hint + 1u) & 3u;
        uint32_t tbl_idx = mcs * 4u + bw_idx;

        if (retry == 1)       tbl = rc_tb1_data;
        else if (retry == 2)  tbl = rc_tb1_data;
        else if (retry == 3)  tbl = rc_tb3_data;
        else if (retry == 4)  tbl = rc_tb4_data;
        else                  tbl = rc_tb5_data;

        mcs = tbl[tbl_idx] & 0xfu;
        bw_hint = (tbl[tbl_idx] >> 4) + 3u & 3u;
    }

    if (bw_hint != 3u && mcs == 10u)
        mcs = 1u;

apply_limits:
    if (ah_lmac.beacon_s1g_format_flags & 1u) {
        mcs_clamped = ah_lmac.tx_mcs_max_limit;
        if (mcs < ah_lmac.tx_mcs_max_limit)
            mcs_clamped = mcs;
        floor_mcs = ah_lmac.mcs_floor;
        mcs = mcs_clamped;
        if (floor_mcs != 0u && mcs_clamped != 10u && floor_mcs <= mcs_clamped)
            mcs = mcs_clamped;
        goto finalize;
    }

    mcs_clamped = ah_lmac.tx_mcs_max_limit;
    if (mcs < ah_lmac.tx_mcs_max_limit)
        mcs_clamped = mcs;
    mcs = ah_lmac.mcs_floor;
    if (ah_lmac.mcs_floor < mcs_clamped)
        mcs = mcs_clamped;

finalize:
    if (bw_hint != 3u && mcs > 7u)
        mcs = 1u;

    if (ah_lmac.bss_bw < bw_map_sig2bss[bw_hint]) {
        bw_hint = 3u;
        if (!(ah_lmac.beacon_s1g_format_flags & 1u))
            bw_hint = 0u;
    }

    if (txd->frame_len < ah_lmac.tx_bw_len_threshold) {
        bw_hint = 3u;
        if (!(ah_lmac.beacon_s1g_format_flags & 1u))
            bw_hint = 0u;
    }

    *mcs_out = (uint8_t)mcs;
    *bw_out = (uint8_t)bw_hint;
    ah_lmac.tx_success_pkt_count = mcs;
    ah_lmac.tx_fail_err_count = bw_hint;
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
    uint8_t *lm  = _LM;
    uint8_t *lmx = _LMX;
    struct sk_buff *skb;
    lmac_txd_t *txd;
    uint8_t *skb_bf;
    uint8_t *sta_p;
    int16_t aligned_len;
    uint32_t ac;
    int32_t i, keep;
    int32_t completed = 0;
    uint8_t agg_cnt;
    uint32_t ac_ofs;
    uint8_t can_complete;
    uint8_t acked;

    for (ac = 0; ac < 4; ac++) {
        ac_ofs = ac * AH_AC_STRIDE;
        agg_cnt = ac_tx_ext(ac)->agg_cnt;
        keep = 0;

        for (i = 0; i < (int32_t)agg_cnt; i++) {
            skb = *(struct sk_buff **)&lmx[ac_ofs + AH_AGGLIST_OFS + i * 4];
            txd = (lmac_txd_t *)skb->head;
            skb_bf = (uint8_t *)skb + 0x2A; /* priority/acked/cloned bitfield byte */

            /* Allow immediate completion when RTS needed but no NAV pending */
            can_complete = ((*(uint16_t *)&lm[AH_LMAC_MISC9E2_OFS] & 0x000Au) == 0x0002u) ? 1u : 0u;

            if ((int8_t)txd->tx_flags < 0) {
                /* ---- completed frame (bit 7 set) ---- */
                *skb_bf = (*skb_bf & 0xEFu) | 0x10u; /* set acked */

                if (txd->_reserved_2c[0] == 0)
                    can_complete = 1;

                /* PM deadline: if frame is not mcast and deadline is set, write margin */
                if ((int8_t)txd->tx_ctrl >= 0 &&
                    (*(uint32_t *)&lm[AH_LMAC_PM_DEADLINE_LO_OFS] != 0 ||
                     *(uint32_t *)&lm[AH_LMAC_PM_DEADLINE_HI_OFS] != 0))
                    *(uint16_t *)&lm[AH_LMAC_PM_MARGIN_OFS] = 0x96u;

                if (can_complete) goto do_complete;

keep_in_list:
                *(struct sk_buff **)&lmx[ac_ofs + AH_AGGLIST_OFS + keep * 4] = skb;
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
            ah_lmac.tx_state_75c += 1;

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
            skb_list_queue(&ah_lmac_tx_orig.tx_frames_pending_queue, skb);
            ac_tx_ext(ac)->agg_cnt -= 1;
            ah_lmac_tx_orig.pTx_agg_count_per_ac[ac] -= 1;
        }

        /* Clear aggr flags bit 2 (AGGR_CTRL_START) */
        ac_tx_ext(ac)->aggr_hdr_ctrl &= ~0x0400u;
    }

    if (completed != 0) {
        os_sema_up(&ah_lmac_tx_orig.tx_status_sem);
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
    uint8_t  *lmx = _LMX;
    uint8_t  *lm  = _LM;
    uint32_t  ac_ofs = ac * AH_AC_STRIDE;
    lmac_ac_tx_ext_t *ext = ac_tx_ext(ac);

    /* First skb in the aggregation list -> TXD at skb->head */
    struct sk_buff *skb = *(struct sk_buff **)&lmx[ac_ofs + AH_AGGLIST_OFS];
    uint8_t *txi = (uint8_t *)skb->head;
    lmac_txd_t *txd = (lmac_txd_t *)txi;

    /* --- TX power selection --- */
    uint8_t pwr = (uint8_t)lmac_tx_pwr_sel(txi, mcs);

    /* TXVEC.flags0: power [4:0] | bw_mode [7:6] */
    ext->txvec.flags0 = (pwr & 0x1F) | (uint8_t)((bw_hint % 3u) << 6);

    /* TXVEC.bw_fmt bits [1:0] <- bw_cfg bit 3 */
    ext->txvec.bw_fmt = (ext->txvec.bw_fmt & 0xFC) | ((txd->bw_cfg & 0x0F) >> 3);

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
    ext->txvec.bw_fmt = (ext->txvec.bw_fmt & 0x03) |
                         (uint8_t)(((txd->bw_cfg & 0x06) >> 1) << 2) |
                         (uint8_t)(mcs_nib << 4);

    /* TXVEC.fmt_byte: scramble code [6:0] from hardware RAND_GEN */
    uint32_t rand_val = LMAC_HW->RAND_GEN;
    uint8_t scramble = (uint8_t)((rand_val % 127u) + 1u) & 0x7F;
    ext->txvec.fmt_byte = (ext->txvec.fmt_byte & 0x80) | scramble;

    /* Clear LDPC flag when bw > 1 MHz or bss_bw < 2 */
    if ((ext->txvec.flags0 & 0xC0) != 0 || ah_lmac.bss_bw < 2)
        txd->frame_type_hi &= 0xDF;

    /* TXVEC.fmt_byte bit 7 <- frame_type_hi bit 5 */
    ext->txvec.fmt_byte = (ext->txvec.fmt_byte & 0x7F) |
                           (uint8_t)((txd->frame_type_hi >> 5) << 7);

    /* Copy agg symbol length -> TXVEC.tx_symbol_len */
    uint32_t agg_sym = ext->aggr_sym_len;
    ext->txvec.tx_symbol_len = agg_sym;

    /* Zero ctrl words */
    ext->txvec.ctrl_word_lo = 0;
    ext->txvec.ctrl_word_hi = 0;

    /* GI flag: only for MCS 5/6/7 under certain power or sta conditions */
    if ((((uint8_t)((ext->txvec.flags0 & 0x1F) - 3) < 2 ||
          (txd->sta != NULL &&
           *(int8_t *)((uint8_t *)txd->sta + 0xB4) > 0x25)) &&
         ((mcs_nib + 0x0B) & 0x0F) < 3)) {
        txd->bw_cfg = (txd->bw_cfg & 0xFE) | (ah_lmac.chan_busy_threshold_0 & 0x01);
    }

    /* TX vector format type (from preamble bits) */
    uint32_t txvec_type = (ext->txvec.bw_fmt & 0x0C) >> 2;
    uint8_t *cw_lo = (uint8_t *)&ext->txvec.ctrl_word_lo;
    uint8_t *cw_hi = (uint8_t *)&ext->txvec.ctrl_word_hi;

    /* TXVEC.rsvd03 bits [1:0] <- rts_cfg bit 5 */
    ext->txvec.rsvd03 = (ext->txvec.rsvd03 & 0xFC) |
                         ((txd->rts_cfg & 0x3F) >> 5);

    /* ---- Format-specific TXVEC fields ---- */
    if (txvec_type == 1) {
        /* S1G Short format */
        cw_lo[0] |= 0x01;
        ext->aggr_hdr_ctrl = (ext->aggr_hdr_ctrl & 0xFC3F) | 0x0180;

        cw_lo[0] = (cw_lo[0] & 0xE3) |
                    (uint8_t)((txd->tx_ctrl >> 6) & 1) << 2 |
                    (uint8_t)((ext->txvec.flags0 >> 6) & 1) << 3;

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
        ext->aggr_hdr_ctrl = (ext->aggr_hdr_ctrl & 0xFC3F) | 0x0380;

        cw_lo[0] = (cw_lo[0] & 0xAB) |
                    (uint8_t)((txd->bw_cfg & 0x01) << 2) | 0x50;

        *(uint16_t *)&cw_lo[0] =
            (*(uint16_t *)&cw_lo[0] & 0xF87F) |
            (uint16_t)(mcs_nib << 7);

        cw_lo[1] = (cw_lo[1] & 0xF7) | 0x08;

        ext->txvec.ctrl_word_lo =
            (ext->txvec.ctrl_word_lo & 0xFFE00FFF) |
            ((agg_sym & 0x1FF) << 12);

        uint32_t resp = lmac_select_resp_ind();
        cw_lo[2] = (cw_lo[2] & 0x9F) |
                    (uint8_t)((resp & 0x03) << 5);
        cw_lo[3] = (cw_lo[3] & 0xFC) |
                    (ah_lmac.resp_ind_ctrl & 0x01);
    } else if (txvec_type == 2) {
        /* S1G >=2 MHz format */
        ext->aggr_hdr_ctrl = (ext->aggr_hdr_ctrl & 0xFC3F) | 0x0200;

        cw_lo[0] = (cw_lo[0] & 0xE3) |
                    (uint8_t)((txd->tx_ctrl >> 6) & 1) << 2 |
                    (uint8_t)((ext->txvec.flags0 >> 6) & 1) << 3;

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
            (ext->txvec.tx_symbol_len +
             ((ext->aggr_hdr_ctrl & 0x01FF) >> 6)) * 0x28);
    }

    /* Mark TXVEC valid (aggr_hdr_ctrl bit 10) */
    ext->aggr_hdr_ctrl = (ext->aggr_hdr_ctrl & 0xFBFF) | 0x0400;

    return &ext->txvec;
}

/* --------------------------------------------------------------------------
 * lmac_select_resp_ind  —  determine response indication for the current
 * aggregation window.  Returns 0 (no response), 2 (ACK/BA expected).
 *
 * Original binary: 0x200393E0 (lmac_select_resp_ind_orig)
 * -------------------------------------------------------------------------- */
uint32_t lmac_select_resp_ind(void)
{
    uint8_t *lmx = _LMX;
    uint8_t  ac  = _LM[AH_LMAC_ACLAST_OFS] & 0x0F;
    uint32_t ac_ofs = (uint32_t)ac * AH_AC_STRIDE;
    lmac_ac_tx_ext_t *ext = ac_tx_ext(ac);

    struct sk_buff *skb = *(struct sk_buff **)&lmx[ac_ofs + AH_AGGLIST_OFS];
    lmac_txd_t *txd = (lmac_txd_t *)skb->head;

    /* Multicast / broadcast -> no response */
    if (txd->dest_mac[0] & 0x01)
        return 0;

    /* Frame count in the current aggregation window */
    uint32_t cnt = ((uint32_t)ext->seq_win_end + 1u - ext->seq_win_start) & 0xFFu;

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
 * When power control flags (lm[0x36D] bits [3:2]) are set and base power is
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
 * lm[0x83E–0x848].
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
    ah_lmac.tx_write_word_848 = *(uint16_t *)((uint8_t *)txd->sta + 0x68);
    ah_lmac.tx_write_byte_841 = ((uint8_t *)&ah_lmac.last_rx_pv0_ctrl_info)[3];
    ah_lmac.tx_write_byte_83e = (uint8_t)mcs;
    ah_lmac.tx_byte_840 = (uint8_t)pwr;
    ah_lmac.tx_state_844 += 1;

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
    uint8_t *lm  = _LM;
    uint32_t ac  = lm[AH_LMAC_ACLAST_OFS] & 0x0F;

    if (ac >= 4) {
        log_error("bad ac %u", ac);
        return 0;
    }

    lmac_ac_tx_ext_t *ext = ac_tx_ext(ac);
    if (!(ext->aggr_hdr_ctrl & 0x0400u))
        log_debug("txvec not valid");

    ah_lmac_tx_orig.pPv0_txvec = (uint8_t *)&ext->txvec;
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
    uint8_t *tv = (uint8_t *)ah_lmac_tx_orig.pPv0_txvec;
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
 * lmac_tx_ba  —  build and transmit a Block ACK frame (PV0 response).
 *
 * Original binary: 0x2003A0A8 (lmac_tx_ba_orig)
 * -------------------------------------------------------------------------- */
int32_t lmac_tx_ba(struct sk_buff *skb)
{
    (void)skb;

    if (!(ah_lmac.tx_ac_state_flags & 0x20)) {
        if (!(ah_lmac.bo_nav_ctrl & 0x02)) {
            uint16_t dur = lmac_hdr_dur_calc(ah_lmac.tx_time_part2);
            *(uint16_t *)&ah_lmac.ba_resp_frame[2] = dur;
        }
        lhw_cfg_dma_list_cnt(1);
        lhw_cfg_tx_sub_frm(0, (uint32_t)ah_lmac.ba_resp_frame, 0x22);
        LMAC_HW->TX_BYTCNT = 0x26;
        LMAC_HW->AGGR_CTRL &= ~0x01u;
        LMAC_HW->AGGR_CTRL = LMAC_HW->AGGR_CTRL;
    }

    void *sta = lmac_sta_search(0xFFFF, &ah_lmac.ba_resp_frame[4]);
    ah_lmac.pTx_current_sta = sta;

    lmac_cfg_txvec_part2();

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

/* --------------------------------------------------------------------------
 * lmac_tx_cts  —  build and transmit a CTS frame (PV0 response).
 *
 * Original binary: 0x2003A178 (lmac_tx_cts_orig)
 * -------------------------------------------------------------------------- */
int32_t lmac_tx_cts(struct sk_buff *skb)
{
    (void)skb;

    if (!(ah_lmac.tx_ac_state_flags & 0x10)) {
        lhw_cfg_dma_list_cnt(1);
        lhw_cfg_tx_sub_frm(ah_lmac.tx_ac_state_flags & 0x10, (uint32_t)ah_lmac.cts_resp_frame, 0x10);
        LMAC_HW->TX_BYTCNT = 0x14;

        if (ah_lmac.beacon_pending_state_flags & 0x10) {
            int16_t remain = (int16_t)lmac_dtim_timer_rem();
            *(int16_t *)&ah_lmac.cts_resp_frame[2] = remain + 4000;
            memcpy(&ah_lmac.cts_resp_frame[4], ah_lmac.mac_addr, 6);
        }

        LMAC_HW->AGGR_CTRL &= ~0x01u;
        LMAC_HW->AGGR_CTRL = LMAC_HW->AGGR_CTRL;
    }

    void *sta = lmac_sta_search(0xFFFF, &ah_lmac.cts_resp_frame[4]);
    ah_lmac.pTx_current_sta = sta;

    lmac_cfg_txvec_part2();

    return 0;
}

/* --------------------------------------------------------------------------
 * lmac_tx_rts  —  build and transmit an RTS frame, then bump the retry
 * counter for all frames in the current AC's aggregation list.
 *
 * Original binary: 0x2003A320 (lmac_tx_rts_orig)
 * -------------------------------------------------------------------------- */
int32_t lmac_tx_rts(struct sk_buff *skb)
{
    uint8_t *lmx = _LMX;
    (void)skb;

    lhw_cfg_dma_list_cnt(1);
    lhw_cfg_tx_sub_frm(0, (uint32_t)ah_lmac.rts_resp_frame, 0x10);

    LMAC_HW->TX_BYTCNT = 0x18;
    LMAC_HW->AGGR_CTRL = (LMAC_HW->AGGR_CTRL & ~0x03u) | 0x03u;

    void *sta = lmac_sta_search(0xFFFF, &ah_lmac.rts_resp_frame[4]);
    ah_lmac.pTx_current_sta = sta;

    lmac_cfg_txvec_part2();

    /* Increment _reserved_29 for every frame in the aggr list */
    uint32_t ac = ah_lmac.tx_ac_state_flags & 0x0F;
    if (ac < 4) {
        uint32_t ac_ofs = ac * AH_AC_STRIDE;
        lmac_ac_tx_ext_t *ext = ac_tx_ext(ac);
        uint8_t cnt = ext->agg_num;
        for (uint32_t i = 0; i < cnt; i++) {
            struct sk_buff *s = *(struct sk_buff **)&lmx[ac_ofs + AH_AGGLIST_OFS + i * 4];
            lmac_txd_t *t = (lmac_txd_t *)s->head;
            t->_reserved_29 += 1;
        }
    }

    return 0;
}

/* ======================================================================
 * C re-implementations of _orig functions.
 * Each replaces a WRAP entry in mars_lmac_tx_orig.c (comment it out there).
 * ====================================================================== */

/* Trivial forwarders to RF digital calibration */
void lmac_bknoise_calc_en(void)  { ah_rfdigicali_bknoise_calc_en(); }
void lmac_bknoise_calc_dis(void) { ah_rfdigicali_bknoise_calc_dis(); }

/* Get background noise measurement — simplified to avoid PHY crash */
uint32 lmac_bknoise_get(void)
{
    os_sleep_us(1);
    int8_t noise = ah_rfdigicali_bknoise_get();
    if (noise == 0)
        return (uint32)(-60);

    return (uint32)(noise - ah_lmac.bknoise_base_offset);
}

/* Forward declaration needed by bgrssi_update */
static uint32_t bgrssi_init_done;

/* Update background RSSI: accumulate per-channel noise stats and adjust thresholds */
void lmac_bgrssi_update(void)
{
    if (!ah_rfdigicali_bknoise_valid_pd_get())
        return;

    int32_t noise = (int32_t)lmac_bknoise_get();
    ah_rfdigicali_bknoise_calc_dis();
    ah_rfdigicali_bknoise_valid_pd_clr();

    uint8_t ch_idx = ah_lmac.bgrssi_chan_index;
    uint8_t *lm = _LM;
    int32_t ch_base = ch_idx * 0x18;

    /* Bounds check: ch_base + max offset (0xCC+3) must fit in ah_lmac (0xBC4) */
    if (ch_base + 0xCF >= 0xBC4) {
        ah_lmac.bgrssi_chan_index = 0;
        return;
    }

    int32_t noise_sum  = *(int32_t *)&lm[ch_base + 0xC8];
    int32_t noise_cnt  = *(int32_t *)&lm[ch_base + 0xCC];
    int32_t new_cnt    = noise_cnt + 1;

    *(int32_t *)&lm[ch_base + 0xC8] = noise_sum + noise;
    *(int32_t *)&lm[ch_base + 0xCC] = new_cnt;

    if (noise < (int8_t)lm[ch_base + 0xC5])
        lm[ch_base + 0xC5] = (uint8_t)noise;
    if ((int8_t)lm[ch_base + 0xC6] < noise)
        lm[ch_base + 0xC6] = (uint8_t)noise;

    uint32_t budget = (*((uint32_t *)&ah_lmac.cca_ctrl_low_byte) & 0x7ffff) >> 0xc;
    if ((int32_t)budget <= new_cnt) {
        int8_t ch_max = (int8_t)lm[ch_base + 0xC6];
        int8_t ch_min = (int8_t)lm[ch_base + 0xC5];
        int8_t avg = (int8_t)(((noise_sum + noise - ch_max - ch_min) / (noise_cnt - 1)));
        lm[ch_base + 0xC7] = (uint8_t)avg;

        uint8_t primary_ch = ah_lmac.lo_table_index;
        if (primary_ch == ch_idx) {
            ah_lmac.tx_write_flags_70d = (uint8_t)avg;
            ah_lmac.tx_write_flags_70c = (uint8_t)ch_min;
            ah_lmac.tx_write_flags_70e = (uint8_t)ch_max;

            if (!bgrssi_init_done) {
                ah_lmac.cca_threshold_base = avg;
                bgrssi_init_done = 1;
            } else {
                int8_t cur = ah_lmac.cca_threshold_base;
                if (avg < cur)
                    avg = avg / 2 + cur / 2;
                ah_lmac.cca_threshold_base = avg;
            }

            if (ah_lmac.cca_agc_ctrl_flags & 0x04)
                lmac_adjust_cca_threshold((int32_t)ah_lmac.cca_threshold_base);
            lmac_adjust_agc_threshold((int32_t)ah_lmac.cca_threshold_base);

            if ((ah_lmac.tx_channel_set_824 & 1) && ah_lmac.tx_result_834 > 0x27ff) {
                uint8_t *tdma_buf = (uint8_t *)ah_lmac.init_param_tdma_buff;
                for (int16_t *p = (int16_t *)(tdma_buf + 0x1e00);
                     p != (int16_t *)(tdma_buf + 0x1e80); p++) {
                    int32_t v = (int32_t)*p;
                    if (v < 0) v = -v;
                    ah_lmac.tx_state_7e0 += v;
                    if ((int16_t)ah_lmac.tx_state_7e4 < v)
                        ah_lmac.tx_state_7e4 = (uint16_t)v;
                    if (ah_lmac.bgrssi_spur_threshold < v)
                        ah_lmac.tx_state_7e6++;
                }
                ah_lmac.tx_state_7e8++;
            }
        }

        lm[ch_base + 0xC5] = 0;
        lm[ch_base + 0xC6] = 0x80;
        *(int32_t *)&lm[ch_base + 0xC8] = 0;
        *(int32_t *)&lm[ch_base + 0xCC] = 0;
    }

    /* Channel rotation */
    if (!(ah_lmac.auto_chan_switch_flags & 1)) {
        ch_idx = ah_lmac.lo_table_index;
    } else {
        uint8_t next = ah_lmac.bgrssi_chan_index + 1;
        if (next < ah_lmac.chan_list_count)
            return;
        ch_idx = 0;
    }
    ah_lmac.bgrssi_chan_index = ch_idx;
}

/* Switch control: backs up and clears sys_con8 bits 30-31 (TX/RX switch) */
#define SYS_CTRL_REG_BASE  ((volatile uint32_t *)0x40026000u)
static uint32_t sys_con8_bak;

void switch_ctrl_normal_mode(void)
{
    sys_con8_bak = SYS_CTRL_REG_BASE[0x54 / 4];
    SYS_CTRL_REG_BASE[0x54 / 4] &= ~0xC0000000u;
}

void switch_ctrl_recover(void)
{
    SYS_CTRL_REG_BASE[0x54 / 4] = sys_con8_bak;
}

/* CCA threshold configuration */
void lmac_spec_cca_cfg(uint32_t enable)
{
    ah_lmac.cca_agc_ctrl_flags &= ~(uint8_t)(1u << 2);

    uint8_t cfg[10];
    if (enable == 1) {
        cfg[0] = 0x9e; cfg[1] = 0xa4; cfg[2] = 0xa7; cfg[3] = 0xa7;
        cfg[4] = 0xaa; cfg[5] = 0xaa;
    } else {
        uint8_t v = (ah_lmac.bss_bw == 3) ? 0xaa : 0xa7;
        cfg[0] = v; cfg[1] = v; cfg[2] = 0xaa; cfg[3] = 0xaa;
        cfg[4] = 0xae; cfg[5] = 0xae;
    }
    cfg[6] = 0xb5; cfg[7] = 0xb8; cfg[8] = 0xb8; cfg[9] = 0xbb;
    ah_wphy_cca_th_cfg(cfg);
}

/* Adjust CCA thresholds based on background RSSI */
void lmac_adjust_cca_threshold(int32_t rssi)
{
    if (rssi < -90) rssi = -90;

    int8_t adj = (int8_t)rssi;
    int8_t cca_max = ah_lmac.cca_threshold_max;
    if (cca_max != 0 && cca_max <= adj)
        adj = cca_max;

    if (ah_lmac.bss_bw == 2)      adj += -3;
    else if (ah_lmac.bss_bw == 3) adj += -6;

    int8_t base = ah_lmac.cca_threshold_offset + adj;

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

/* --------------------------------------------------------------------------
 * Queue counter functions — thin wrappers around skb_list_count.
 * Original binary: trivial skb_list_count calls with different list offsets.
 * -------------------------------------------------------------------------- */
uint32 lmac_txsq_count(void)
{
    return skb_list_count((struct skb_list *)&_LMX[0x70]);
}

uint32 lmac_statq_count(void)
{
    return skb_list_count((struct skb_list *)&_LMX[0x538]);
}

uint32 lmac_txq_count(void)
{
    return skb_list_count((struct skb_list *)&_LMX[0x64]);
}

uint32 lmac_acq_count(uint32 ac)
{
    return skb_list_count((struct skb_list *)&_LMX[ac * 12 + 0x88]);
}

uint32 lmac_txagg_count(uint32 ac)
{
    if (ac >= 4) return 0;
    return _LMX[ac * 0x120 + 0x1c5];
}

/* Sum of all cached TX SKBs across all queues and aggregation counts. */
int32 tx_skbs_cached(void)
{
    uint32_t total = lmac_txsq_count();
    total += skb_list_count((struct skb_list *)&_LMX[0x88]);
    total += skb_list_count((struct skb_list *)&_LMX[0x94]);
    total += skb_list_count((struct skb_list *)&_LMX[0xA0]);
    total += skb_list_count((struct skb_list *)&_LMX[0xAC]);
    total += _LMX[0x1c5] + _LMX[0x2e5] + _LMX[0x405] + _LMX[0x525];
    return total;
}

/* Check if current AC has prepared data and configure its TX vector.
 * Original binary: 0x2003730C (lmac_tx_date_prepared_orig) */
int32 lmac_tx_date_prepared(void)
{
    uint32_t ac = _LM[0x9dc] & 0xf;
    if (ac < 4 && (_LMX[ac * 0x120 + 0x1c7] >> 2 & 1)) {
        *(void **)&_LMX[4] = &_LMX[ac * 0x120 + 0x1c8];
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
    if (_LM[0x3e2] & 1)
        data_scrambler(_LMX[0x55c] & 0x7f);

    uint32_t scrambler, ssn, mask;
    if (ext == 0) {
        scrambler = (_LMX[0x55c] & 0x7f) | ((*(uint32_t *)&_LMX[0x558] >> 23) & 0x180);
        ssn = rx0 >> 24;
        mask = 0x7ff;
    } else {
        scrambler = (_LMX[0x55c] & 0x7f) | (*(uint16_t *)&_LMX[0x55a] & 0xffffff80);
        ssn = rx1 >> 3;
        mask = 0x3ffff;
    }

    if (*(int32_t *)&_LM[0x998] == 1) {
        if (((ssn & 1) == 0) && (scrambler == (rx0 & mask) >> 3))
            lmac_update_tx_state_ack(1, 0, 0);
        else
            lmac_update_tx_state_ack(0, 0, 0);
        *(uint32_t *)&_LM[0x998] = 0;
    }
    return 0;
}

/* NDP BA reception handler.
 * Original binary: 0x20039218 (ndp_ba_rx_hdl_orig) */
int32 ndp_ba_rx_hdl(uint32 rx0, uint32 rx1, uint32 ext)
{
    if (_LM[0x3e2] & 1)
        data_scrambler(_LMX[0x55c] & 0x7f);

    uint32_t ba_ssn, ba_bitmap, ba_scrambler, mask;
    if (ext == 0) {
        ba_scrambler = _LMX[0x55c] & 3;
        mask = 0xf;
        ba_ssn = (rx0 & 0xffff) >> 5;
        ba_bitmap = (rx0 & 0xffffff) >> 17;
    } else {
        mask = 0xff;
        ba_ssn = (rx0 & 0xfffff) >> 9;
        ba_scrambler = _LMX[0x55c] & 0x3f;
        ba_bitmap = ((rx1 & 0x1f) << 11) | (rx0 >> 21);
    }

    if (*(int32_t *)&_LM[0x998] == 1) {
        if ((rx0 & mask) >> 3 == ba_scrambler)
            lmac_update_tx_state_ba(ba_ssn, ba_bitmap, 0);
        *(uint32_t *)&_LM[0x998] = 0;
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
    ah_ant_status((_LM[0x55d] >> 2) & 1, ok);
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
    *(void **)&_LMX[4] = &_LMX[0x5d4];
    pv0_ctrl_uplink_txpwr_gen();
    lmac_cfg_txvec_part1();
    return 0;
}

int32 lmac_update_pv0_wpack_tx_vec(void)
{
    *(void **)&_LMX[4] = &_LMX[0x5e4];
    pv0_ctrl_uplink_txpwr_gen();
    lmac_cfg_txvec_part1();
    return 0;
}

int32 lmac_update_pv0_wpcts_tx_vec(void)
{
    _LMX[0x5c6] = (_LMX[0x5c6] & 0x7f) | ((_LM[0x338] >> 2) << 7);
    *(void **)&_LMX[4] = &_LMX[0x5c4];
    pv0_ctrl_uplink_txpwr_gen();
    uint8_t *vec = *(uint8_t **)&_LMX[4];
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
    *(uint32 *)&_LMX[0x56c] = arg0;
    *(uint32 *)&_LMX[0x570] = arg1;
    if (!(_LM[0x34a] & 1)) {
        _LMX[0x565] = (_LMX[0x565] & 0xfc) | (uint8_t)(arg0 >> 30);
        _LMX[0x570] = (_LMX[0x570] & 0xdf) | 0x20;
    } else {
        _LMX[0x56f] = (_LMX[0x56f] & 0xfd) | 0x02;
    }
    *(void **)&_LMX[4] = &_LMX[0x56c];
    lmac_cfg_txvec_part1();
    return 0;
}

int32 lmac_update_ndp_ack_tx_vec(uint32 arg0, uint32 arg1)
{
    *(uint32 *)&_LMX[0x57c] = arg0;
    *(uint32 *)&_LMX[0x580] = arg1;
    if (!(_LM[0x34a] & 1)) {
        _LMX[0x580] = (_LMX[0x580] & 0xdf) | 0x20;
    } else {
        _LMX[0x57f] = (_LMX[0x57f] & 0xfd) | 0x02;
    }
    *(void **)&_LMX[4] = &_LMX[0x57c];
    lmac_cfg_txvec_part1();
    return 0;
}

int32 lmac_update_ndp_ba_tx_vec(uint32 arg0, uint32 arg1)
{
    *(uint32 *)&_LMX[0x58c] = arg0;
    *(uint32 *)&_LMX[0x590] = arg1;
    if (!(_LM[0x34a] & 1)) {
        _LMX[0x590] = (_LMX[0x590] & 0xdf) | 0x20;
    } else {
        _LMX[0x58f] = (_LMX[0x58f] & 0xfd) | 0x02;
    }
    *(void **)&_LMX[4] = &_LMX[0x58c];
    lmac_cfg_txvec_part1();
    return 0;
}

/* ======================================================================
 * Stubs for functions not needed in modem-only mode.
 * Beacons, management frames, PS/CF-poll, STA/AP — none of these exist
 * in a data-modem configuration.  Original WRAPs are commented out in
 * mars_lmac_tx_orig.c so callers reach these stubs instead of _orig.
 * ====================================================================== */

/* Beacon */
int32_t lmac_beacon_add_s1g_beacon_compatibility(struct sk_buff *skb) { (void)skb; return 0; }
int32_t lmac_beacon_build_s1gbeacon(struct sk_buff *skb)              { (void)skb; return 0; }
int32_t lmac_tx_beacon(struct sk_buff *skb)                           { (void)skb; return 0; }

/* PV0 PS / CF frames */
int32_t lmac_tx_pv0_null(struct sk_buff *skb)   { (void)skb; return 0; }
int32_t lmac_tx_pv0_pspoll(struct sk_buff *skb) { (void)skb; return 0; }
int32_t lmac_tx_pv0_cfpoll(struct sk_buff *skb) { (void)skb; return 0; }
int32_t lmac_tx_pv0_cfend(struct sk_buff *skb)  { (void)skb; return 0; }

/* PV0 inits for unused frame types */
void lmac_pv0_pspoll_init(void)  {}
void lmac_pv0_cfpoll_init(void)  {}
void lmac_pv0_cfend_init(void)   {}
void lmac_pv0_qos_null_init(void){}

/* PV0 CF-end TX vector */
int32_t lmac_update_pv0_cfend_tx_vec(void) { return 0; }

/* NDP PS-Poll RX handler */
int32_t ndp_pspoll_ack_rx_hdl(void) { return 0; }

/* Management frames */
int32_t lmac_send_mgmt_meas_req(void)    { return 0; }
int32_t lmac_send_mgmt_meas_report(void) { return 0; }
int32_t lmac_send_bss_announcement(void)  { return 0; }
int32_t lmac_send_scan_probe(void)       { return 0; }
int32_t lmac_send_ant_pkt(void)          { return 0; }
int32_t lmac_send_probe_resp(void)       { return 0; }

/* STA / AP — never used in modem mode */
int32_t lmac_tx_to_pm_ap(void)  { return 0; }
void   *get_worst_node(void)    { return NULL; }
int32_t lmac_auto_channel_select(void) { return 0; }

/* NDP PS-Poll TX vector generators */
uint64_t lmac_gen_pspack_ndp2m(void)      { return 0; }
uint64_t lmac_gen_pspoll_ndp2m(void)      { return 0; }
uint64_t lmac_gen_pspoll_ack_ndp2m(void)  { return 0; }

/* DTIM — no beacons, no DTIM */
uint32_t lmac_dtim_timer_rem(void) { return 0; }

/* VHT info — not applicable to S1G */
uint32_t lmac_vht_info_get(uint32_t info) { (void)info; return 0; }

/* Test TX — production modem doesn't need it */
int32_t lmac_ah_test_tx(struct lmac_ops *ops, struct sk_buff *skb)
{ (void)ops; (void)skb; return 0; }

/* ======================================================================
 * Functions that were previously WRAP'd to _orig.
 * Now have full C or stub implementations.
 * ====================================================================== */

/* lmac_check_tx_queue_empty — clear AC_PD bits for queues with no data.
 * AC→bit mapping: [1,0,2,3] for AC[0,1,2,3] (EDCA priority ordering). */
void lmac_check_tx_queue_empty(void)
{
    static const uint8_t ac_bit[4] = {1, 0, 2, 3};
    uint8_t *lmx = _LMX;

    for (uint32_t ac = 0; ac < 4; ac++) {
        uint32_t q_cnt = skb_list_count((struct skb_list *)&lmx[ac * 12 + 0x88]);
        uint32_t a_cnt = lmx[ac * 0x120 + 0x1c5];
        if (q_cnt + a_cnt == 0)
            LMAC_HW->AC_PD &= ~(1u << ac_bit[ac]);
    }
}

/* ndp_tx_vec_init_one — initialize one NDP TX vector cache entry.
 * Ported from Ghidra decompilation of ndp_tx_vec_init_orig. */
void ndp_tx_vec_init_one(uint8_t *tv)
{
    /* Minimal init: zero the TX vector, set S1G format defaults.
     * The _LM offsets from Ghidra decompilation (0xc20, 0xd28, 0xdb0, 0x19a0)
     * exceed ah_lmac's ~0xBB4-byte boundary — they referred to the unified
     * lmac+tx context block in the original binary. NDP vectors are only used
     * for ACK/BA/CTS response frames which are rebuilt per-TX anyway. */
    for (int i = 0; i < 8; i++) tv[i] = 0;
    tv[2] = 0x0f;
    tv[1] = 0x10;
}

/* lmac_irq_tx_tmo — TX timeout interrupt handler.
 * Simplified for modem mode: abort FSM and re-enable AC interrupts. */
void lmac_irq_tx_tmo(void)
{
    lmac_cancle_tx_tmo();

    uint32_t tx_state = *(uint32_t *)&_LM[AH_LMAC_TXSTART_OFS];
    if (tx_state >= 1u && tx_state <= 6u) {
        /* Substate handlers — for modem mode, just abort */
        lhw_abort_fsm();
    }

    if ((int8_t)_LM[AH_LMAC_ACLAST_OFS + 1] < 0)
        ah_tdma_abort();

    *(uint32_t *)&_LM[AH_LMAC_TXSTART_OFS] = 0;

    if ((_LM[AH_LMAC_MISC9E0_OFS] & 1) == 0)
        lhw_enable_irq_ac();
}

/* lmac_attempt_tx_obss — attempt TX on overlapping BSS channel.
 * In modem mode, fall through to normal attempt_tx. */
int32 lmac_attempt_tx_obss(uint32 ch)
{
    (void)ch;
    uint32_t ac = lmac_current_ac();
    return lmac_attempt_tx(ac);
}

/* PV0 response frame init functions — stubs for modem mode */
void lmac_pv0_rts_init(void)   {}
void lmac_pv0_wpack_init(void) {}
void lmac_pv0_wpcts_init(void) {}
void lmac_pv0_wpba_init(void)  {}

/* lmac_tx_queue_agglist_init — already handled by lmac_tx_init's memset */
void lmac_tx_queue_agglist_init(void) {}

/* lmac_tx_vec_init — init all NDP TX vectors */
void lmac_tx_vec_init(void)
{
    for (uint32_t i = 0; i < 5; i++)
        ndp_tx_vec_init_one((uint8_t *)&ah_lmac_tx_orig.pTx_vector_cache[i]);
}

/* lmac_tx_frame_regen — regenerate TX frame with new rate parameters */
int32_t lmac_tx_frame_regen(uint32_t ac, uint32_t ac_hint, uint32_t mcs, void *arg)
{
    (void)ac; (void)ac_hint; (void)mcs; (void)arg;
    return 0;
}

