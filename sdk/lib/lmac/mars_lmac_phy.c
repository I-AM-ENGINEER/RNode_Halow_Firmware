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

#define LMAC_AGGR_CTRL_START   (1u << 0)
#define LMAC_AGGR_CTRL_AMPDU   (1u << 1)

#define LMAC_U8(off)        (*(volatile uint8_t  *)((uint8_t *)&ah_lmac + (off)))
#define LMAC_U16(off)       (*(volatile uint16_t *)((uint8_t *)&ah_lmac + (off)))
#define LMAC_U32(off)       (*(volatile uint32_t *)((uint8_t *)&ah_lmac + (off)))

#define LMAC_IRQ_CLR_BO     0x20u
#define LMAC_CCA_STAT_CLR   0x0ff0u
#define LMAC_IRQ_CLR_TX_END 0x04u

/* EDCA CW parameters in ah_lmac.ce_ctx (set per-AC before lmac_attempt_tx_orig reads them) */
/* MCS/rate fields in ah_lmac (accessed via LMAC_U8/U16/U32 macros) */
#define AH_MCS_FLOOR        0x865u   /* uint8:  MCS floor set by lmac_cfg_set_bss_bw */
#define AH_MCS_REQUESTED    0x866u   /* uint8:  requested MCS from rate table */
#define AH_MCS_SELECTED     0x6e8u   /* uint32: actual MCS used for TX */

/* TX state fields in ah_lmac */
#define AH_CURRENT_AC       0x9dcu   /* uint8:  low 4 bits = current AC index */

extern lmac_tx_ctx_t ah_lmac_tx_orig;
extern void lmac_ant_sel_orig(uint32 ant);
extern struct lmac_ops *g_pAhLmacOps;

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

static inline uint8_t lmac_current_ac(void)
{
    return LMAC_U8(AH_CURRENT_AC) & 0x0fu;
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

    LMAC_U8(AH_MCS_FLOOR) = 0u;   /* belt-and-suspenders: keep floor clear for next ac_pd */
    {
        static uint32_t s_frm_cnt = 0;
        s_frm_cnt++;
        if ((s_frm_cnt % 200u) == 1u) {
            uint8_t *dbg_buf = (uint8_t *)ah_lmac_tx_orig.pPv0_txvec;
            uint32_t dbg_tv3 = dbg_buf ? *(uint32_t *)(dbg_buf + 8u) : 0u;
            /* retry count is at txd[0x28] of the first skb in aggregate */
            uint8_t retry = 0;
            uint8_t no_ack_flag = 0;
            struct sk_buff *dbg_skb = aggr->skb_list[0];
            if (dbg_skb && dbg_skb->head) {
                retry      = dbg_skb->head[0x28];
                no_ack_flag = (dbg_skb->head[0x25] >> 1u) & 1u;
            }
            log_warn("tx_frm[%u]: tv1_mcs=%u tv3_mcs=%u req=%u sel=%u retry=%u no_ack=%u",
                     s_frm_cnt,
                     (LMAC_HW->TXVEC1 >> 12) & 0xfu,
                     (dbg_tv3 >> 7u) & 0xfu,
                     LMAC_U8(0x866u),
                     LMAC_U32(0x6e8u),
                     retry,
                     no_ack_flag);
        }
    }

    lmac_send_data_to_phy(ac);
    lmac_cfg_txvec_part2();

    aggr->reserved_10f &= (uint8_t)~0x04u;
    ((volatile uint32_t *)&ah_lmac)[(uint32_t)ac + 0x1c7u] += 1u;
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
    extern void lmac_irq_ac_pd_orig(void);

    /* Bug 1 fix: clear MCS floor so lmac_update_tx_rate_orig doesn't clamp
     * MCS0/MCS10 to floor=1. */
    LMAC_U8(0x865u) = 0u;

    if (lmac_custom_cfg.bypass_backoff) {
        for (uint32_t ac = 0u; ac < 4u; ac++) {
            ah_lmac.ce_ctx.cw_min[ac] = 1u;
            ah_lmac.ce_ctx.cw_max[ac] = 1u;
        }
    }

    lmac_irq_ac_pd_orig();

    /* Bug 2 fix: when retry count > 0, lmac_update_tx_rate_orig falls into
     * the retry rate table which maps MCS10→MCS1 (table only has 32 entries).
     * Patch the TXVEC buffer back to MCS10 if that was the configured rate. */
    uint8_t requested_mcs = LMAC_U8(AH_MCS_REQUESTED);
    if (requested_mcs == 10u && ah_lmac_tx_orig.pPv0_txvec != NULL) {
        uint8_t *tv = (uint8_t *)ah_lmac_tx_orig.pPv0_txvec;
        uint8_t tv_mcs = (tv[1] >> 4u) & 0xfu;
        if (tv_mcs != 10u) {
            tv[1] = (tv[1] & 0x0fu) | (10u << 4u);
            uint16_t tv3 = *(uint16_t *)(tv + 8u);
            tv3 = (tv3 & ~(0xfu << 7u)) | (10u << 7u);
            *(uint16_t *)(tv + 8u) = tv3;
            LMAC_HW->TXVEC1 = *(uint32_t *)(tv);
        }
    }
}


/*
 * Minimal lmac_gen_tx_agglist: dequeue one frame from AC queue,
 * place it in the aggregate list, compute symbol length.
 * Returns pointer to first skb on success, NULL on empty queue.
 */
struct sk_buff *lmac_gen_tx_agglist(uint32_t ac, uint32_t rate,
                                   uint32_t bw, uint32_t max_frames)
{
    lmac_tx_ctx_buff *aggr;
    uint8_t *txd;
    struct sk_buff *skb;

    (void)rate;
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

    aggr->rate_cfg = (uint8_t)((bw & 3u) << 6u);
    if ((bw <= 7u) || (bw == 10u))
        aggr->rate_cfg = (aggr->rate_cfg & 0xc3u) | (uint8_t)((bw & 0xfu) << 2u);

    skb = skb_list_dequeue(&ah_lmac_tx_orig.pTx_ac_queues[ac]);
    if (skb == NULL)
        return NULL;

    txd = skb->head;
    log_debug("agglist: skb=%p txd16=%u txd18=%u", skb, txd[0x16], txd[0x18]);

    aggr->skb_list[0]       = skb;
    aggr->selected_count    = 1u;
    aggr->queued_count      = 1u;
    aggr->total_len_bytes   = (uint32_t)(int16_t)txd[0x16];
    aggr->first_seq         = (int16_t)(uint16_t)txd[0x18];
    aggr->last_seq          = aggr->first_seq;

    uint32_t sym = calc_symbol_len(aggr->total_len_bytes + 4u, bw,
                                   (rate >> 8u) & 0xfu);
    aggr->symbol_len = (uint16_t)sym;
    log_debug("agglist: bytes=%u sym=%u", aggr->total_len_bytes, sym);

    aggr->reserved_10f &= ~0x04u;

    return skb;
}


/*
 * Minimal lmac_attempt_tx: start CCA timer for one AC.
 * Replicates the essential orig logic: check conditions, compute
 * random backoff from CW, call lhw_start_cca + lhw_start_tx.
 */
int32 lmac_attempt_tx(uint32_t ac)
{
    uint32_t cw_min, cw_max, backoff, cca_dur, slot_time;

    if (ac > 3u)
        ac = 3u;

    if (ah_lmac_tx_orig.pTx_ac_aggr_data[ac].queued_count == 0u)
        return -1;

    cw_min = ah_lmac.ce_ctx.cw_min[ac];
    cw_max = ah_lmac.ce_ctx.cw_max[ac];

    slot_time = LMAC_U16((uint16_t)(ac + 0x1c) * 2u);
    if (slot_time == 0u)
        slot_time = 7u;

    cca_dur = lhw_get_cca_remain();
    if (cca_dur == 0u) {
        uint32_t seed = (uint32_t)os_jiffies();
        backoff = (seed % (cw_max - cw_min + 1u)) + cw_min;
    } else {
        backoff = 0u;
    }

    if ((LMAC_U8(0x892u) & 2u) == 0u)
        lmac_lo_table_kick((uint16_t)LMAC_U16(0x33cu));

    log_debug("attempt_tx: ac=%u cw=%u/%u backoff=%u slot=%u", ac, cw_min, cw_max, backoff, slot_time);

    lhw_start_cca((uint32_t)((uint8_t)ac + 3u), backoff);
    lhw_start_tx(0u);
    lmac_cfg_txvec_part1();

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
        if (!(ah_lmac.ba_ctrl_flags & 0x08u))
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
            int no_ack = (first && first->head) ? ((first->head[0x25] & 0x02u) != 0u) : 0;
            if (no_ack)
                lmac_update_tx_state_ack(1u, 0u, 0u);
            else
                flags = lmac_wait_sync(0x1c0u);
        }
    } else {
        ah_lmac.tx_irq_error_flags |= 2u;
        if (LMAC_U32(0x3b8u) & 0x10u) {
            uint32_t err = ah_wphy_err_code_get();
            log_warn("tx_end err: sub=%u wphy=0x%x stat=0x%x tv1=0x%x",
                     ah_lmac.bo_frame_type, err, LMAC_HW->TX_STAT, LMAC_HW->TXVEC1);
        }
        uint16_t gain_reg = LMAC_U16(0x362u);
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
                skb->head[0x27] |= 0x80u;
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

    /* Re-kick AC_PD if AC queue has more packets — keeps the pipeline full. */
    if (ac < 4u && skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[ac]) > 0) {
        LMAC_HW->AC_PD = 0u;
        LMAC_HW->AC_PD = 0xfu;
    }
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
    if (skb != NULL && skb->head != NULL)
        skb->head[0x27] |= 0x80u;
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
        if (skb != NULL && skb->head != NULL)
            skb->head[0x27] |= 0x80u;
    }
    return 0;
}

/* No-op in modem mode: Partial AID requires a STA table entry, which we don't use. */
void lmac_partial_aid_update(void *txi)
{
    (void)txi;
}

