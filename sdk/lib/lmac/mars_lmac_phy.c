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

#define LMAC_IRQ_CLR_BO     0x20u
#define LMAC_CCA_STAT_CLR   0x0ff0u
#define LMAC_IRQ_CLR_TX_END 0x04u

extern lmac_tx_ctx_t ah_lmac_tx_orig;
extern void lmac_ant_sel_orig(uint32 ant);
extern struct sk_buff *lmac_get_first_skb_orig(uint32 ac);

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
    return LMAC_U8(0x9dcu) & 0x0fu;
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

    lmac_send_data_to_phy(ac);
    lmac_cfg_txvec_part2();

    aggr->reserved_10f &= (uint8_t)~0x04u;
    ((volatile uint32_t *)&ah_lmac)[(uint32_t)ac + 0x1c7u] += 1u;
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

    LMAC_HW->IRQ_PD = LMAC_IRQ_CLR_TX_END;
    lhw_abort_fsm();
    ah_tdma_abort();

    if ((LMAC_HW->TX_STAT & 3u) == 0u) {
        /* TX success: wait for sync window on data/response paths */
        uint32_t sub_state = ah_lmac.bo_tx_substate;
        if (sub_state < 7u && ((1u << sub_state) & 0x6eu))
            flags = lmac_wait_sync(0x1c0u);
    } else {
        /* TX error: log, clear HW error bits, restore RX gain */
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

    ah_lmac.bo_frame_type = 0u;
    update_rx_buff_addr();
    lmac_tdma_start();
    lhw_start_rx(flags);
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

/*
 * Modem-mode rate selection: pass forced MCS/BW from TXI through to gen_txvec
 * without the binary's two failure modes:
 *   1. TXI[0x3d] >= 8 causes binary to re-read lmac[0x866] as mcs, silently
 *      replacing MCS10 with the auto-default unless auto-default is also 10.
 *   2. Min-MCS floor lmac[0x865] silently raises MCS0 to >=1.
 *
 * Explicit TXI[0x3d] (!=0xff): use it directly, only cap at HW max.
 * Explicit TXI[0x3c] (!=0xff): use it directly, no config override.
 * MCS10 hardware requires S1G_1M mode (bw_hint=3); any other BW is a hard error.
 * Invalid MCS (>7 and not 10): clamp to 1 with a warning.
 */
int32 lmac_update_tx_rate(uint32 ac, uint8 *bw_hint_out, uint8 *mcs_out)
{
    struct sk_buff *skb;
    uint8_t *txi;
    uint8_t mcs, bw_hint, max_mcs;

    if (ac >= 4u)
        return -1;

    skb = lmac_get_first_skb_orig(ac);
    if (skb == NULL)
        return -1;

    txi = (uint8_t *)skb->head;
    max_mcs = LMAC_U8(0x864u);

    mcs = txi[0x3du];
    if (mcs == 0xffu) {
        /* Auto MCS: read default and apply min/max config clamping */
        mcs = LMAC_U8(0x866u);
        uint8_t min_mcs = LMAC_U8(0x865u);
        if (mcs != 10u) {
            if (mcs > max_mcs) mcs = max_mcs;
            if (mcs < min_mcs) mcs = min_mcs;
        }
    } else {
        /* Explicit MCS: cap at HW max only, skip the min-floor */
        if (mcs != 10u && mcs > max_mcs)
            mcs = max_mcs;
    }

    if (mcs > 7u && mcs != 10u) {
        log_warn("update_tx_rate: ac=%u invalid mcs=%u, clamping to 1", ac, mcs);
        mcs = 1u;
    }

    bw_hint = txi[0x3cu];
    if (bw_hint == 0xffu)
        bw_hint = (LMAC_U8(0x34au) & 1u) ? 3u : 0u;

    /* MCS10 is only valid in S1G_1M mode (2 MHz physical, bw_hint=3). */
    if (mcs == 10u && bw_hint != 3u) {
        log_warn("update_tx_rate: ac=%u MCS10 needs S1G_1M (bw=3), got bw=%u, clamping to mcs=1", ac, bw_hint);
        mcs = 1u;
    }

    *bw_hint_out = (char)bw_hint;
    *mcs_out     = (char)mcs;
    LMAC_U32(0x6e8u) = (uint32_t)mcs;
    LMAC_U32(0x6ecu) = (uint32_t)bw_hint;
    return 0;
}
