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
extern void lmac_irq_ac_pd_orig(void);

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

    LMAC_U8(0x865u) = 0u;   /* belt-and-suspenders: keep floor clear for next ac_pd */
    {
        static uint32_t s_tx_dbg = 0;
        static uint8_t  s_last_mcs = 0xffu;
        uint8_t req_mcs = LMAC_U8(0x866u);
        if (req_mcs != s_last_mcs) {
            s_last_mcs = req_mcs;
            s_tx_dbg   = 0u;
        }
        if (s_tx_dbg < 5u) {
            s_tx_dbg++;
            uint8_t *dbg_buf = (uint8_t *)ah_lmac_tx_orig.pPv0_txvec;
            uint32_t dbg_tv2 = dbg_buf ? *(uint32_t *)(dbg_buf + 4u) : 0u;
            uint32_t dbg_tv3 = dbg_buf ? *(uint32_t *)(dbg_buf + 8u) : 0u;
            log_warn("tx_frm[%u]: tv1_mcs=%u tv2_syms=%u tv3_mcs=%u req=%u sel=%u",
                     s_tx_dbg,
                     (LMAC_HW->TXVEC1 >> 12) & 0xfu,
                     dbg_tv2,
                     (dbg_tv3 >> 7u) & 0xfu,
                     req_mcs,
                     LMAC_U32(0x6e8u));
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
    LMAC_U8(0x865u) = 0u;      /* Bug 1 fix: clear MCS floor before rate selection */
    lmac_irq_ac_pd_orig();

    /* Bug 2 fix: patch txvec buffer if MCS10 was downgraded by retry table.
     *
     * lmac_gen_txvec_orig is called with mcs=1 (from retry table), so it writes:
     *   buf[1][7:4]     = 1   (TXVEC1 MCS field)
     *   TXVEC3[10:7]    = 1   (TXVEC3 MCS field)
     *   TXVEC2          = calc_symbol_len(bytes, bw=3, mcs=1)  — NDBPS=24
     *   TXVEC3[20:12]   = same symbol count low 9 bits
     *   stride[0x1bc]   = same (used by lmac_send_data_to_phy for Duration field)
     *
     * We must patch all five locations.  For 1MHz (bw_idx=0):
     *   NDBPS(MCS=1)=24, NDBPS(MCS=10)=6  →  4x more symbols needed for MCS=10.
     * Formula: n_syms = ceil((total_bytes + 4) * 8 + 14) / 6)
     */
    if (LMAC_U8(0x866u) == 10u) {
        uint8_t *buf = ah_lmac_tx_orig.pPv0_txvec;
        if (buf != NULL && ((buf[1] >> 4u) & 0xfu) != 10u) {
            /* Derive AC from buffer address: buf = &ah_lmac_tx_orig + ac*0x120 + 0x1c8 */
            uint32_t ac = ((uintptr_t)buf - (uintptr_t)&ah_lmac_tx_orig - 0x1c8u) / 0x120u;

            /* Patch MCS in TXVEC1 (buf[1] bits[7:4]) */
            buf[1] = (uint8_t)((buf[1] & 0x0fu) | (10u << 4u));

            /* Recompute symbol count for MCS=10 at 1MHz: NDBPS=6 (from ndbps_table[40]) */
            uint32_t total_bytes = *(uint32_t *)((uint8_t *)&ah_lmac_tx_orig + ac * 0x120u + 0x1b8u);
            uint32_t bits = (total_bytes + 4u) * 8u + 14u;
            uint32_t n_syms = (bits + 5u) / 6u;   /* ceil(bits / NDBPS=6) */

            /* Patch source field (Duration calc in lmac_send_data_to_phy) */
            *(uint32_t *)((uint8_t *)&ah_lmac_tx_orig + ac * 0x120u + 0x1bcu) = n_syms;

            /* Patch TXVEC2 = full symbol count */
            *(uint32_t *)(buf + 4u) = n_syms;

            /* Patch TXVEC3: clear MCS bits[10:7] AND sym_len bits[20:12] in one uint32
             * write to avoid compiler aliasing issues between uint16 and uint32 writes.
             * Mask 0xffe0087f: keep bits[31:21] + bit[11] + bits[6:0]; clear bits[20:12] + bits[10:7]. */
            *(uint32_t *)(buf + 8u) =
                (*(uint32_t *)(buf + 8u) & 0xffe0087fu)  /* clear bits[20:12] + bits[10:7] */
                | ((uint32_t)(10u) << 7u)                 /* MCS=10 in bits[10:7]           */
                | ((n_syms & 0x1ffu) << 12u);             /* sym_len in bits[20:12]          */

            /* Re-write TXVEC1 (lmac_cfg_txvec_part1_orig wrote stale value) */
            LMAC_HW->TXVEC1  = *(uint32_t *)buf;

            /* Fix AH_AGGHDR_OFS bits[5:2] = MCS (set by agglist with wrong MCS=1) */
            uint8_t *stride_base = (uint8_t *)&ah_lmac_tx_orig + ac * 0x120u;
            stride_base[AH_AGGHDR_OFS] =
                (stride_base[AH_AGGHDR_OFS] & 0xc3u) | (uint8_t)((10u & 0xfu) << 2u);

            /* Sync cached actual-MCS (lmac[0x6e8]) */
            LMAC_U32(0x6e8u) = 10u;
        }
    }
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

