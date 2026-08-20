#include "typesdef.h"
#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_WARN//LOG_LEVEL_MARS_LMAC_TX
#include "lib/logc/log.h"

#include "lib/lmac/lmac_ctx.h"
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/lmac_regmap.h"
#include "lib/lmac/mars_lmac_tx.h"
#include "lib/skb/skb.h"
#include "lib/skb/skb_list.h"
#include "lib/skb/skbuff.h"
#include "osal/semaphore.h"
#include "osal/string.h"
#include "osal/task.h"
#include "osal/time.h"


extern int32 _os_task_set_priority(struct os_task *task, uint8 priority);
extern void lmac_sta_put(void *sta);
extern void lmac_get_rx_addr(uint8 *addr, uint8 *hdr);
extern void *lmac_sta_get(uint16 aid, uint8 *addr);
extern uint32 lmac_get_seq_num(void *hdr);
extern uint32 lmac_get_hdr_len_pv0(void *hdr);
extern void ndp_tx_vec_init_one(uint8_t *txvec);
extern uint32 lmac_get_ack_policy(void *txd);
extern void lmac_partial_aid_update(void *txd);
extern void halow_tx_skb_complete(struct sk_buff *skb);   /* halow.c: budget+free */
lmac_tx_ctx_t ah_lmac_tx;

/* Hard-wedge recovery request (see halow_tx_vacancy_watchdog). Deliberately a
 * standalone global, NOT a struct field: lmac_tx_ctx_t is a frozen ABI -- the
 * precompiled LMAC binaries address its packed fields at hard-coded offsets,
 * so even appending a field shifts/changes it and breaks the binary side
 * (verified the hard way: an inserted byte moved every queue and crashed boot
 * with a misaligned access inside skb_list_init). Set from the watchdog
 * (workqueue), consumed by lmac_tx_task below. */
volatile uint8_t lmac_tx_purge_request = 0u;


static void lmac_tx_drop_min(struct sk_buff *skb);
static void lmac_tx_task(void *arg);
static void lmac_tx_status_task(void *arg);

int32 lmac_tx_queue_init(void);
void lmac_tx_data_reload(void);
int32 lmac_tx_pv0_data(struct sk_buff *skb);


typedef struct sk_buff sk_buff;
typedef struct skb_list skb_list;


#define LMAC_TX_AC_COUNT 4

/* Hard-wedge purge (see halow_tx_vacancy_watchdog tier 2). Runs in tx_task
 * context: the AC queues' only producers are tx_task itself (reload) and their
 * only consumer is the LMAC IRQ, so brief irq-off windows around the drains
 * make the purge race-free without touching any other task. tx_pending/
 * tx_status/tx_frames_pending are NOT purged -- their consumer tasks are alive
 * and drain them normally; only the IRQ-owned AC queues can hold
 * permanently-stuck skbs. Purged skbs complete through the normal accounting
 * path so the TX-vacancy budget and the heap stay consistent.
 * No fixed cap on the number of completed skbs: a full 29200-byte budget can
 * hold ~110 small frames -- the old dead[64] array silently leaked everything
 * past 64, so the purge could never clear the wedge and ate heap each cycle. */
static void lmac_tx_purge_ac_queues(void){
    uint32_t total = 0;

    /* If the HW TX FSM is armed it owns the selected aggregate (DMA may be
     * reading skb->data right now): abort it exactly like lmac_irq_tx_tmo
     * before completing those skbs, or the free races the DMA engine.
     * IRQ-guarded: a tx_end landing between the check and the abort would
     * restart RX/TDMA itself, and the second abort would then kill the fresh
     * FSM -- the same abort-inside-live-TXOP damage reverted in b51. */
    if( ah_lmac.bo_frame_type != 0u ){
        uint32_t pflag = disable_irq();
        if( ah_lmac.bo_frame_type != 0u ){
            lhw_abort_fsm();
            ah_lmac.bo_frame_type  = 0u;
            ah_lmac.bo_tx_substate = 0u;
            lhw_enable_irq_ac();
        }
        enable_irq(pflag);
    }

    /* Drain the AC queues in small batches: the irq-off window stays short and
     * completion (sema_up + kfree_skb, which may reschedule) runs with IRQs
     * back on. */
    for( uint32_t ac = 0; ac < LMAC_TX_AC_COUNT; ac++ ){
        for(;;){
            struct sk_buff *batch[8];
            uint32_t n = 0;
            uint32_t flag = disable_irq();
            while( n < 8u ){
                struct sk_buff *skb = skb_list_dequeue(&ah_lmac_tx.pTx_ac_queues[ac]);
                if( skb == NULL ) break;
                batch[n++] = skb;
            }
            enable_irq(flag);
            if( n == 0u ) break;
            for( uint32_t i = 0; i < n; i++ ){
                halow_tx_skb_complete(batch[i]);
                total++;
            }
        }
    }

    /* Complete the per-AC in-flight aggregates the same way. Their skbs were
     * already dequeued from the AC queues by gen_tx_agglist -- the old code
     * just memset the list and leaked them together with their budget bytes.
     * Ordering rules this loop obeys (learned the hard way):
     *  - queued_count must be reset in the SAME irq-off window that NULLs the
     *    last skb_list entry: lmac_reorder_tx_agglist (ac_pd IRQ) reads
     *    queued_count then indexes skb_list[] -- a window with a stale count
     *    and NULLed entries is a NULL deref in IRQ context (hard fault; the
     *    "purge then permanent wedge" signature).
     *  - re-abort the FSM inside each window: producers (fast_tx from tcps /
     *    acktk / RX-ACK) re-arm AC_PD while the purge runs, so ac_pd can
     *    re-enter an aggregate between batches and arm a TXOP whose skbs we
     *    are about to free. Aborting under the window (idempotent re-check,
     *    same as tier-0) keeps the free from ever racing live DMA. */
    for( uint32_t ac = 0; ac < LMAC_TX_AC_COUNT; ac++ ){
        struct lmac_tx_ctx_buff *aggr = &ah_lmac_tx.pTx_ac_aggr_data[ac];
        for(;;){
            struct sk_buff *batch[8];
            uint32_t n = 0;
            uint32_t more;
            uint32_t flag = disable_irq();
            if( ah_lmac.bo_frame_type != 0u ){
                lhw_abort_fsm();
                ah_lmac.bo_frame_type  = 0u;
                ah_lmac.bo_tx_substate = 0u;
                lhw_enable_irq_ac();
            }
            for( uint32_t i = 0; i < 64u && n < 8u; i++ ){
                struct sk_buff *skb = aggr->skb_list[i];
                if( skb != NULL ){
                    aggr->skb_list[i] = NULL;
                    batch[n++] = skb;
                }
            }
            more = 0u;
            for( uint32_t j = 0; j < 64u; j++ ){
                if( aggr->skb_list[j] != NULL ){ more = 1u; break; }
            }
            if( more == 0u ){
                aggr->total_len_bytes = 0;
                aggr->symbol_len = 0;
                aggr->first_seq = -1;
                aggr->last_seq = -1;
                aggr->selected_count = 0;
                aggr->queued_count = 0;
                aggr->rate_cfg = 0;
                aggr->tx_flags = 0;
                memset(&aggr->txvec, 0, sizeof(aggr->txvec));
            }
            enable_irq(flag);
            for( uint32_t i = 0; i < n; i++ ){
                halow_tx_skb_complete(batch[i]);
                total++;
            }
            if( more == 0u ) break;
        }
    }

    log_warn("tx_task: hard-wedge purge, %u stuck skb(s) completed", (unsigned)total);
}



static const uint8_t ieee802_1d_to_ac_tbl[8] = {0, 1, 1, 0, 2, 2, 3, 3};


int32 lmac_ah_tx(struct lmac_ops *ops, struct sk_buff *skb)
{
    uint32_t headroom;
    int32 ret;

    if (!skb || !ops->radio_on){
        if( skb ) kfree_skb(skb);
        return -1;
    }

    headroom = skb_headroom(skb);
    if (headroom <= 0x47) {
        log_warn("ah_tx: skb=%p headroom=%u too small (need>0x47)", skb, headroom);
        kfree_skb(skb);
        return -1;
    }

    /* low 32: submission timestamp; high 32: headroom (used by cipher path) */
    skb->lifetime = (uint64_t)(uint32_t)os_jiffies() | ((uint64_t)headroom << 32);

    ret = skb_list_queue(&ah_lmac_tx.tx_pending_queue, skb);
    if (ret) {
        log_error("ah_tx: queue failed ret=%d", ret);
        kfree_skb(skb);
        return ret;
    }

    os_sema_up(&ah_lmac_tx.tx_sem);
    ah_lmac.pending_pkg_to_status_check++;

    log_trace("ah_tx: skb=%p len=%u headroom=%u", skb, skb->len, headroom);
    return 0;
}

static inline uint16_t lmac_tx_align_len_min(uint16_t len);
int32 lmac_fast_tx(struct sk_buff *skb, uint8_t mcs)
{
    lmac_txd_t *txd;
    uint16_t fc, combined;
    uint32_t headroom;

    if (!skb)
        return -1;

    headroom = skb_headroom(skb);
    if (headroom <= 0x47) {
        log_warn("fast_tx: skb=%p headroom=%u too small", skb, headroom);
        kfree_skb(skb);
        return -2;
    }

    if (((uintptr_t)skb->data & 1) != 0) {
        log_debug("fast_tx: skb=%p unaligned data=%p", skb, skb->data);
        kfree_skb(skb);
        return -3;
    }

    skb->lifetime = (uint64_t)(uint32_t)os_jiffies() | ((uint64_t)headroom << 32);

    txd = (lmac_txd_t *)skb->head;
    memset(txd, 0, sizeof(*txd));

    txd->tx_bw_hint      = ah_lmac.tx_bw_sig;
    txd->tx_rate_mcs     = mcs;
    txd->fallback_count   = 0x0F;
    txd->rts_cfg          = (txd->rts_cfg & 0x9F) | 0x60;

    txd->frame     = skb->data;
    txd->frame_len = skb->len;

    txd->frame_type_lo = (txd->frame_type_lo & 0xFC) | (skb->data[0] & 3);
    txd->tx_flags     |= 0x02;

    lmac_get_rx_addr(txd->dest_mac, skb->data);
    txd->sta = lmac_sta_get(0xFFFF, txd->dest_mac);

    if ((txd->dest_mac[0] & 1) != 0)
        txd->tx_ctrl |= 0x80;

    {
        uint32_t ack = lmac_get_ack_policy(txd);
        txd->frame_type_hi = (txd->frame_type_hi & 0xFD) | ((ack & 1) << 1);
    }

    txd->tx_ctrl &= 0xF0;

    txd->seq_num = (int16_t)lmac_get_seq_num((void *)txd->frame);

    fc = *(uint16_t *)skb->data;
    txd->frame_type_lo = (txd->frame_type_lo & 0xE3) | (uint8_t)(((fc >> 2) & 7) << 2);
    combined = ((uint16_t)txd->frame_type_hi << 8) | txd->frame_type_lo;
    combined = (combined & 0xFE1F) | (((fc >> 4) & 0x0F) << 5);
    txd->frame_type_lo = (uint8_t)combined;
    txd->frame_type_hi = (uint8_t)(combined >> 8);

    txd->frame_type_hi = (txd->frame_type_hi & 0xBF) | (((skb->data[1] >> 1) & 1) << 6);
    txd->frame_type_hi = (txd->frame_type_hi & 0x7F) | (skb->data[1] << 7);

    txd->hdr_len = lmac_get_hdr_len_pv0((uint16_t *)skb->data);
    txd->bw_cfg  = (txd->bw_cfg & 0xE7) | ((ah_lmac.bss_bw & 3) << 3);

    if (txd->frame_type_hi & 0x02u) {
        txd->fallback_count  = 0;
    }

    lmac_tx_pv0_data(skb);

    txd->aligned_len = lmac_tx_align_len_min(skb->len);

    lmac_partial_aid_update(txd);

    *(uint16_t *)skb->data &= ~0x1000;
    txd->tx_ctrl &= ~0x10;

    if ((txd->tx_ctrl & 0x0F) > 7)
        txd->tx_ctrl = (txd->tx_ctrl & 0xF0) | 7;

    skb->tx       = 1;
    skb->lmaced   = 0;
    skb->acked    = 0;

    {
        /* 802.1d tid -> AC: ACK frames (tid 7, set by halow_tx_p) go to the
         * priority AC3 queue so they are not buried behind a saturated data
         * AC0 -- retransmit timers outran the ACKs and both directions
         * collapsed under load (bench build 44: thousands of dup-ACKs, 75% RF
         * loss on the starved side). */
        uint8_t acq = ieee802_1d_to_ac_tbl[skb->priority & 7u];
        if (acq > 3u) acq = 0u;
        skb->priority = 0;
        int32_t ret = skb_list_queue(&ah_lmac_tx.pTx_ac_queues[acq], skb);
        if (ret) {
            kfree_skb(skb);
            return -5;
        }
    }

    ah_lmac.pending_pkg_to_status_check++;

    if (!lmac_custom_cfg.defer_ac_pd) {
        LMAC_HW->AC_PD = 0;
        LMAC_HW->AC_PD = 0xF;
    }

    log_trace("fast_tx: skb=%p len=%u fc=0x%04x queued", skb, skb->len, fc);
    return 0;
}


void lmac_kick_tx_task(void)
{
    os_sema_up(&ah_lmac_tx.tx_sem);
}



void lmac_tx_init(void) {
    log_info("tx_init: start ctx=%p", &ah_lmac_tx);

    memset(&ah_lmac_tx, 0, sizeof(ah_lmac_tx));
    lmac_tx_queue_init();

    for (uint32_t ac = 0; ac < LMAC_TX_AC_COUNT; ac++) {
        struct lmac_tx_ctx_buff *aggr = &ah_lmac_tx.pTx_ac_aggr_data[ac];

        memset(aggr->skb_list, 0, sizeof(aggr->skb_list));
        aggr->total_len_bytes = 0;
        aggr->symbol_len = 0;
        aggr->first_seq = -1;
        aggr->last_seq = -1;
        aggr->selected_count = 0;
        aggr->queued_count = 0;
        aggr->rate_cfg = 0;
        aggr->tx_flags = 0;
        memset(&aggr->txvec, 0, sizeof(aggr->txvec));
    }

    for (uint32_t i = 0; i < 5; i++)
        ndp_tx_vec_init_one(&ah_lmac_tx.pTx_vector_cache[i * 16]);
    log_debug("tx_init: vec_init done");

    os_sema_init(&ah_lmac_tx.tx_sem, 0);
    os_sema_init(&ah_lmac_tx.tx_status_sem, 0);

    os_task_init((const uint8 *)"lmac tx",
                 (struct os_task *)&ah_lmac_tx.tx_task,
                 (void (*)(void *))lmac_tx_task,
                 (uint32)&ah_lmac_tx);
    os_task_set_stacksize(&ah_lmac_tx.tx_task, 2048);
    _os_task_set_priority(&ah_lmac_tx.tx_task, 81);
    os_task_run(&ah_lmac_tx.tx_task);
    log_debug("tx_init: tx task started");

    os_task_init((const uint8 *)"lmac tx status",
                 (struct os_task *)&ah_lmac_tx.tx_status_task,
                 (void (*)(void *))lmac_tx_status_task,
                 (uint32)&ah_lmac_tx);
    os_task_set_stacksize(&ah_lmac_tx.tx_status_task, 2048);
    _os_task_set_priority(&ah_lmac_tx.tx_status_task, 0x50);
    os_task_run(&ah_lmac_tx.tx_status_task);
    log_debug("tx_init: status task started");

    log_info("tx_init: done");
}


static inline uint16_t lmac_tx_align_len_min(uint16_t len) {
    uint16_t v = len + 8;

    if ((len & 3) != 0) {
        v = (v & 0xfffc) + 4;
    }
    return v;
}

static void lmac_tx_drop_min(struct sk_buff *skb) {
    skb->acked = 0;
    skb_list_queue(&ah_lmac_tx.tx_frames_pending_queue, skb);
    os_sema_up(&ah_lmac_tx.tx_status_sem);
}


static void lmac_tx_task(void *_arg) {
    uint32_t loop_iter = 0;

    log_info("tx_task: start arg=%p", _arg);

    while (((uint8_t)ah_lmac_tx.exit_flag & 1) == 0) {
        struct sk_buff *skb;
        int sema_result;

        loop_iter++;
        /* Every enqueue already os_sema_up()'s tx_sem (lmac_ah_tx / kick), so the
         * timeout here is only a defensive reload poll. 1 tick (1ms) made the task
         * wake 1000x/s and call lmac_tx_data_reload() on every idle tick — a large
         * share of the ~22% idle CPU. Stretching to 50 ticks cuts that by ~50x
         * with zero added TX latency: real frames still wake the task instantly. */
        sema_result = os_sema_down(&ah_lmac_tx.tx_sem, 50);
//
//        log_trace("tx_task: wake iter=%u sema=%d pending=%u",
//                  loop_iter, sema_result,
//                  skb_list_count(&ah_lmac_tx.tx_pending_queue));

        if (sema_result == 0) {
            lmac_tx_data_reload();
            continue;
        }

        /* Hard-wedge recovery: the vacancy watchdog detected pending TX with
         * zero TX-complete progress. Purge the stuck AC queues now (we are
         * their only producer; IRQs are off for the drain). */
        if (lmac_tx_purge_request) {
            lmac_tx_purge_request = 0u;
            lmac_tx_purge_ac_queues();
            continue;
        }

        while ((skb = skb_list_dequeue(&ah_lmac_tx.tx_pending_queue)) != NULL) {
            lmac_txd_t *txd;
            uint16_t fc, combined;

            fc = *(uint16_t *)skb->data;

            log_trace("tx_task: skb=%p len=%u fc=0x%04x lmaced=%u",
                      skb, skb->len, fc, skb->lmaced);

            if (((uintptr_t)skb->data & 1) != 0) {
                log_debug("tx_task: drop skb=%p unaligned data=%p", skb, skb->data);
                lmac_tx_drop_min(skb);
                continue;
            }

            txd = (lmac_txd_t *)skb->head;
            memset(txd, 0, sizeof(*txd));

            txd->tx_bw_hint      = ah_lmac.tx_bw_sig;
            txd->tx_rate_mcs     = ah_lmac.tx_mcs;
            txd->fallback_count   = 0x0F;
            txd->rts_cfg          = (txd->rts_cfg & 0x9F) | 0x60;

            txd->frame     = skb->data;
            txd->frame_len = skb->len;

            txd->frame_type_lo = (txd->frame_type_lo & 0xFC) | (skb->data[0] & 3);
            txd->tx_flags     |= 0x02;

            lmac_get_rx_addr(txd->dest_mac, skb->data);
            txd->sta = lmac_sta_get(0xFFFF, txd->dest_mac);

            log_trace("tx_task: skb=%p sta=%p mac=%02x:%02x:%02x:%02x:%02x:%02x",
                      skb, txd->sta,
                      txd->dest_mac[0], txd->dest_mac[1], txd->dest_mac[2],
                      txd->dest_mac[3], txd->dest_mac[4], txd->dest_mac[5]);

            if ((txd->dest_mac[0] & 1) != 0)
                txd->tx_ctrl |= 0x80;

            {
                uint32_t ack = lmac_get_ack_policy(txd);
                txd->frame_type_hi = (txd->frame_type_hi & 0xFD) | ((ack & 1) << 1);
            }

            txd->tx_ctrl &= 0xF0;

            txd->seq_num = (int16_t)lmac_get_seq_num((void *)txd->frame);

            txd->frame_type_lo = (txd->frame_type_lo & 0xE3) | (uint8_t)(((fc >> 2) & 7) << 2);
            combined = ((uint16_t)txd->frame_type_hi << 8) | txd->frame_type_lo;
            combined = (combined & 0xFE1F) | (((fc >> 4) & 0x0F) << 5);
            txd->frame_type_lo = (uint8_t)combined;
            txd->frame_type_hi = (uint8_t)(combined >> 8);

            txd->frame_type_hi = (txd->frame_type_hi & 0xBF) | (((skb->data[1] >> 1) & 1) << 6);
            txd->frame_type_hi = (txd->frame_type_hi & 0x7F) | (skb->data[1] << 7);

            txd->hdr_len = lmac_get_hdr_len_pv0((uint16_t *)skb->data);
            txd->bw_cfg  = (txd->bw_cfg & 0xE7) | ((ah_lmac.bss_bw & 3) << 3);

            /* No-ack: fire-and-forget, zero retry limits */
            if (txd->frame_type_hi & 0x02u) {
                txd->fallback_count  = 0;
            }

            lmac_tx_pv0_data(skb);

            txd->aligned_len = lmac_tx_align_len_min(skb->len);

            lmac_partial_aid_update(txd);

            log_trace("tx_task: after partial_aid skb=%p tx_ctrl=0x%02x tx_flags=0x%02x",
                      skb, txd->tx_ctrl, txd->tx_flags);

            *(uint16_t *)skb->data &= ~0x1000;

            txd->tx_ctrl &= ~0x10;

            if ((txd->tx_ctrl & 0x0F) > 7)
                txd->tx_ctrl = (txd->tx_ctrl & 0xF0) | 7;

            skb_list_queue(&ah_lmac_tx.tx_status_queue, skb);

            log_info("tx: skb=%p len=%u fc=0x%04x ac=%u queued",
                     skb, skb->len, fc, txd->tx_ctrl & 3);

            lmac_tx_data_reload();
        }

        log_trace("tx_task: iter=%u drain done, final reload", loop_iter);
        lmac_tx_data_reload();
    }

    log_info("tx_task: exit exit_flag=0x%02x", (uint8_t)ah_lmac_tx.exit_flag);
}


static void lmac_tx_status_task(void *_arg) {
    sk_buff *skb;

    log_info("tx_status_task: start arg=%p", _arg);

    while (((uint8_t)ah_lmac_tx.exit_flag & 1) == 0) {
        os_sema_down(&ah_lmac_tx.tx_status_sem, -1);

        while ((skb = skb_list_dequeue(&ah_lmac_tx.tx_frames_pending_queue)) != NULL) {
            lmac_txd_t *txd = (lmac_txd_t *)skb->head;

            ah_lmac.tx_irq_ctrl_flags &= 0xfe;
            ah_lmac.pending_pkg_to_status_check--;

            if (skb->users.counter > 1) {
                ah_lmac.tx_retry_or_multi_count++;
            }

            lmac_sta_put(txd->sta);

            if ((txd->tx_flags & 0x02) != 0) {
                uint32_t now = (uint32_t)os_jiffies();
                uint32_t dt = now - (uint32_t)skb->lifetime;

                ah_lmac.send_time_sum += dt;
                if ((int32_t)ah_lmac.last_send_time < (int32_t)dt) {
                    ah_lmac.last_send_time = dt;
                }
                log_trace("tx_status: skb=%p send_time=%u ms", skb, dt);
            }

            if (!skb->lmaced) {
                ah_ops.tx_status(&ah_ops, skb);
            } else {
                kfree_skb(skb);
            }

            log_trace("tx_status: skb=%p done lmaced=%u", skb, skb->lmaced);
        }
    }

    log_info("tx_status_task: exit");
}


int32 lmac_tx_queue_init(void) {
    int32 ret;

    log_debug("tx_queue_init: start ctx=%p", &ah_lmac_tx);

    ret = skb_list_init(&ah_lmac_tx.tx_pending_queue);
    if (ret) {
        log_error("tx_queue_init: tx_pending_queue failed ret=%d", ret);
        return -1;
    }

    ret = skb_list_init(&ah_lmac_tx.tx_status_queue);
    if (ret) {
        log_error("tx_queue_init: tx_status_queue failed ret=%d", ret);
        return -1;
    }

    for (int32_t i = 0; i < LMAC_TX_AC_COUNT; i++) {
        ret = skb_list_init(&ah_lmac_tx.pTx_ac_queues[i]);
        if (ret) {
            log_error("tx_queue_init: ac_queue[%d] failed ret=%d", i, ret);
            return -1;
        }
    }

    ret = skb_list_init(&ah_lmac_tx.tx_frames_pending_queue);
    if (ret) {
        log_error("tx_queue_init: tx_frames_pending_queue failed ret=%d", ret);
        return -1;
    }

    log_debug("tx_queue_init: done");
    return 0;
}

void lmac_tx_data_reload(void) {
    struct skb_list *src = &ah_lmac_tx.tx_status_queue;
    struct sk_buff *skb;
    uint32_t moved = 0;

    while ((skb = skb_list_dequeue(src)) != NULL) {
        lmac_txd_t *txd = (lmac_txd_t *)skb->head;
        uint8_t tid = (txd != NULL) ? (txd->tx_ctrl & 7) : 0;
        uint8_t ac = ieee802_1d_to_ac_tbl[tid];

        if (ac > 3)
            ac = 0;

        skb_list_queue(&ah_lmac_tx.pTx_ac_queues[ac], skb);
        ah_lmac_tx.pTx_agg_count_per_ac[ac]++;
        moved++;

        log_trace("reload: skb=%p tid=%u ac=%u", skb, tid, ac);
    }

    if (skb_list_count(src) == 0) {
        ah_lmac.diag_tx_reload_count++;
    }

    LMAC_HW->AC_PD = 0;
    LMAC_HW->AC_PD = 0xf;

    if (moved != 0) {
        log_debug("reload: moved=%u ac0=%u ac1=%u ac2=%u ac3=%u",
                  moved,
                  skb_list_count(&ah_lmac_tx.pTx_ac_queues[0]),
                  skb_list_count(&ah_lmac_tx.pTx_ac_queues[1]),
                  skb_list_count(&ah_lmac_tx.pTx_ac_queues[2]),
                  skb_list_count(&ah_lmac_tx.pTx_ac_queues[3]));
    }
}



int32 lmac_tx_pv0_data(struct sk_buff *skb) {
    lmac_txd_t *txd = (lmac_txd_t *)skb->head;
    log_trace("pv0_data: skb=%p len=%u", skb, skb->len);
    skb->data[1] &= 0xBF;
    txd->tx_ctrl &= ~0x10;
    return 0;
}



