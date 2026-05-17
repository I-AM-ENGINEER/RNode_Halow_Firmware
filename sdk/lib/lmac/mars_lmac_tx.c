#include "typesdef.h"
#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_MARS_LMAC_TX
#include "lib/logc/log.h"

#include "lib/lmac/lmac_ctx.h"
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/lmac_regmap.h"
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
extern void lmac_irq_ac_pd_orig(void);
extern void ndp_tx_vec_init_orig(uint8_t *txvec);
extern uint32 lmac_get_ack_policy_orig(void *txd);
extern void lmac_partial_aid_update_orig(void *txd);
extern lmac_tx_ctx_t ah_lmac_tx_orig;


static void lmac_tx_drop_min(struct sk_buff *skb);
static void lmac_tx_task(void *arg);
static void lmac_tx_status_task(void *arg);

int32 lmac_tx_queue_init(void);
int32 lmac_check_aggregation(struct sk_buff *skb0, struct sk_buff *skb1);
uint32 seq_num_space_update(void *sta, uint32 tid);
void lmac_tx_data_reload(void);
int32 lmac_tx_pv0_data(struct sk_buff *skb);


typedef struct sk_buff sk_buff;
typedef struct skb_list skb_list;


#define LMAC_TX_AC_COUNT 4

/* Raw byte access to LMAC context structs */
#define _LM ((uint8_t *)&ah_lmac)
#define _LMX ((uint8_t *)&ah_lmac_tx_orig)


static const uint8_t ieee802_1d_to_ac_tbl[8] = {0, 1, 1, 0, 2, 2, 3, 3};


int32 lmac_ah_tx(struct lmac_ops *ops, struct sk_buff *skb)
{
    uint32_t headroom;
    int32 ret;

    if (!skb || !ops->radio_on)
        return -1;

    headroom = skb_headroom(skb);
    if (headroom <= 0x47) {
        log_warn("ah_tx: skb=%p headroom=%u too small (need>0x47)", skb, headroom);
        return -1;
    }

    /* low 32: submission timestamp; high 32: headroom (used by cipher path) */
    skb->lifetime = (uint64_t)(uint32_t)os_jiffies() | ((uint64_t)headroom << 32);

    ret = skb_list_queue(&ah_lmac_tx_orig.tx_pending_queue, skb);
    if (ret) {
        log_error("ah_tx: queue failed ret=%d", ret);
        return ret;
    }

    os_sema_up(&ah_lmac_tx_orig.tx_sem);
    ah_lmac.pending_pkg_to_status_check++;

    log_trace("ah_tx: skb=%p len=%u headroom=%u", skb, skb->len, headroom);
    return 0;
}


void lmac_kick_tx_task(void)
{
    os_sema_up(&ah_lmac_tx_orig.tx_sem);
}


void lmac_irq_ac_pd(void) {
    static uint32_t n;

    n++;

//    if ((n & 0x3f) == 0) {
//        log_trace("irq_ac_pd n=%u ac0=%u ag0_q=%u ag0_sel=%u pend=%u pd=0x%08x",
//                  n,
//                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
//                  ah_lmac_tx_orig.pTx_ac_aggr_data[0].queued_count,
//                  ah_lmac_tx_orig.pTx_ac_aggr_data[0].selected_count,
//                  skb_list_count(&ah_lmac_tx_orig.tx_frames_pending_queue),
//                  LMAC_HW->AC_PD);
//    }

    lmac_irq_ac_pd_orig();
//
//    if ((n & 0x3f) == 0) {
//        log_trace("irq_ac_pd exit n=%u ac0=%u ag0_sel=%u first=%p pend=%u pd=0x%08x",
//                  n,
//                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
//                  ah_lmac_tx_orig.pTx_ac_aggr_data[0].selected_count,
//                  ah_lmac_tx_orig.pTx_ac_aggr_data[0].skb_list[0],
//                  skb_list_count(&ah_lmac_tx_orig.tx_frames_pending_queue),
//                  LMAC_HW->AC_PD);
//    }
}


__attribute__((weak)) void lmac_tx_init(void) {
    log_info("tx_init: start ctx=%p", &ah_lmac_tx_orig);

    memset(&ah_lmac_tx_orig, 0, 0x6d4);
    lmac_tx_queue_init();

    for (uint32_t ac = 0; ac < LMAC_TX_AC_COUNT; ac++) {
        struct lmac_tx_ctx_buff *aggr = &ah_lmac_tx_orig.pTx_ac_aggr_data[ac];

        memset(aggr->skb_list, 0, sizeof(aggr->skb_list));
        aggr->total_len_bytes = 0;
        aggr->symbol_len = 0;
        aggr->first_seq = -1;
        aggr->last_seq = -1;
        aggr->selected_count = 0;
        aggr->queued_count = 0;
        aggr->rate_cfg = 0;
    }

    ndp_tx_vec_init_orig(&ah_lmac_tx_orig.pTx_vector_cache[0].fmt_byte);
    ndp_tx_vec_init_orig(&ah_lmac_tx_orig.pTx_vector_cache[1].fmt_byte);
    ndp_tx_vec_init_orig(&ah_lmac_tx_orig.pTx_vector_cache[2].fmt_byte);
    ndp_tx_vec_init_orig(&ah_lmac_tx_orig.pTx_vector_cache[3].fmt_byte);
    ndp_tx_vec_init_orig(&ah_lmac_tx_orig.pTx_vector_cache[4].fmt_byte);
    log_debug("tx_init: vec_init done");

    os_sema_init(&ah_lmac_tx_orig.tx_sem, 0);
    os_sema_init(&ah_lmac_tx_orig.tx_status_sem, 0);

    os_task_init((const uint8 *)"lmac tx",
                 (struct os_task *)&ah_lmac_tx_orig.tx_task,
                 (void (*)(void *))lmac_tx_task,
                 (uint32)&ah_lmac_tx_orig);
    os_task_set_stacksize(&ah_lmac_tx_orig.tx_task, 2048);
    _os_task_set_priority(&ah_lmac_tx_orig.tx_task, 81);
    os_task_run(&ah_lmac_tx_orig.tx_task);
    log_debug("tx_init: tx task started");

    os_task_init((const uint8 *)"lmac tx status",
                 (struct os_task *)&ah_lmac_tx_orig.tx_status_task,
                 (void (*)(void *))lmac_tx_status_task,
                 (uint32)&ah_lmac_tx_orig);
    os_task_set_stacksize(&ah_lmac_tx_orig.tx_status_task, 2048);
    _os_task_set_priority(&ah_lmac_tx_orig.tx_status_task, 0x50);
    os_task_run(&ah_lmac_tx_orig.tx_status_task);
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
    skb_list_queue(&ah_lmac_tx_orig.tx_frames_pending_queue, skb);
    os_sema_up(&ah_lmac_tx_orig.tx_status_sem);
}


static void lmac_tx_task(void *_arg) {
    uint32_t loop_iter = 0;

    log_info("tx_task: start arg=%p", _arg);

    while (((uint8_t)ah_lmac_tx_orig.exit_flag & 1) == 0) {
        struct sk_buff *skb;
        int sema_result;

        loop_iter++;
        sema_result = os_sema_down(&ah_lmac_tx_orig.tx_sem, 1);
//
//        log_trace("tx_task: wake iter=%u sema=%d pending=%u",
//                  loop_iter, sema_result,
//                  skb_list_count(&ah_lmac_tx_orig.tx_pending_queue));

        if (sema_result == 0) {
            lmac_tx_data_reload();
            continue;
        }

        while ((skb = skb_list_dequeue(&ah_lmac_tx_orig.tx_pending_queue)) != NULL) {
            uint8_t *txd_raw;
            uint16_t fc;

            fc = *(uint16_t *)skb->data;

            log_trace("tx_task: skb=%p len=%u fc=0x%04x lmaced=%u",
                      skb, skb->len, fc, skb->lmaced);

            if (((uintptr_t)skb->data & 1) != 0) {
                log_debug("tx_task: drop skb=%p unaligned data=%p", skb, skb->data);
                lmac_tx_drop_min(skb);
                continue;
            }

            txd_raw = skb->head;
            memset(txd_raw, 0, 0x44);

            txd_raw[0x3c] = 0xff;
            txd_raw[0x3d] = 0xff;
            txd_raw[0x3e] = 0x0f;
            txd_raw[0x3f] = (txd_raw[0x3f] & 0x9f) | 0x60;

            *(uint32_t *)(txd_raw + 0x10) = (uint32_t)skb->data;
            *(uint16_t *)(txd_raw + 0x14) = skb->len;

            txd_raw[0x24] = (txd_raw[0x24] & 0xfc) | (skb->data[0] & 3);

            txd_raw[0x27] |= 0x02;

            lmac_get_rx_addr(txd_raw + 0x1a, skb->data);
            *(uint32_t *)(txd_raw + 0x0c) = (uint32_t)lmac_sta_get(0xffff, txd_raw + 0x1a);

            log_trace("tx_task: skb=%p sta=%p mac=%02x:%02x:%02x:%02x:%02x:%02x",
                      skb,
                      (void *)*(uint32_t *)(txd_raw + 0x0c),
                      txd_raw[0x1a], txd_raw[0x1b], txd_raw[0x1c],
                      txd_raw[0x1d], txd_raw[0x1e], txd_raw[0x1f]);

            if ((txd_raw[0x1a] & 1) != 0) {
                txd_raw[0x26] |= 0x80;
            }

            {
                uint32_t ack = lmac_get_ack_policy_orig(txd_raw);
                txd_raw[0x25] = (txd_raw[0x25] & 0xfd) | ((ack & 1) << 1);
            }

            txd_raw[0x26] &= 0xf0;

            *(int16_t *)(txd_raw + 0x18) =
                (int16_t)lmac_get_seq_num((void *)*(uint32_t *)(txd_raw + 0x10));

            {
                uint16_t combined;

                txd_raw[0x24] = (txd_raw[0x24] & 0xe3) | (uint8_t)(((fc >> 2) & 7) << 2);
                combined = ((uint16_t)txd_raw[0x25] << 8) | txd_raw[0x24];
                combined = (combined & 0xfe1f) | (((fc >> 4) & 0x0f) << 5);
                txd_raw[0x24] = (uint8_t)combined;
                txd_raw[0x25] = (uint8_t)(combined >> 8);

                txd_raw[0x25] = (txd_raw[0x25] & 0xbf) | (((skb->data[1] >> 1) & 1) << 6);
                txd_raw[0x25] = (txd_raw[0x25] & 0x7f) | (skb->data[1] << 7);

                txd_raw[0x2a] = lmac_get_hdr_len_pv0((uint16_t *)skb->data);
                txd_raw[0x2b] = (txd_raw[0x2b] & 0xe7) | ((ah_lmac.bss_bw & 3) << 3);
            }

            lmac_tx_pv0_data(skb);

            *(uint16_t *)(txd_raw + 0x16) = lmac_tx_align_len_min(skb->len);

            if (((ah_lmac.beacon_s1g_format_flags & 1) == 0) &&
                (*(uint16_t *)(txd_raw + 0x16) > 0x067b)) {
                log_warn("tx_task: drop skb=%p frame too large aligned_len=%u",
                         skb, *(uint16_t *)(txd_raw + 0x16));
                lmac_tx_drop_min(skb);
                continue;
            }

            lmac_partial_aid_update_orig(txd_raw);

            log_trace("tx_task: after partial_aid skb=%p txd26=0x%02x txd27=0x%02x",
                      skb, txd_raw[0x26], txd_raw[0x27]);

            *(uint16_t *)skb->data &= ~0x1000;

            txd_raw[0x26] &= ~0x10;

            if ((txd_raw[0x26] & 0x0f) > 7) {
                txd_raw[0x26] = (txd_raw[0x26] & 0xf0) | 7;
            }

            skb_list_queue(&ah_lmac_tx_orig.tx_status_queue, skb);

            log_info("tx: skb=%p len=%u fc=0x%04x ac=%u queued",
                     skb, skb->len, fc, txd_raw[0x26] & 3);

            lmac_tx_data_reload();
        }

        log_trace("tx_task: iter=%u drain done, final reload", loop_iter);
        lmac_tx_data_reload();
    }

    log_info("tx_task: exit exit_flag=0x%02x", (uint8_t)ah_lmac_tx_orig.exit_flag);
}


static void lmac_tx_status_task(void *_arg) {
    sk_buff *skb;

    log_info("tx_status_task: start arg=%p", _arg);

    while (((uint8_t)ah_lmac_tx_orig.exit_flag & 1) == 0) {
        os_sema_down(&ah_lmac_tx_orig.tx_status_sem, -1);

        while ((skb = skb_list_dequeue(&ah_lmac_tx_orig.tx_frames_pending_queue)) != NULL) {
            uint8_t *txd = skb->head;

            ah_lmac._rsv_a64[0] &= 0xfe;
            ah_lmac.pending_pkg_to_status_check--;

            if (skb->users.counter > 1) {
                ah_lmac.tx_retry_or_multi_count++;
            }

            lmac_sta_put((void *)*(uint32_t *)(txd + 0x0c));

            if ((txd[0x27] & 2) != 0) {
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

    log_debug("tx_queue_init: start ctx=%p", _LMX);

    ret = skb_list_init(&ah_lmac_tx_orig.tx_pending_queue);
    if (ret) {
        log_error("tx_queue_init: tx_pending_queue failed ret=%d", ret);
        return -1;
    }

    ret = skb_list_init(&ah_lmac_tx_orig.tx_status_queue);
    if (ret) {
        log_error("tx_queue_init: tx_status_queue failed ret=%d", ret);
        return -1;
    }

    ret = skb_list_init(&ah_lmac_tx_orig.tx_retry_queue);
    if (ret) {
        log_error("tx_queue_init: tx_retry_queue failed ret=%d", ret);
        return -1;
    }

    for (int32_t i = 0; i < LMAC_TX_AC_COUNT; i++) {
        ret = skb_list_init(&ah_lmac_tx_orig.pTx_ac_queues[i]);
        if (ret) {
            log_error("tx_queue_init: ac_queue[%d] failed ret=%d", i, ret);
            return -1;
        }
    }

    ret = skb_list_init(&ah_lmac_tx_orig.tx_frames_pending_queue);
    if (ret) {
        log_error("tx_queue_init: tx_frames_pending_queue failed ret=%d", ret);
        return -1;
    }

    log_debug("tx_queue_init: done");
    return 0;
}

void lmac_tx_data_reload(void) {
    struct skb_list *src = &ah_lmac_tx_orig.tx_status_queue;
    struct sk_buff *skb;
    uint32_t moved = 0;

    while ((skb = skb_list_dequeue(src)) != NULL) {
        uint8_t tid = (skb->head != NULL) ? (skb->head[0x26] & 7) : 0;
        uint8_t ac = ieee802_1d_to_ac_tbl[tid];

        if (ac > 3)
            ac = 0;

        skb_list_queue(&ah_lmac_tx_orig.pTx_ac_queues[ac], skb);
        ah_lmac_tx_orig.pTx_agg_count_per_ac[ac]++;
        moved++;

        log_trace("reload: skb=%p tid=%u ac=%u", skb, tid, ac);
    }

    if (skb_list_count(src) == 0) {
        ah_lmac.tx_state_7ac++;
    }

    LMAC_HW->AC_PD = 0;
    LMAC_HW->AC_PD = 0xf;

    if (moved != 0) {
        log_debug("reload: moved=%u ac0=%u ac1=%u ac2=%u ac3=%u",
                  moved,
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[1]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[2]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[3]));
    }
}


int32 lmac_tx_pv0_data(struct sk_buff *skb) {
    log_trace("pv0_data: skb=%p len=%u", skb, skb->len);
    skb->data[1] &= 0xbf;
    skb->head[0x26] &= 0xef;
    return 0;
}


#define _STUB(name) \
    log_warn("STUB: " #name " skb=%p len=%u", skb, skb->len); \
    (void)skb; \
    return 0

int32 lmac_check_aggregation(struct sk_buff *skb0, struct sk_buff *skb1) {
    log_warn("STUB: lmac_check_aggregation skb0=%p skb1=%p", skb0, skb1);
    (void)skb0; (void)skb1;
    return -1;
}

uint32 seq_num_space_update(void *sta, uint32 tid) {
    log_warn("STUB: seq_num_space_update sta=%p tid=%u", sta, tid);
    (void)sta; (void)tid;
    return 0;
}

int32 lmac_tx_pv0_mgmt(struct sk_buff *skb)  { _STUB(lmac_tx_pv0_mgmt);  }
int32 lmac_tx_pv0_ctrl(struct sk_buff *skb)  { _STUB(lmac_tx_pv0_ctrl);  }
int32 lmac_tx_pv0_ext(struct sk_buff *skb)   { _STUB(lmac_tx_pv0_ext);   }
int32 lmac_tx_pv1_data1(struct sk_buff *skb) { _STUB(lmac_tx_pv1_data1); }
int32 lmac_tx_pv1_data2(struct sk_buff *skb) { _STUB(lmac_tx_pv1_data2); }
int32 lmac_tx_pv1_mgmt(struct sk_buff *skb)  { _STUB(lmac_tx_pv1_mgmt);  }
int32 lmac_tx_pv1_ctrl(struct sk_buff *skb)  { _STUB(lmac_tx_pv1_ctrl);  }

#undef _STUB

#undef _LM
#undef _LMX
