// Auto-reconstructed: lmac_lmac_rxq.c
#include "typesdef.h"
#include "osal/csky/semaphore.h"
#include "osal/string.h"
#include "lib/lmac/lmac_rxq.h"

extern int32 os_sema_init(struct os_semaphore *sem, int32 val);
extern int32 os_sema_down(struct os_semaphore *sem, int32 tmo_ms);
extern int32 os_sema_up(struct os_semaphore *sem);
extern void assert_internal(const char *__function, unsigned int __line, const char *__assertion);

int32 lmac_rxq_init(struct lmac_rxq *rxq, uint8 *qbuf, int32 qsize) {
    memset(rxq, 0, sizeof(*rxq));
    os_sema_init(&rxq->sem, 0);
    rxq->rxq = (struct lmac_frm_info *)qbuf;
    rxq->size = (uint32)qsize;
    return 0;
}

int32 lmac_rxq_put(struct lmac_rxq *rxq, struct lmac_frm_info *frm_info, int32 count) {
    if (count <= 0) {
        return 0;
    }

    uint16 wpos = rxq->wpos;
    uint16 rpos = rxq->rpos;
    uint32 size = rxq->size;
    uint32 used = (wpos >= rpos) ? ((uint32)wpos - rpos) : ((uint32)size + wpos - rpos);

    if (used + (uint32)count >= size) {
        hgprintf("");
        return 0;
    }

    int32 put_count = 0;
    while (put_count < count) {
        uint16 cur = rxq->wpos;
        uint32 next = (uint32)cur + 1U;
        uint16 next_pos = (next >= size) ? 0U : (uint16)next;

        if (next_pos == rpos) {
            break;
        }

        rxq->rxq[cur] = *frm_info;
        rxq->wpos = next_pos;
        ++put_count;
        ++frm_info;
    }

    os_sema_up(&rxq->sem);

    if (put_count != count) {
        assert_internal(__func__, 58, "");
    }

    return put_count;
}

int32 lmac_rxq_get(struct lmac_rxq *rxq, struct lmac_frm_info *frm_info, int32 count, int32 tmo) {
    if (rxq->wpos == rxq->rpos) {
        os_sema_down(&rxq->sem, tmo);
    }

    int32 get_count = 0;
    while ((rxq->wpos != rxq->rpos) && (get_count < count)) {
        uint16 rpos = rxq->rpos;
        *frm_info = rxq->rxq[rpos];

        uint32 next = (uint32)rpos + 1U;
        rxq->rpos = (next >= rxq->size) ? 0U : (uint16)next;

        ++get_count;
        ++frm_info;
    }

    return get_count;
}

int32 lmac_rxq_free(struct lmac_rxq *rxq) {
    uint16 rpos = rxq->rpos;
    uint16 wpos = rxq->wpos;

    if (wpos >= rpos) {
        return (int32)(rxq->size - 1U + rpos - wpos);
    }

    return (int32)(rpos - wpos - 1U);
}

int32 lmac_rxq_count(struct lmac_rxq *rxq) {
    uint16 wpos = rxq->wpos;
    uint16 rpos = rxq->rpos;

    if (wpos >= rpos) {
        return (int32)(wpos - rpos);
    }

    return (int32)(rxq->size + wpos - rpos);
}
