#ifndef _HGIC_LMAC_DEF_H_
#define _HGIC_LMAC_DEF_H_
#include "typesdef.h"
#include "list.h"
#include "lmac.h"
#include "lib/skb/skb.h"
#include "lib/lmac/hgic.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lmac_txq_param {
    uint16 txop;
    uint16 cw_min;
    uint16 cw_max;
    uint8  aifs;
    uint8  acm;
};

struct lmac_acs_ctl;

struct lmac_ops {
    void *priv;
    void *btops;
    uint8  headroom, tailroom;
    uint16 radio_on : 1; //flags
    int32(*open)(struct lmac_ops *ops);
    int32(*close)(struct lmac_ops *ops);
    int32(*tx)(struct lmac_ops *ops, struct sk_buff *skb);
    int32(*test_tx)(struct lmac_ops *ops, struct sk_buff *skb);
    int32(*tx_status)(struct lmac_ops *ops, struct sk_buff *skb);
    int32(*rx)(struct lmac_ops *ops, struct hgic_rx_info *info, uint8 *data, int32 len);
    int32(*notify)(struct lmac_ops *ops, uint8 evt_id, uint8 *data, int32 len);
    int32(*set_chan_list)(struct lmac_ops *ops, uint16 *chan_list, uint16 count);
    int32(*set_freq_range)(struct lmac_ops *ops, uint16 freq_start, uint16 freq_end, uint8 chan_bw);
    int32(*set_freq)(struct lmac_ops *ops, uint32 center_freq);
    int32(*start_acs)(struct lmac_ops *ops, struct lmac_acs_ctl *p_ctl, uint32 sync);
    int32(*add_sta)(struct lmac_ops *ops, uint8 ifidx, uint16 aid, uint8 *addr);
    int32(*del_sta)(struct lmac_ops *ops, uint8 ifidx, uint8 *addr);
    int32(*set_key)(struct lmac_ops *ops, uint8 cmd, uint8 *addr, uint8 *key, uint32 len);
    int32(*sleep)(struct lmac_ops *ops, uint32 sleep_en, uint32 sleep_tm, uint32 flags);
    int32(*ioctl)(struct lmac_ops *ops, uint32 cmd, uint32 param1, uint32 param2);
    struct sk_buff *(*test_cmd)(struct lmac_ops *ops, struct sk_buff *skb);
};

typedef struct lmac_ops lmac_ops_t;

_Static_assert(sizeof(lmac_ops_t) == 0x50, "lmac_ops_t size");

//////////////////////////////////////////////////////////////////////////////////

static inline int32 lmac_open(struct lmac_ops *ops)
{
    return ops->open(ops);
}
static inline int32 lmac_close(struct lmac_ops *ops)
{
    return ops->close(ops);
}
static inline struct sk_buff *lmac_do_test_cmd(struct lmac_ops *ops, struct sk_buff *skb)
{
    return ops->test_cmd(ops, skb);
}
static inline int32 lmac_tx(struct lmac_ops *ops, struct sk_buff *skb)
{
    return ops->tx(ops, skb);
}
static inline int32 lmac_test_tx(struct lmac_ops *ops, struct sk_buff *skb)
{
    return ops->test_tx(ops, skb);
}
//static inline int32 lmac_set_chan_list(struct lmac_ops *ops, uint16 *chan_list, uint32 chan_cnt)
//{
//    if(ops->set_chan_list)
//        return ops->set_chan_list(ops, chan_list, chan_cnt);
//    return RET_ERR;
//}
static inline int32 lmac_set_freq_range(struct lmac_ops *ops, uint32 freq_start, uint32 freq_end, uint8 chan_bw)
{
    if(ops->set_freq_range)
        return ops->set_freq_range(ops, freq_start, freq_end, chan_bw);
    return RET_ERR;
}
static inline int32 lmac_add_sta(struct lmac_ops *ops, uint8 ifidx, uint16 aid, uint8 *addr)
{
    return ops->add_sta(ops, ifidx, aid, addr);
}
static inline int32 lmac_del_sta(struct lmac_ops *ops, uint8 ifidx, uint8 *addr)
{
    return ops->del_sta(ops, ifidx, addr);
}
static inline int32 lmac_set_key(struct lmac_ops *ops, uint8 cmd, uint8 *addr, uint8 *key, uint32 len)
{
    return ops->set_key(ops, cmd, addr, key, len);
}
static inline int32 lmac_sleep(struct lmac_ops *ops, uint32 sleep_en, uint32 sleep_tm, uint32 flags)
{
    return ops->sleep(ops, sleep_en, sleep_tm, flags);
}
static inline int32 lmac_set_freq(struct lmac_ops *ops, uint32 center_freq)
{
    return ops->set_freq(ops, center_freq);
}

#ifdef __cplusplus
}
#endif

#endif
