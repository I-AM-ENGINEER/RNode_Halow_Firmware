// Auto-reconstructed: mars_lmac_tx.c
#include "sys_config.h"
//#define LOG_LOCAL_LEVEL LOG_LEVEL_MARS_LMAC_TX
#include "lib/logc/log.h"

#include "typesdef.h"
#include "osal/string.h"
#include "osal/semaphore.h"
#include "osal/task.h"
#include "osal/time.h"
#include "lib/lmac/lmac_ctx.h"
#include "lib/lmac/lmac_def.h"

/* Function declarations for functions used in this file */
extern int32 _os_task_set_priority(struct os_task *task, uint8 priority);
extern int32 lmac_send_data_to_phy(uint32 ac);
extern int ah_ce_start(void *ctx, void *cfg);
#include "lib/lmac/ieee802_11_defs.h"
#include "lib/lmac/lmac_regmap.h"
#include "lib/lmac/mars_tdma.h"
#include "lib/skb/skb.h"
#include "lib/skb/skbuff.h"
#include "lib/skb/skb_list.h"

extern int32 os_sema_up(struct os_semaphore *sem);
extern int32 skb_list_init(struct skb_list *list);
extern uint32 skb_list_count(struct skb_list *list);
extern void assert_internal(const char *__function, unsigned int __line, const char *__assertion);
extern int32 os_task_set_priority(struct os_task *task, uint8 priority);
extern void lmac_sta_put(void *sta);
extern void lhw_cfg_dma_list_cnt(uint32 cnt);
extern void lhw_cfg_tx_sub_frm(uint32 idx, uint32 v0, uint32 v1);
extern void lhw_abort_fsm(void);
extern void lhw_start_rx(uint32 flags);
extern uint32 lhw_get_cca_remain(void);
extern void lhw_start_cca(uint32 bw, uint32 dur);
extern void lhw_start_tx(uint32 flags);
extern void hgics_print_hex(void *buf, uint32 len);
extern uint16 partial_bssid_calc(uint8 *bssid);
extern uint16 partial_aid_calc(uint16 aid, uint8 *bssid);
extern void lmac_lo_table_kick(uint16 id);
extern int32 lmac_tdma_start(void);
extern void lmac_set_basic_nav(uint32 nav);
extern void lmac_get_rx_addr(uint8 *addr, uint8 *hdr);
extern void *lmac_sta_get(uint16 aid, uint8 *addr);
extern void *lmac_sta_search(uint16 aid, uint8 *addr);
extern uint32 lmac_get_tid(void *hdr);
extern uint32 lmac_get_seq_num(void *hdr);
extern uint32 lmac_get_hdr_len_pv0(void *hdr);
extern uint32 lmac_get_hdr_len_pv1(void *hdr);
extern uint8 *lmac_convert_sid2mac(uint16 sid);
void lmac_tx_pv0_s1g_beacon(struct sk_buff *skb);
extern uint32 calc_max_agg_bytes(uint32 bw, uint32 mcs);
extern uint32 calc_symbol_len(uint32 bytes, uint32 bw, uint32 mcs);
extern void ah_rfdigicali_tx_pwr(uint32 arg0);
extern void config_ft_att_val(void);
extern int jtag_map_set(uint8 val);
extern int32 gpio_set_dir(uint32 pin, int32 direction);
extern int32 gpio_set_val(uint32 pin, int32 value);
extern void lhw_enable_irq_ac(void);
extern void lmac_delay_us(uint32 us);
extern void lmac_cancle_tx_tmo(void);
extern uint32 ah_wphy_err_code_get(void);
extern void lmac_rx_gain_cfg(uint32 gain);
extern void update_rx_buff_addr(void);
extern void os_sleep_us(int us);
extern void ah_rfdigicali_bknoise_calc_en(void);
extern void ah_rfdigicali_bknoise_calc_dis(void);
extern uint32 ah_rfdigicali_bknoise_valid_pd_get(void);
extern void ah_rfdigicali_bknoise_valid_pd_clr(void);
extern int8 ah_rfdigicali_bknoise_get(void);
extern uint32 ah_wphy_agc_info_get(void);
extern int32 ah_wphy_rx_gain_para_get(int32 idx);
extern void ah_wphy_cca_th_cfg(void *cfg);
extern void ah_wphy_obss_para_cfg(int32 a, int32 b, int32 c, int32 d);
extern uint64 lhw_get_ndp2m(void);
extern void ah_rfdigicali_config_hw_bknoise(uint16_t arg0, uint16_t arg1);
extern void ah_wphy_auto_sig_err_rst_disable(void);
extern void ah_wphy_auto_sig_err_rst_enable(void);
extern void ah_wphy_pri_channel_cfg(uint32 cfg);
extern int32 lmac_lo_freq_set(uint16 id);
extern void lmac_notify_channel_switch(uint8 chan);
extern void lmac_beacon_timer_start(uint32 us);
static void lmac_check_tx_queue_empty(void);
int32 lmac_tx_queue_init(void);
static void lmac_tx_task(void *arg);
static void lmac_tx_status_task(void *arg);


__attribute__((weak)) void ndp_tx_vec_init_one(uint8_t *txvec);
int32 lmac_check_aggregation(struct sk_buff *skb0, struct sk_buff *skb1);
__attribute__((weak)) void lmac_partial_aid_update(void *txi);
uint32 seq_num_space_update(void *sta, uint32 tid);
__attribute__((weak)) uint32 lmac_hdr_dur_calc(uint32 len);
__attribute__((weak)) uint32 lmac_dtim_timer_rem(void);
__attribute__((weak)) int32 lmac_tx_to_pm_ap(void);
__attribute__((weak)) int32 lmac_cfg_txvec_part1(void);
__attribute__((weak)) int32 lmac_cfg_txvec_part2(void);
__attribute__((weak)) uint32 lmac_get_ack_policy(void *txi);
static uint32 tx_pwr_adjust_by_mcs(uint32 tx_pwr, uint32 mcs);
__attribute__((weak)) int32 lmac_tx_pwr_sel(void *txi, uint32 mcs);
__attribute__((weak)) uint32 pv0_ctrl_uplink_txpwr_gen(void);
__attribute__((weak)) uint32 lmac_select_resp_ind(void);
__attribute__((weak)) uint32 lmac_select_tx_acq(void);
__attribute__((weak)) int32 lmac_tx_frame_regen(uint32 ac, uint32 ac_hint, uint32 mcs, void *arg);
__attribute__((weak)) int32 lmac_tx_date_prepared(void);
__attribute__((weak)) void *lmac_gen_txvec(uint32 ac, uint32 ac_hint, uint32 mcs);
static int32 lmac_attempt_tx_obss(int32 lo_id);
static int32 lmac_attempt_tx(uint32 ac);
__attribute__((weak)) void ndp_tx_vec_init(void);
__attribute__((weak)) void lmac_pv0_rts_init(void);
__attribute__((weak)) void lmac_pv0_wpcts_init(void);
__attribute__((weak)) void lmac_pv0_wpack_init(void);
__attribute__((weak)) void lmac_pv0_wpba_init(void);
__attribute__((weak)) void lmac_pv0_cfpoll_init(void);
__attribute__((weak)) void lmac_pv0_cfend_init(void);
__attribute__((weak)) void lmac_pv0_qos_null_init(void);
__attribute__((weak)) void lmac_pv0_pspoll_init(void);
__attribute__((weak)) int32 lmac_tx_ba(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_ack(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_cts(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_rts(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_pv0_null(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_pv0_pspoll(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_pv0_cfpoll(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_pv0_cfend(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_frm(struct sk_buff *skb);
__attribute__((weak)) int32 lmac_tx_beacon(struct sk_buff *skb);
__attribute__((weak)) int32 ndp_pspoll_ack_rx_hdl(void);

extern void *lmac_gen_tx_agglist_orig(uint32 ac, uint32 ac_hint, uint32 mcs, void *arg);
/* ---- Ghidra decompilation porting aids ---- */

typedef unsigned short ushort;
typedef unsigned int   uint;
typedef uint8_t  undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;

#define CONCAT11(hi, lo) ((uint16_t)((uint8_t)(hi) << 8 | (uint8_t)(lo)))

/* struct sk_buff / skb_list without struct keyword */
typedef struct sk_buff  sk_buff;
typedef struct skb_list skb_list;
typedef struct lmac_tx_ctx lmac_tx_ctx;

/* 802.11 frame-control: 2 bytes accessible as word or individual bytes */
typedef union {
    struct { uint8_t frame_control; uint8_t field_0x1; };
    uint16_t word;
} astruct;

/* TX info (txinfo) struct – only accessed fields named, rest opaque */
typedef struct {
    uint8_t  _p0;
    uint8_t  field1_0x1;   /* beacon_ch_type */
    uint8_t  _p2;
    uint8_t  field3_0x3;   /* rate_flags source */
    uint32_t field4_0x4;   /* hw_ctrl_word source */
    uint16_t field5_0x8;   /* frame_ctrl source */
    uint8_t  field6_0xa;   /* bw_tx_level source */
    uint8_t  _rest[329];
} astruct_1;

/* TX descriptor – 68 bytes, lives at tx_skb->head */
typedef struct {
    uint32_t  dwHw_ctrl_word;           /* offset  0 */
    uint32_t  dwFrame_ctrl_from_txinfo; /* offset  4 */
    uint32_t  dwSeq_dup_flags;          /* offset  8 */
    uint32_t  sta_idx_ptr;              /* offset 12 */
    void     *frame_data_ptr;           /* offset 16 */
    uint16_t  frame_len;                /* offset 20 */
    uint16_t  frame_ctrl;               /* offset 22 */
    int16_t   seq_num_frag;             /* offset 24 */
    uint8_t   receiver_mac[6];          /* offset 26 */
    uint8_t   pFrame_subtype_reserved[4]; /* offset 32 */
    uint8_t   frame_type_flags;         /* offset 36 */
    uint8_t   ack_mf_md_flags;          /* offset 37 */
    uint8_t   tid_ac_partial_aid;       /* offset 38 */
    uint8_t   data_beacon_flag;         /* offset 39 */
    uint8_t   pRsv_hdr_gap[2];          /* offset 40 */
    uint8_t   hdr_len;                  /* offset 42 */
    uint8_t   bandwidth_field;          /* offset 43 */
    uint8_t   mcast_dup_filter;         /* offset 44 */
    uint8_t   pCcmp_aad_scratch[15];    /* offset 45 */
    uint8_t   beacon_ch_type;           /* offset 60 */
    uint8_t   mcs_index;                /* offset 61 */
    uint8_t   bw_tx_level;              /* offset 62 */
    uint8_t   rate_flags;               /* offset 63 */
    uint8_t   pRsv_end_pad[4];          /* offset 64 */
} lmac_txd;

/* indirect call type for PV0/PV1 handler tables */
typedef int lmac_tx_handler_t(struct sk_buff *skb);

/* Binary splits sk_buff->lifetime (uint64) into start_send_time(u32)+Data_to_send(u32*).
   Access the first 4 bytes without modifying skbuff.h. */
#define skb_start_send_time(skb) (*(uint32_t *)&(skb)->lifetime)

/* renamed from GCC-mangled dot-named statics (local to lmac_tx_task) */
static uint8_t  key_id_13616;
static uint32_t pn_num_13617;
static uint32_t pn_num_hi;      /* was DAT_20052e28 (high 32 bits of PN) */
static uint16_t sn_dup_13763;

/* helpers from binary */
extern void lmac_tx_vec_init(void);
void lmac_tx_data_reload(void);  /* defined later in this file */

/* TX context global — use the _orig symbol from mars_lmac_tx_origfuncs.o */
extern lmac_tx_ctx_t ah_lmac_tx_orig;

/* PV0/PV1 subtype handlers — defined later in this file */
int32 lmac_tx_pv0_mgmt(struct sk_buff *);
int32 lmac_tx_pv0_ctrl(struct sk_buff *);
int32 lmac_tx_pv0_data(struct sk_buff *);
int32 lmac_tx_pv0_ext(struct sk_buff *);
int32 lmac_tx_pv1_data1(struct sk_buff *);
int32 lmac_tx_pv1_mgmt(struct sk_buff *);
int32 lmac_tx_pv1_ctrl(struct sk_buff *);
int32 lmac_tx_pv1_data2(struct sk_buff *);

/* Subtype dispatch tables: index = (frame_type_flags & 0xf) >> 2 */
static lmac_tx_handler_t *lmac_tx_pv0_hdl[4] = {
    lmac_tx_pv0_mgmt,
    lmac_tx_pv0_ctrl,
    lmac_tx_pv0_data,
    lmac_tx_pv0_ext,
};
static lmac_tx_handler_t *lmac_tx_pv1_hdl[4] = {
    lmac_tx_pv1_data1,
    lmac_tx_pv1_mgmt,
    lmac_tx_pv1_ctrl,
    lmac_tx_pv1_data2,
};

/* Cipher engine TX parameters: decompiled from lmac_cfg_tx_ce_para.isra.5.constprop.21.
 * Configures ah_lmac_tx_orig cipher fields from the TX descriptor (head = tx_skb->head).
 * Offsets verified against Ghidra @ 20036d24. */
static void lmac_cfg_tx_ce_para_isra5(uint8_t *head)
{
    uint8_t *tx      = (uint8_t *)&ah_lmac_tx_orig;
    uint8_t *lmac_b  = (uint8_t *)&ah_lmac;
    uint8_t  bw_val;
    void    *key_ptr;

    if ((int8_t)head[0x26] < 0) {
        /* multicast/group-key path: read from ah_lmac.key0 area */
        bw_val  = lmac_b[0x693];
        key_ptr = (void *)(lmac_b + 0x694);
    } else {
        /* unicast STA path: read from sta struct */
        uint8_t *sta = (uint8_t *)*(uint32_t *)(head + 0x0c);
        bw_val  = sta[0x76];
        key_ptr = (void *)(sta + 0x77);
    }

    if      (bw_val == 0x10) tx[0x6ac] = 0;  /* 1 MHz → cipher_bw = 0 */
    else if (bw_val == 0x20) tx[0x6ac] = 2;  /* 2 MHz → cipher_bw = 2 */
    else    log_debug("\x02lmac error!!!ce bw= 0x%x\r\n", (uint32_t)bw_val);

    tx[0x6ad] = tx[0x69a] & 7;
    tx[0x6ae] = (tx[0x69a] >> 4) & 1;
    tx[0x6af] = (tx[0x69a] >> 5) & 1;
    *(void **)(tx + 0x6b0) = (void *)(tx + 0x69b);  /* CCMP nonce ptr */
    *(void **)(tx + 0x6b4) = (void *)(tx + 0x6a1);  /* CCMP nonce + 6 */
    tx[0x6bc] = tx[0x6c8];
    {
        uint8_t  hlen  = head[0x2a];
        uint8_t  ftype = head[0x24];
        uint8_t *data  = (uint8_t *)*(uint32_t *)(head + 0x10) + hlen;
        *(void **)(tx + 0x6a8)    = key_ptr;
        *(uint16_t *)(tx + 0x6be) = *(uint16_t *)(head + 0x14) - (uint16_t)hlen;
        *(uint32_t *)(tx + 0x6c0) = (uint32_t)data;
        if ((ftype & 3) == 0) {
            *(void **)(tx + 0x6b8) = (void *)(tx + 0x660);  /* PV0 CCMP AAD buf */
            data += 8;
        } else {
            *(void **)(tx + 0x6b8) = (void *)(tx + 0x67e);  /* PV1 CCMP AAD buf */
        }
        *(uint32_t *)(tx + 0x6c4) = (uint32_t)data;
    }
    tx[0x6bd] = 0;
}

extern int32 os_sema_init(struct os_semaphore *sem, int32 val);
extern int32 os_sema_down(struct os_semaphore *sem, int32 timeout);
/* os_task_init / os_task_set_stacksize / os_task_run declared in osal/task.h */
/* os_jiffies declared in osal/time.h (returns uint64) */
extern int   ieee80211_is_data_qos(uint16_t fc);

/* ---- end porting aids ---- */

void lmac_tx_task(void *_arg);
void lmac_tx_status_task(void *_arg);

#define LMAC_TX_AC_COUNT        4

#ifndef LMAC_HW_BASE
#define LMAC_HW_BASE 0x40008000u
#endif

#ifndef LMAC_REG32
#define LMAC_REG32(off) (*(volatile uint32_t *)(LMAC_HW_BASE + (off)))
#endif

#ifndef LMAC_AC_PD
#define LMAC_AC_PD LMAC_REG32(0x4c)
#endif

void lmac_irq_ac_pd(void)
{
    static uint32_t n;

    n++;

    if ((n & 0x3f) == 0) {
        log_debug("irq_ac_pd: enter n=%u ac0=%u ag0_q=%u ag0_sel=%u pend=%u pd=0x%08x",
                  n,
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
                  ah_lmac_tx_orig.pTx_ac_aggr_data[0].queued_count,
                  ah_lmac_tx_orig.pTx_ac_aggr_data[0].selected_count,
                  skb_list_count(&ah_lmac_tx_orig.tx_frames_pending_queue),
                  LMAC_AC_PD);
    }

    lmac_irq_ac_pd_orig();

    if ((n & 0x3f) == 0) {
        log_debug("irq_ac_pd: exit  n=%u ac0=%u ag0_q=%u ag0_sel=%u first=%p pend=%u pd=0x%08x",
                  n,
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
                  ah_lmac_tx_orig.pTx_ac_aggr_data[0].queued_count,
                  ah_lmac_tx_orig.pTx_ac_aggr_data[0].selected_count,
                  ah_lmac_tx_orig.pTx_ac_aggr_data[0].skb_list[0],
                  skb_list_count(&ah_lmac_tx_orig.tx_frames_pending_queue),
                  LMAC_AC_PD);
    }
}

__attribute__((weak)) void lmac_tx_init(void)
{
  int iVar1;
  int iVar2;
  int ac_index;
  lmac_tx_ctx *pplVar4;

  log_info("lmac_tx_init: start ctx=%p", &ah_lmac_tx_orig);
  memset(&ah_lmac_tx_orig,0,0x6d4);
  lmac_tx_queue_init();
  log_debug("lmac_tx_init: queue_init done");

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

  log_debug("lmac_tx_init: aggr_data zero done");
  //lmac_tx_vec_init();
  ndp_tx_vec_init_orig(&ah_lmac_tx_orig.pTx_vector_cache[0].fmt_byte);
  ndp_tx_vec_init_orig(&ah_lmac_tx_orig.pTx_vector_cache[1].fmt_byte);
  ndp_tx_vec_init_orig(&ah_lmac_tx_orig.pTx_vector_cache[2].fmt_byte);
  ndp_tx_vec_init_orig(&ah_lmac_tx_orig.pTx_vector_cache[3].fmt_byte);
  ndp_tx_vec_init_orig(&ah_lmac_tx_orig.pTx_vector_cache[4].fmt_byte);

  log_debug("lmac_tx_init: vec_init done");
  os_sema_init(&ah_lmac_tx_orig.tx_sem,0);
  os_sema_init(&ah_lmac_tx_orig.tx_status_sem,0);
  log_debug("lmac_tx_init: semas init done, starting lmac tx task");
  os_task_init((const uint8 *)"lmac tx",(struct os_task *)&ah_lmac_tx_orig.tx_task,
               (void (*)(void *))lmac_tx_task,(uint32)&ah_lmac_tx_orig);
  os_task_set_stacksize(&ah_lmac_tx_orig.tx_task,2048);
  _os_task_set_priority(&ah_lmac_tx_orig.tx_task,81);
  os_task_run(&ah_lmac_tx_orig.tx_task);
  log_debug("lmac_tx_init: lmac tx task running, starting status task");
  os_task_init((const uint8 *)"lmac tx status",(struct os_task *)&ah_lmac_tx_orig.tx_status_task,
               (void (*)(void *))lmac_tx_status_task,(uint32)&ah_lmac_tx_orig);
  os_task_set_stacksize(&ah_lmac_tx_orig.tx_status_task,2048);
  _os_task_set_priority(&ah_lmac_tx_orig.tx_status_task,0x50);
  os_task_run(&ah_lmac_tx_orig.tx_status_task);
  log_debug("lmac_tx_init: status task running, alloc beacon skb");
  ah_lmac_tx_orig.pBeacon_skb = (struct sk_buff *)alloc_tx_skb(0x400);
  if (ah_lmac_tx_orig.pBeacon_skb == (struct sk_buff *)0x0) {
    log_error("lmac_tx_init: alloc beacon failed!");
    log_debug("\x02lmac error!!!alloc beacon failed\r\n");
  }
  else {
    skb_reserve(ah_lmac_tx_orig.pBeacon_skb,0x100);
    ah_lmac_tx_orig.pBeacon_skb->lmaced = 1;
    log_debug("lmac_tx_init: beacon skb=%p", ah_lmac_tx_orig.pBeacon_skb);
  }
  log_info("lmac_tx_init: done");
  return;
}

static inline uint16_t lmac_tx_align_len_min(uint16_t len)
{
    uint16_t v = len + 8;

    if ((len & 3) != 0) {
        v = (v & 0xfffc) + 4;
    }

    return v;
}

static void lmac_tx_drop_min(struct sk_buff *skb)
{
    skb->acked = 0;
    skb_list_queue(&ah_lmac_tx_orig.tx_frames_pending_queue, skb);
    os_sema_up(&ah_lmac_tx_orig.tx_status_sem);
}

void lmac_tx_task(void *_arg)
{
    struct sk_buff *skb;
    uint32_t loop_iter = 0;

    log_debug("tx_task: start arg=%p ctx=%p pending_q=%p status_q=%p",
              _arg,
              &ah_lmac_tx_orig,
              &ah_lmac_tx_orig.tx_pending_queue,
              &ah_lmac_tx_orig.tx_status_queue);

    while (((uint8_t)ah_lmac_tx_orig.exit_flag & 1) == 0) {
        int sema_result;
        uint32_t processed = 0;
        uint32_t queued = 0;
        uint32_t dropped = 0;

        loop_iter++;

        sema_result = os_sema_down(&ah_lmac_tx_orig.tx_sem, 1);

        // log_debug("tx_task: wake iter=%u sema=%d pending=%u status=%u ac0=%u ac1=%u ac2=%u ac3=%u pend_frames=%u",
        //           loop_iter,
        //           sema_result,
        //           skb_list_count(&ah_lmac_tx_orig.tx_pending_queue),
        //           skb_list_count(&ah_lmac_tx_orig.tx_status_queue),
        //           skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
        //           skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[1]),
        //           skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[2]),
        //           skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[3]),
        //           skb_list_count(&ah_lmac_tx_orig.tx_frames_pending_queue));

        if (sema_result == 0) {
            //log_debug("tx_task: sema timeout -> reload");
            lmac_tx_data_reload();
            // log_debug("tx_task: after timeout reload status=%u ac0=%u ac1=%u ac2=%u ac3=%u pend_frames=%u",
            //           skb_list_count(&ah_lmac_tx_orig.tx_status_queue),
            //           skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
            //           skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[1]),
            //           skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[2]),
            //           skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[3]),
            //           skb_list_count(&ah_lmac_tx_orig.tx_frames_pending_queue));
            continue;
        }

        while ((skb = skb_list_dequeue(&ah_lmac_tx_orig.tx_pending_queue)) != NULL) {
            lmac_txd *txd;
            uint16_t fc;
            uint8_t subtype;
            uint8_t *txd_raw;
            int hdl_ret;

            processed++;

            log_debug("tx_task: skb=%p head=%p data=%p len=%u txinfo=%p users=%u lmaced=%u pending_left=%u",
                      skb,
                      skb->head,
                      skb->data,
                      skb->len,
                      skb->txinfo,
                      skb->users.counter,
                      skb->lmaced,
                      skb_list_count(&ah_lmac_tx_orig.tx_pending_queue));

            if (((uintptr_t)skb->data & 1) != 0) {
                log_debug("tx_task: drop skb=%p reason=unaligned_data data=%p",
                          skb, skb->data);
                dropped++;
                lmac_tx_drop_min(skb);
                continue;
            }

            fc = *(uint16_t *)skb->data;

            log_debug("tx_task: skb=%p fc=0x%04x type=%u subtype_raw=%u protected=%u",
                      skb,
                      fc,
                      (fc >> 2) & 3,
                      (fc >> 4) & 0x0f,
                      (fc >> 14) & 1);

            if ((fc & 0x0003) != 0) {
                log_debug("tx_task: drop skb=%p reason=not_pv0 fc=0x%04x",
                          skb, fc);
                dropped++;
                lmac_tx_drop_min(skb);
                continue;
            }

            if ((fc & 0x4000) != 0) {
                log_debug("tx_task: drop skb=%p reason=protected_frame fc=0x%04x",
                          skb, fc);
                dropped++;
                lmac_tx_drop_min(skb);
                continue;
            }

            txd = (lmac_txd *)skb->head;
            txd_raw = (uint8_t *)txd;

            log_debug("tx_task: txd init skb=%p txd=%p", skb, txd);

            memset(txd, 0, 0x44);

            txd->beacon_ch_type = 0xff;
            txd->mcs_index = 0xff;
            txd->bw_tx_level = 0x0f;
            txd->rate_flags = (txd->rate_flags & 0x9f) | 0x60;

            txd->frame_data_ptr = (void *)skb->data;
            txd->frame_len = skb->len;

            txd->frame_type_flags =
                (txd->frame_type_flags & 0xfc) | (skb->data[0] & 3);

            if (ieee80211_is_data(fc)) {
                txd->data_beacon_flag =
                    (txd->data_beacon_flag & 0xfd) | 0x02;
            } else {
                txd->data_beacon_flag =
                    (txd->data_beacon_flag & 0xfd);
            }

            lmac_get_rx_addr(txd->receiver_mac, skb->data);
            txd->sta_idx_ptr = lmac_sta_get(0xffff, txd->receiver_mac);

            log_debug("tx_task: rx_addr=%02x:%02x:%02x:%02x:%02x:%02x sta=%p data_flag=0x%02x",
                      txd->receiver_mac[0],
                      txd->receiver_mac[1],
                      txd->receiver_mac[2],
                      txd->receiver_mac[3],
                      txd->receiver_mac[4],
                      txd->receiver_mac[5],
                      (void *)txd->sta_idx_ptr,
                      txd->data_beacon_flag);

            if ((txd->receiver_mac[0] & 1) != 0) {
                txd->tid_ac_partial_aid |= 0x80;
                log_debug("tx_task: multicast/broadcast skb=%p tid_aid=0x%02x",
                          skb, txd->tid_ac_partial_aid);
            }

            {
                uint8_t ack = lmac_get_ack_policy_orig(txd);
                txd->ack_mf_md_flags =
                    (txd->ack_mf_md_flags & 0xfd) | ((ack & 1) << 1);

                log_debug("tx_task: ack_policy=%u ack_mf_md=0x%02x",
                          ack, txd->ack_mf_md_flags);
            }

            txd->tid_ac_partial_aid &= 0xf0;

            txd->seq_num_frag =
                (int16_t)lmac_get_seq_num(txd->frame_data_ptr);

            log_debug("tx_task: seq=%d tid_aid=0x%02x",
                      txd->seq_num_frag,
                      txd->tid_ac_partial_aid);

            {
                uint16_t combined;

                txd->frame_type_flags =
                    (txd->frame_type_flags & 0xe3) |
                    (((fc >> 2) & 7) << 2);

                combined =
                    ((uint16_t)txd->ack_mf_md_flags << 8) |
                    txd->frame_type_flags;

                combined =
                    (combined & 0xfe1f) |
                    (((fc >> 4) & 0x0f) << 5);

                txd->frame_type_flags = (uint8_t)combined;
                txd->ack_mf_md_flags = (uint8_t)(combined >> 8);

                txd->ack_mf_md_flags =
                    (txd->ack_mf_md_flags & 0xbf) |
                    (((skb->data[1] >> 1) & 1) << 6);

                txd->ack_mf_md_flags =
                    (txd->ack_mf_md_flags & 0x7f) |
                    (skb->data[1] << 7);

                txd->hdr_len = lmac_get_hdr_len_pv0((uint16_t *)skb->data);

                txd->bandwidth_field =
                    (txd->bandwidth_field & 0xe7) |
                    ((ah_lmac.bss_bw & 3) << 3);
            }

            subtype = (txd->frame_type_flags & 0x0f) >> 2;

            log_debug("tx_task: decoded skb=%p subtype=%u hdr_len=%u frame_type=0x%02x ack_mf=0x%02x bw_field=0x%02x",
                      skb,
                      subtype,
                      txd->hdr_len,
                      txd->frame_type_flags,
                      txd->ack_mf_md_flags,
                      txd->bandwidth_field);

            if (subtype >= 4) {
                log_debug("tx_task: drop skb=%p reason=bad_subtype subtype=%u",
                          skb, subtype);
                dropped++;
                lmac_tx_drop_min(skb);
                continue;
            }

            log_debug("tx_task: call pv0_hdl subtype=%u fn=%p skb=%p",
                      subtype,
                      lmac_tx_pv0_hdl[subtype],
                      skb);

            hdl_ret =
                ((int (*)(struct sk_buff *))
                    ((uintptr_t)lmac_tx_pv0_hdl[subtype] & ~1U))(skb);

            log_debug("tx_task: pv0_hdl ret=%d skb=%p txd26=0x%02x txd27=0x%02x txd2a=0x%02x",
                      hdl_ret,
                      skb,
                      txd_raw[0x26],
                      txd_raw[0x27],
                      txd_raw[0x2a]);

            if (hdl_ret != 0) {
                log_debug("tx_task: drop skb=%p reason=pv0_handler_failed ret=%d",
                          skb, hdl_ret);
                dropped++;
                lmac_tx_drop_min(skb);
                continue;
            }

            txd->frame_ctrl = lmac_tx_align_len_min(skb->len);

            log_debug("tx_task: frame_ctrl=%u len=%u s1g=%u",
                      txd->frame_ctrl,
                      skb->len,
                      ah_lmac.beacon_s1g_format_flags & 1);

            if (((ah_lmac.beacon_s1g_format_flags & 1) == 0) &&
                ((uint16_t)txd->frame_ctrl > 0x067b)) {
                log_debug("tx_task: drop skb=%p reason=frame_too_large frame_ctrl=%u",
                          skb, txd->frame_ctrl);
                dropped++;
                lmac_tx_drop_min(skb);
                continue;
            }

            lmac_partial_aid_update_orig(txd);

            log_debug("tx_task: after partial_aid skb=%p tid_aid=0x%02x txd24=0x%02x txd25=0x%02x txd26=0x%02x txd27=0x%02x",
                      skb,
                      txd->tid_ac_partial_aid,
                      txd_raw[0x24],
                      txd_raw[0x25],
                      txd_raw[0x26],
                      txd_raw[0x27]);

            if ((ah_lmac.sleep_ctrl_flags & 2) == 0) {
                *(uint16_t *)skb->data &= ~0x1000;
                log_debug("tx_task: pm_bit cleared skb=%p fc=0x%04x",
                          skb, *(uint16_t *)skb->data);
            } else {
                *(uint16_t *)skb->data |= 0x1000;
                log_debug("tx_task: pm_bit set skb=%p fc=0x%04x",
                          skb, *(uint16_t *)skb->data);
            }

            txd_raw[0x26] &= ~0x10;

            if ((txd_raw[0x26] & 0x0f) > 7) {
                log_debug("tx_task: clamp tid/ac old_txd26=0x%02x", txd_raw[0x26]);
                txd_raw[0x26] = (txd_raw[0x26] & 0xf0) | 7;
            }

            log_debug("tx_task: queue status skb=%p txd26=0x%02x tid=%u status_before=%u",
                      skb,
                      txd_raw[0x26],
                      txd_raw[0x26] & 7,
                      skb_list_count(&ah_lmac_tx_orig.tx_status_queue));

            skb_list_queue(&ah_lmac_tx_orig.tx_status_queue, skb);
            queued++;

            log_debug("tx_task: status queued skb=%p status_after=%u -> reload",
                      skb,
                      skb_list_count(&ah_lmac_tx_orig.tx_status_queue));

            lmac_tx_data_reload();

            log_debug("tx_task: after per-skb reload skb=%p status=%u ac0=%u ac1=%u ac2=%u ac3=%u pend_frames=%u",
                      skb,
                      skb_list_count(&ah_lmac_tx_orig.tx_status_queue),
                      skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
                      skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[1]),
                      skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[2]),
                      skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[3]),
                      skb_list_count(&ah_lmac_tx_orig.tx_frames_pending_queue));
        }

        log_debug("tx_task: drain done iter=%u processed=%u queued=%u dropped=%u pending=%u status=%u ac0=%u ac1=%u ac2=%u ac3=%u pend_frames=%u -> final reload",
                  loop_iter,
                  processed,
                  queued,
                  dropped,
                  skb_list_count(&ah_lmac_tx_orig.tx_pending_queue),
                  skb_list_count(&ah_lmac_tx_orig.tx_status_queue),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[1]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[2]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[3]),
                  skb_list_count(&ah_lmac_tx_orig.tx_frames_pending_queue));

        lmac_tx_data_reload();

        log_debug("tx_task: final reload done iter=%u pending=%u status=%u ac0=%u ac1=%u ac2=%u ac3=%u pend_frames=%u",
                  loop_iter,
                  skb_list_count(&ah_lmac_tx_orig.tx_pending_queue),
                  skb_list_count(&ah_lmac_tx_orig.tx_status_queue),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[1]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[2]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[3]),
                  skb_list_count(&ah_lmac_tx_orig.tx_frames_pending_queue));
    }

    log_debug("tx_task: exit exit_flag=0x%02x", (uint8_t)ah_lmac_tx_orig.exit_flag);
    log_debug("lmac_tx_task_min exit!!!\r\n");
}

void lmac_tx_status_task(void *_arg)
{
  sk_buff *sk_buff_log;
  uint32_t send_duration;
  uint32_t send_time;
  lmac_txd *txd;

  while (((byte)ah_lmac_tx_orig.exit_flag & 1) == 0) {
    os_sema_down(&ah_lmac_tx_orig.tx_status_sem,-1);
    sk_buff_log = skb_list_dequeue(&ah_lmac_tx_orig.tx_frames_pending_queue);
    while (sk_buff_log != (sk_buff *)0x0) {
      ah_lmac._rsv_a64[0] = ah_lmac._rsv_a64[0] & 0xfe;
      txd = (lmac_txd *)sk_buff_log->head;
      ah_lmac.pending_pkg_to_status_check = ah_lmac.pending_pkg_to_status_check - 1;
      if (1 < (sk_buff_log->users).counter) {
        ah_lmac.tx_retry_or_multi_count = ah_lmac.tx_retry_or_multi_count + 1;
      }
      lmac_sta_put((void *)txd->sta_idx_ptr);
      if ((txd->data_beacon_flag & 2) != 0) {
        send_duration = (uint32_t)os_jiffies();
        send_time = send_duration - (int32_t)sk_buff_log->lifetime;
        ah_lmac.send_time_sum = ah_lmac.send_time_sum + send_time;
        if ((int)ah_lmac.last_send_time < (int)send_time) {
          ah_lmac.last_send_time = send_time;
        }
      }
      if (!sk_buff_log->lmaced) {
        ah_ops.tx_status(&ah_ops, sk_buff_log);
      }
      else if (sk_buff_log == (sk_buff *)*(uint32_t *)(ah_lmac._rsv_a64 + 5)) {
        if ((ah_lmac.debug_flags & 8) != 0) {
          log_debug("\x02SP_Tx over\r\n");
        }
        ah_lmac._rsv_a64[0] = ah_lmac._rsv_a64[0] & 0xef;
      }
      else {
        kfree_skb(sk_buff_log);
      }
      sk_buff_log = skb_list_dequeue(&ah_lmac_tx_orig.tx_frames_pending_queue);
    }
  }
  log_debug("\x02%s exit!!!\r\n", "lmac tx status");
  return;
}

/* ============================================================
 * Functions formerly static in the original binary.
 * Ported from Ghidra decompilation (TXW8301-PHY.elf).
 * ============================================================ */

/* Raw byte access helpers */
#define _LM  ((uint8_t *)&ah_lmac)
#define _LMX ((uint8_t *)&ah_lmac_tx_orig)

/* LMAC HW register at offset from the base stored in *(uint32_t*)0x20006c4c */
static inline volatile uint32_t *lmac_hw_reg(uint32_t offset)
{
    return (volatile uint32_t *)(*(uint32_t *)0x40008000 + offset);
}

#define LMAC_HW_BASE        0x40008000u

#define LMAC_REG32(off)     (*(volatile uint32_t *)(LMAC_HW_BASE + (off)))

#define LMAC_MACADDRL       LMAC_REG32(0x000)
#define LMAC_MACADDRH       LMAC_REG32(0x004)
#define LMAC_AID            LMAC_REG32(0x008)
#define LMAC_TSFL           LMAC_REG32(0x010)
#define LMAC_TSFH           LMAC_REG32(0x014)
#define LMAC_NAV_CNT        LMAC_REG32(0x018)
#define LMAC_SIFS_INIT      LMAC_REG32(0x01c)
#define LMAC_BO_CNT0        LMAC_REG32(0x020)
#define LMAC_BO_CNT1        LMAC_REG32(0x024)
#define LMAC_FSM_TSF        LMAC_REG32(0x02c)
#define LMAC_FSM_CFG        LMAC_REG32(0x030)
#define LMAC_FSM_STAT       LMAC_REG32(0x034)
#define LMAC_FSM_TSF1       LMAC_REG32(0x038)
#define LMAC_RAND_GEN       LMAC_REG32(0x03c)
#define LMAC_COMN_CTRL      LMAC_REG32(0x040)
#define LMAC_IRQ_EN         LMAC_REG32(0x044)
#define LMAC_IRQ_PD         LMAC_REG32(0x048)
#define LMAC_AC_PD          LMAC_REG32(0x04c)
#define LMAC_FCS_RES        LMAC_REG32(0x054)
#define LMAC_AGGR_CTRL      LMAC_REG32(0x058)
#define LMAC_END_TO_LIMIT   LMAC_REG32(0x05c)

#define LMAC_TXVEC1         LMAC_REG32(0x064)
#define LMAC_TXVEC2         LMAC_REG32(0x068)
#define LMAC_TXVEC3         LMAC_REG32(0x06c)
#define LMAC_TXVEC4         LMAC_REG32(0x070)

#define LMAC_TX_STAT        LMAC_REG32(0x074)
#define LMAC_TX_DLY1        LMAC_REG32(0x078)
#define LMAC_TX_BYTCNT      LMAC_REG32(0x07c)
#define LMAC_TX_EOFBYT      LMAC_REG32(0x080)
#define LMAC_TX_DLY2        LMAC_REG32(0x084)
#define LMAC_TX_PRBS_GEN    LMAC_REG32(0x088)
#define LMAC_TX_DLY3        LMAC_REG32(0x08c)

#define LMAC_RX_CTRL        LMAC_REG32(0x0a0)
#define LMAC_RXVEC1         LMAC_REG32(0x0a4)
#define LMAC_RXVEC2         LMAC_REG32(0x0a8)
#define LMAC_RXVEC3         LMAC_REG32(0x0ac)
#define LMAC_RXVEC4         LMAC_REG32(0x0b0)
#define LMAC_RX_STAT        LMAC_REG32(0x0b4)
#define LMAC_CCA_STAT       LMAC_REG32(0x0bc)

#define LMAC_HF_TIMER1      LMAC_REG32(0x0c0)
#define LMAC_HF_TIMER2      LMAC_REG32(0x0c4)
#define LMAC_LF_TIMER       LMAC_REG32(0x0c8)
#define LMAC_TIMER_CTL      LMAC_REG32(0x0cc)
#define LMAC_HF_TIMER3      LMAC_REG32(0x0d0)
#define LMAC_HF_TIMER4      LMAC_REG32(0x0d4)
#define LMAC_HF_TIMER5      LMAC_REG32(0x0d8)
#define LMAC_HF_TIMER6      LMAC_REG32(0x0dc)

#define LMAC_TEST_CTRL      LMAC_REG32(0x0f8)
#define LMAC_DBG_CTRL       LMAC_REG32(0x0fc)

#define LMAC_TXDMACTL       LMAC_REG32(0x100)
#define LMAC_CURTXDMACNT    LMAC_REG32(0x104)
#define LMAC_TXDMASTAT      LMAC_REG32(0x108)

#define LMAC_RXDMACTL       LMAC_REG32(0x400)
#define LMAC_RXFSTADDR      LMAC_REG32(0x404)
#define LMAC_RXFENADDR      LMAC_REG32(0x408)
#define LMAC_CURRXDMACNT    LMAC_REG32(0x410)
#define LMAC_RXDMASTAT      LMAC_REG32(0x414)
#define LMAC_RXFCS1         LMAC_REG32(0x418)
#define LMAC_RXFCS2         LMAC_REG32(0x41c)

#define LMAC_RXFSTADDR_SEC  LMAC_REG32(0x620)
#define LMAC_RXFENADDR_SEC  LMAC_REG32(0x624)
#define LMAC_CCADBGCTL      LMAC_REG32(0x630)
#define LMAC_CCAINFO1       LMAC_REG32(0x634)
#define LMAC_CCAINFO2       LMAC_REG32(0x638)
#define LMAC_CCAINFO3       LMAC_REG32(0x63c)
#define LMAC_CCAINFO4       LMAC_REG32(0x640)
#define LMAC_CCAINFO5       LMAC_REG32(0x644)
#define LMAC_DUMMY1         LMAC_REG32(0x648)
#define LMAC_DUMMY2         LMAC_REG32(0x64c)

/* ---- lmac_tx_queue_init ----------------------------------------- */

int32 lmac_tx_queue_init(void){
    int32 ret;

    log_info("initialising TX queues");

    ret = skb_list_init(&ah_lmac_tx_orig.tx_pending_queue);
    if (ret) {
        log_fatal("tx_pending_queue init failed ret=%d", ret);
        return -1;
    }

    ret = skb_list_init(&ah_lmac_tx_orig.tx_status_queue);
    if (ret) {
        log_fatal("tx_status_queue init failed ret=%d", ret);
        return -1;
    }

    ret = skb_list_init(&ah_lmac_tx_orig.tx_retry_queue);
    if (ret) {
        log_fatal("tx_retry_queue init failed ret=%d", ret);
        return -1;
    }

    for (int32_t i = 0; i < 4; i++) {
        ret = skb_list_init(&ah_lmac_tx_orig.pTx_ac_queues[i]);
        if (ret) {
            log_fatal("ac_queue[%d] init failed ret=%d", i, ret);
            return -1;
        }
    }

    ret = skb_list_init(&ah_lmac_tx_orig.tx_frames_pending_queue);
    if (ret) {
        log_fatal("tx_frames_pending_queue init failed ret=%d", ret);
        return -1;
    }

    log_info("done, tx_ctx base=0x%08x", (uint32_t)_LMX);
    return ret;
}

/* ---- lmac_check_aggregation ------------------------------------- */

int32 lmac_check_aggregation(struct sk_buff *skb0, struct sk_buff *skb1)
{
    uint8_t *txd0, *txd1;
    uint8_t b0, b1;

    if (!skb0 || !skb1) {
        log_trace("check_agg: null skb skb0=%p skb1=%p -> -1", skb0, skb1);
        return -1;
    }

    txd0 = skb0->head;
    txd1 = skb1->head;

    if (!txd0 || !txd1) {
        log_warn("check_agg: null head txd0=%p txd1=%p -> -1", txd0, txd1);
        return -1;
    }

    if ((*(uint32_t *)(txd0 + 0x08) & 1u) != 0) return -1;  /* dup flag */
    if ((*(uint32_t *)(txd1 + 0x08) & 1u) != 0) return -1;
    if ((txd0[0x27] & 0x08) != 0) return -1;  /* data_beacon_flag: not-data */
    if ((txd1[0x27] & 0x08) != 0) return -1;
    if (((txd0[0x25] ^ txd1[0x25]) & 0x40) != 0) return -1;  /* ack policy */
    if ((int8_t)txd0[0x3c] != (int8_t)txd1[0x3c]) return -1; /* bw */
    if ((int8_t)txd0[0x3d] != (int8_t)txd1[0x3d]) return -1; /* mcs */
    if (((txd0[0x3f] ^ txd1[0x3f]) & 0x60) != 0) return -1;  /* rate_flags */
    if (((txd0[0x26] ^ txd1[0x26]) & 0x0f) != 0) return -1;  /* tid/AC */

    if (!ieee80211_is_data(*(uint16_t *)skb0->data)) return -1;
    if (!ieee80211_is_data(*(uint16_t *)skb1->data)) return -1;

    /* Reject QoS-null aggregation (0x188 = data|qos|null subtype) */
    if ((*(uint16_t *)(txd0 + 0x24) & 0x1fc) == 0x188) return -1;

    b0 = txd0[0x1a];
    b1 = txd1[0x1a] ^ b0;
    if ((b1 & 1) != 0) return -1;  /* addr mismatch */
    if ((b0 & 1) != 0) {
        log_trace("check_agg: mcast aggregate OK skb0=%p skb1=%p", skb0, skb1);
        return 0;
    }

    if (*(uint16_t *)(txd0 + 0x1a) != *(uint16_t *)(txd1 + 0x1a)) return -1;
    if (*(uint32_t *)(txd0 + 0x1c) != *(uint32_t *)(txd1 + 0x1c)) return -1;

    log_trace("check_agg: ucast aggregate OK skb0=%p skb1=%p", skb0, skb1);
    return 0;
}

/* ---- seq_num_space_update --------------------------------------- */

uint32 seq_num_space_update(void *sta, uint32 tid)
{
    uint8_t *tx = _LMX;
    uint32_t sn, next;

    if (sta == NULL) {
        /* Broadcast/management: use global counter at ah_lmac_tx_orig+0x6cc */
        sn   = *(uint32_t *)(tx + 0x6cc) & 0xffff;
        next = (*(uint32_t *)(tx + 0x6cc) + 1) & 0xfff;
        *(uint32_t *)(tx + 0x6cc) = (next == 0xfff) ? 0 : next;
    } else {
        /* Per-STA per-TID counter at sta+0x152+tid*0x10 */
        uint16_t *p = (uint16_t *)((uint8_t *)sta + tid * 0x10 + 0x152);
        sn = (uint32_t)*p;
        *p = (*p + 1) & 0xfff;
    }
    return sn;
}
static const uint8_t ieee802_1d_to_ac_tbl[8] = {
    0, 1, 1, 0, 2, 2, 3, 3
};

#define LMAC_AC_PD (*(volatile uint32_t *)0x4000804cu)

void lmac_tx_data_reload(void)
{
    struct skb_list *src_queue = &ah_lmac_tx_orig.tx_status_queue;
    struct sk_buff *skb;
    uint32_t moved = 0;

    while ((skb = skb_list_dequeue(src_queue)) != NULL) {
        uint8_t tid = 0;
        uint8_t ac;

        if (skb->head != NULL) {
            tid = skb->head[0x26] & 7;
        }

        ac = ieee802_1d_to_ac_tbl[tid];

        if (ac > 3) {
            ac = 0;
        }

        skb_list_queue(&ah_lmac_tx_orig.pTx_ac_queues[ac], skb);
        ah_lmac_tx_orig.pTx_agg_count_per_ac[ac]++;
        moved++;
    }

    if (skb_list_count(src_queue) == 0) {
        ah_lmac.tx_state_7ac++;
    }

    LMAC_AC_PD = 0;
    LMAC_AC_PD = 0xf;

    if (moved != 0) {
        log_debug("reload_min: moved=%u status_q=%u ac0=%u ac1=%u ac2=%u ac3=%u pend=%u",
                  moved,
                  skb_list_count(&ah_lmac_tx_orig.tx_status_queue),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[0]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[1]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[2]),
                  skb_list_count(&ah_lmac_tx_orig.pTx_ac_queues[3]),
                  skb_list_count(&ah_lmac_tx_orig.tx_frames_pending_queue));
    }
}

/* ---- lmac_tx_pv0_mgmt ------------------------------------------- */

int32 lmac_tx_pv0_mgmt(struct sk_buff *skb)
{
    uint8_t *lm  = _LM;
    uint8_t *txd = skb->head;
    uint16_t fc  = *(uint16_t *)skb->data;
    log_debug("pv0_mgmt: skb=%p txd=%p fc=0x%04x subtype=%u",
              skb, txd, fc, (fc >> 4) & 0xf);

    /* If this is the beacon skb: set wide-bw flag based on bss_bw, mark retransmit */
    if ((uint32_t)skb == *(uint32_t *)(lm + 0xa54)) {
        txd[0x25] = (txd[0x25] & 0xdf) | (uint8_t)((1 < lm[0x308]) << 5);
        *(uint32_t *)(txd + 0x08) |= 9u;
    }

    /* Clear protected-frame flag for broadcast/group frames */
    if ((*(uint32_t *)(txd + 0x04) & 2u) != 0 && (int8_t)txd[0x26] >= 0)
        txd[0x25] &= 0xfd;

    /* Frame subtype check for BSS announcement / probe response */
    uint32_t subtype = (*(uint16_t *)(txd + 0x24) & 0xff) >> 5;
    if (subtype == 5) {
        /* Probe response: scan IE list (no state change needed here) */
    } else if (subtype == 0xd &&
               (*(uint8_t *)((uint8_t *)skb + 0x2a) & 0x40) != 0 &&
               (*(uint16_t *)(txd + 0x24) & 0x1ff) == 0x1a0) {
        /* BSS announcement frame */
        uint8_t *sta = (uint8_t *)*(uint32_t *)(txd + 0x10);
        if (*(int8_t *)(sta + 0x18) == (int8_t)0xdd) {
            if ((*(int8_t *)(sta + 0x1a) == 0) &&
                (*(int8_t *)(sta + 0x1b) == 0x40) &&
                (*(int8_t *)(sta + 0x1c) == 1) &&
                (*(int8_t *)(sta + 0x1f) == 2)) {
                /* Rotate frequency index */
                uint8_t *freq_idx = lm + 0x430; /* bss_ann_freq_idx */
                uint8_t  new_idx  = *freq_idx + 1;
                *(uint32_t *)(txd + 0x08) |= 5u;
                txd[0x3f] = (txd[0x3f] & 0xe0) | (new_idx & 0x1f);
                *freq_idx  = new_idx;
                if (lm[0x378] <= new_idx) *freq_idx = 0;
            }
        } else if (*(int8_t *)(sta + 0x18) == 0x27) {
            *(uint32_t *)(txd + 0x08) |= 3u;
        }
    }
    return 0;
}

/* ---- lmac_tx_pv0_ctrl ------------------------------------------- */

int32 lmac_tx_pv0_ctrl(struct sk_buff *skb)
{
    uint8_t *lm  = _LM;
    uint8_t *txd = skb->head;
    log_debug("pv0_ctrl: skb=%p txd=%p fc=0x%04x", skb, txd, *(uint16_t *)skb->data);

    if ((*(uint8_t *)((uint8_t *)skb + 0x2a) & 0x40) != 0 &&
        (*(uint16_t *)(txd + 0x24) & 0x1e0) == 0x160) {
        /* Antenna-probing packet (subtype = 0xb) */
        uint8_t *ant_cnt = lm + 0x430; /* ant_cnt field */
        uint8_t  cnt     = *ant_cnt;
        uint8_t  opt     = lm[0x875];

        *(uint32_t *)(txd + 0x08) |= 0x11u;
        txd[0x28] = (int8_t)(lm[0x313] - 1);
        log_debug("\x02lmac ant sel: cnt=%d, opt=%d/%d\r\n",
                 (uint32_t)cnt, (opt >> 3) & 1, (opt >> 4) & 1);

        /* Toggle antenna bit */
        txd[0x3f] = (txd[0x3f] & 0x9f) |
                    ((uint8_t)((cnt & 1) ? 3u : 0u) << 5);
        txd[0x25] &= 0xfd;
        *ant_cnt = cnt + 1;
    }

    txd[0x27] = (txd[0x27] & 0xfe) | 1; /* mark as ctrl */
    return 0;
}

/* ---- lmac_tx_pv0_data ------------------------------------------- */
int32 lmac_tx_pv0_data(struct sk_buff *skb)
{
    uint8_t *txd = skb->head;
    uint8_t *frame = skb->data;

    log_debug("pv0_data_min: skb=%p txd=%p data=%p len=%u",
              skb, txd, frame, skb->len);

    frame[1] &= 0xbf;
    txd[0x26] &= 0xef;

    return 0;
}

/* ---- lmac_tx_pv0_ext -------------------------------------------- */

int32 lmac_tx_pv0_ext(struct sk_buff *skb)
{
    uint8_t ext_type = *(uint8_t *)skb->data >> 4;

    log_debug("pv0_ext: skb=%p ext_type=%u", skb, ext_type);

    if (ext_type == 0) {
        log_error("pv0_ext: unsupported ext type 0");
        log_debug("\x02lmac error!!!%s: unsupported ext type 0\r\n", __func__);
    } else if (ext_type == 1) {
        log_info("pv0_ext: S1G beacon, invoking lmac_tx_pv0_s1g_beacon");
        lmac_tx_pv0_s1g_beacon(skb);
    } else if (ext_type != 0xf) {
        log_error("pv0_ext: unknown ext type %u", ext_type);
        log_debug("\x02lmac error!!!unknown ext type\r\n");
        return -1;
    }
    return 0;
}

/* ---- lmac_tx_pv0_s1g_beacon ------------------------------------- */
/* Decompiled from lmac_tx_pv0_s1g_beacon_orig @ 0x20036dfc */

void lmac_tx_pv0_s1g_beacon(struct sk_buff *skb)
{
    uint8_t *lm   = _LM;
    uint8_t *data = skb->data;
    uint8_t *tail = skb->tail;
    log_info("s1g_beacon: skb=%p data=%p tail=%p len=%u", skb, data, tail, skb->len);
    uint8_t  b1   = data[1];
    uint8_t *ie;

    /* Store change-sequence / beacon control byte */
    lm[0x3f0] = data[0x0e];

    /* Extra IEs: reset length field */
    uint8_t *extra_ies = lm + 0x3f0;
    extra_ies[1] = 0;
    extra_ies[2] = 0;

    /* Copy BSSID into extra-IE header from mac_addr (lm+0x302) */
    memcpy(extra_ies + 0x136, lm + 0x302, 6);

    /* Skip fixed fields to reach IEs */
    if ((b1 & 1) == 0)
        ie = data + 0x0f;
    else
        ie = data + 0x12;
    if (b1 & 2) ie += 4;
    if (b1 & 4) ie += 1;

    /* Set s1g_compat_info bits [6:8] = 7 (0x1c0) — field at lm+0x9de */
    *(uint16_t *)(lm + 0x9de) = (*(uint16_t *)(lm + 0x9de) & 0xfe3f) | 0x1c0;

    /* Walk IEs */
    while (1) {
        if (ie >= tail) {
            /* All IEs processed — finalise and enqueue */
            /* Write TSF from beacon frame (data[6..9]) into LMAC HW reg+0x3c,
             * then use it to update beacon_airtime at ah_lmac+0x656 */
            volatile uint32_t *tsf_reg = lmac_hw_reg(0x3c);
            *tsf_reg = *(uint32_t *)(data + 6);
            uint32_t ai = ((uint32_t)*(uint16_t *)(lm + 0x656) +
                           (*tsf_reg % 20u)) & 0xffff;
            *(uint16_t *)(lm + 0x656) = (uint16_t)ai;
            *(uint32_t *)(lm + 0x658) = (ai & 0xffff) << 10;

            *(uint8_t *)((uint8_t *)skb + 0x2a) =
                (*(uint8_t *)((uint8_t *)skb + 0x2a) & 0xef) | 0x10;
            log_info("s1g_beacon: IE walk done, beacon_interval=%u ai=%u, enqueue to tx_status_queue",
                     *(uint16_t *)(lm + 0x656), (uint32_t)*(uint16_t *)(lm + 0x656));
            memset(skb->head, 0, 0x44);
            skb_list_queue((struct skb_list *)(_LMX + 0x70), skb);
            os_sema_up(&ah_lmac_tx_orig.tx_status_sem);

            if ((lm[0x9de] & 0x20) == 0) {
                lmac_beacon_timer_start(1000);
                lm[0x9de] = (lm[0x9de] & 0xdf) | 0x20;
                lm[0x9df] = lm[0x9df] & 0xdf;
            }

            uint32_t bc = *(uint32_t *)(lm + 0xbc);
            if (bc == 0)
                *(uint32_t *)(lm + 0xbc) = 2;
            else if (bc == 1)
                *(uint32_t *)(lm + 0xbc) = 3;
            return;
        }

        uint8_t id  = ie[0];
        uint8_t len = ie[1];
        log_trace("s1g_beacon: IE id=0x%02x len=%u ie=%p tail=%p", id, len, ie, tail);

        if (id == 0x0c) {
            /* BSS Load IE */
            memcpy(extra_ies + 0x112, ie + 2, 0x12);
        } else if (id == 0x00) {
            /* SSID */
            if (len < 0x21) {
                memcpy(lm + 0x52c, ie, (size_t)(len + 2));
                lm[0x52c + len + 2] = 0; /* null-terminate */
            }
        } else if (id == 0x05) {
            /* TIM */
            lm[0x554] = ie[1];
            lm[0x556] = ie[3];
            lm[0x557] = ie[4] & 1;
            memcpy(lm + 0x559, ie + 4, (size_t)(len - 2));
        } else if (id == 0xd6) {
            /* S1G Operation IE: beacon interval */
            uint16_t bint = *(uint16_t *)(ie + 2);
            *(uint16_t *)(lm + 0x656) = bint;
            *(uint32_t *)(lm + 0x658) = (uint32_t)bint << 10;
        } else if (id == 0xd9) {
            /* S1G Capabilities */
            if (len == 0x0f) {
                memcpy(lm + 0x3f4, ie + 2, 0x0f);
                uint8_t combined = data[7] + data[8] + data[9];
                lm[0x668] = (lm[0x668] & 0xf8) | (combined & 7);
                ie[10]    = (ie[10] & 0xe3) | ((combined & 7) << 2);
            } else {
                log_debug("\x02lmac error!!!S1G CAP len=%d\r\n", (uint32_t)len);
            }
        } else if (id == 0xd5) {
            /* S1G Short Beacon Interval */
            if (len == 0x08) {
                *(uint16_t *)(lm + 0x654) = *(uint16_t *)(ie + 2);
                *(uint16_t *)(lm + 0x656) = *(uint16_t *)(ie + 4);
            } else {
                log_debug("\x02lmac error!!!S1G SBI len=%d\r\n", (uint32_t)len);
            }
        } else {
            /* Generic IE: append to extra_ies data buffer */
            uint32_t used = (*(uint32_t *)(lm + 0x3f0) & 0x7fffff) >> 8;
            if (used + (uint32_t)len <= 0xfdu) {
                memcpy((void *)(used + (uint32_t)(lm + 0x3f3)), ie,
                       (size_t)(len + 2));
                uint32_t new_used = used + len + 2;
                extra_ies[1] = (uint8_t)(new_used & 0xff);
                extra_ies[2] = (uint8_t)(new_used >> 8);
            } else {
                log_debug("\x02lmac error!!!extra IE overflow\r\n");
            }
        }
        ie += len + 2;
    }
}

/* ---- PV1 handlers (trivial stubs from binary) ------------------- */

int32 lmac_tx_pv1_data1(struct sk_buff *skb) { log_trace("pv1_data1: skb=%p", skb); (void)skb; return 0; }
int32 lmac_tx_pv1_data2(struct sk_buff *skb) { log_trace("pv1_data2: skb=%p", skb); (void)skb; return 0; }
int32 lmac_tx_pv1_mgmt(struct sk_buff *skb)  { log_trace("pv1_mgmt:  skb=%p", skb); (void)skb; return 0; }

int32 lmac_tx_pv1_ctrl(struct sk_buff *skb)
{
    log_debug("pv1_ctrl: skb=%p head=%p", skb, skb->head);
    skb->head[0x27] = (skb->head[0x27] & 0xfe) | 1; /* set ctrl bit */
    return 0;
}

#undef _LM
#undef _LMX
