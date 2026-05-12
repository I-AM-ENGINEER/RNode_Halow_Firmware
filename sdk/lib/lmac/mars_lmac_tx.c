// Auto-reconstructed: mars_lmac_tx.c
#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_MARS_LMAC_TX
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
static void *lmac_gen_tx_agglist(uint32 ac, uint32 ac_hint, uint32 mcs, void *arg);
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

/* helpers from binary (wrappers in mars_lmac_tx.c call the  versions) */
extern void lmac_tx_vec_init(void);
extern void lmac_tx_data_reload(void);

/* TX context global – binary symbol (GLOBAL BSS in mars_lmac_tx_origfuncs.o) */
extern lmac_tx_ctx ah_lmac_tx_orig;
#define ah_lmac_tx ah_lmac_tx_orig

/* PV0 subtype handlers from binary */
extern int32 lmac_tx_pv0_mgmt(struct sk_buff *);
extern int32 lmac_tx_pv0_ctrl(struct sk_buff *);
extern int32 lmac_tx_pv0_data(struct sk_buff *);
extern int32 lmac_tx_pv0_ext(struct sk_buff *);
/* PV1 subtype handlers from binary */
extern int32 lmac_tx_pv1_data1(struct sk_buff *);
extern int32 lmac_tx_pv1_mgmt(struct sk_buff *);
extern int32 lmac_tx_pv1_ctrl(struct sk_buff *);
extern int32 lmac_tx_pv1_data2(struct sk_buff *);

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
 * Configures ah_lmac_tx cipher fields from the TX descriptor (head = tx_skb->head).
 * Offsets verified against Ghidra @ 20036d24. */
static void lmac_cfg_tx_ce_para_isra5(uint8_t *head)
{
    uint8_t *tx      = (uint8_t *)&ah_lmac_tx;
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
    else    hgprintf("\x02lmac error!!!ce bw= 0x%x\r\n", (uint32_t)bw_val);

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

void lmac_tx_init(void)
{
  int iVar1;
  int iVar2;
  int ac_index;
  lmac_tx_ctx *pplVar4;

  memset(&ah_lmac_tx,0,0x6d4);
  lmac_tx_queue_init();
  pplVar4 = (lmac_tx_ctx *)&ah_lmac_tx;
  ac_index = 0;
  do {
    pplVar4->pTx_ac_aggr_data[0].field1_0x100 = 0;
    *(undefined4 *)&pplVar4->pTx_ac_aggr_data[0].field2_0x104 = 0;
    ah_lmac_tx.pTx_ac_aggr_data[ac_index].field9_0x10d = 0;
    iVar1 = 0;
    do {
      iVar2 = iVar1 + 1;
      pplVar4->pTx_ac_aggr_data[0].field0_0x0[iVar1] = (struct sk_buff *)0x0;
      iVar1 = iVar2;
    } while (iVar2 != 0x40);
    ac_index = ac_index + 1;
    pplVar4 = (lmac_tx_ctx *)(pplVar4->pTx_ac_aggr_data[0].field0_0x0 + 0x1a);
  } while (ac_index != 4);
  lmac_tx_vec_init();
  os_sema_init(&ah_lmac_tx.tx_sem,0);
  os_sema_init(&ah_lmac_tx.tx_status_sem,0);
  os_task_init((const uint8 *)"lmac tx",(struct os_task *)&ah_lmac_tx.tx_task,
               (void (*)(void *))lmac_tx_task,(uint32)&ah_lmac_tx);
  os_task_set_stacksize(&ah_lmac_tx.tx_task,512);
  _os_task_set_priority(&ah_lmac_tx.tx_task,81);
  os_task_run(&ah_lmac_tx.tx_task);
  os_task_init((const uint8 *)"lmac tx status",(struct os_task *)&ah_lmac_tx.tx_status_task,
               (void (*)(void *))lmac_tx_status_task,(uint32)&ah_lmac_tx);
  os_task_set_stacksize(&ah_lmac_tx.tx_status_task,0x200);
  _os_task_set_priority(&ah_lmac_tx.tx_status_task,0x50);
  os_task_run(&ah_lmac_tx.tx_status_task);
  ah_lmac_tx.pBeacon_skb = (struct sk_buff *)alloc_tx_skb(0x400);
  if (ah_lmac_tx.pBeacon_skb == (struct sk_buff *)0x0) {
    hgprintf("\x02lmac error!!!alloc beacon failed\r\n");
  }
  else {
    skb_reserve(ah_lmac_tx.pBeacon_skb,0x100);
    ah_lmac_tx.pBeacon_skb->lmaced = 1;
  }
  return;
}


void lmac_tx_task(void *_arg)
{
  byte bVar1;
  byte bVar2;
  byte is_data_frame;
  byte temp_byte;
  uint8_t hdr_len;
  int sema_result;
  sk_buff *tx_skb;
  bool bVar6;
  astruct aVar7;
  uint32_t ret_val_ptr;
  int nAggCheckResult;
  skb_list *psVar3;
  void *pvVar4;
  uint8_t *__dest;
  ushort frame_ctrl_short;
  int iVar5;
  uint param1;
  byte bandwidth_bits;
  ushort aligned_frame_len;
  uint8_t *pJumpOrCtx;
  uint temp_uint;
  astruct *frame_start_ptr;
  lmac_txd *txd;
  astruct *frame_data_ptr;
  uint8_t *tx_desc_ptr;
  astruct_1 *tx_info_ptr;
  ushort *frame_ptr_short;
  ushort *tx_stat_ptr;
  uint8_t *pBufOrHead;
  uint8_t mcs;
  bool global_mcs_correct_b;
  byte txd_mcs;
  byte bandwidth_mhz;
  ushort frame_control_short;
  ushort frame_control_word;
  uint16 frame_len;

main_loop:
  if (((byte)ah_lmac_tx.exit_flag & 1) != 0) {
    hgprintf("\x02lmac error!!!task exit!!!\r\n");
    return;
  }
  sema_result = os_sema_down(&ah_lmac_tx.tx_sem,1);
process_frame:
  do {
    while( true ) {
      if ((sema_result == 0) ||
         (tx_skb = skb_list_dequeue(&ah_lmac_tx.tx_pending_queue), tx_skb == (sk_buff *)0x0))
      goto reload_and_retry;
      frame_data_ptr = (astruct *)tx_skb->data;
                    /* beacon send */
      if (frame_data_ptr->frame_control != '\x1c') break;
      lmac_tx_pv0_s1g_beacon(tx_skb);
    }
    txd = (lmac_txd *)tx_skb->head;
    tx_info_ptr = (astruct_1 *)tx_skb->txinfo;
    if (((uint)frame_data_ptr & 1) == 0) {
      memset(txd,0,0x44);
      if (tx_info_ptr == (astruct_1 *)0x0) {
        txd->beacon_ch_type = 0xff;
        txd->mcs_index = 0xff;
        txd->bw_tx_level = '\x0f';
        temp_byte = txd->rate_flags & 0x9f | 0x60;
      }
      else {
        temp_uint = tx_info_ptr->field4_0x4;
        txd->dwHw_ctrl_word = temp_uint;
        frame_ctrl_short = tx_info_ptr->field5_0x8;
        txd->ack_mf_md_flags = txd->ack_mf_md_flags & 0xdf | (byte)((temp_uint >> 0x1f) << 5);
        txd->data_beacon_flag = txd->data_beacon_flag & 0xf7 | (byte)((frame_ctrl_short & 1) << 3);
        txd->dwFrame_ctrl_from_txinfo = (uint)frame_ctrl_short;
        txd->beacon_ch_type = tx_info_ptr->field1_0x1;
        txd->mcs_index = 0xff;
        txd->rate_flags = txd->rate_flags & 0x9f | tx_info_ptr->field3_0x3 & 0x60;
        txd->bw_tx_level = tx_info_ptr->field6_0xa;
        temp_byte = txd->rate_flags & 0xe0 | tx_info_ptr->field3_0x3 & 0x1f;
      }
      txd->rate_flags = temp_byte;
      if ((txd->data_beacon_flag & 8) != 0) {
        txd->bw_tx_level = '\a';
        txd->mcs_index = 1;
        hdr_len = '\x03';
        if ((ah_lmac.beacon_s1g_format_flags & 1) == 0) {
          hdr_len = '\0';
        }
        txd->beacon_ch_type = hdr_len;
      }
      txd_mcs = txd->mcs_index;
      temp_byte = ah_lmac.beacon_s1g_format_flags & 1;
      bVar1 = ah_lmac.beacon_s1g_format_flags & 1;
      bVar2 = ah_lmac.beacon_s1g_format_flags & 1;
      bandwidth_bits = ah_lmac.beacon_s1g_format_flags & 1;
      mcs = ah_lmac.tx_mcs;
      if ((ah_lmac.beacon_s1g_format_flags & 1) == 0) {
        if (7 < txd_mcs) {
          global_mcs_correct_b = 7 < ah_lmac.tx_mcs;
mcs_clamp_check:
          if (global_mcs_correct_b) {
            mcs = 0xff;
          }
          goto mcs_apply;
        }
      }
      else if ((7 < txd_mcs) && (txd_mcs != 10)) {
        if (7 < ah_lmac.tx_mcs) {
          global_mcs_correct_b = ah_lmac.tx_mcs != 10;
          goto mcs_clamp_check;
        }
mcs_apply:
        txd->mcs_index = mcs;
      }
      bandwidth_mhz = txd->beacon_ch_type;
      if (bandwidth_mhz == 2) {
        if (bVar1 == 0) goto bw_apply;
        goto bw_s1g_2mhz;
      }
      if (bandwidth_mhz < 3) {
        if (bandwidth_mhz == 1) goto bw_s1g_2mhz;
bw_default:
        bandwidth_bits = 0xff;
bw_apply:
        txd->beacon_ch_type = bandwidth_bits;
      }
      else {
        if (bandwidth_mhz != 4) {
          if (bandwidth_mhz != 8) goto bw_default;
          txd->beacon_ch_type = 2;
          if (temp_byte == 0) {
            if (ah_lmac.bss_bw != 1) {
              if (ah_lmac.bss_bw != '\x02') goto chan_list_check;
              bandwidth_bits = 1;
            }
            goto bw_apply;
          }
bw_s1g_2mhz:
          bandwidth_bits = 3;
          goto bw_apply;
        }
        txd->beacon_ch_type = '\x01';
        if (bVar2 != 0) goto bw_s1g_2mhz;
        if (ah_lmac.bss_bw == '\x01') goto bw_apply;
      }
chan_list_check:
      if (ah_lmac.chan_list_count < (txd->rate_flags & 0x1f)) {
        txd->rate_flags = txd->rate_flags & 0xe0;
      }
      frame_start_ptr = (astruct *)tx_skb->data;
      frame_len = tx_skb->len;
      txd->frame_data_ptr = frame_start_ptr;
      txd->frame_len = frame_len;
      temp_byte = frame_start_ptr->frame_control;
      temp_uint = temp_byte & 3;
      txd->frame_type_flags = txd->frame_type_flags & 0xfc | (byte)temp_uint;
      if ((temp_byte & 3) != 0) {
        hgprintf("\x02lmac error!!!pv= %d\r\n", temp_uint);
        goto err_set_and_drop;
      }
      is_data_frame = ieee80211_is_data((uint)frame_data_ptr->word);
      txd->data_beacon_flag = txd->data_beacon_flag & 0xfd | (is_data_frame & 1) << 1;
      lmac_get_rx_addr(txd->receiver_mac,tx_skb->data);
      ret_val_ptr = (uint32_t)lmac_sta_get(0xffff,txd->receiver_mac);
                    /* Is MAC unicast? */
      txd->sta_idx_ptr = ret_val_ptr;
      if ((txd->receiver_mac[0] & 1) == 0) {
        if (ret_val_ptr != 0) {
          if ((*(byte *)(ret_val_ptr + 0x6b) & 0x10) != 0) {
            temp_uint = txd->data_beacon_flag >> 1 & 1;
            hgprintf("\x02sta roaming out, drop(%d)\r\n", temp_uint);
            goto err_set_and_drop;
          }
          if (((*(byte *)(ret_val_ptr + 0x6b) & 0x20) != 0) && ((txd->data_beacon_flag & 2) != 0)) {
            hgprintf("\x02sta deleted, drop data\r\n");
            goto err_set_and_drop;
          }
        }
      }
      else {
        txd->tid_ac_partial_aid = txd->tid_ac_partial_aid & 0x7f | 0x80;
      }
      temp_byte = lmac_get_ack_policy(txd);
      txd->ack_mf_md_flags = txd->ack_mf_md_flags & 0xfd | (temp_byte & 1) << 1;
      if ((byte)(txd->bw_tx_level - 1) < 7) {
        temp_byte = txd->tid_ac_partial_aid & 0xf0 | txd->bw_tx_level & 0xf;
      }
      else {
        tx_desc_ptr = tx_skb->data;
        lmac_get_tid(tx_desc_ptr);
        temp_byte = txd->tid_ac_partial_aid & 0xf0 | (byte)tx_desc_ptr & 0xf;
      }
      txd->tid_ac_partial_aid = temp_byte;
      if (7 < (txd->tid_ac_partial_aid & 0xf)) {
        txd->tid_ac_partial_aid = txd->tid_ac_partial_aid & 0xf0 | 7;
      }
      frame_ctrl_short = (uint16_t)txd->tid_ac_partial_aid |
                         ((uint16_t)txd->data_beacon_flag << 8);
      if (((frame_ctrl_short & 0x280) == 0x280) &&
         (temp_byte = ah_lmac.mcast_dup_filter_cfg & 0xf,
         txd->mcast_dup_filter = ah_lmac.mcast_dup_filter_cfg & 0xf, temp_byte != 0)) {
        txd->tid_ac_partial_aid = txd->tid_ac_partial_aid & 0xf0 | 1;
        if ((ah_lmac.link_mode_flags & 0x20) == 0) {
          txd->dwSeq_dup_flags = txd->dwSeq_dup_flags | 1;
          iVar5 = (sn_dup_13763 & 0xfff) << 4;
          frame_data_ptr[0xb].frame_control = (uint8_t)iVar5;
          sn_dup_13763 = sn_dup_13763 + 1 & 0xfff;
          frame_data_ptr[0xb].field_0x1 = (char)((uint)iVar5 >> 8);
          goto seq_num_legacy;
        }
seq_num_s1g:
        frame_ptr_short = (ushort *)txd->frame_data_ptr;
        temp_uint = (uint)*frame_ptr_short;
        ret_val_ptr = txd->sta_idx_ptr;
        temp_byte = txd->tid_ac_partial_aid & 0xf;
        if ((*frame_ptr_short & 3) == 0) {
          temp_uint = (temp_uint & 7) >> 2;
          if ((temp_uint == 0) || (temp_uint == 2)) {
            temp_uint = seq_num_space_update(ret_val_ptr,temp_byte);
            pvVar4 = (void *)(temp_uint & 0xffff);
            iVar5 = (temp_uint & 0xfff) << 4;
            *(char *)(frame_ptr_short + 0xb) = (char)iVar5;
            *(char *)((int)frame_ptr_short + 0x17) = (char)((uint)iVar5 >> 8);
            goto seq_num_done;
          }
        }
        else if ((temp_uint & 3) == 1) {
          param1 = (temp_uint & 0xf) >> 2;
          if (param1 == 1) {
            if ((temp_uint & 0x7f) >> 5 < 2) goto seq_num_pv1_data;
          }
          else {
            if (param1 == 0) {
seq_num_pv1_data:
              temp_uint = seq_num_space_update(ret_val_ptr,temp_byte);
              pvVar4 = (void *)(temp_uint & 0xffff);
              frame_ptr_short[5] = (ushort)(temp_uint << 4);
              goto seq_num_done;
            }
            if (param1 != 2) {
              if (param1 == 3) {
                temp_uint = seq_num_space_update(ret_val_ptr,temp_byte);
                pvVar4 = (void *)(temp_uint & 0xffff);
                frame_ptr_short[7] = (ushort)(temp_uint << 4);
                goto seq_num_done;
              }
              hgprintf("\x02lmac error!!!invalid pv1 type= %d unknow!\r\n",param1);
            }
          }
        }
        pvVar4 = (void *)0xffff;
      }
      else {
seq_num_legacy:
        if ((ah_lmac.link_mode_flags & 0x20) != 0) goto seq_num_s1g;
        pvVar4 = txd->frame_data_ptr;
        lmac_get_seq_num(pvVar4);
      }
seq_num_done:
      temp_byte = txd->frame_type_flags;
      txd->seq_num_frag = (int16_t)(uint32_t)pvVar4;
      if ((temp_byte & 3) == 0) {
        aVar7 = *frame_data_ptr;
        txd->frame_type_flags = temp_byte & 0xe3 | aVar7.frame_control & 4;
        aligned_frame_len = (uint16_t)txd->frame_type_flags |
                            ((uint16_t)txd->ack_mf_md_flags << 8);
        frame_ctrl_short =
             aligned_frame_len & 0xfe1f | (ushort)(((int)(uint)aVar7.word >> 4 & 0xfU) << 5);
        txd->frame_type_flags = (char)frame_ctrl_short;
        txd->ack_mf_md_flags = (char)(frame_ctrl_short >> 8);
        txd->ack_mf_md_flags =
             txd->ack_mf_md_flags & 0xbf | ((byte)frame_data_ptr->field_0x1 >> 1 & 1) << 6;
        txd->ack_mf_md_flags = txd->ack_mf_md_flags & 0x7f | frame_data_ptr->field_0x1 << 7;
        temp_uint = lmac_get_hdr_len_pv0((ushort *)tx_skb->data);
        txd->hdr_len = (uint8_t)temp_uint;
        txd->bandwidth_field = txd->bandwidth_field & 0xe7 | (ah_lmac.bss_bw & 3) << 3;
        if ((frame_data_ptr->field_0x1 & 0x10) != 0) {
          hgprintf("\x02TX_PM DET\r\n");
        }
        if (((txd->frame_type_flags & 0x1c) == 8) &&
           (frame_control_word = (uint16_t)txd->frame_type_flags |
                                 ((uint16_t)txd->ack_mf_md_flags << 8),
           (frame_control_word & 0xe0) == 0x80)) {
          txd->data_beacon_flag = txd->data_beacon_flag & 0xf7 | 8;
          hgprintf("\x02tx_null:\r\n");
          hgics_print_hex(tx_skb->data,tx_skb->len);
        }
        ret_val_ptr = ah_lmac.qa_rx_channel_map;
        if ((txd->frame_type_flags & 0xf) >> 2 < 4) {
          if (((*(byte *)(ah_lmac.qa_rx_channel_map + 0x15) & 7) == 1) &&
             (*(uint *)(ah_lmac.qa_rx_channel_map + 4) != 0)) {
            tx_desc_ptr = tx_skb->data;
            temp_byte = tx_skb->head[0x2a];
            if ((CONCAT11(tx_desc_ptr[temp_byte + 6],tx_desc_ptr[temp_byte + 7]) == 0x800) &&
               ((((tx_desc_ptr[temp_byte + 0x11] == '\x11' ||
                  (tx_desc_ptr[temp_byte + 0x11] == '\x06')) &&
                 (*(uint *)(ah_lmac.qa_rx_channel_map + 4) ==
                  ((uint)tx_desc_ptr[temp_byte + 0x18] << 0x18 |
                   (uint)tx_desc_ptr[temp_byte + 0x19] << 0x10 | (uint)tx_desc_ptr[temp_byte + 0x1b]
                  | (uint)tx_desc_ptr[temp_byte + 0x1a] << 8))) &&
                (*(short *)(ah_lmac.qa_rx_channel_map + 8) ==
                 CONCAT11(tx_desc_ptr[temp_byte + 0x1e],tx_desc_ptr[temp_byte + 0x1f]))))) {
              frame_ctrl_short = tx_skb->len;
              *(char *)(ah_lmac.qa_rx_channel_map + 0x12) = (char)frame_ctrl_short;
              memcpy((void *)(ret_val_ptr + 0x17),tx_desc_ptr,(uint)frame_ctrl_short);
              hgprintf("\x02HEARTBEAT tx det: len= %d\r\n",(uint)*(byte *)(ah_lmac.qa_rx_channel_map + 0x12));
            }
          }
          temp_uint = (txd->frame_type_flags & 0xf) >> 2;
          pJumpOrCtx = (uint8_t *)lmac_tx_pv0_hdl;
          goto call_subtype_handler;
        }
err_unknown_frame_type:
        temp_uint = (uint)frame_data_ptr->word;
        hgprintf("\x02lmac error!!!fc= %d\r\n", temp_uint);
        goto err_set_and_drop;
      }
      if ((temp_byte & 3) == 1) {
        aVar7 = *frame_data_ptr;
        txd->frame_type_flags = temp_byte & 0xe3 | (byte)(((int)(uint)aVar7.word >> 2 & 7U) << 2);
        frame_control_short = (uint16_t)txd->frame_type_flags |
                              ((uint16_t)txd->ack_mf_md_flags << 8);
        frame_ctrl_short = frame_control_short & 0xfe1f | (ushort)aVar7.word & 0x60;
        txd->frame_type_flags = (char)frame_ctrl_short;
        txd->ack_mf_md_flags = (char)(frame_ctrl_short >> 8);
        frame_data_ptr->field_0x1 = frame_data_ptr->field_0x1 & 0xef;
        txd->tid_ac_partial_aid = txd->tid_ac_partial_aid & 0xef;
        txd->ack_mf_md_flags = txd->ack_mf_md_flags & 0xbf | (frame_data_ptr->field_0x1 & 1) << 6;
        hdr_len = lmac_get_hdr_len_pv1((ushort *)tx_skb->data);
        temp_uint = (txd->frame_type_flags & 0xf) >> 2;
        txd->hdr_len = hdr_len;
        if (3 < temp_uint) goto err_unknown_frame_type;
        pJumpOrCtx = (uint8_t *)lmac_tx_pv1_hdl;
call_subtype_handler:
        iVar5 = ((lmac_tx_handler_t *)(*(uint *)(pJumpOrCtx + temp_uint * 4) & 0xfffffffe))(tx_skb);
        if (iVar5 != 0) goto err_set_and_drop;
      }
      frame_ctrl_short = tx_skb->len + 8;
      if ((tx_skb->len & 3) != 0) {
        frame_ctrl_short = (frame_ctrl_short & 0xfffc) + 4;
      }
      temp_byte = ah_lmac.beacon_s1g_format_flags & 1;
      temp_uint = (uint)(short)frame_ctrl_short;
      txd->frame_ctrl = frame_ctrl_short;
      if (temp_byte == 0) {
        iVar5 = 0x67b;
      }
      else if (ah_lmac.tx_mcs_min_limit == 0) {
        iVar5 = 0x17f;
      }
      else {
        iVar5 = *(int *)(max_byte_table + (uint)ah_lmac.tx_mcs_min_limit * 0x10);
      }
      if (iVar5 < (int)temp_uint) {
        hgprintf("\x02lmac error!!!packet= %dB too long, drop!\r\n", temp_uint);
        goto err_set_and_drop;
      }
      lmac_partial_aid_update(txd);
      if (((ah_lmac.sta0_added_or_assoc_flag == 1) && ((ah_lmac.beacon_s1g_format_flags & 1) == 0))
         && (txd->sta_idx_ptr != 0)) {
        txd->tid_ac_partial_aid = txd->tid_ac_partial_aid & 0xbf | 0x40;
      }
      if ((ah_lmac.sleep_ctrl_flags & 2) == 0) {
        aVar7.word = frame_data_ptr->word & 0xefff;
      }
      else {
        aVar7.word = frame_data_ptr->word | 0x1000;
      }
      *frame_data_ptr = aVar7;
      if ((int)ah_lmac._rsv_9cc - 2U < 2) {
        frame_data_ptr->word = frame_data_ptr->word | 0x1000;
      }
      tx_desc_ptr = tx_skb->head;
      if ((tx_desc_ptr[0x26] & 0x10) == 0) {
ce_start_ok:
        pBufOrHead = tx_skb->head;
        if (7 < (pBufOrHead[0x26] & 0xf)) {
          pBufOrHead[0x26] = pBufOrHead[0x26] & 0xf0 | 7;
          hgprintf("\x02lmac error!!!*tid= %d\r\n",7);
          hgics_print_hex(*(undefined4 *)(pBufOrHead + 0x10),0x20);
        }
        temp_byte = *(byte *)((pBufOrHead[0x26] & 7) + 0x2004b885);
        psVar3 = ah_lmac_tx.pTx_ac_queues + (short)(ushort)temp_byte;
        iVar5 = (int)skb_list_last(psVar3);
        nAggCheckResult = lmac_check_aggregation(tx_skb,(struct sk_buff *)iVar5);
        if (nAggCheckResult != 0) {
          psVar3 = &ah_lmac_tx.tx_status_queue;
        }
        skb_list_queue(psVar3,tx_skb);
        hdr_len = ah_lmac_tx.pTx_agg_count_per_ac[temp_byte];
        ah_lmac_tx.pTx_agg_count_per_ac[temp_byte] = hdr_len + '\x01';
        if (((ah_lmac_tx.pTx_agg_count_per_ac[3] == '\0') || (iVar5 != 0)) &&
           ((ah_lmac_tx.pTx_agg_count_per_ac[2] < ah_lmac.aggcnt >> 1 &&
            ((byte)(hdr_len + 1) < ah_lmac.aggcnt)))) {
          if (((uint)tx_desc_ptr & 0x40) == 0) goto process_frame;
          bVar6 = false;
agg_check_done:
          if (!bVar6) goto process_frame;
        }
        else if (((uint)tx_desc_ptr & 0x40) != 0) {
          bVar6 = true;
          goto agg_check_done;
        }
        lmac_tx_data_reload();
        goto process_frame;
      }
      ah_lmac_tx.tx_packet_count_low = ah_lmac_tx.tx_packet_count_low + 1;
      if (ah_lmac_tx.tx_packet_count_low == 0) {
        ah_lmac_tx.tx_packet_count_high = ah_lmac_tx.tx_packet_count_high + 1;
      }
      if (0xffff < ah_lmac_tx.tx_packet_count_high) {
        ah_lmac_tx.tx_packet_count_low = 1;
        ah_lmac_tx.tx_packet_count_high = 0;
      }
      if ((tx_desc_ptr[0x24] & 3) == 0) {
        pn_num_13617 = pn_num_13617 + 1;
        if (pn_num_13617 == 0) {
          pn_num_hi = pn_num_hi + 1;
        }
        hdr_len = ah_lmac.key0.cipher;
        if (-1 < (char)tx_desc_ptr[0x26]) {
          if (*(int *)(tx_desc_ptr + 0xc) == 0) {
            hgprintf("\x02lmac error!!!null sta for ccmp\r\n");
            hdr_len = key_id_13616;
          }
          else {
            hdr_len = *(uint8_t *)(*(int *)(tx_desc_ptr + 0xc) + 0x75);
          }
        }
        key_id_13616 = hdr_len;
        ah_lmac_tx.pCcmp_auth_header[1] = (uint8_t)((uint)pn_num_13617 >> 8);
        ah_lmac_tx.pCcmp_auth_header[2] = '\0';
        ah_lmac_tx.pCcmp_auth_header[3] = key_id_13616 << 6 | 0x20;
        ah_lmac_tx.pCcmp_auth_header[0] = (uint8_t)pn_num_13617;
        ah_lmac_tx.pCcmp_auth_header[6] = (uint8_t)pn_num_hi;
        ah_lmac_tx.pCcmp_auth_header[7] = (uint8_t)((uint)pn_num_hi >> 8);
        ah_lmac_tx.pCcmp_auth_header[4] = (uint8_t)((uint)pn_num_13617 >> 0x10);
        ah_lmac_tx.pCcmp_auth_header[5] = (uint8_t)((uint)pn_num_13617 >> 0x18);
        tx_stat_ptr = (ushort *)tx_skb->data;
        pBufOrHead = tx_skb->head;
        *(uint16_t *)ah_lmac_tx.pTx_ccmp_aad_additional_data_a =
             *tx_stat_ptr & 0xc78f | 0x4000;
        memcpy(ah_lmac_tx.pTx_ccmp_aad_additional_data_a + 2,tx_stat_ptr + 2,0x12);
        frame_ptr_short = tx_stat_ptr + 0xc;
        *(uint16_t *)(ah_lmac_tx.pTx_ccmp_aad_additional_data_a + 20) =
             *(byte *)(*(int *)(pBufOrHead + 0xc) + 0xb9) & 1;
        if ((*(byte *)(*(int *)(pBufOrHead + 0xc) + 0xb9) & 1) != 0) {
          *(uint16_t *)(ah_lmac_tx.pTx_ccmp_aad_additional_data_a + 20) =
               *(ushort *)(pBufOrHead + 0x18) & 0xf;
        }
        ah_lmac_tx.pTx_cipher_desc_reserved[0] = '\x16';
        if ((pBufOrHead[0x25] & 0xc0) == 0xc0) {
          memcpy(ah_lmac_tx.pTx_ccmp_aad_additional_data_a + 0x16,frame_ptr_short,6);
          frame_ptr_short = tx_stat_ptr + 0xf;
          ah_lmac_tx.pTx_cipher_desc_reserved[0] = '\x1c';
          pBufOrHead = ah_lmac_tx.pTx_ccmp_aad_additional_data_a + 0x1c;
        }
        else {
          pBufOrHead = ah_lmac_tx.pTx_ccmp_aad_additional_data_a + 0x16;
        }
        iVar5 = ieee80211_is_data_qos(*(undefined2 *)tx_skb->data);
        if (iVar5 != 0) {
          *(uint16_t *)ah_lmac_tx.pTx_ccmp_aad_additional_data_a &= 0x3fff;
          *pBufOrHead = (uint8_t)*frame_ptr_short;
          pBufOrHead[1] = *(uint8_t *)((int)frame_ptr_short + 1);
          ah_lmac_tx.pTx_cipher_desc_reserved[0] = ah_lmac_tx.pTx_cipher_desc_reserved[0] + '\x02';
        }
        pBufOrHead = tx_skb->data;
        lmac_get_tid(pBufOrHead);
        ah_lmac_tx.pCcmp_auth_nonce[0] = (byte)pBufOrHead & 0xf;
        memcpy(ah_lmac_tx.pCcmp_auth_nonce + 1,tx_skb->data + 10,6);
        ah_lmac_tx.pCcmp_auth_nonce[7] = ah_lmac_tx.pCcmp_auth_header[0];
        ah_lmac_tx.pCcmp_auth_nonce[8] = ah_lmac_tx.pCcmp_auth_header[1];
        ah_lmac_tx.pCcmp_auth_nonce[9] = ah_lmac_tx.pCcmp_auth_header[4];
        ah_lmac_tx.pCcmp_auth_nonce[10] = ah_lmac_tx.pCcmp_auth_header[5];
        ah_lmac_tx.pCcmp_auth_nonce[0xb] = ah_lmac_tx.pCcmp_auth_header[6];
        ah_lmac_tx.pCcmp_auth_nonce[0xc] = ah_lmac_tx.pCcmp_auth_header[7];
        pBufOrHead = tx_skb->head;
        lmac_cfg_tx_ce_para_isra5(pBufOrHead);
        iVar5 = ah_ce_start(pBufOrHead,&ah_lmac_tx.cipher_engine_descriptor);
        temp_byte = ah_lmac.key0.key_len;
        if (-1 < (char)tx_desc_ptr[0x26]) {
          temp_byte = *(byte *)(*(int *)(tx_desc_ptr + 0xc) + 0x76);
        }
        temp_uint = (temp_byte >> 1) + 8;
        memcpy((void *)(*(int *)(tx_desc_ptr + 0x10) + (uint)tx_desc_ptr[0x2a]),
               ah_lmac_tx.pCcmp_auth_header,8);
      }
      else {
        ah_lmac_tx.pTx_cipher_desc_reserved[0] = '\x10';
        temp_uint = (tx_desc_ptr[0x24] & 0xf) >> 2;
        if (temp_uint < 3) {
          if (temp_uint == 0) {
            pBufOrHead = tx_skb->data;
            if ((tx_desc_ptr[0x25] & 0x40) == 0) {
              memcpy(ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 2,pBufOrHead + 2,6);
              pvVar4 = (void *)lmac_convert_sid2mac(*(undefined2 *)(pBufOrHead + 8));
              memcpy(ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 8,pvVar4,6);
              if ((pBufOrHead[9] & 0x20) == 0) {
                if ((tx_desc_ptr[0x26] & 0x20) != 0) {
                  ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x10] = '\x02';
                  ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x11] = 0xd2;
                  ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x12] = 0xe1;
                  ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x13] = '(';
                  ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x14] = 0xa5;
                  ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x15] = '|';
                  goto ccmp_aad_htc;
                }
                __dest = ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 0x10;
              }
              else {
                memcpy(ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 0x10,tx_skb->data + 0xc,6);
ccmp_aad_htc:
                ah_lmac_tx.pTx_cipher_desc_reserved[0] =
                     ah_lmac_tx.pTx_cipher_desc_reserved[0] + '\x06';
                __dest = ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 0x16;
              }
              temp_byte = pBufOrHead[9];
            }
            else {
              memcpy(ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 2,ah_lmac.bssid_or_peer_mac,6);
              memcpy(ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 8,tx_desc_ptr + 0x1a,6);
              if ((pBufOrHead[3] & 0x20) == 0) {
                __dest = ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 0x10;
              }
              else {
                memcpy(ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 0x10,tx_skb->data + 0xc,6);
                ah_lmac_tx.pTx_cipher_desc_reserved[0] = '\x16';
                __dest = ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 0x16;
              }
              temp_byte = pBufOrHead[3];
            }
            if ((temp_byte & 0x40) != 0) {
              memcpy(__dest,tx_skb->data + 0x12,6);
              ah_lmac_tx.pTx_cipher_desc_reserved[0] =
                   ah_lmac_tx.pTx_cipher_desc_reserved[0] + '\x06';
            }
            goto ccmp_aad_done;
          }
          /* temp_uint == 1 or 2: unsupported PV1 subtype for AAD generation */
          hgprintf("\x02lmac error!!!generate aad for PV1 MGMT/CTRL not supported!\r\n");
          /* falls through to after the if-else → after_pv1_aad */
        }
        else {
          if (temp_uint != 3) {
            hgprintf("\x02lmac error!!!generate aad for invalid PV1 type!\r\n");
            goto after_pv1_aad;
          }
          hgprintf("\x02lmac error!!!not sure about A3/A4, just suppose they are stored in receiver!\r\n");
          memcpy(ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 2,tx_skb->data + 2,6);
          memcpy(ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 8,tx_skb->data + 8,6);
          ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x10] = '\x02';
          ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x11] = 0xd2;
          ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x12] = 0xe1;
          ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x13] = '(';
          ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x14] = 0xa5;
          ah_lmac_tx.pTx_ccmp_aad_additional_data_b[0x15] = '|';
          ah_lmac_tx.pTx_cipher_desc_reserved[0] = ah_lmac_tx.pTx_cipher_desc_reserved[0] + '\x06';
ccmp_aad_done:
          *(uint16_t *)ah_lmac_tx.pTx_ccmp_aad_additional_data_b =
               *(ushort *)tx_skb->data & 0x3ff | 0x1000;
          *(uint16_t *)(ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 14) =
               *(ushort *)(tx_desc_ptr + 0x18) & 0xf;
        }
after_pv1_aad:
        pBufOrHead = tx_skb->head;
        pBufOrHead[0x26] = pBufOrHead[0x26] & 0xf0 | 3;
        ah_lmac_tx.pCcmp_auth_nonce[0] = ' ';
        memcpy(ah_lmac_tx.pCcmp_auth_nonce + 1,ah_lmac_tx.pTx_ccmp_aad_additional_data_b + 8,6);
        ah_lmac_tx.pCcmp_auth_nonce[0xc] = '\0';
        ah_lmac_tx.pCcmp_auth_nonce[0xb] = '\0';
        ah_lmac_tx.pCcmp_auth_nonce[10] = '\0';
        ah_lmac_tx.pCcmp_auth_nonce[9] = '{';
        ah_lmac_tx.pCcmp_auth_nonce[7] = (uint8_t)*(undefined2 *)(pBufOrHead + 0x18);
        ah_lmac_tx.pCcmp_auth_nonce[8] = (uint8_t)((ushort)*(undefined2 *)(pBufOrHead + 0x18) >> 8);
        pBufOrHead = tx_skb->head;
        lmac_cfg_tx_ce_para_isra5(pBufOrHead);
        iVar5 = ah_ce_start(pBufOrHead,&ah_lmac_tx.cipher_engine_descriptor);
        temp_byte = ah_lmac.key0.key_len;
        if (-1 < (char)tx_desc_ptr[0x26]) {
          temp_byte = *(byte *)(*(int *)(tx_desc_ptr + 0xc) + 0x76);
        }
        temp_uint = (uint)(temp_byte >> 1);
      }
      skb_put(tx_skb,temp_uint);
      frame_ctrl_short = tx_skb->len;
      *(ushort *)(tx_desc_ptr + 0x14) = frame_ctrl_short;
      aligned_frame_len = frame_ctrl_short + 8;
      if ((frame_ctrl_short & 3) != 0) {
        aligned_frame_len = (aligned_frame_len & 0xfffc) + 4;
      }
      *(ushort *)(tx_desc_ptr + 0x16) = aligned_frame_len;
      if (iVar5 == 0) goto ce_start_ok;
      hgprintf("\x02Func:lmac_encrypt_hdl failed\r\n");
      goto err_cleanup;
    }
    else {
      hgprintf("\x02lmac error!!!unaligned addr= 0x%x\r\n",(uint)frame_data_ptr);
      hgics_print_hex(tx_skb->data,tx_skb->len);
err_set_and_drop:
      hgprintf("\x02Func:lmac_gen_tx_info failed\r\n");
    }
err_cleanup:
    tx_skb->acked = 0;
    skb_list_queue(&ah_lmac_tx.tx_frames_pending_queue,tx_skb);
    os_sema_up(&ah_lmac_tx.tx_status_sem);
    hgprintf("\x02lmac error!!!tx skb drop\r\n");
  } while( true );
reload_and_retry:
  lmac_tx_data_reload();
  goto main_loop;
}


void lmac_tx_status_task(void *_arg)
{
  sk_buff *sk_buff_log;
  uint32_t send_duration;
  uint32_t send_time;
  lmac_txd *txd;

  while (((byte)ah_lmac_tx.exit_flag & 1) == 0) {
    os_sema_down(&ah_lmac_tx.tx_status_sem,-1);
    sk_buff_log = skb_list_dequeue(&ah_lmac_tx.tx_frames_pending_queue);
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
        send_time = send_duration - skb_start_send_time(sk_buff_log);
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
          hgprintf("\x02SP_Tx over\r\n");
        }
        ah_lmac._rsv_a64[0] = ah_lmac._rsv_a64[0] & 0xef;
      }
      else {
        kfree_skb(sk_buff_log);
      }
      sk_buff_log = skb_list_dequeue(&ah_lmac_tx.tx_frames_pending_queue);
    }
  }
  hgprintf("\x02%s exit!!!\r\n", "lmac tx status");
  return;
}
