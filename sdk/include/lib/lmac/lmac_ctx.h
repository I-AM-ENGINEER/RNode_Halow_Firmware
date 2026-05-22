#ifndef __LMAC_CTX_H__
#define __LMAC_CTX_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "list.h"
#include "osal/semaphore.h"
#include "osal/mutex.h"
#include "osal/task.h"
#include "osal/timer.h"
#include "lib/lmac/lmac.h"
#include "lib/skb/skb_list.h"

/* SDK types */
struct sk_buff;
struct list_head;

typedef struct lmac_ops lmac_ops_t;
typedef struct lmac_ctx lmac_ctx_t;
typedef uint8_t byte;

typedef struct ah_ce_cfg {
    const uint8_t *key;        // [0x00] key pointer
    uint8_t        mode;       // [0x04] cipher mode (0=AES-CCM, 2=WEP-like)
    uint8_t        ctrl5;      // [0x05] lower nibble → CE_MODE bits[3:0]
    uint8_t        ctrl6;      // [0x06] bit0 → CE_MODE bit4
    uint8_t        ctrl7;      // [0x07] bit0 → CE_MODE bit5
    const uint8_t *iv;         // [0x08] IV pointer (6 bytes used)
    const uint8_t *aad;        // [0x0C] AAD pointer (6 bytes used)
    const uint8_t *key2;       // [0x10] secondary/GHASH key pointer
    uint8_t        key2_len;   // [0x14] secondary key length (must be < 31)
    uint8_t        direction;  // [0x15] 0=encrypt, 1=decrypt
    uint16_t       data_len;   // [0x16] data length (must be < 16385)
    uint32_t       src_addr;   // [0x18]
    uint32_t       dst_addr;   // [0x1C]
} __attribute__((packed)) ah_ce_cfg_t;

struct lmac_ctx_key {
    uint8_t cipher;
    uint8_t key_len;
    uint8_t key[32];
} __attribute__((packed));

struct lmac_ctx_extra_ies {
    uint8_t s1g_beacon_hdr_field;
    uint16_t len_flags;
    uint8_t data[256];
} __attribute__((packed));

#define undefined uint8_t

struct ah_ce_ctx {
    uint8_t _pre_cw_0[0x18];      /* 0x004-0x01B: cipher engine + misc */
    uint8_t cca_mode_per_ac[4];   /* 0x01C-0x01F: CCA mode per AC (0=ED, 1=CS, 2=ED+CS) */
    uint8_t _pre_cw_1c[8];        /* 0x020-0x027 */
    uint16_t cw_min[4];           /* 0x028-0x02F: EDCA CW_min per AC (read by lmac_attempt_tx_orig) */
    uint8_t _gap_030[8];          /* 0x030-0x037 */
    uint16_t cw_max[4];           /* 0x038-0x03F: EDCA CW_max per AC */
    uint8_t _post_cw[0x7C];      /* 0x040-0x0BB: remaining opaque */
} __attribute__((packed));

struct lmac_chan_candidate {
    uint8_t _opaque[24];
} __attribute__((packed));

struct lmac_ctx_s1g_capabilities {
    uint8_t capabilities_info[10];
    uint8_t mcs_nss_set[5];
} __attribute__((packed));

struct lmac_ctx_ssid {
    uint8_t eid;
    uint8_t len;
    uint8_t ssid[32];
} __attribute__((packed));

struct lmac_ctx_edca_ac_param {
    uint8_t aci_aifsn;
    uint8_t ecw_min_max;
    uint16_t txop_limit;
} __attribute__((packed));

struct lmac_ctx_edca_params {
    uint8_t qos_info;
    uint8_t reserved;
    struct lmac_ctx_edca_ac_param ac_be;
    struct lmac_ctx_edca_ac_param ac_bk;
    struct lmac_ctx_edca_ac_param ac_vi;
    struct lmac_ctx_edca_ac_param ac_vo;
} __attribute__((packed));

struct pv0_pspoll_frame {
    uint8_t _opaque[16];
} __attribute__((packed));

typedef struct lmac_ah_cipher_ctx {
    volatile uint32_t   *base_addr;    // [0x00] CE hardware register base
    struct os_mutex      mutex;        // [0x04] access mutex (8 bytes)
    struct os_semaphore  sema;         // [0x0C] completion semaphore (8 bytes)
    uint32_t             irq_num;      // [0x14] interrupt number
} __attribute__((packed)) lmac_ah_cipher_ctx_t;

struct pv0_cfend_frame {
    uint8_t _opaque[16];
} __attribute__((packed));

struct rx_vendor_bss_cache_entry {
    uint32_t key;
    uint8_t ie_param0;
    uint8_t ie_param1;
    uint8_t ie_param2;
    int8_t best_rssi_or_metric;
    uint8_t ie_param3;
    uint8_t unknown[3];
}; __attribute__((packed))

struct lmac_ctx {
    struct lmac_ops *ops;
    struct ah_ce_ctx ce_ctx;
    uint32_t sta0_added_or_assoc_flag;
    struct lmac_chan_candidate chan_list[16];
    struct rx_vendor_bss_cache_entry rx_vendor_bss_cache[16];
    uint8_t obss_threshold;
    uint8_t obss_edca_select_flag;
    uint8_t mac_addr[6];
    uint8_t bss_bw;
    uint8_t pri_channel;
    uint8_t _rsv_30a[2];
    uint8_t chan_busy_threshold_0;
    uint8_t chan_busy_threshold_1;
    uint8_t chan_busy_threshold_2;
    uint8_t chan_busy_threshold_3;
    uint8_t link_mode_flags;
    uint8_t mcs_encoding_format;
    uint8_t rate_budget_threshold;    /* 0x312: compared with txd->_reserved_29 in reorder */
    uint8_t retry_count_threshold;    /* 0x313: compared with txd->retry_count in reorder */
    uint8_t mcast_dup_filter_cfg;
    uint8_t aggcnt;
    uint8_t hw_init_param;
    uint8_t sta_priv_alloc_size;
    uint8_t ps_timeout_retry_count;
    uint8_t sleep_ctrl_flags;
    uint8_t uplink_ctrl_flags0;
    uint8_t uplink_ctrl_flags1;
    int8_t tx_power_high_threshold;
    int8_t tx_power_low_threshold;
    int8_t cca_threshold_base;
    int8_t agc_threshold_high;
    int8_t agc_threshold_low;
    int8_t bknoise_gain_ref[6];
    int8_t bknoise_base_offset;
    int8_t cca_threshold_offset;
    int8_t cca_threshold_max;
    int8_t s1g_short_beacon_optional_ie_flag;
    uint8_t _rsv_32b[1];
    int16_t bgrssi_spur_threshold;
    uint16_t rts_threshold;
    uint16_t ps_heartbeat_period;
    uint8_t adc_dump_id;
    uint8_t tdma_rx_buff_flags;
    uint16_t tx_bw_len_threshold;
    uint16_t sta_partial_aid_bits;
    uint32_t lo_freq_or_channel_bits;
    uint8_t lo_table_index;
    uint8_t lo_active_freq_b0;
    uint16_t lo_active_freq_b1b2;
    uint8_t lo_active_index;
    uint8_t _rsv_341[3];
    uint32_t s1g_optional_ie_time_value;
    uint8_t s1g_optional_ie_param;
    uint8_t _rsv_349[1];
    uint8_t beacon_s1g_format_flags;
    uint8_t _rsv_34b[1];
    uint32_t beacon_init_zero_a;
    uint32_t beacon_init_zero_b;
    uint8_t _rsv_354[8];
    uint32_t acs_sample_count;
    uint8_t cca_ctrl_low_byte;
    uint8_t cca_agc_ctrl_flags;
    uint16_t rx_gain_cfg_bits;
    uint8_t pcf_period;
    uint8_t pcf_percent;
    uint8_t _rsv_366[2];
    uint32_t rx_iface_queue_head;
    uint16_t tx_power_config;     /* 0x36C: bits[4:0]=base_pwr, bits[12:5]=pwr_cap */
    uint8_t tx_rate_ctrl_flags;
    uint8_t _rsv_36f[1];
    uint32_t tx_rx_ratio_statics;
    uint32_t tx_freq_or_init_param;
    uint8_t chan_list_count;
    uint8_t bgrssi_chan_index;
    uint16_t bgrssi_scan_param;
    uint16_t auto_chan_switch_flags;
    uint16_t obss_cca_param_bits;
    uint8_t txvec_phy_opt;
    uint8_t _rsv_381[3];
    uint32_t pv0_ctrl_duration;
    uint32_t phy_watchdog_period;
    uint32_t event6_period;
    uint32_t mode_event_period;
    uint32_t tick_unit;
    uint32_t event3_7_period;
    uint32_t obss_scan_period;
    uint32_t obss_ap_period;
    uint32_t hw_scan_interval_us;
    uint32_t hw_scan_param_3a8;
    uint32_t periodic_event13_period;
    uint32_t reset_countdown_period;
    uint32_t ant_auto_period;
    uint32_t debug_flags;
    uint16_t bw_restore_count_threshold;
    uint16_t bgr_sample_threshold;
    uint64_t ap_sleep_timer;          /* 0x3C0: jiffies timestamp, 0 when inactive */
    uint16_t ap_sleep_timeout_active;
    uint16_t ap_sleep_timeout_reload;
    uint64_t bss_rx_activity;         /* 0x3CC: jiffies of last BSS RX activity */
    uint32_t beacon_timeout_low;
    uint32_t beacon_timeout_high;
    uint16_t ack_timeout_extra;
    uint8_t psconnect_period;
    uint8_t pwr_cca_flags;
    uint8_t rxg_offset;
    uint8_t obss_per;
    uint8_t ndp_scramble_enable;     /* 0x3E2: bit0=enable NDP scrambling */
    uint8_t _rsv_3e3[1];
    uint8_t resp_ind_ctrl;        /* 0x3E4: bit0=ack_resp_ind_override for TXVEC */
    uint8_t _rsv_3e5[3];
    uint8_t _rsv_3e8[4];
    uint8_t _rsv_3ec[4];
    struct lmac_ctx_extra_ies extra_ies;
    struct lmac_ctx_s1g_capabilities payload;
    struct lmac_ctx_edca_params edca_params;
    struct lmac_ctx_edca_params obss_edca_params;
    uint8_t bssid_or_peer_mac[6];
    struct lmac_ctx_ssid _lmac_ctx_ssid_52c;
    uint8_t _rsv_54e[2];
    uint8_t _rsv_550[4];
    uint8_t tim;
    uint8_t DTIM;
    uint8_t dtim_period;
    uint8_t bitmap_control_bit0;
    uint8_t bitmap_control;
    uint8_t _rsv_559[4];            /* 0x559-0x55C */
    uint8_t tx_antenna_byte;       /* 0x55D: bits[2]=ant_sel for TX status */
    uint8_t _rsv_55e[246];         /* 0x55E-0x655 */
    uint16_t s1g_compat_info;
    uint16_t beacon_interval;
    uint32_t TSF;
    uint32_t beacon;
    uint32_t last_beacon_tsf_low;
    uint32_t last_beacon_tsf_high;
    uint16_t s1g_operation_bits;
    uint8_t _rsv_66a[2];
    uint16_t tx_time_part0;
    uint16_t tx_symbol_duration;
    uint16_t tx_time_part2;
    uint16_t tx_time_ctrl;            /* 0x672-0x673: cleared with tx_time_part2 on TX start */
    uint16_t beacon_airtime;
    uint16_t bss_max_idle;
    int32_t chip_temp_adj;
    uint32_t vcc_meas_value;
    uint8_t thermal_pmu_flags;
    uint8_t _rsv_681[1];
    uint16_t tx_digi_gain[6];
    uint8_t tx_power;
    uint8_t xo_cs_trim_offset;
    uint8_t chan_score_weight_a;
    uint8_t chan_score_weight_b;
    struct lmac_ctx_key key0;
    struct lmac_ctx_key key1;
    uint8_t _rsv_6d6[2];
    uint32_t vdd13b_meas_value;
    uint32_t vdd13c_meas_value;
    uint32_t diag_last_tx_mcs;         /* 0x6E8: last TX MCS written by lmac_update_tx_rate */
    uint32_t diag_last_tx_bw_hint;     /* 0x6EC: last TX BW hint written by lmac_update_tx_rate */
    uint32_t last_tx_mcs;
    uint32_t last_tx_bw_sig;
    uint32_t tx_some_counter_6f0;
    uint32_t tx_some_counter_6f4;
    uint32_t padding_6f8_6fb[2];
    uint32_t tx_state_700;
    uint32_t tx_state_704;
    uint8_t pwr_ft_att_flags;          /* 0x708: front-end attenuator flags (bits[5:0]), compared for PA reconfig */
    uint8_t _rsv_709[3];
    uint8_t tx_write_flags_70c;
    uint8_t tx_write_flags_70d;
    uint8_t tx_write_flags_70e;
    uint8_t tx_last_mcs_bw;       /* 0x70F: last TX MCS/BW byte from TXVEC1 (bits[3:0]=MCS-lo, bits[7:4]=BW) */
    uint8_t pwr_sel_result;            /* 0x710: power select result (pwr_arg) written by lmac_tx_pwr_sel */
    uint8_t _rsv_711[1];
    int16_t rx_dcoc_i_offset;
    int16_t rx_dcoc_q_offset;
    uint8_t _rsv_716[2];
    uint32_t ac_pd_irq_tx_attempt_count;
    uint32_t ac_tx_attempt_count[4];   /* 0x71C-0x72B: per-AC TX attempt counter */
    uint32_t tx_queue_state_72c;
    uint32_t tx_queue_state_730;
    uint32_t tx_queue_state_734;
    uint32_t tx_queue_state_738;
    uint32_t tx_queue_state_73c;
    uint32_t tx_attempt_count;    /* 0x740: TX event counter (+1 per backoff→TX, data and beacon) */
    uint32_t tx_mpdu_count;       /* 0x744: total MPDUs transmitted (+=selected_count per aggregate) */
    uint32_t tx_byte_count_total; /* 0x748: total TX bytes (+=total_len_bytes per aggregate) */
    uint32_t tx_queue_state_74c;
    uint32_t tx_sym_time_acc;     /* 0x750: accumulated TXCTX symbol time (+=TXCTX[0x560]+[0x562]) */
    uint32_t rx_queue_state_754;
    uint32_t rx_duration_high;
    uint32_t diag_tx_rate_updates;     /* 0x75C: count of lmac_update_tx_rate calls */
    uint32_t last_send_time;
    uint32_t send_time_sum;
    uint32_t tx_queue_entry_768;
    uint32_t tx_queue_state_76c;
    uint32_t tx_queue_state_770;
    uint32_t tx_queue_state_774;
    uint32_t tx_queue_state_778;
    uint32_t tx_write_only_77c;
    uint32_t tx_write_only_780;
    uint32_t tx_state_784;
    uint32_t tx_state_788;
    uint32_t tx_state_78c;
    uint32_t tx_state_790;
    uint32_t tx_state_794;
    uint32_t tx_state_798;
    uint32_t tx_state_79c;
    uint32_t tx_state_7a0;
    uint32_t tx_state_7a4;
    uint32_t tx_state_7a8;
    uint32_t diag_tx_reload_count;     /* 0x7AC: count of lmac_tx_data_reload empty-queue events */
    uint32_t tx_retry_count_7b0;
    uint32_t tx_retry_limit_7b4;
    uint32_t tx_state_7b8;
    uint32_t tx_state_7bc;
    uint32_t tx_state_7c0;
    uint32_t tx_state_7c4;
    uint32_t tx_state_7c8;
    uint32_t tx_state_7cc;
    uint32_t tx_state_7d0;
    uint32_t tx_state_7d4;
    uint32_t tx_state_7d8;
    uint32_t tx_state_7dc;
    uint32_t tx_state_7e0;
    uint16_t tx_state_7e4;
    uint16_t tx_state_7e6;
    uint16_t tx_state_7e8;
    uint8_t _rsv_7ea[2];
    uint32_t tx_state_7ec;
    uint32_t tx_state_7f0;
    uint32_t tx_state_7f4;
    uint32_t tx_state_7f8;
    uint8_t _rsv_7fc[4];
    uint32_t tx_channel_state_800;
    uint16_t tx_state_804;
    uint16_t tx_state_806;
    uint32_t tx_latency_acc_lo;   /* 0x808: TX latency accumulator low word  (jiffies: acc -= enqueue_time + now) */
    uint32_t tx_latency_acc_hi;   /* 0x80C: TX latency accumulator high word */
    uint32_t tx_airtime_acc_lo;   /* 0x810: TX airtime accumulator low word  (half-symbol units, scaled) */
    uint32_t tx_airtime_acc_hi;   /* 0x814: TX airtime accumulator high word */
    uint8_t _rsv_818[4];
    uint32_t tx_state_81c;
    uint32_t tx_write_only_820;
    uint32_t tx_channel_set_824;
    uint32_t tx_channel_state_828;
    uint32_t tx_result_82c;
    uint32_t tx_result_830;
    uint32_t tx_result_834;
    uint16_t rx_dcoc_i_last;
    int16_t rx_dcoc_q_last;
    uint8_t _rsv_83c[1];
    int8_t  tx_airtime_scale_offset; /* 0x83D: signed; effective airtime scale = (100 - this) % */
    uint8_t diag_pwr_sel_mcs;          /* 0x83E: last MCS passed to lmac_tx_pwr_sel */
    uint8_t _rsv_83f[1];
    uint8_t diag_pwr_sel_power;        /* 0x840: last power level from lmac_tx_pwr_sel */
    uint8_t diag_pwr_sel_rx_ctrl;      /* 0x841: RX PV0 ctrl byte saved by lmac_tx_pwr_sel */
    uint8_t _rsv_842[2];
    uint32_t diag_pwr_sel_count;       /* 0x844: count of lmac_tx_pwr_sel calls */
    uint32_t diag_pwr_sel_sta_word;    /* 0x848: sta+0x68 word saved by lmac_tx_pwr_sel */
    int16_t chan_scan_rssi_0;
    int16_t chan_scan_rssi[1];
    int16_t chan_scan_rssi_2;
    int16_t chan_scan_rssi_3;
    int16_t chan_scan_rssi_4;
    int16_t chan_scan_rssi_5;
    int16_t chan_scan_rssi_6;
    int16_t chan_scan_rssi_7;
    int16_t chan_scan_rssi_8;
    int16_t chan_scan_rssi_9;
    uint8_t tx_byte_860;
    uint8_t _rsv_861[3];
    uint8_t tx_mcs_max_limit;
    uint8_t mcs_floor;
    uint8_t tx_mcs;
    uint8_t tx_bw_sig;
    uint8_t mcast_tx_rate;
    uint8_t mcast_txbw;
    uint8_t _rsv_86a[11];
    uint8_t tx_bw_ctrl_flags;
    uint8_t gpio0_pin_flags;
    uint8_t gpio1_pin_flags;
    uint8_t force_nav_flags;
    uint8_t _rsv_879[3];
    uint16_t cfpoll_duration_calc;
    uint16_t tx_timestamp_disable_or_reset_flag;
    uint8_t _rsv_880[16];
    uint8_t qa_tx_thresholds_0;
    uint8_t qa_tx_thresholds[1];
    uint8_t qa_freq_hop_flags;
    uint8_t _rsv_893[1];
    uint32_t qa_tx_params_word0;
    uint8_t qa_tx_thresholds_6;
    uint8_t qa_tx_thresholds_7;
    int8_t qa_rx_metric_2;
    int8_t qa_rx_metric_3;
    int8_t qa_rx_metric_4;
    uint8_t qa_rx_metric_reserved;
    int16_t qa_rx_metric_5;
    uint8_t _rsv_8a0[2];
    int8_t qa_rx_avg_power;
    int8_t qa_rx_avg_evm;
    int8_t qa_rx_freq_offset;
    uint8_t qa_rx_agc_index;
    uint8_t _rsv_8a6[2];
    int8_t qa_rx_metric_6;
    int8_t qa_rx_metric_7;
    int8_t qa_rx_metric_8;
    int8_t qa_rx_metric_9;
    uint8_t qa_rx_threshold_flags;
    uint8_t qa_tx_threshold_flags;
    uint8_t rf_temp_calib_0;
    uint8_t rf_temp_calib[1];
    uint8_t rf_temp_calib_2;
    uint8_t rf_temp_calib_3;
    uint16_t rf_temp_calib_4;
    uint16_t init_param_rxbuf_size;
    void *init_param_rxbuf;
    void *init_param_tdma_buff;
    uint32_t init_param_rxbuf_size2;
    uint8_t init_param_uart_tx_io;
    uint8_t init_param_dual_ant;
    uint8_t init_param_field_8c4;
    uint8_t init_param_field_8c5;
    uint8_t init_param_field_8c6;
    uint8_t init_param_field_8c7;
    uint8_t tdma_aux_timing_b0;
    uint8_t tdma_aux_timing_b1;
    uint8_t _rsv_8ca[2];
    uint32_t qa_rx_channel_map;
    uint8_t _rsv_8d0[8];
    uint32_t ba_resp_timeout_or_tdma;
    uint8_t _rsv_8dc[8];                       /* 0x8DC-0x8E3: gap before response frames */
    uint8_t rts_resp_frame[16];                /* 0x8E4-0x8F3: RTS response frame buffer (DMA source) */
    uint8_t cts_resp_frame[16];                /* 0x8F4-0x903: CTS response frame buffer (DMA source) */
    uint8_t ack_resp_frame[16];                /* 0x904-0x913: ACK response frame buffer (DMA source) */
    uint8_t ba_resp_frame[34];                 /* 0x914-0x935: Block ACK response frame buffer (DMA source) */
    uint8_t _rsv_936[34];                      /* 0x936-0x957 */
    struct pv0_cfend_frame pv0_cfend;
    struct pv0_pspoll_frame pv0_pspoll;
    uint8_t mac_state_978;
    uint32_t frame_rx_state;
    uint32_t rx_frame_counter;
    uint32_t rx_frame_byte_count;
    uint32_t rx_frame_info;
    uint32_t tx_active_flags;
    uint16_t tx_state_9c8;
    uint8_t _rsv_9ca[2];
    uint8_t  _rsv_991[3];
    uint32_t bo_frame_type;    /* 0x994: type of frame scheduled for next backoff (1=data, 2=ACK, 3=BA, 4=RTS, 5=CTS, 6=CFPoll, 7=CFEnd, 8=Beacon, 9=Null, 10=PSPoll) */
    uint32_t bo_tx_substate;   /* 0x998: result code written by lmac_irq_bo_fns, consumed by lmac_irq_tx_end (0=none, 1=data, 2=RTS, 3=CFPoll, 4=ACK/BA/Beacon, 5=Null, 6=PSPoll) */
    uint8_t _rsv_9cc[4];
    struct os_task main_task;
    uint32_t tx_irq_error_flags; /* 0x9B4: error accumulator: bit0=unknown_bo_state, bit1=tx_hw_error, bit14=no_data_in_aggr */
    char *allocated_print_buffer;
    struct os_semaphore print_queue_sem;
    struct os_task print_task;
    uint8_t tx_ac_state_flags;
    uint8_t beacon_pending_state_flags;
    uint8_t beacon_obss_slot_flags;
    uint8_t irq_ac_control_flags;
    uint8_t current_ac_flags;
    uint8_t ps_tim_state;    /* 0x9DD: low nibble = TIM PS delivery state; nonzero = PS delivery pending after beacon */
    undefined field370_0x9de;
    int8_t field371_0x9df;
    uint8_t  _rsv_9e0[2];     /* 0x9E0-0x9E1: reserved */
    uint16_t bo_nav_ctrl;     /* 0x9E2: bit[1]=rts_needed bit[3]=nav_pending bit[5]=bo_active bits[12:6]=nav_dur_ms */
    uint32_t tdma_buff_size;  /* 0x9E4 */
    struct os_mutex sta_list_mutex;
    undefined field375_0x9f0;
    undefined field376_0x9f1;
    undefined field377_0x9f2;
    undefined field378_0x9f3;
    undefined field379_0x9f4;
    undefined field380_0x9f5;
    undefined field381_0x9f6;
    undefined field382_0x9f7;
    void    *pSta_list_head;      /* 0x9F8: circular STA linked list head (sentinel = &ah_lmac.pSta_list_head) */
    undefined field387_0x9fc;
    undefined field388_0x9fd;
    undefined field389_0x9fe;
    undefined field390_0x9ff;
    undefined field391_0xa00;
    undefined field392_0xa01;
    undefined field393_0xa02;
    undefined field394_0xa03;
    undefined field395_0xa04;
    undefined field396_0xa05;
    undefined field397_0xa06;
    undefined field398_0xa07;
    undefined field399_0xa08;
    undefined field400_0xa09;
    uint16_t ps_beacon_sta_cnt;      /* 0xA0A: count of PS STAs expecting data after beacon; 0 = normal sync path */
    uint16_t ps_data_delivery_ctrl;  /* 0xA0C: cleared when data TX occurs during PS delivery */
    undefined field405_0xa0e;
    undefined field406_0xa0f;
    undefined field407_0xa10;
    undefined field408_0xa11;
    undefined field409_0xa12;
    struct os_timer tick_timer;
    struct os_timer scan_timer;
    uint32_t last_rx_pv0_ctrl_info;
    uint8_t tx_irq_ctrl_flags;    /* 0xA4F: bit3=PS-retry-skip; set when TX frame has PS flag, checked in lmac_irq_tx_end */
    void   *pTx_current_sta;     /* 0xA50: pointer to last TX STA, used by lmac_irq_tx_end to update STA stats */
    uint32_t beacon_cur_timer;   /* 0xA54: beacon current timer, cleared on TX reconfig */
    uint8_t _rsv_a58[19];       /* 0xA58-0xA6A */
    uint32_t evt_queue_head;
    uint32_t evt_queue_tail;
    uint32_t evt_queue_capacity;
    undefined field417_0xa77;
    uint16_t pending_pkg_to_status_check;
    uint16_t tx_retry_or_multi_count;
    uint32_t evt_slot_count;
    uint32_t evt_ring[29];
    undefined field422_0xaf4;
    undefined field423_0xaf5;
    undefined field424_0xaf6;
    undefined field425_0xaf7;
    undefined field426_0xaf8;
    undefined field427_0xaf9;
    undefined field428_0xafa;
    undefined field429_0xafb;
    undefined field430_0xafc;
    undefined field431_0xafd;
    undefined field432_0xafe;
    undefined field433_0xaff;
    undefined field434_0xb00;
    undefined field435_0xb01;
    undefined field436_0xb02;
    undefined field437_0xb03;
    undefined field438_0xb04;
    undefined field439_0xb05;
    undefined field440_0xb06;
    undefined field441_0xb07;
    undefined field442_0xb08;
    undefined field443_0xb09;
    undefined field444_0xb0a;
    undefined field445_0xb0b;
    undefined field446_0xb0c;
    undefined field447_0xb0d;
    undefined field448_0xb0e;
    undefined field449_0xb0f;
    undefined field450_0xb10;
    undefined field451_0xb11;
    undefined field452_0xb12;
    undefined field453_0xb13;
    undefined field454_0xb14;
    undefined field455_0xb15;
    undefined field456_0xb16;
    undefined field457_0xb17;
    undefined field458_0xb18;
    undefined field459_0xb19;
    undefined field460_0xb1a;
    undefined field461_0xb1b;
    undefined field462_0xb1c;
    undefined field463_0xb1d;
    undefined field464_0xb1e;
    undefined field465_0xb1f;
    undefined field466_0xb20;
    undefined field467_0xb21;
    undefined field468_0xb22;
    undefined field469_0xb23;
    undefined field470_0xb24;
    undefined field471_0xb25;
    undefined field472_0xb26;
    undefined field473_0xb27;
    undefined field474_0xb28;
    undefined field475_0xb29;
    undefined field476_0xb2a;
    undefined field477_0xb2b;
    undefined field478_0xb2c;
    undefined field479_0xb2d;
    undefined field480_0xb2e;
    undefined field481_0xb2f;
    undefined field482_0xb30;
    undefined field483_0xb31;
    undefined field484_0xb32;
    undefined field485_0xb33;
    undefined field486_0xb34;
    undefined field487_0xb35;
    undefined field488_0xb36;
    undefined field489_0xb37;
    undefined field490_0xb38;
    undefined field491_0xb39;
    undefined field492_0xb3a;
    undefined field493_0xb3b;
    undefined field494_0xb3c;
    undefined field495_0xb3d;
    undefined field496_0xb3e;
    undefined field497_0xb3f;
    undefined field498_0xb40;
    undefined field499_0xb41;
    undefined field500_0xb42;
    undefined field501_0xb43;
    undefined field502_0xb44;
    undefined field503_0xb45;
    undefined field504_0xb46;
    undefined field505_0xb47;
    undefined field506_0xb48;
    undefined field507_0xb49;
    undefined field508_0xb4a;
    undefined field509_0xb4b;
    undefined field510_0xb4c;
    undefined field511_0xb4d;
    undefined field512_0xb4e;
    undefined field513_0xb4f;
    undefined field514_0xb50;
    undefined field515_0xb51;
    undefined field516_0xb52;
    undefined field517_0xb53;
    undefined field518_0xb54;
    undefined field519_0xb55;
    undefined field520_0xb56;
    undefined field521_0xb57;
    undefined field522_0xb58;
    undefined field523_0xb59;
    undefined field524_0xb5a;
    undefined field525_0xb5b;
    undefined field526_0xb5c;
    undefined field527_0xb5d;
    undefined field528_0xb5e;
    undefined field529_0xb5f;
    undefined field530_0xb60;
    undefined field531_0xb61;
    undefined field532_0xb62;
    undefined field533_0xb63;
    undefined field534_0xb64;
    undefined field535_0xb65;
    undefined field536_0xb66;
    undefined field537_0xb67;
    undefined field538_0xb68;
    undefined field539_0xb69;
    undefined field540_0xb6a;
    undefined field541_0xb6b;
    undefined field542_0xb6c;
    undefined field543_0xb6d;
    undefined field544_0xb6e;
    undefined field545_0xb6f;
    undefined field546_0xb70;
    undefined field547_0xb71;
    undefined field548_0xb72;
    undefined field549_0xb73;
    undefined field550_0xb74;
    undefined field551_0xb75;
    undefined field552_0xb76;
    undefined field553_0xb77;
    undefined field554_0xb78;
    undefined field555_0xb79;
    undefined field556_0xb7a;
    undefined field557_0xb7b;
    undefined field558_0xb7c;
    undefined field559_0xb7d;
    undefined field560_0xb7e;
    undefined field561_0xb7f;
    undefined field562_0xb80;
    undefined field563_0xb81;
    undefined field564_0xb82;
    undefined field565_0xb83;
    undefined field566_0xb84;
    undefined field567_0xb85;
    undefined field568_0xb86;
    undefined field569_0xb87;
    undefined field570_0xb88;
    undefined field571_0xb89;
    undefined field572_0xb8a;
    undefined field573_0xb8b;
    undefined field574_0xb8c;
    undefined field575_0xb8d;
    undefined field576_0xb8e;
    undefined field577_0xb8f;
    struct os_semaphore main_sem;
    uint32_t tsf_low_at_sleep;
    uint32_t tsf_high_at_sleep;
    uint32_t tsf_last_beacon_low;
    uint32_t tsf_last_beacon_high;
    uint32_t tsf_target_low;
    uint32_t skbpool_free_units;
    undefined field585_0xbb0;
    undefined field586_0xbb1;
    undefined field587_0xbb2;
    undefined field588_0xbb3;
    undefined field589_0xbb4;
    undefined field590_0xbb5;
    undefined field591_0xbb6;
    undefined field592_0xbb7;
    struct os_mutex auto_chanel_select_mutex;
    undefined field594_0xbc0;
    undefined field595_0xbc1;
    undefined field596_0xbc2;
    uint8_t rx_frame_flag;
} __attribute__((packed));

typedef struct lmac_tx_ctx lmac_tx_ctx_t;

struct lmac_tx_vector {
    byte flags0;
    byte bw_fmt;
    byte fmt_byte;
    byte rsvd03;
    uint32_t tx_symbol_len;
    uint32_t ctrl_word_lo;
    uint32_t ctrl_word_hi;
} __attribute__((packed));

typedef struct lmac_tx_ctx_buff {
    struct sk_buff *skb_list[64];

    uint32_t total_len_bytes;
    uint32_t symbol_len;

    int16_t first_seq;
    int16_t last_seq;

    uint8_t selected_count;
    uint8_t queued_count;
    uint8_t rate_cfg;
    uint8_t tx_flags;                  /* bit2 = TXVEC ready flag */

    struct lmac_tx_vector txvec;       /* per-AC TX vector (was reserved_110) */
} __attribute__((packed)) lmac_tx_ctx_buff;

/* TX Descriptor — 0x44 bytes stored at skb->head.
 * Filled by lmac_fast_tx / lmac_tx_task, read by the TX pipeline (AC_PD → attempt_tx → tx_frm). */
typedef struct lmac_txd {
    uint8_t  _reserved_00[0x0C];   /* 0x00-0x0B: unused */
    void    *sta;                   /* 0x0C: station table entry (lmac_sta_get result) */
    uint8_t *frame;                 /* 0x10: 802.11 frame pointer (skb->data) */
    uint16_t frame_len;             /* 0x14: frame byte count (skb->len) */
    uint16_t aligned_len;           /* 0x16: PHY-aligned frame length */
    int16_t  seq_num;               /* 0x18: 802.11 sequence number */
    uint8_t  dest_mac[6];           /* 0x1A-0x1F: destination MAC address */
    uint8_t  _reserved_20[0x04];    /* 0x20-0x23 */
    uint8_t  frame_type_lo;         /* 0x24: derived from FC: proto_ver[1:0]|type[4:2]|subtype[7:5] */
    uint8_t  frame_type_hi;         /* 0x25: subtype_ext[0]|no_ack[1]|fc_bits[4:2]|more_data[6]|order[7] */
    uint8_t  tx_ctrl;               /* 0x26: TID[3:0]|_reserved[5:4]|_reserved[6]|mcast[7] */
    uint8_t  tx_flags;              /* 0x27: _reserved[0]|started[1]|_reserved[6:2]|completed[7] */
    uint8_t  retry_count;           /* 0x28: current retry counter */
    uint8_t  _reserved_29;          /* 0x29 */
    uint8_t  hdr_len;               /* 0x2A: S1G header length (from lmac_get_hdr_len_pv0) */
    uint8_t  bw_cfg;               /* 0x2B: bss_bw in bits[5:3] */
    uint8_t  _reserved_2c[0x10];    /* 0x2C-0x3B */
    uint8_t  tx_bw_hint;            /* 0x3C: TX bandwidth hint/signaling index */
    uint8_t  tx_rate_mcs;           /* 0x3D: TX MCS override/rate field */
    uint8_t  fallback_count;        /* 0x3E: rate fallback count (0x0F max) */
    uint8_t  rts_cfg;              /* 0x3F: RTS config (bits[6:5] = mode, etc.) */
    uint8_t  _reserved_40[0x04];    /* 0x40-0x43 */
} __attribute__((packed)) lmac_txd_t;

/* Per-AC TX extension area: legacy overlay on lmac_tx_ctx_buff tail.
 * Access via: ac_aggr(ac) for the aggr buffer, then use named fields. */
typedef struct lmac_ac_tx_ext {
    uint32_t _pad;                     /* 0x1B8-0x1BB */
    uint32_t aggr_sym_len;             /* 0x1BC: total symbol length for aggregated TX */
    uint8_t  seq_win_start;            /* 0x1C0: sequence window start index */
    uint8_t  _rsv_1c1;
    uint8_t  seq_win_end;              /* 0x1C2: sequence window end index */
    uint8_t  _rsv_1c3;
    uint8_t  agg_num;                  /* 0x1C4: frames in aggregate */
    uint8_t  agg_cnt;                  /* 0x1C5: selected frame count */
    uint16_t aggr_hdr_ctrl;            /* 0x1C6: aggregation header control bits */
    struct lmac_tx_vector txvec;       /* 0x1C8-0x1D7: per-AC TX vector */
} __attribute__((packed)) lmac_ac_tx_ext_t;

struct lmac_ce_desc {
    uint32_t key_ptr;
    uint8_t algo;
    uint8_t tid;
    uint8_t amsdu;
    uint8_t mfp_or_rsv;
    uint32_t nonce_ptr;
    uint32_t key_def_ptr;
    uint32_t aad_ptr;
    uint8_t aad_len;
    uint8_t rsv;
    uint16_t payload_len;
    uint32_t in_ptr;
    uint32_t out_ptr;
} __attribute__((packed));

struct lmac_tx_ctx {
    uint32_t exit_flag;
    uint8_t *pPv0_txvec;

    /* OS tasks and semaphores */
    struct os_task tx_task;
    struct os_task tx_status_task;
    struct os_semaphore tx_sem;
    struct os_semaphore tx_status_sem;

    /* Packet queues */
    struct skb_list tx_pending_queue;
    struct skb_list tx_status_queue;

    /* Per-AC queues */
    struct skb_list pTx_ac_queues[4];

    /* Per-AC aggregation data (single skb per AC in modem mode) */
    struct lmac_tx_ctx_buff pTx_ac_aggr_data[4];

    /* Completion queue for tx_status_task */
    struct skb_list tx_frames_pending_queue;

    /* Per-AC counters */
    uint8_t pTx_agg_count_per_ac[4];
    uint8_t _pad0[4];

    /* TX completion status */
    uint32_t tx_last_fcs;
    uint16_t tx_last_rate_packed;
    uint16_t tx_pending_nav_dur;
    uint16_t tx_cca_slot_count;
    uint16_t tx_cca_remain;

    /* NDP TX vector cache (5 entries x 16 bytes, raw byte access for HW) */
    uint8_t pTx_vector_cache[80];

    /* Response TX vectors (PV0 response frames) */
    struct lmac_tx_vector resp_cts_txvec;
    struct lmac_tx_vector resp_ba_txvec;
    struct lmac_tx_vector resp_ack_txvec;
} __attribute__((packed));


/* ============================================================================
   External Global Variables (from lmac_globals.h)
   ========================================================================== */

extern lmac_ctx_t           ah_lmac;           // main context
extern lmac_tx_ctx_t        ah_lmac_tx;        // TX subsystem context
//extern lmac_ah_rx_ctx_t   ah_lmac_rx;        // RX subsystem
//extern lmac_dsleep_ctx_t  ah_dsleep;         // deep-sleep
extern lmac_ops_t         ah_ops;            // device vtable

/* Calibration data */
extern int32_t  tx_dcoc_res;                 // 
extern int16_t  rx_dcoc_res[48];             // 
extern int16_t  tx_epa_imb_res_pm;           // 
extern int16_t  rx_imb_gain_comp[6];         // 
extern int16_t  dpd_epa_phase_comp;          // 
extern int16_t  dpd_epa_gain_comp;           // 

/* RF shadow registers */
extern uint16_t rf_regs[56];                 // 
extern uint16_t rf_agc_reg_hw_val[144];      // 
extern uint32_t dpd_ram[432];                // 

/* Rate table and MCS lookup */
extern uint32_t rate_tbl[16];                // 
extern uint8_t  max_byte_table[176];         // 

#endif // __LMAC_CTX_H__
