/* LMAC Context Structure - 2026-04-26 */

#pragma once

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

#define LMAC_FLAG_DEBUG_PRINT    (1U << 6)
#define LMAC_FLAG_TX_IN_PROGRESS (1U << 7)
#define LMAC_PHY_TX_ACK_PENDING  (1U << 0)
#define LMAC_PHY_RX_ACK_PENDING  (1U << 1)
#define LMAC_PHY_RX_ACTIVE       (1U << 2)
#define LMAC_PHY_SCAN_TIMER      (1U << 3)
#define LMAC_PHY_SLEEP_ACTIVE    (1U << 6)
#define RX_FLAG_ENCRYPTED        (1U << 0)
#define RX_FLAG_AMSDU            (1U << 1)
#define RX_FLAG_DUPLICATE        (1U << 2)

typedef struct lmac_sta_info {
    struct list_head node;                  // [0x00] Linked list node
    uint8_t     rsv_004[0x68 - 0x008];
    uint16_t    assoc_id;                  // [0x68] Association ID (AID)
    uint16_t    rsv_06a_00;                // [0x6A-0x6B] Padding
    uint8_t     sta_flags_0;               // [0x6C] STA flags byte 0
    uint8_t     sta_flags_1;               // [0x6D] STA flags byte 1
    uint8_t     sta_flags_2;               // [0x6E] STA flags byte 2
    uint8_t     sta_flags_3;               // [0x6F] STA status/capability byte 3
    uint8_t     sta_flags_4;               // [0x70] STA state byte 4
    uint8_t     sta_flags_5;               // [0x71] STA state byte 5
    uint8_t     sta_flags_6;               // [0x72] STA state byte 6
    uint8_t     sta_flags_7;               // [0x73] STA state byte 7
    uint8_t     sta_flags_8;               // [0x74] STA state byte 8
    uint8_t     rsv_75[0xA3 - 0x75];       // [0x75-0xA2] Reserved
    int8_t      rssi_dbm;                  // [0xA3] RSSI in dBm
    uint8_t     rsv_a4[5];                 // [0xA4-0xA8] Reserved
    uint8_t     rx_mcs_info;               // [0xA9] RX MCS info
    uint8_t     tx_rate_probe;             // [0xAA] TX rate probe/attempt byte
    uint8_t     rate_flags;                // [0xAB] Rate control flags
    uint8_t     phy_bw_mcs;                // [0xAC] PHY bandwidth & MCS
    uint8_t     rate_ctrl_state;           // [0xAD] Rate control state
    uint8_t     rate_shift_nss;            // [0xAE] Rate shift/NSS info (bits 3:0 = shift, 7:4 = NSS)
    uint8_t     rate_nss_info;             // [0xAF] NSS/spatial info (bits 3:0 = NSS from 0xAE>>4, 7:4 reserved)
    uint8_t     rsv_b0[2];                 // [0xB0-0xB1] Reserved
    uint8_t     mcs_index;                 // [0xB2] MCS index
    uint8_t     rsv_b3;                    // [0xB3] Reserved
    int8_t      rssi_offset;               // [0xB4] RSSI offset for calibration
    uint8_t     rc_attempt_flags;          // [0xB5] RC attempt flags
    int8_t      power_offset;              // [0xB6] TX power offset
    uint8_t     rx_bw_mcs;                 // [0xB7] RX bandwidth & MCS info
    int8_t      rssi_smooth;               // [0xB8] Smoothed RSSI value
    uint8_t     rsv_b9[0x128 - 0xB9];      // [0xB9-0x127] Reserved
    uint8_t     tx_mcs;                    // [0x128] TX Modulation & Coding Scheme
    uint8_t     rsv_129[0x1C4 - 0x129];    // [0x129-0x1C3] Reserved
    uint16_t    frame_duration_calc;       // [0x1C4] Frame duration calculation result
    uint16_t    tx_bytes_window;           // [0x1C6] TX bytes in window
    uint32_t    tx_airtime_ticks;          // [0x1C8] TX airtime (timing ticks)
    uint32_t    rsv_1cc;                   // [0x1CC] Timing-related
    uint32_t    rx_airtime_ticks;          // [0x1D0] RX airtime (timing ticks)
    uint16_t    tx_airtime_us;             // [0x1D4] TX air time (microseconds)
    uint16_t    tx_time_offset;            // [0x1D6] TX timing offset
    uint32_t    rx_timing_comp;            // [0x1D8] RX timing compensation
    uint32_t    tx_timing_comp;            // [0x1DC] TX timing compensation
    uint16_t    timing_drift;              // [0x1E0] Timing drift adjustment
    uint16_t    rx_bytes_window;           // [0x1E2] RX bytes in window
    uint32_t    rx_timestamp_ref;          // [0x1E4] RX reference timestamp
    uint8_t     rsv_1e8[8];                // [0x1E8-0x1EF] Reserved
    uint32_t    rx_frame_count;            // [0x1F0] Total RX frames
    uint8_t     rsv_1f4[0x250 - 0x1F4];
} lmac_sta_info_t;

typedef struct lmac_rc_state {
    uint8_t     current_mcs;            // [0x00] Current MCS index (0-7)
    uint8_t     sample_attempts;        // [0x01] Probe/sample frame count
    uint8_t     sample_success;         // [0x02] Successful probes
    uint8_t     sample_fail;            // [0x03] Failed probes
    uint16_t    success_probability;    // [0x04] Success rate (0-10000 = 0-100%)
    uint16_t    reserved_06;
    uint32_t    rssi_ewma;              // [0x08] Exponential moving avg RSSI
    uint32_t    last_rate_update_ts;    // [0x0C] Timestamp of last rate change
    uint32_t    tx_frame_count;         // [0x10] Total frames at this rate
    uint32_t    tx_success_count;       // [0x14] Successful frames at rate
    uint8_t     reserved[0x120 - 0x18];
} lmac_rc_state_t;

typedef struct lmac_tx_descriptor {
    uint32_t    frame_address;             // SKB data address
    uint16_t    frame_length;              // Total frame length
    uint16_t    mpdu_length;               // MPDU length (per frame in A-MPDU)
    uint8_t     mcs_index;                 // MCS 0-7
    uint8_t     bandwidth_code;            // 0=1MHz, 1=2MHz, 2=4MHz, 3=8MHz, 4=16MHz
    uint8_t     max_retry_count;           // Max retries
    uint8_t    agg_frame_count;            // Number of frames in A-MPDU
    uint32_t    tx_flags;                  // Encryption, aggregation flags
    uint32_t    sequence_number;           // Per-TID sequence number
    uint32_t    cipher_key_index;          // Encryption key index
} lmac_tx_descriptor_t;

typedef struct lmac_rx_frame_info {
    uint16_t    frame_control;          // [0x00] FC field
    uint16_t    duration_id;            // [0x02] Duration/ID
    uint8_t     dest_address[6];        // [0x04] Destination MAC
    uint8_t     src_address[6];         // [0x0A] Source MAC
    uint8_t     bssid_address[6];       // [0x10] BSSID
    uint16_t    sequence_number;        // [0x16] Sequence number
    int8_t      rssi_dbm;               // [0x18] Received Signal Strength
    uint8_t     mcs_index;              // [0x19] Modulation & Coding Scheme
    uint8_t     bandwidth_used;         // [0x1A] Bandwidth (MHz)
    uint8_t     rx_status;              // [0x1B] Additional RX info
    uint32_t    timestamp_us;           // [0x1C] RX timestamp
    uint8_t     cipher_key_index;       // [0x20] Key index for decryption
    uint8_t     rx_flags;               // [0x21] RX flags (encrypted, duplicate, etc.)
} lmac_rx_frame_info_t;

typedef struct lmac_dsleep_ctx {
    uint8_t     sleep_mode;                 // [0x00] Deep-sleep mode type
    uint8_t     wake_source;                // [0x01] Wakeup source reason
    uint8_t     sleep_flags;                // [0x02] Sleep-related flags
    uint8_t     reserved_003;
    uint32_t    saved_mac_state;            // [0x04] Saved LMAC state
    uint32_t    saved_rf_registers[8];      // [0x08] RF register values
    uint32_t    power_timer_reload;         // [0x28] Power-down timer reload
    uint32_t    power_timer_counter;        // [0x2C] Timer counter
    uint8_t     gpio_wakeup_config[16];    // [0x30] GPIO wake pin config
    void        *tx_context_backup;         // [0x40] TX subsystem backup
    void        *rx_context_backup;         // [0x44] RX subsystem backup
    uint8_t     dma_temp_buffer[0x50];      // [0x48] DMA temporary buffer
    uint8_t     reserved[0x12C - 0x98];
} lmac_dsleep_ctx_t;

typedef union lmac_txvec_word {
    uint32_t word;                          // 32-bit TX vector word view
    uint16_t half[2];                       // 16-bit TX vector halfword view
    uint8_t  byte[4];                       // 8-bit TX vector byte view
} lmac_txvec_word_t;

typedef struct lmac_txvec_slot {
    uint8_t           ctrl0;                // [0x00] TX vector control byte 0
    uint8_t           ctrl1;                // [0x01] TX vector control byte 1
    uint8_t           ctrl2;                // [0x02] TX vector control byte 2
    uint8_t           ctrl3;                // [0x03] TX vector control byte 3
    lmac_txvec_word_t word_04;              // [0x04] TX vector word at slot +0x4
    lmac_txvec_word_t word_08;              // [0x08] TX vector word at slot +0x8
    lmac_txvec_word_t word_0c;              // [0x0C] TX vector word at slot +0xC
} lmac_txvec_slot_t;

typedef union lmac_s1g_beacon_scratch {
    uint8_t  raw[8];                        // Shared S1G beacon/control scratch bytes
    uint32_t word[2];                       // Shared S1G beacon/control scratch words
    struct {
        uint32_t short_beacon_interval_ticks; // [0x00] Cached short-beacon interval scaled by 1024
        uint32_t aux_word;                  // [0x04] Shared aux word reused by beacon/control paths
    } short_beacon;
    struct {
        uint8_t addr_byte0;                 // [0x00] Cached control-frame address byte 0
        uint8_t addr_byte1;                 // [0x01] Cached control-frame address byte 1
        uint8_t addr_pad;                   // [0x02] Cleared padding byte when address view is active
        uint8_t ctrl_flags;                 // [0x03] Control/address flags byte
        uint8_t addr_byte2;                 // [0x04] Cached control-frame address byte 2
        uint8_t addr_byte3;                 // [0x05] Cached control-frame address byte 3
        uint8_t addr_byte4;                 // [0x06] Cached control-frame address byte 4
        uint8_t addr_byte5;                 // [0x07] Cached control-frame address byte 5
    } ctrl_addr;
} lmac_s1g_beacon_scratch_t;

typedef union lmac_s1g_beacon_aux {
    uint8_t  raw[8];                        // Shared S1G beacon/control aux scratch bytes
    uint32_t word[2];                       // Shared S1G beacon/control aux scratch words
    struct {
        uint8_t pv0_cfend_addr[6];          // [0x00] Cached PV0 CF-END address bytes
        uint8_t reserved_06[2];             // [0x06] Unresolved tail bytes in CF-END view
    } cfend;
} lmac_s1g_beacon_aux_t;

typedef struct lmac_s1g_beacon_state {
    uint16_t                    compat_field0; // [0x00] First cached field from S1G compatibility IE
    uint16_t                    short_beacon_interval; // [0x02] Short beacon interval from IE
    lmac_s1g_beacon_scratch_t   scratch;      // [0x04] Shared short-beacon/control scratch
    lmac_s1g_beacon_aux_t       aux;          // [0x0C] Shared aux cache for S1G beacon/control builders
} lmac_s1g_beacon_state_t;

typedef struct lmac_pv0_ctrl_airtime_cache {
    uint16_t wpcts_airtime_ticks;           // [0x00] Cached PV0 WPCTS airtime
    uint16_t wpack_airtime_ticks;           // [0x02] Cached PV0 WPACK airtime
    uint16_t wpba_airtime_ticks;            // [0x04] Cached PV0 WPBA airtime
    uint16_t cfend_airtime_ticks;           // [0x06] Cached PV0 CF-END airtime
    uint16_t cfpoll_airtime_ticks;          // [0x08] Cached PV0 CFPOLL airtime
    uint16_t short_beacon_timeout_limit;    // [0x0A] Short-beacon timeout / guard limit
} lmac_pv0_ctrl_airtime_cache_t;

typedef struct lmac_chip_monitor_gain_cache {
    uint8_t  pmu_vref_track_state;          // [0x00] PMU Vref tracking state bits
    uint8_t  reserved_01;                   // [0x01] Reserved / unknown
    uint16_t tx_digi_gain_primary[4];       // [0x02-0x09] Four TX digital gain slots populated during chip-monitor init
    uint16_t tx_digi_gain_cached[2];        // [0x0A-0x0D] Cached gain/config words reused by runtime tuning
} lmac_chip_monitor_gain_cache_t;

/* Forward declarations from osal subsystems (included above) */

/* ============================================================================
   Main LMAC Context - Extended Definition
   ========================================================================== */

struct lmac_ctx_key {
    uint8_t cipher;      // offset 0x00
    uint8_t key_len;     // offset 0x01
    uint8_t key[0x20];   // offset 0x02
};

struct lmac_ctx_ssid {
    uint8_t eid;          // offset 0x00, Element ID = 0
    uint8_t len;          // offset 0x01, SSID length
    uint8_t ssid[0x20];   // offset 0x02, SSID buffer[32]
};

struct lmac_ctx_edca_ac_param {
    uint8_t aci_aifsn;      // +0x00
    uint8_t ecw_min_max;    // +0x01
    uint16_t txop_limit;    // +0x02
};                          // size = 0x04

struct lmac_ctx_edca_params {
    uint8_t qos_info;       // +0x00
    uint8_t reserved;       // +0x01

    struct lmac_ctx_edca_ac_param ac_be; // +0x02
    struct lmac_ctx_edca_ac_param ac_bk; // +0x06
    struct lmac_ctx_edca_ac_param ac_vi; // +0x0a
    struct lmac_ctx_edca_ac_param ac_vo; // +0x0e
};                          // size = 0x12

struct lmac_ctx_s1g_capabilities {
    uint8_t capabilities_info[10];   // 0x4f3 .. 0x4fc
    uint8_t mcs_nss_set[5];          // 0x4fd .. 0x501
};                                   // sizeof = 0x0f

struct __attribute__((packed)) lmac_ctx_extra_ies {
    uint8_t s1g_beacon_hdr_field;   // 0x3f0
    uint16_t len_flags;             // 0x3f1 .. 0x3f2
    uint8_t data[0x100];            // 0x3f3 .. 0x4f2
};                                  // size = 0x103

struct rx_vendor_bss_cache_entry {
    uint32_t key;                 // +0x00, 4 bytes

    uint8_t  ie_param0;           // +0x04
    uint8_t  ie_param1;           // +0x05
    uint8_t  ie_param2;           // +0x06

    int8_t   best_rssi_or_metric; // +0x07, signed comparison

    uint8_t  ie_param3;           // +0x08

    uint8_t  unknown[3];          // +0x09 .. +0x0b
};                                // size = 0x0c
/* LMAC_CTX_GENERATED_BEGIN */
/* --- Opaque stubs for compound types not defined elsewhere --- */
struct ah_ce_ctx { uint8_t _opaque[184]; };
struct lmac_chan_candidate { uint8_t _opaque[24]; };
struct pv0_cfend_frame { uint8_t _opaque[16]; };
struct pv0_pspoll_frame { uint8_t _opaque[16]; };

typedef struct lmac_ctx {
    lmac_ops_t *ops;  /* 0x0, 4B */
    struct ah_ce_ctx              ce_ctx;  /* 0x4, 184B */
    uint32_t sta0_added_or_assoc_flag;  /* 0xbc, 4B */
    struct lmac_chan_candidate    chan_list[16];  /* 0xc0, 384B */
    struct rx_vendor_bss_cache_entry rx_vendor_bss_cache[16];  /* 0x240, 192B */
    uint8_t  obss_threshold;  /* 0x300, 1B */
    uint8_t  obss_edca_select_flag;  /* 0x301, 1B */
    uint8_t  mac_addr[6];  /* 0x302, 6B */
    uint8_t  bss_bw;  /* 0x308, 1B */
    uint8_t  pri_channel;  /* 0x309, 1B */
    uint8_t _rsv_30a[2];  /* 0x30a, 2B */
    uint8_t  chan_busy_threshold_0;  /* 0x30c, 1B */
    uint8_t  chan_busy_threshold_1;  /* 0x30d, 1B */
    uint8_t  chan_busy_threshold_2;  /* 0x30e, 1B */
    uint8_t  chan_busy_threshold_3;  /* 0x30f, 1B */
    uint8_t  link_mode_flags;  /* 0x310, 1B */
    uint8_t  mcs_encoding_format;  /* 0x311, 1B */
    uint8_t  tx_cnt_max_0;  /* 0x312, 1B */
    uint8_t  tx_cnt_max_1;  /* 0x313, 1B */
    uint8_t  mcast_dup_filter_cfg;  /* 0x314, 1B */
    uint8_t  aggcnt;  /* 0x315, 1B */
    uint8_t  hw_init_param;  /* 0x316, 1B */
    uint8_t  sta_priv_alloc_size;  /* 0x317, 1B */
    uint8_t  ps_timeout_retry_count;  /* 0x318, 1B */
    uint8_t  sleep_ctrl_flags;  /* 0x319, 1B */
    uint8_t  uplink_ctrl_flags0;  /* 0x31a, 1B */
    uint8_t  uplink_ctrl_flags1;  /* 0x31b, 1B */
    int8_t   tx_power_high_threshold;  /* 0x31c, 1B */
    int8_t   tx_power_low_threshold;  /* 0x31d, 1B */
    int8_t   cca_threshold_base;  /* 0x31e, 1B */
    int8_t   agc_threshold_high;  /* 0x31f, 1B */
    int8_t   agc_threshold_low;  /* 0x320, 1B */
    int8_t   bknoise_gain_ref[6];  /* 0x321, 6B */
    int8_t   bknoise_base_offset;  /* 0x327, 1B */
    int8_t   cca_threshold_offset;  /* 0x328, 1B */
    int8_t   cca_threshold_max;  /* 0x329, 1B */
    int8_t   s1g_short_beacon_optional_ie_flag;  /* 0x32a, 1B */
    uint8_t _rsv_32b[1];  /* 0x32b, 1B */
    int16_t  bgrssi_spur_threshold;  /* 0x32c, 2B */
    uint16_t rts_threshold;  /* 0x32e, 2B */
    uint16_t ps_heartbeat_period;  /* 0x330, 2B */
    uint8_t  adc_dump_id;  /* 0x332, 1B */
    uint8_t  tdma_rx_buff_flags;  /* 0x333, 1B */
    uint16_t tx_bw_len_threshold;  /* 0x334, 2B */
    uint16_t sta_partial_aid_bits;  /* 0x336, 2B */
    uint32_t lo_freq_or_channel_bits;  /* 0x338, 4B */
    uint8_t  lo_table_index;  /* 0x33c, 1B */
    uint8_t  lo_active_freq_b0;  /* 0x33d, 1B */
    uint16_t lo_active_freq_b1b2;  /* 0x33e, 2B */
    uint8_t  lo_active_index;  /* 0x340, 1B */
    uint8_t _rsv_341[3];  /* 0x341, 3B */
    uint32_t s1g_optional_ie_time_value;  /* 0x344, 4B */
    uint8_t  s1g_optional_ie_param;  /* 0x348, 1B */
    uint8_t _rsv_349[1];  /* 0x349, 1B */
    uint8_t  beacon_s1g_format_flags;  /* 0x34a, 1B */
    uint8_t _rsv_34b[1];  /* 0x34b, 1B */
    uint32_t beacon_init_zero_a;  /* 0x34c, 4B */
    uint32_t beacon_init_zero_b;  /* 0x350, 4B */
    uint8_t _rsv_354[8];  /* 0x354, 8B */
    uint32_t acs_sample_count;  /* 0x35c, 4B */
    uint8_t  cca_ctrl_low_byte;  /* 0x360, 1B */
    uint8_t  cca_agc_ctrl_flags;  /* 0x361, 1B */
    uint16_t rx_gain_cfg_bits;  /* 0x362, 2B */
    uint8_t  pcf_period;  /* 0x364, 1B */
    uint8_t  pcf_percent;  /* 0x365, 1B */
    uint8_t _rsv_366[2];  /* 0x366, 2B */
    uint32_t rx_iface_queue_head;  /* 0x368, 4B */
    uint16_t rx_iface_queue_tail;  /* 0x36c, 2B */
    uint8_t  tx_rate_ctrl_flags;  /* 0x36e, 1B */
    uint8_t _rsv_36f[1];  /* 0x36f, 1B */
    uint32_t tx_rx_ratio_statics;  /* 0x370, 4B */
    uint32_t tx_freq_or_init_param;  /* 0x374, 4B */
    uint8_t  chan_list_count;  /* 0x378, 1B */
    uint8_t  bgrssi_chan_index;  /* 0x379, 1B */
    uint16_t bgrssi_scan_param;  /* 0x37a, 2B */
    uint16_t auto_chan_switch_flags;  /* 0x37c, 2B */
    uint16_t obss_cca_param_bits;  /* 0x37e, 2B */
    uint8_t  txvec_phy_opt;  /* 0x380, 1B */
    uint8_t _rsv_381[3];  /* 0x381, 3B */
    uint32_t pv0_ctrl_duration;  /* 0x384, 4B */
    uint32_t phy_watchdog_period;  /* 0x388, 4B */
    uint32_t event6_period;  /* 0x38c, 4B */
    uint32_t mode_event_period;  /* 0x390, 4B */
    uint32_t tick_unit;  /* 0x394, 4B */
    uint32_t event3_7_period;  /* 0x398, 4B */
    uint32_t obss_scan_period;  /* 0x39c, 4B */
    uint32_t obss_ap_period;  /* 0x3a0, 4B */
    uint32_t hw_scan_interval_us;  /* 0x3a4, 4B */
    uint32_t hw_scan_param_3a8;  /* 0x3a8, 4B */
    uint32_t periodic_event13_period;  /* 0x3ac, 4B */
    uint32_t reset_countdown_period;  /* 0x3b0, 4B */
    uint32_t ant_auto_period;  /* 0x3b4, 4B */
    uint32_t debug_flags;  /* 0x3b8, 4B */
    uint16_t bw_restore_count_threshold;  /* 0x3bc, 2B */
    uint16_t bgr_sample_threshold;  /* 0x3be, 2B */
    uint32_t ap_sleep_timer_base;  /* 0x3c0, 4B */
    uint32_t ap_sleep_timer_hi_or_mark;  /* 0x3c4, 4B */
    uint16_t ap_sleep_timeout_active;  /* 0x3c8, 2B */
    uint16_t ap_sleep_timeout_reload;  /* 0x3ca, 2B */
    uint32_t bss_rx_activity_jiffies;  /* 0x3cc, 4B */
    uint32_t bss_rx_activity_ref;  /* 0x3d0, 4B */
    uint32_t beacon_timeout_low;  /* 0x3d4, 4B */
    uint32_t beacon_timeout_high;  /* 0x3d8, 4B */
    uint16_t ack_timeout_extra;  /* 0x3dc, 2B */
    uint8_t  psconnect_period;  /* 0x3de, 1B */
    uint8_t  pwr_cca_flags;  /* 0x3df, 1B */
    uint8_t  rxg_offset;  /* 0x3e0, 1B */
    uint8_t  obss_per;  /* 0x3e1, 1B */
    uint8_t _rsv_3e2[1];  /* 0x3e2, 1B */
    uint8_t _rsv_3e3[1];  /* 0x3e3, 1B */
    uint8_t  allways;  /* 0x3e4, 1B */
    uint8_t _rsv_3e5[3];  /* 0x3e5, 3B */
    uint8_t _rsv_3e8[4];  /* 0x3e8, 4B */
    uint8_t _rsv_3ec[4];  /* 0x3ec, 4B */
    struct lmac_ctx_extra_ies     extra_ies;  /* 0x3f0, 259B */
    struct lmac_ctx_s1g_capabilities payload;  /* 0x4f3, 15B */
    struct lmac_ctx_edca_params   edca_params;  /* 0x502, 18B */
    struct lmac_ctx_edca_params   obss_edca_params;  /* 0x514, 18B */
    uint8_t  bssid_or_peer_mac[6];  /* 0x526, 6B */
    struct lmac_ctx_ssid          _lmac_ctx_ssid_52c;  /* 0x52c, 34B */
    uint8_t _rsv_54e[2];  /* 0x54e, 2B */
    uint8_t _rsv_550[4];  /* 0x550, 4B */
    uint8_t  tim;  /* 0x554, 1B */
    uint8_t  DTIM;  /* 0x555, 1B */
    uint8_t  dtim_period;  /* 0x556, 1B */
    uint8_t  bitmap_control_bit0;  /* 0x557, 1B */
    uint8_t  bitmap_control;  /* 0x558, 1B */
    uint8_t _rsv_559[251];  /* 0x559, 251B */
    uint16_t s1g_compat_info;  /* 0x654, 2B */
    uint16_t beacon_interval;  /* 0x656, 2B */
    uint32_t TSF;  /* 0x658, 4B */
    uint32_t beacon;  /* 0x65c, 4B */
    uint32_t last_beacon_tsf_low;  /* 0x660, 4B */
    uint32_t last_beacon_tsf_high;  /* 0x664, 4B */
    uint16_t s1g_operation_bits;  /* 0x668, 2B */
    uint8_t _rsv_66a[2];  /* 0x66a, 2B */
    uint16_t tx_time_part0;  /* 0x66c, 2B */
    uint16_t tx_symbol_duration;  /* 0x66e, 2B */
    uint16_t tx_time_part2;  /* 0x670, 2B */
    uint8_t _rsv_672[2];  /* 0x672, 2B */
    uint16_t beacon_airtime;  /* 0x674, 2B */
    uint16_t bss_max_idle;  /* 0x676, 2B */
    int32_t  chip_temp_adj;  /* 0x678, 4B */
    uint32_t vcc_meas_value;  /* 0x67c, 4B */
    uint8_t  thermal_pmu_flags;  /* 0x680, 1B */
    uint8_t _rsv_681[1];  /* 0x681, 1B */
    uint16_t tx_digi_gain[6];  /* 0x682, 12B */
    uint8_t  tx_power;  /* 0x68e, 1B */
    uint8_t  xo_cs_trim_offset;  /* 0x68f, 1B */
    uint8_t  chan_score_weight_a;  /* 0x690, 1B */
    uint8_t  chan_score_weight_b;  /* 0x691, 1B */
    struct lmac_ctx_key           key0;  /* 0x692, 34B */
    struct lmac_ctx_key           key1;  /* 0x6b4, 34B */
    uint8_t _rsv_6d6[2];  /* 0x6d6, 2B */
    uint32_t vdd13b_meas_value;  /* 0x6d8, 4B */
    uint32_t vdd13c_meas_value;  /* 0x6dc, 4B */
    uint32_t tx_success_pkt_count;  /* 0x6e0, 4B */
    uint32_t tx_fail_err_count;  /* 0x6e4, 4B */
    uint32_t last_tx_mcs;  /* 0x6e8, 4B */
    uint32_t last_tx_bw_sig;  /* 0x6ec, 4B */
    uint32_t tx_some_counter_6f0;  /* 0x6f0, 4B */
    uint32_t tx_some_counter_6f4;  /* 0x6f4, 4B */
    uint32_t padding_6f8_6fb[2];  /* 0x6f8, 8B */
    uint32_t tx_state_700;  /* 0x700, 4B */
    uint32_t tx_state_704;  /* 0x704, 4B */
    uint8_t  tx_flags_708;  /* 0x708, 1B */
    uint8_t _rsv_709[3];  /* 0x709, 3B */
    uint8_t  tx_write_flags_70c;  /* 0x70c, 1B */
    uint8_t  tx_write_flags_70d;  /* 0x70d, 1B */
    uint8_t  tx_write_flags_70e;  /* 0x70e, 1B */
    uint8_t  tx_flags_70f;  /* 0x70f, 1B */
    uint8_t  tx_write_only_710;  /* 0x710, 1B */
    uint8_t _rsv_711[1];  /* 0x711, 1B */
    int16_t  rx_dcoc_i_offset;  /* 0x712, 2B */
    int16_t  rx_dcoc_q_offset;  /* 0x714, 2B */
    uint8_t _rsv_716[2];  /* 0x716, 2B */
    uint32_t ac_pd_irq_tx_attempt_count;  /* 0x718, 4B */
    uint32_t ac_pd_read_only_71c;  /* 0x71c, 4B */
    uint32_t ac_pd_read_only_720;  /* 0x720, 4B */
    uint32_t ac_pd_read_only_724;  /* 0x724, 4B */
    uint32_t ac_pd_read_only_728;  /* 0x728, 4B */
    uint32_t tx_queue_state_72c;  /* 0x72c, 4B */
    uint32_t tx_queue_state_730;  /* 0x730, 4B */
    uint32_t tx_queue_state_734;  /* 0x734, 4B */
    uint32_t tx_queue_state_738;  /* 0x738, 4B */
    uint32_t tx_queue_state_73c;  /* 0x73c, 4B */
    uint32_t tx_duration_low;  /* 0x740, 4B */
    uint32_t tx_duration_high;  /* 0x744, 4B */
    uint32_t tx_state_748;  /* 0x748, 4B */
    uint32_t tx_queue_state_74c;  /* 0x74c, 4B */
    uint32_t rx_duration_low;  /* 0x750, 4B */
    uint32_t rx_queue_state_754;  /* 0x754, 4B */
    uint32_t rx_duration_high;  /* 0x758, 4B */
    uint32_t tx_state_75c;  /* 0x75c, 4B */
    uint32_t tx_state_760;  /* 0x760, 4B */
    uint32_t tx_state_764;  /* 0x764, 4B */
    uint32_t tx_queue_entry_768;  /* 0x768, 4B */
    uint32_t tx_queue_state_76c;  /* 0x76c, 4B */
    uint32_t tx_queue_state_770;  /* 0x770, 4B */
    uint32_t tx_queue_state_774;  /* 0x774, 4B */
    uint32_t tx_queue_state_778;  /* 0x778, 4B */
    uint32_t tx_write_only_77c;  /* 0x77c, 4B */
    uint32_t tx_write_only_780;  /* 0x780, 4B */
    uint32_t tx_state_784;  /* 0x784, 4B */
    uint32_t tx_state_788;  /* 0x788, 4B */
    uint32_t tx_state_78c;  /* 0x78c, 4B */
    uint32_t tx_state_790;  /* 0x790, 4B */
    uint32_t tx_state_794;  /* 0x794, 4B */
    uint32_t tx_state_798;  /* 0x798, 4B */
    uint32_t tx_state_79c;  /* 0x79c, 4B */
    uint32_t tx_state_7a0;  /* 0x7a0, 4B */
    uint32_t tx_state_7a4;  /* 0x7a4, 4B */
    uint32_t tx_state_7a8;  /* 0x7a8, 4B */
    uint32_t tx_state_7ac;  /* 0x7ac, 4B */
    uint32_t tx_retry_count_7b0;  /* 0x7b0, 4B */
    uint32_t tx_retry_limit_7b4;  /* 0x7b4, 4B */
    uint32_t tx_state_7b8;  /* 0x7b8, 4B */
    uint32_t tx_state_7bc;  /* 0x7bc, 4B */
    uint32_t tx_state_7c0;  /* 0x7c0, 4B */
    uint32_t tx_state_7c4;  /* 0x7c4, 4B */
    uint32_t tx_state_7c8;  /* 0x7c8, 4B */
    uint32_t tx_state_7cc;  /* 0x7cc, 4B */
    uint32_t tx_state_7d0;  /* 0x7d0, 4B */
    uint32_t tx_state_7d4;  /* 0x7d4, 4B */
    uint32_t tx_state_7d8;  /* 0x7d8, 4B */
    uint32_t tx_state_7dc;  /* 0x7dc, 4B */
    uint32_t tx_state_7e0;  /* 0x7e0, 4B */
    uint16_t tx_state_7e4;  /* 0x7e4, 2B */
    uint16_t tx_state_7e6;  /* 0x7e6, 2B */
    uint16_t tx_state_7e8;  /* 0x7e8, 2B */
    uint8_t _rsv_7ea[2];  /* 0x7ea, 2B */
    uint32_t tx_state_7ec;  /* 0x7ec, 4B */
    uint32_t tx_state_7f0;  /* 0x7f0, 4B */
    uint32_t tx_state_7f4;  /* 0x7f4, 4B */
    uint32_t tx_state_7f8;  /* 0x7f8, 4B */
    uint8_t _rsv_7fc[4];  /* 0x7fc, 4B */
    uint32_t tx_channel_state_800;  /* 0x800, 4B */
    uint16_t tx_state_804;  /* 0x804, 2B */
    uint16_t tx_state_806;  /* 0x806, 2B */
    uint32_t tx_state_808;  /* 0x808, 4B */
    uint32_t tx_state_80c;  /* 0x80c, 4B */
    uint32_t tx_state_810;  /* 0x810, 4B */
    uint32_t tx_state_814;  /* 0x814, 4B */
    uint8_t _rsv_818[4];  /* 0x818, 4B */
    uint32_t tx_state_81c;  /* 0x81c, 4B */
    uint32_t tx_write_only_820;  /* 0x820, 4B */
    uint32_t tx_channel_set_824;  /* 0x824, 4B */
    uint32_t tx_channel_state_828;  /* 0x828, 4B */
    uint32_t tx_result_82c;  /* 0x82c, 4B */
    uint32_t tx_result_830;  /* 0x830, 4B */
    uint32_t tx_result_834;  /* 0x834, 4B */
    uint16_t rx_dcoc_i_last;  /* 0x838, 2B */
    int16_t  rx_dcoc_q_last;  /* 0x83a, 2B */
    uint8_t _rsv_83c[1];  /* 0x83c, 1B */
    uint8_t  tx_byte_83d;  /* 0x83d, 1B */
    uint8_t  tx_write_byte_83e;  /* 0x83e, 1B */
    uint8_t _rsv_83f[1];  /* 0x83f, 1B */
    uint8_t  tx_byte_840;  /* 0x840, 1B */
    uint8_t  tx_write_byte_841;  /* 0x841, 1B */
    uint8_t _rsv_842[2];  /* 0x842, 2B */
    uint32_t tx_state_844;  /* 0x844, 4B */
    uint32_t tx_write_word_848;  /* 0x848, 4B */
    int16_t  chan_scan_rssi_0;  /* 0x84c, 2B */
    int16_t  chan_scan_rssi[1];  /* 0x84e, 2B */
    int16_t  chan_scan_rssi_2;  /* 0x850, 2B */
    int16_t  chan_scan_rssi_3;  /* 0x852, 2B */
    int16_t  chan_scan_rssi_4;  /* 0x854, 2B */
    int16_t  chan_scan_rssi_5;  /* 0x856, 2B */
    int16_t  chan_scan_rssi_6;  /* 0x858, 2B */
    int16_t  chan_scan_rssi_7;  /* 0x85a, 2B */
    int16_t  chan_scan_rssi_8;  /* 0x85c, 2B */
    int16_t  chan_scan_rssi_9;  /* 0x85e, 2B */
    uint8_t  tx_byte_860;  /* 0x860, 1B */
    uint8_t _rsv_861[3];  /* 0x861, 3B */
    uint8_t  tx_mcs_max_limit;  /* 0x864, 1B */
    uint8_t  tx_mcs_min_limit;  /* 0x865, 1B */
    uint8_t  tx_mcs;  /* 0x866, 1B */
    uint8_t  tx_bw_sig;  /* 0x867, 1B */
    uint8_t  mcast_tx_rate;  /* 0x868, 1B */
    uint8_t  mcast_txbw;  /* 0x869, 1B */
    uint8_t _rsv_86a[11];  /* 0x86a, 11B */
    uint8_t  tx_bw_ctrl_flags;  /* 0x875, 1B */
    uint8_t  gpio0_pin_flags;  /* 0x876, 1B */
    uint8_t  gpio1_pin_flags;  /* 0x877, 1B */
    uint8_t  cfend_or_cfp_active_flags;  /* 0x878, 1B */
    uint8_t _rsv_879[3];  /* 0x879, 3B */
    uint16_t cfpoll_duration_calc;  /* 0x87c, 2B */
    uint16_t tx_timestamp_disable_or_reset_flag;  /* 0x87e, 2B */
    uint8_t _rsv_880[16];  /* 0x880, 16B */
    uint8_t  qa_tx_thresholds_0;  /* 0x890, 1B */
    uint8_t  qa_tx_thresholds[1];  /* 0x891, 1B */
    uint8_t  qa_freq_hop_flags;  /* 0x892, 1B */
    uint8_t _rsv_893[1];  /* 0x893, 1B */
    uint32_t qa_tx_params_word0;  /* 0x894, 4B */
    uint8_t  qa_tx_thresholds_6;  /* 0x898, 1B */
    uint8_t  qa_tx_thresholds_7;  /* 0x899, 1B */
    int8_t   qa_rx_metric_2;  /* 0x89a, 1B */
    int8_t   qa_rx_metric_3;  /* 0x89b, 1B */
    int8_t   qa_rx_metric_4;  /* 0x89c, 1B */
    uint8_t  qa_rx_metric_reserved;  /* 0x89d, 1B */
    int16_t  qa_rx_metric_5;  /* 0x89e, 2B */
    uint8_t _rsv_8a0[2];  /* 0x8a0, 2B */
    int8_t   qa_rx_avg_power;  /* 0x8a2, 1B */
    int8_t   qa_rx_avg_evm;  /* 0x8a3, 1B */
    int8_t   qa_rx_freq_offset;  /* 0x8a4, 1B */
    uint8_t  qa_rx_agc_index;  /* 0x8a5, 1B */
    uint8_t _rsv_8a6[2];  /* 0x8a6, 2B */
    int8_t   qa_rx_metric_6;  /* 0x8a8, 1B */
    int8_t   qa_rx_metric_7;  /* 0x8a9, 1B */
    int8_t   qa_rx_metric_8;  /* 0x8aa, 1B */
    int8_t   qa_rx_metric_9;  /* 0x8ab, 1B */
    uint8_t  qa_rx_threshold_flags;  /* 0x8ac, 1B */
    uint8_t  qa_tx_threshold_flags;  /* 0x8ad, 1B */
    uint8_t  rf_temp_calib_0;  /* 0x8ae, 1B */
    uint8_t  rf_temp_calib[1];  /* 0x8af, 1B */
    uint8_t  rf_temp_calib_2;  /* 0x8b0, 1B */
    uint8_t  rf_temp_calib_3;  /* 0x8b1, 1B */
    uint16_t rf_temp_calib_4;  /* 0x8b2, 2B */
    uint16_t init_param_rxbuf_size;  /* 0x8b4, 2B */
    void *init_param_rxbuf;  /* 0x8b6, 4B */
    void *init_param_tdma_buff;  /* 0x8ba, 4B */
    uint32_t init_param_rxbuf_size2;  /* 0x8be, 4B */
    uint8_t  init_param_uart_tx_io;  /* 0x8c2, 1B */
    uint8_t  init_param_dual_ant;  /* 0x8c3, 1B */
    uint8_t  init_param_field_8c4;  /* 0x8c4, 1B */
    uint8_t  init_param_field_8c5;  /* 0x8c5, 1B */
    uint8_t  init_param_field_8c6;  /* 0x8c6, 1B */
    uint8_t  init_param_field_8c7;  /* 0x8c7, 1B */
    uint8_t  tdma_aux_timing_b0;  /* 0x8c8, 1B */
    uint8_t  tdma_aux_timing_b1;  /* 0x8c9, 1B */
    uint8_t _rsv_8ca[2];  /* 0x8ca, 2B */
    uint32_t qa_rx_channel_map;  /* 0x8cc, 4B */
    uint8_t _rsv_8d0[8];  /* 0x8d0, 8B */
    uint32_t ba_resp_timeout_or_tdma;  /* 0x8d8, 4B */
    uint8_t _rsv_8dc[80];  /* 0x8dc, 80B */
    uint32_t tx_vec_hdr_config;  /* 0x92c, 4B */
    uint8_t _rsv_930[40];  /* 0x930, 40B */
    struct pv0_cfend_frame        pv0_cfend;  /* 0x958, 16B */
    struct pv0_pspoll_frame       pv0_pspoll;  /* 0x968, 16B */
    uint8_t  mac_state_978;  /* 0x978, 1B */
    uint8_t _rsv_979[3];  /* 0x979, 3B */
    uint8_t _rsv_97c[20];  /* 0x97c, 20B */
    uint32_t frame_rx_state;  /* 0x990, 4B */
    uint32_t rx_frame_counter;  /* 0x994, 4B */
    uint32_t rx_frame_byte_count;  /* 0x998, 4B */
    uint32_t rx_frame_info;  /* 0x99c, 4B */
    uint8_t _rsv_9a0[20];  /* 0x9a0, 20B */
    uint32_t tx_active_flags;  /* 0x9b4, 4B */
    uint8_t _rsv_9b8[12];  /* 0x9b8, 12B */
    uint8_t  tx_write_only_9c4;  /* 0x9c4, 1B */
    uint8_t _rsv_9c5[3];  /* 0x9c5, 3B */
    uint16_t tx_state_9c8;  /* 0x9c8, 2B */
    uint8_t _rsv_9ca[2];  /* 0x9ca, 2B */
    uint8_t _rsv_9cc[4];  /* 0x9cc, 4B */
    struct os_task                main_task;  /* 0x9d0, 20B */
    uint8_t _rsv_9e4[4];  /* 0x9e4, 4B */
    uint8_t _rsv_9e8[4];  /* 0x9e8, 4B */
    struct os_semaphore           _os_semaphore_9ec;  /* 0x9ec, 8B */
    struct os_task                print_task;  /* 0x9f4, 20B */
    uint8_t  tx_ac_state_flags;  /* 0xa08, 1B */
    uint8_t  beacon_pending_state_flags;  /* 0xa09, 1B */
    uint8_t _rsv_a0a[1];  /* 0xa0a, 1B */
    uint8_t  beacon_obss_slot_flags;  /* 0xa0b, 1B */
    uint8_t  irq_ac_control_flags;  /* 0xa0c, 1B */
    uint8_t _rsv_a0d[1];  /* 0xa0d, 1B */
    uint8_t  tx_global_flags;  /* 0xa0e, 1B */
    uint8_t _rsv_a0f[1];  /* 0xa0f, 1B */
    void *tdma_buff;  /* 0xa10, 4B */
    uint32_t tdma_buff_size;  /* 0xa14, 4B */
    uint8_t _rsv_a18[8];  /* 0xa18, 8B */
    struct os_mutex               sta_list_mutex;  /* 0xa20, 8B */
    struct os_timer               tick_timer;  /* 0xa28, 28B */
    struct os_timer               scan_timer;  /* 0xa44, 28B */
    uint32_t last_rx_pv0_ctrl_info;  /* 0xa60, 4B */
    uint8_t _rsv_a64[28];  /* 0xa64, 28B */
    uint32_t evt_queue_head;  /* 0xa80, 4B */
    uint32_t evt_queue_tail;  /* 0xa84, 4B */
    uint32_t evt_queue_capacity;  /* 0xa88, 4B */
    uint32_t evt_write_index;  /* 0xa8c, 4B */
    uint32_t evt_slot_count;  /* 0xa90, 4B */
    uint32_t evt_ring[29];  /* 0xa94, 116B */
    uint8_t _rsv_b08[28];  /* 0xb08, 28B */
    struct os_semaphore           main_sem;  /* 0xb24, 8B */
    uint8_t  main_runtime_info[24];  /* 0xb2c, 24B */
    uint8_t _rsv_b44[16];  /* 0xb44, 16B */
    uint32_t free_kb;  /* 0xb54, 4B */
    uint8_t _rsv_b58[68];  /* 0xb58, 68B */
    uint32_t tsf_low_at_sleep;  /* 0xb9c, 4B */
    uint32_t tsf_high_at_sleep;  /* 0xba0, 4B */
    uint32_t tsf_last_beacon_low;  /* 0xba4, 4B */
    uint32_t tsf_last_beacon_high;  /* 0xba8, 4B */
    uint32_t tsf_target_low;  /* 0xbac, 4B */
    uint32_t skbpool_free_units;  /* 0xbb0, 4B */
    uint8_t  rx_frame_flag;  /* 0xbb4, 1B */
    uint8_t _rsv_bb5[11];  /* 0xbb5, 11B */
    uint8_t _rsv_bc0[4];  /* 0xbc0, 4B */
} lmac_ctx_t;

_Static_assert(sizeof(lmac_ctx_t) == 0xBC4U, "lmac_ctx_t total size");

/* OSAL type size anchors */
_Static_assert(sizeof(struct os_task) == 20U, "os_task size");
_Static_assert(sizeof(struct os_semaphore) == 8U, "os_semaphore size");
_Static_assert(sizeof(struct os_mutex) == 8U, "os_mutex size");
_Static_assert(sizeof(struct os_timer) == 28U, "os_timer size");

/* Field offset anchors -- tasks and semaphores */
_Static_assert(offsetof(lmac_ctx_t, main_task) == 0x9D0U, "lmac_ctx_t::main_task offset");
_Static_assert(sizeof(((lmac_ctx_t *)0)->main_task) == 20U, "lmac_ctx_t::main_task size");
_Static_assert(offsetof(lmac_ctx_t, _os_semaphore_9ec) == 0x9ECU, "lmac_ctx_t::_os_semaphore_9ec offset");
_Static_assert(sizeof(((lmac_ctx_t *)0)->_os_semaphore_9ec) == 8U, "lmac_ctx_t::_os_semaphore_9ec size");
_Static_assert(offsetof(lmac_ctx_t, print_task) == 0x9F4U, "lmac_ctx_t::print_task offset");
_Static_assert(sizeof(((lmac_ctx_t *)0)->print_task) == 20U, "lmac_ctx_t::print_task size");
_Static_assert(offsetof(lmac_ctx_t, sta_list_mutex) == 0xA20U, "lmac_ctx_t::sta_list_mutex offset");
_Static_assert(sizeof(((lmac_ctx_t *)0)->sta_list_mutex) == 8U, "lmac_ctx_t::sta_list_mutex size");
_Static_assert(offsetof(lmac_ctx_t, tick_timer) == 0xA28U, "lmac_ctx_t::tick_timer offset");
_Static_assert(sizeof(((lmac_ctx_t *)0)->tick_timer) == 28U, "lmac_ctx_t::tick_timer size");
_Static_assert(offsetof(lmac_ctx_t, scan_timer) == 0xA44U, "lmac_ctx_t::scan_timer offset");
_Static_assert(sizeof(((lmac_ctx_t *)0)->scan_timer) == 28U, "lmac_ctx_t::scan_timer size");
_Static_assert(offsetof(lmac_ctx_t, main_sem) == 0xB24U, "lmac_ctx_t::main_sem offset");
_Static_assert(sizeof(((lmac_ctx_t *)0)->main_sem) == 8U, "lmac_ctx_t::main_sem size");
/* LMAC_CTX_GENERATED_END */

/* ============================================================================
   TX Subsystem Context
   ========================================================================== */

typedef struct lmac_ah_tx_ctx {
    uint8_t             rsv_000[0x02C];
    struct os_task      tx_task;            // [0x02C] TX task (20 bytes)
    struct os_task      tx_status_task;     // [0x040] TX status task (20 bytes)
    struct os_semaphore tx_sem;             // [0x054] TX semaphore (8 bytes)
    struct os_semaphore tx_status_sem;      // [0x05C] TX status semaphore (8 bytes)
    struct skb_list     txq;               // [0x064] TX queue (from AH_TXQ_OFS=0x064)
    struct skb_list     txsq;              // [0x070] TX status queue (from AH_TXSQ_OFS=0x070)
    uint8_t             rsv_07c[0x088 - 0x07C]; // Padding to ACQ offset
    struct skb_list     ac_queue[4];       // [0x088] AC queues (from AH_ACQ_OFS=0x88, stride 0x120)

    /* Per-AC data area (stride 0x120 each, 4 ACs total) */
    uint8_t             ac_data[4][0x120]; // [0x0B8] agg_list + agg_bytes + agg_sym + agg_cnt per AC
    /* Within each AC's 0x120 bytes:
     * - agg_list[64] at offset 0x000 (64 words = 256 bytes = 0x100)
     * - agg_bytes at offset 0x100 (from original: 0x1B8-0x0B8=0x100)
     * - agg_sym at offset 0x104 (from 0x1BC-0x0B8=0x104)
     * - agg_num at offset 0x108 (word)
     * - agg_cnt at offset 0x10D (byte)
     */

    /* After ac_data: 0x0B8 + 4*0x120 = 0x0B8 + 0x480 = 0x538 */
    uint8_t             rsv_538[0x6AC - 0x538]; // Reserved to cipher section

    uint8_t             cipher_rate_ac0;    // [0x6AC] Cipher engine MCS for AC0
    uint8_t             cipher_rate_ac1;    // [0x6AD] Cipher engine MCS for AC1
    uint8_t             cipher_rate_ac2;    // [0x6AE] Cipher engine MCS for AC2
    uint8_t             cipher_rate_ac3;    // [0x6AF] Cipher engine MCS for AC3
    uint32_t            cipher_ptr_frame;   // [0x6B0] CE frame pointer
    uint32_t            cipher_ptr_shadow;  // [0x6B4] CE shadow pointer
    uint8_t             rsv_6b8[4];
    uint8_t             cipher_bw_config;   // [0x6BC] CE bandwidth config
    uint8_t             rsv_6bd;
    uint16_t            cipher_frame_len;   // [0x6BE] CE frame length
    uint8_t             cipher_bw;          // [0x6C8] CE bandwidth (MHz)
    uint8_t             rsv_6c9[3];
    uint32_t            seq_num_space;      // [0x6CC] Sequence number space
    uint8_t             rsv_6d0[4];       // [0x6D0] Padding to 0x6D4
} lmac_ah_tx_ctx_t;

/* ============================================================================
   RX Subsystem Context (Opaque)
   ========================================================================== */

typedef struct {
    uint8_t _opaque[0x588];  // 1416 bytes total
} lmac_ah_rx_ctx_t;

/* ============================================================================
   Cipher Engine Context
   ============================================================================
   Layout confirmed from mars_lmac_cipher.S disassembly:
     ah_ce_init:  mutex at +4, sema at +12, irq_num at +0x14
     ah_ce_start: base_addr at +0, mutex at +4, sema at +12
   ========================================================================== */

typedef struct lmac_ah_cipher_ctx {
    volatile uint32_t   *base_addr;    // [0x00] CE hardware register base
    struct os_mutex      mutex;        // [0x04] access mutex (8 bytes)
    struct os_semaphore  sema;         // [0x0C] completion semaphore (8 bytes)
    uint32_t             irq_num;      // [0x14] interrupt number
} lmac_ah_cipher_ctx_t;

/* Config struct passed to ah_ce_start (layout from assembly offsets) */
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
} ah_ce_cfg_t;

/* ============================================================================
   External Global Variables (from lmac_globals.h)
   ========================================================================== */

extern lmac_ctx_t         ah_lmac;           // @ 0x20063784 (main context)
extern lmac_ah_tx_ctx_t   ah_lmac_tx;        // @ 0x20055710 (TX subsystem)
extern lmac_ah_rx_ctx_t   ah_lmac_rx;        // @ 0x20054f68 (RX subsystem)
extern lmac_dsleep_ctx_t  ah_dsleep;         // @ 0x20005504 (deep-sleep)
extern lmac_ops_t         ah_ops;            // @ 0x20063734 (device vtable)

/* Calibration data */
extern int32_t  tx_dcoc_res;                 // @ 0x20064404
extern int16_t  rx_dcoc_res[48];             // @ 0x20064408
extern int16_t  tx_epa_imb_res_pm;           // @ 0x20064468
extern int16_t  rx_imb_gain_comp[6];         // @ 0x2006446c
extern int16_t  dpd_epa_phase_comp;          // @ 0x2006447c
extern int16_t  dpd_epa_gain_comp;           // @ 0x2006447e

/* RF shadow registers */
extern uint16_t rf_regs[56];                 // @ 0x20064394
extern uint16_t rf_agc_reg_hw_val[144];      // @ 0x20006d20
extern uint32_t dpd_ram[432];                // @ 0x20050e80

/* Rate table and MCS lookup */
extern uint32_t rate_tbl[16];                // @ 0x20050d36
extern uint8_t  max_byte_table[176];         // @ 0x20050d78

/* Hardware base pointer */
extern uint32_t LMAC;                        // @ 0x20006d1c (hardware register base)
