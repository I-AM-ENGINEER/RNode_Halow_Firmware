/* LMAC Context Structure - 2026-04-26 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "list.h"
#include "osal/semaphore.h"
#include "osal/mutex.h"
#include "osal/task.h"
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
    uint8_t     rsv_06a[0xB7 - 0x06A];
    uint8_t     rx_bw_mcs;                 // [0xB7] RX bandwidth & MCS info
    uint8_t     rsv_0b8[0x128 - 0x0B8];
    uint8_t     tx_mcs;                    // [0x128] TX Modulation & Coding Scheme
    uint8_t     rsv_129[0x1C6 - 0x129];
    uint16_t    tx_bytes_window;           // [0x1C6] TX bytes in window
    uint8_t     rsv_1c8[0x1D4 - 0x1C8];
    uint16_t    tx_airtime_us;             // [0x1D4] TX air time (microseconds)
    uint8_t     rsv_1d6[0x1E2 - 0x1D6];
    uint16_t    rx_bytes_window;           // [0x1E2] RX bytes in window
    uint8_t     rsv_1e4[0x1F0 - 0x1E4];
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

/* ============================================================================
   Main LMAC Context - Extended Definition
   ========================================================================== */

typedef struct lmac_ctx {
    lmac_ops_t *ops;                        // [0x000]
    uint8_t  rsv_004[0x2bc - 0x004];
    uint32_t dsleep_wakeup_timer;           // [0x2bc] Deep-sleep wakeup timer
    uint8_t  rsv_2c0[0x302 - 0x2C0];

    uint8_t  self_mac[6];                   // [0x302]
    uint8_t  bss_bw;                        // [0x308]
    uint8_t  pri_chan_cfg;                  // [0x309]
    uint8_t  rsv_30a[2];
    uint8_t  txq_thresh0, txq_thresh1, txq_thresh2, txq_thresh3;  // [0x30C]
    uint8_t  rsv_310;
    uint8_t  rate_mode;                     // [0x311]
    uint8_t  tx_power_levels;               // [0x312]
    uint8_t  rate_fallback_limit;           // [0x313]
    uint8_t  rsv_314;
    uint8_t  max_agg_frames;                // [0x315]
    uint8_t  phy_mode;                      // [0x316]
    uint8_t  sta_priv_len;                  // [0x317]
    uint8_t  psm_state;                     // [0x318]
    uint8_t  sleep_flags;                   // [0x319]
    uint8_t  sleep_gpio_shift;              // [0x31A]
    uint8_t  sleep_gpio_mask;               // [0x31B]
    int8_t   rssi_threshold_low;            // [0x31C]
    int8_t   rssi_threshold_high;           // [0x31D]
    int8_t   cal_temp_offset;               // [0x31E]
    int8_t   cal_voltage_offset;            // [0x31F]
    int8_t   cal_rssi_offset;               // [0x320]
    uint8_t  rsv_321[0x32A - 0x321];
    int8_t   sta_event_state;               // [0x32A]
    uint8_t  rsv_32b;
    uint16_t rssi_lower_threshold;          // [0x32C]
    uint16_t rssi_upper_threshold;          // [0x32E]
    uint16_t aid;                           // [0x330] Association ID
    uint8_t  rsv_332[0x336 - 0x332];        // [0x332-0x335] Reserved (RX buffer state flags)
    uint16_t partial_aid_pack;              // [0x336] Partial AID / AP BSSID Info
    uint8_t  rsv_338[0x33C - 0x338];        // [0x338-0x33B] Reserved
    uint8_t  meas_report_flags;             // [0x33C] Measurement report state/flags
    uint8_t  rsv_33d[0x360 - 0x33D];        // [0x33D-0x35F] Reserved (AP/channel info)
    uint16_t tx_max_syms_config;            // [0x360] TX max symbols config (9-bit field at bits 9:1)
    uint16_t beacon_timestamp_high;         // [0x362] Beacon timestamp MSW
    uint8_t  rsv_364[0x36C - 0x364];        // [0x364-0x36B] Reserved
    uint32_t rf_cfg;                        // [0x36C] RF configuration register
    uint32_t event_payload;                 // [0x370] Event-specific payload
    uint32_t misc_ctrl_word;                // [0x374] Misc control (NAV_DIFF, rate modulation, BA ctrl)
    uint8_t  rsv_378;                       // [0x378] Reserved
    uint8_t  rsv_379;                       // [0x379] Reserved
    uint8_t  flags_37a;                     // [0x37A] State/control flags
    uint8_t  rsv_37b;                       // [0x37B] Reserved
    uint8_t  flags_37c;                     // [0x37C] LO table / Scan state / Dialog token
    uint8_t  flags_37d;                     // [0x37D] LO table / Rate control / ACS state
    uint8_t  flags_37e;                     // [0x37E] Beacon / RX / TX control state
    uint8_t  flags_37f;                     // [0x37F] PHY state / ACS / Status flags
    uint8_t  rsv_380[0x3d4 - 0x380];
    uint32_t hw_tsf_estimate;               // [0x3D4] Hardware TSF estimate / timing reference
    uint8_t  rsv_3d8[0x3DC - 0x3D8];
    uint16_t beacon_offset;                 // [0x3DC] Beacon timing offset
    uint8_t  rx_state_flags;                // [0x3DE] RX state flags
    uint8_t  rx_filter_flags;               // [0x3DF] RX filter flags
    uint8_t  frame_filter_state;            // [0x3E0] Frame filtering state
    uint8_t  ba_win_flags;                  // [0x3E1] Block Ack window flags
    uint8_t  rsv_3e2[6];
    uint32_t rx_active_time_ms;             // [0x388] RX channel active time (milliseconds)
    uint32_t tx_active_time_ms;             // [0x38C] TX channel active time (milliseconds)
    uint32_t beacon_timer_reload;           // [0x390] Beacon timer reload/countdown value
    uint32_t beacon_interval_scaled;        // [0x394] Beacon interval * 1024
    uint32_t beacon_interval_next;          // [0x398] Next beacon interval
    uint32_t rsv_39c;
    uint32_t beacon_interval_current;       // [0x3A0] Current beacon interval (TU)
    uint8_t  rsv_3a4[0x3AC - 0x3A4];
    uint32_t beacon_timer_control;          // [0x3AC] Beacon timer control register
    uint32_t antenna_probe_flag;            // [0x3B0] Rate control / antenna probe flag
    uint32_t dsleep_countdown;              // [0x3B4] Deep-sleep duration countdown
    uint32_t flags_3b8;                     // [0x3B8] Debug/control flags
    uint8_t  rsv_3bc[0x3C0 - 0x3BC];
    uint32_t ap_sleep_state;                // [0x3C0] AP sleep state
    uint8_t  rsv_3c4[0x526 - 0x3C4];
    uint8_t  bssid[6];                      // [0x526] BSSID
    uint8_t  rsv_52c[0x52E - 0x52C];        // [0x52C-0x52D] Reserved (IE element)
    uint16_t ie_length;                     // [0x52E] Information Elements length
    uint8_t  rsv_530[0x55C - 0x530];        // [0x530-0x55B] Reserved (IE data)
    uint16_t s1g_compat_values;             // [0x55C] S1G compatibility field (bits 7-9)
    uint8_t  rsv_55e[0x654 - 0x55E];        // [0x55E-0x653] Reserved
    uint16_t s1g_beacon_elem1;              // [0x654] S1G beacon element 1
    uint16_t s1g_beacon_elem2;              // [0x656] S1G beacon element 2
    uint32_t probe_resp_timestamp;          // [0x658] Probe response timestamp
    uint8_t  rsv_65c[0x660 - 0x65C];        // [0x65C-0x65F] Reserved
    uint32_t beacon_interval;               // [0x660] Beacon interval (TU)
    uint32_t capability_info;               // [0x664] 802.11 capability bits
    uint16_t listen_interval;               // [0x668] STA listen interval
    uint8_t  rsv_66a[0x676 - 0x66A];        // [0x66A-0x675] Reserved
    uint16_t last_assoc_req_seq;            // [0x676] Last association request seq
    uint8_t  rsv_678[0x68E - 0x678];        // [0x678-0x68D] Reserved
    uint8_t  bg_rssi_cfg;                   // [0x68E] Background RSSI config
    uint8_t  bg_rssi_src;                   // [0x68F] Background RSSI source
    uint8_t  rsv_690[0x692 - 0x690];        // [0x690-0x691] Reserved
    uint8_t  sec_key_index;                 // [0x692] Security key index
    uint8_t  sec_key_len;                   // [0x693] Security key length
    uint8_t  sec_key[32];                   // [0x694] Security key material (Group key)
    uint8_t  sec_key_index2;                // [0x6B4] Security key index 2 (Pairwise key)
    uint8_t  sec_key_len2;                  // [0x6B5] Security key length 2
    uint8_t  sec_key2[32];                  // [0x6B6] Security key material 2 (Pairwise key)
    uint8_t  rsv_6d6[0x6F4 - 0x6D6];        // [0x6D6-0x6F3] Reserved
    uint32_t channel_err_count;             // [0x6F4] Channel/decode error counter
    uint8_t  rsv_6f8[0x754 - 0x6F8];        // [0x6F8-0x753] Reserved
    uint32_t failed_frame_count;            // [0x754] TX failed frame counter
    uint32_t error_frame_count;             // [0x758] RX error frame counter
    uint8_t  rsv_75c[0x788 - 0x75C];        // [0x75C-0x787] Reserved (44 bytes)
    uint32_t phy_error_count;               // [0x788] PHY error counter
    uint32_t phy_error_code;                // [0x78C] Last PHY error code
    uint8_t  rsv_790[0x798 - 0x790];        // [0x790-0x797] Reserved (8 bytes)
    uint32_t rx_error_counter;              // [0x798] RX error/event counter (incremented on frame error)
    uint8_t  rsv_79c[0x7A0 - 0x79C];        // [0x79C-0x79F] Reserved (4 bytes)
    uint32_t rssi_peak_calib;               // [0x7A0] RSSI peak value for calibration
    uint8_t  rsv_7a4[0x7E0 - 0x7A4];        // [0x7A4-0x7DF] Reserved (60 bytes)
    uint32_t rssi_sum;                      // [0x7E0] RSSI accumulator
    uint16_t rssi_peak;                     // [0x7E4] Peak RSSI
    uint16_t rssi_sample_count;             // [0x7E6] RSSI sample count
    uint16_t rssi_avg_count;                // [0x7E8] RSSI average count
    uint8_t  rsv_7ea[0x804 - 0x7EA];        // [0x7EA-0x803] Reserved (26 bytes)
    uint16_t avg_power_zero_count;          // [0x804] Avg power = 0 counter
    uint16_t avg_power_neg128_count;        // [0x806] Avg power = -128 counter
    uint8_t  rsv_808[0x840 - 0x808];
    uint32_t phy_reset_metric_storage;      // [0x840] PHY reset metric storage
    uint8_t  phy_reset_metric;              // [0x841] PHY reset metric / PCF period (CS_NUM)
    uint8_t  rsv_842[3];
    uint32_t hw_tx_power;                   // [0x844] Hardware TX power setting
    uint32_t rsv_848;
    uint32_t tx_status_counter;             // [0x84C] TX completion counter
    uint8_t  rsv_850[0x875 - 0x850];
    uint8_t  rf_control_flags;              // [0x875] RF control flags
    uint8_t  sleep_gpio_state;              // [0x876] Sleep GPIO pin state
    uint8_t  rf_reset_flags;                // [0x877] RF reset flags
    uint8_t  rf_powerdown_flags;            // [0x878] RF power-down flags
    uint8_t  rsv_879[0x892 - 0x879];
    uint8_t  reset_delay_counter;           // [0x892] Delayed reset counter
    uint8_t  rsv_893[0x898 - 0x893];        // [0x893-0x897] Reserved
    int8_t   rssi_measurement_offset;       // [0x898] RSSI measurement calibration
    int8_t   rxcal_rssi_offset;             // [0x899] RX calibration RSSI offset
    uint8_t  rsv_89a[0x89E - 0x89A];        // [0x89A-0x89D] Reserved
    int8_t   rssi_threshold_cal;            // [0x89E] RSSI threshold calibration offset
    uint8_t  rsv_89f[0x8AE - 0x89F];        // [0x89F-0x8AD] Reserved
    int8_t   rf_cal_offset;                 // [0x8AE] RF calibration offset
    uint8_t  rsv_8af[0x8C2 - 0x8AF];        // [0x8AF-0x8C1] Reserved
    uint8_t  rf_temp_calib[6];              // [0x8C2-0x8C7] RF temperature calibration
    uint8_t  rsv_8c8[0x8CC - 0x8C8];        // [0x8C8-0x8CB] Reserved
    void    *dsleep_cfg;                    // [0x8CC]
    uint8_t  rsv_8d0[0x8f6 - 0x8D0];
    uint16_t ba_timeout_counter;            // [0x8F6] BA/ACK timeout counter
    uint8_t  rsv_8f8[0x99C - 0x8F8];
    uint32_t state;                         // [0x99C]
    uint8_t  main_task_obj[0x9B8 - 0x9A0]; // [0x9A0] OS task structure (20B + extra)
    uint32_t print_buf_ptr;                 // [0x9B8] Print task buffer pointer
    struct os_semaphore print_sem;          // [0x9BC] Print task semaphore (8B)
    uint8_t  rsv_9c4[0x9CC - 0x9C4];        // [0x9C4-0x9CB] Reserved (8B)

    /* Deep-sleep timing configuration backup (from 0x388-0x3AB, 36 bytes total) */
    uint32_t rx_active_time_backup;         // [0x9CC] RX active time (from 0x388)
    uint32_t tx_active_time_backup;         // [0x9D0] TX active time (from 0x38C)
    uint32_t beacon_timer_reload_backup;    // [0x9D4] Beacon timer reload (from 0x390)
    uint32_t beacon_interval_scaled_backup; // [0x9D8] Beacon interval * 1024 (from 0x394)
    uint32_t beacon_interval_next_backup;   // [0x9DC] Next beacon interval (from 0x398)
    uint32_t rsv_9e0_backup;                // [0x9E0] Backup of field at 0x39C
    uint32_t beacon_interval_current_backup;// [0x9E4] Current beacon interval (from 0x3A0)
    uint8_t  rsv_9e8_backup[8];             // [0x9E8-0x9EF] Backup of rsv_3a4 (8B)
    /* End of 36-byte timing backup */

    uint8_t  beacon_ctrl_backup[6];         // [0x9F0] Beacon/timer control backup (from 0x3AC, 6B)
    uint8_t  flags_backup[6];               // [0x9F6] Flags backup (from 0x3B8, 6B)
    void    *sta_list_head;                 // [0x9FC] Station list head pointer
    void    *sta_list_tail;                 // [0xA00] Station list tail pointer
    struct os_mutex sta_list_mutex;         // [0xA04] Station list mutex (8B)
    uint16_t sta_total;                     // [0xA0C] Total station count (shifted +4)
    uint16_t sta_psm1, sta_psm2;            // [0xA0E] STA power-save mode counters (shifted +4)
    uint8_t  rsv_a12[0xA14 - 0xA12];        // [0xA12-0xA13] Reserved
    uint8_t  tick_timer[0xA30 - 0xA14];     // [0xA14] Ticker timer object (28B, shifted +4)
    uint8_t  rsv_a30[0xA53 - 0xA30];        // [0xA30-0xA52] Reserved (shifted +4)
    uint8_t  phy_watchdog_flags;            // [0xA53] PHY watchdog state flags (shifted +4)
    uint32_t scan_duration_ms;              // [0xA54] Scan duration or timeout counter (shifted +4)
    uint8_t  rsv_a58[0xA67 - 0xA58];        // [0xA58-0xA66] Reserved (shifted +4)
    uint8_t  scan_channel_index;            // [0xA67] Current scan channel index (shifted +4)
    uint8_t  rsv_a68[0xA6C - 0xA68];        // [0xA68-0xA6B] Reserved (shifted +4)
    uint8_t  scan_ie_buffer[0xA84 - 0xA6C]; // [0xA6C-0xA83] Scan IE buffer (24 bytes, shifted +4)
    uint32_t evt_rd;                        // [0xA84] (shifted +4)
    uint32_t evt_wr;                        // [0xA88] (shifted +4)
    uint32_t evt_cap;                       // [0xA8C] (shifted +4)
    uint32_t evt_ring[64];                  // [0xA90] (shifted +4)
    uint8_t  rsv_b90[0xB94 - 0xB90];        // (shifted +4)
    uint8_t  main_sem[0xBB4 - 0xB94];       // [0xB94] (shifted +4)
    uint32_t free_kb;                       // [0xBB4] (shifted +4)
    uint8_t  rsv_bb8[0xBC4 - 0xBB8];        // Final padding (reduced by 4 bytes to maintain 0xBC4 size)
} lmac_ctx_t;

/* ============================================================================
   TX Subsystem Context
   ========================================================================== */

typedef struct lmac_ah_tx_ctx {
    uint8_t             rsv_000[0x02C];
    struct os_task      tx_task;            // [0x02C] TX task
    struct os_task      tx_status_task;     // [0x040] TX status task
    struct os_semaphore tx_sem;             // [0x054] TX semaphore
    struct os_semaphore tx_status_sem;      // [0x05C] TX status semaphore
    uint8_t             rsv_064[0x0B8 - 0x064];

    struct skb_list     ac_queue[4];        // [0x0B8] Access Category queues [0-3]
    lmac_rc_state_t     ac_rate_ctrl[4];    // Rate control state per AC (0x120 each)

    uint8_t             rsv_538[0x6AC - 0x538];

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
    uint8_t             rsv_6c0[8];
    uint8_t             cipher_bw;          // [0x6C8] CE bandwidth (MHz)
    uint8_t             rsv_6c9[3];
    uint32_t            seq_num_space;      // [0x6CC] Sequence number space
    uint8_t             rsv_6d0[4];
} lmac_ah_tx_ctx_t;

/* ============================================================================
   RX Subsystem Context (Opaque)
   ========================================================================== */

typedef struct {
    uint8_t _opaque[0x588];  // 1416 bytes total
} lmac_ah_rx_ctx_t;

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

/* ============================================================================
   Inline Helpers
   ========================================================================== */

static inline lmac_sta_info_t *lmac_get_sta_head(void) {
    return (lmac_sta_info_t *)ah_lmac.sta_list_head;
}

static inline bool lmac_is_sta_end(lmac_sta_info_t *sta) {
    return (void *)sta == ah_lmac.sta_list_tail;
}

static inline lmac_sta_info_t *lmac_get_next_sta(lmac_sta_info_t *sta) {
    return list_entry(sta->node.next, lmac_sta_info_t, node);
}

/* Rate table lookup macro */
#define LMAC_GET_RATE(mcs) (rate_tbl[(mcs) & 0x07])
