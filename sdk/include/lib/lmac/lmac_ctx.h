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
    lmac_ops_t *ops;                        // [0x000] Ops vtable pointer
    uint32_t config_word;                   // [0x004] Configuration/init value
    uint8_t  rsv_004a[0x018 - 0x004];
    uint32_t init_marker_18;                // [0x018] Init marker/timer value
    uint8_t  rsv_01c[0x040 - 0x01C];
    uint32_t param_40;                      // [0x040] Parameter/state
    uint32_t param_44;                      // [0x044] Parameter/state
    uint32_t dma_init_param1;               // [0x048] DMA initialization parameter
    uint32_t dma_init_param2;               // [0x04C] DMA initialization parameter
    uint8_t  rsv_050[0x084 - 0x050];
    uint8_t  phy_config_084;                // [0x084] PHY configuration
    uint8_t  phy_config_085;                // [0x085] PHY configuration
    uint8_t  phy_config_086;                // [0x086] PHY configuration
    uint8_t  phy_config_087;                // [0x087] PHY configuration
    uint8_t  rsv_088[0x090 - 0x088];
    uint16_t phy_param_90;                  // [0x090] PHY parameter
    uint16_t phy_param_92;                  // [0x092] PHY parameter
    uint16_t phy_param_94;                  // [0x094] PHY parameter
    uint16_t phy_param_96;                  // [0x096] PHY parameter
    uint8_t  rsv_098[0x0A0 - 0x098];
    uint16_t lo_freq_threshold_a0;          // [0x0A0] LO frequency threshold
    uint16_t lo_freq_threshold_a2;          // [0x0A2] LO frequency threshold
    uint16_t lo_freq_threshold_a4;          // [0x0A4] LO frequency threshold
    uint16_t lo_freq_threshold_a6;          // [0x0A6] LO frequency threshold
    uint8_t  rsv_0a8[0x0fc - 0x0A8];
    uint32_t param_fc;                      // [0x0FC] Parameter/state
    uint32_t rx_frame_tsf;                  // [0x100] RX frame timestamp (TSF)
    uint16_t rx_frame_length;               // [0x104] RX frame length
    uint16_t rx_frame_info;                 // [0x106] RX frame info (MCS, rate, bandwidth)
    uint32_t rx_rssi_value;                 // [0x108] RX RSSI value
    uint16_t rx_cfo;                        // [0x10A] RX carrier frequency offset
    uint16_t rx_phase_offset;               // [0x10C] RX phase offset
    uint32_t rx_evm;                        // [0x10E] RX EVM (Error Vector Magnitude)
    uint32_t rx_snr;                        // [0x110] RX SNR value
    uint8_t  rsv_114[0x116 - 0x114];
    uint8_t  rx_status_flags;               // [0x116] RX status flags (bit field)
    uint16_t rx_seq_ctrl;                   // [0x118] RX sequence control from frame
    uint8_t  rsv_11a[0x11c - 0x11A];
    uint32_t rx_cipher_param;               // [0x11C] RX cipher parameters
    uint32_t rx_timestamp_adj;              // [0x120] RX timestamp adjustment/auxiliary
    uint32_t rx_frame_duration;             // [0x124] RX frame duration calculation
    uint32_t rx_subframe_info;              // [0x128] RX subframe/MPDU info
    uint32_t rx_agg_param;                  // [0x12C] RX aggregation parameters
    uint32_t rx_ampdu_len;                  // [0x130] RX A-MPDU length
    uint8_t  rsv_134[0x138 - 0x134];
    uint32_t rx_descriptor;                 // [0x138] RX frame descriptor
    uint16_t rx_descriptor_ext;             // [0x13C] RX descriptor extension
    uint8_t  rsv_13e[0x140 - 0x13E];
    uint32_t rx_buffer_ptr;                 // [0x140] RX buffer/SKB pointer
    uint32_t rx_processing_state;           // [0x144] RX frame processing state
    uint8_t  rsv_148[0x160 - 0x148];
    uint32_t rx_interrupt_status;           // [0x160] RX interrupt/event status
    uint8_t  rsv_164[0x1B8 - 0x164];        // [0x164-0x1B7] Reserved (RX buffer/descriptor area)
    uint32_t rx_frame_vector;               // [0x1B8] RX frame vector / descriptor
    uint8_t  rsv_1bc[0x1C4 - 0x1BC];        // [0x1BC-0x1C3] Reserved (padding)
    uint16_t rx_frame_count;                // [0x1C4] RX frame counter / valid count
    uint16_t rx_max_frame_count;            // [0x1C6] RX max frame count threshold
    uint8_t  rsv_1c8[0x1D0 - 0x1C8];        // [0x1C8-0x1CF] Reserved (padding)
    uint32_t rx_dma_param;                  // [0x1D0] RX DMA parameter / descriptor address
    uint16_t rx_frame_length_threshold;     // [0x1D4] RX frame length threshold
    uint8_t  rsv_1d6[0x1D8 - 0x1D6];        // [0x1D6-0x1D7] Reserved (padding)
    uint32_t rx_buffer_threshold;           // [0x1D8] RX buffer threshold / level
    uint16_t rx_frame_timeout;              // [0x1DC] RX frame timeout value
    uint8_t  rsv_1de[0x1E0 - 0x1DE];        // [0x1DE-0x1DF] Reserved (padding)
    uint16_t rx_good_count;                 // [0x1E0] RX good frame count
    uint16_t rx_bad_count;                  // [0x1E2] RX bad frame count
    uint8_t  rsv_1e4[0x1E8 - 0x1E4];        // [0x1E4-0x1E7] Reserved (padding)
    uint32_t rx_total_frames;               // [0x1E8] RX total frames processed
    uint32_t rx_frame_body;                 // [0x1EC] RX frame body descriptor
    uint32_t phy_tx_vector_h;               // [0x1F0] PHY TX vector header
    uint32_t phy_tx_vector_l;               // [0x1F4] PHY TX vector lower
    uint8_t  rsv_1f8[0x208 - 0x1F8];        // [0x1F8-0x207] Reserved (final padding)
    uint32_t phy_tx_config;                 // [0x208] PHY TX configuration (packed register)
    uint8_t  rsv_20c[0x210 - 0x20C];
    uint32_t phy_rx_config;                 // [0x210] PHY RX configuration (packed register)
    uint8_t  rsv_214[0x224 - 0x214];
    uint32_t phy_control_flags;             // [0x224] PHY control/status flags
    uint8_t  rsv_228[0x2bc - 0x228];
    uint32_t dsleep_wakeup_timer;           // [0x2bc] Deep-sleep wakeup timer
    uint8_t  dsleep_status_byte;            // [0x2c0] Deep-sleep status control
    uint8_t  rsv_2c1[0x2c8 - 0x2C1];        // [0x2C1-0x2C7] Reserved (padding)
    uint32_t dsleep_state_read_0;           // [0x2c8] Deep-sleep state read 0
    uint32_t dsleep_state_read_1;           // [0x2cc] Deep-sleep state read 1
    uint32_t dsleep_state_read_2;           // [0x2d0] Deep-sleep state read 2
    uint32_t dsleep_state_read_3;           // [0x2d4] Deep-sleep state read 3
    uint32_t dsleep_state_write_0;          // [0x2d8] Deep-sleep state write 0
    uint32_t dsleep_state_write_1;          // [0x2dc] Deep-sleep state write 1
    uint32_t dsleep_state_write_2;          // [0x2e0] Deep-sleep state write 2
    uint32_t dsleep_state_write_3;          // [0x2e4] Deep-sleep state write 3 / OBSS field
    uint8_t  obss_scan_count;               // [0x2e5] OBSS scan counter (part of state_write_3)
    uint8_t  rsv_2e6[0x300 - 0x2E6];        // [0x2E6-0x2FF] Reserved (padding)
    int8_t   obss_threshold;                // [0x300] OBSS detection threshold
    uint8_t  obss_state;                    // [0x301] OBSS state / detection result

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
    uint8_t  rx_buff_addr_state;            // [0x332] RX buffer address update state/flag
    uint8_t  rx_buff_addr_ctrl;             // [0x333] RX buffer address control flags (bit field)
    uint16_t rx_buff_info;                  // [0x334] RX buffer info/size
    uint16_t partial_aid_pack;              // [0x336] Partial AID / AP BSSID Info
    uint32_t chan_cfg_param;                // [0x338] Channel configuration parameter (or frequency-related)
    uint8_t  meas_report_flags;             // [0x33C] Measurement report state/flags
    uint8_t  rsv_33d[0x340 - 0x33D];
    uint8_t  lo_cfg_byte_340;               // [0x340] LO configuration byte
    uint8_t  rsv_341[3];
    uint32_t lo_freq_value;                 // [0x344] LO frequency value
    uint8_t  rsv_348;
    uint8_t  lo_freq_flags;                 // [0x349] LO frequency flags/status
    uint16_t lo_freq_table_idx;             // [0x34A] LO frequency table index (with flags in bit 0)
    uint16_t rsv_34c;
    uint32_t rsv_34e;
    uint8_t  rsv_352[0x360 - 0x352];
    uint16_t tx_max_syms_config;            // [0x360] TX max symbols config (9-bit field at bits 9:1)
    uint16_t beacon_timestamp_high;         // [0x362] Beacon timestamp MSW
    uint8_t  chan_info_364;                 // [0x364] Channel information / AP config
    uint8_t  chan_info_365;                 // [0x365] Channel information / AP config (part 2)
    uint8_t  rsv_366[0x368 - 0x366];
    uint32_t chan_setup_param;              // [0x368] Channel setup parameter
    uint32_t rf_cfg;                        // [0x36C] RF configuration register
    uint32_t event_payload;                 // [0x370] Event-specific payload
    uint32_t misc_ctrl_word;                // [0x374] Misc control (NAV_DIFF, rate modulation, BA ctrl)
    uint8_t  nav_mgmt_state;                // [0x378] NAV management state/control
    uint8_t  ap_state_flags;                // [0x379] AP state flags/status
    uint8_t  flags_37a;                     // [0x37A] State/control flags
    uint8_t  rsv_37b;                       // [0x37B] Reserved
    uint8_t  flags_37c;                     // [0x37C] LO table / Scan state / Dialog token
    uint8_t  flags_37d;                     // [0x37D] LO table / Rate control / ACS state
    uint8_t  flags_37e;                     // [0x37E] Beacon / RX / TX control state
    uint8_t  flags_37f;                     // [0x37F] PHY state / ACS / Status flags
    uint8_t  beacon_fsm_state;              // [0x380] Beacon FSM state / control
    uint8_t  rsv_381[3];
    uint32_t fsm_timeout_counter;           // [0x384] FSM timeout / state machine counter
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
    uint32_t beacon_event_counter;          // [0x3C4] Beacon event counter / beacon processing state
    uint16_t beacon_drift_adj;              // [0x3C8] Beacon drift adjustment (half-word field)
    uint16_t beacon_timing_param;           // [0x3CA] Beacon timing parameter
    uint32_t tsf_adjustment_factor;         // [0x3CC] TSF adjustment factor
    uint32_t beacon_miss_counter;           // [0x3D0] Beacon miss/detection counter
    uint32_t hw_tsf_estimate;               // [0x3D4] Hardware TSF estimate / timing estimate
    uint16_t beacon_offset;                 // [0x3DC] Beacon offset / timing correction
    uint8_t  rx_state_flags2;               // [0x3DE] RX state flags (part 2)
    uint8_t  rx_filter_flags2;              // [0x3DF] RX filter flags (part 2)
    int8_t   rssi_adjustment;               // [0x3E0] RSSI value adjustment/calibration
    uint8_t  ba_window_param;               // [0x3E1] Block Ack window parameter
    uint8_t  ampdu_density;                 // [0x3E2] A-MPDU density setting
    uint8_t  tx_retry_count;                // [0x3E3] TX retry counter / limit
    uint8_t  rate_control_flags;            // [0x3E4] Rate control flags
    uint8_t  rsv_3e5[0x3E8 - 0x3E5];
    uint32_t beacon_int_counter;            // [0x3E8] Beacon interval counter
    uint32_t rx_buffer_usage;               // [0x3EC] RX buffer usage/threshold tracking
    uint32_t tx_queue_state;                // [0x3F0] TX queue state / counter
    uint8_t  rsv_3f4[0x405 - 0x3F4];
    uint8_t  tx_frame_prep_state;           // [0x405] TX frame preparation state
    uint8_t  rsv_406[0x516 - 0x406];
    uint8_t  chan_cfg_516;                  // [0x516] Channel configuration
    uint8_t  chan_cfg_517;                  // [0x517] Channel configuration
    uint8_t  rsv_518[0x51a - 0x518];
    uint8_t  chan_cfg_51a;                  // [0x51A] Channel configuration
    uint8_t  chan_cfg_51b;                  // [0x51B] Channel configuration
    uint8_t  rsv_51c[0x51e - 0x51C];
    uint8_t  chan_cfg_51e;                  // [0x51E] Channel configuration
    uint8_t  chan_cfg_51f;                  // [0x51F] Channel configuration
    uint8_t  rsv_520[0x522 - 0x520];
    uint8_t  chan_cfg_522;                  // [0x522] Channel configuration
    uint8_t  chan_cfg_523;                  // [0x523] Channel configuration
    uint8_t  rsv_524[0x526 - 0x524];
    uint8_t  bssid[6];                      // [0x526] BSSID
    uint8_t  rsv_52c[0x52E - 0x52C];        // [0x52C-0x52D] Reserved (IE element)
    uint16_t ie_length;                     // [0x52E] Information Elements length
    uint8_t  rsv_530[0x550 - 0x530];        // [0x530-0x54F] Reserved (IE data)
    uint32_t probe_req_elem;                // [0x550] Probe request element info
    uint8_t  probe_resp_type;               // [0x554] Probe response type/subtype
    uint8_t  probe_resp_flags;              // [0x555] Probe response flags
    uint8_t  ie_element_index;              // [0x556] IE element index / position
    uint8_t  ie_type_field;                 // [0x557] IE type identifier field
    uint32_t ie_info_558;                   // [0x558] IE info field
    uint8_t  rsv_55c;
    uint16_t s1g_compat_values;             // [0x55C] S1G compatibility field (bits 7-9)
    uint8_t  rsv_55e;
    uint16_t field_55f;                     // [0x55F] TX queue base ptr 0 (via 0x560 accesses)
    uint16_t field_561;                     // [0x561] TX queue base ptr 1 (via 0x562 accesses)
    uint8_t  rsv_563[0x565 - 0x563];        // [0x563-0x564] Reserved (padding)
    uint8_t  tx_state_ctrl_0;               // [0x565] TX state control byte 0
    uint8_t  rsv_566[0x56c - 0x566];        // [0x566-0x56B] Reserved (padding)
    uint32_t tx_state_data_0;               // [0x56C] TX state data 0
    uint32_t tx_state_data_1;               // [0x570] TX state data 1
    uint8_t  rsv_574[0x57c - 0x574];        // [0x574-0x57B] Reserved (padding)
    uint32_t tx_state_data_2;               // [0x57C] TX state data 2
    uint32_t tx_state_data_3;               // [0x580] TX state data 3
    uint8_t  rsv_584[0x58c - 0x584];        // [0x584-0x58B] Reserved (padding)
    uint32_t tx_state_data_4;               // [0x58C] TX state data 4
    uint32_t tx_state_data_5;               // [0x590] TX state data 5
    uint8_t  rsv_594[0x5b6 - 0x594];        // [0x594-0x5B5] Reserved (padding)
    uint8_t  tx_frame_flags;                // [0x5B6] TX frame flags/state
    uint8_t  rsv_5b7[0x5c6 - 0x5B7];        // [0x5B7-0x5C5] Reserved (padding)
    uint16_t field_5c6;                     // [0x5C6] TX-related flag field
    uint8_t  rsv_5c8[0x5f5 - 0x5C8];        // [0x5C8-0x5F4] Reserved (padding)
    uint8_t  tx_retry_state;                // [0x5F5] TX retry state / retry counter (alternate)
    uint8_t  rsv_5f6[0x5fc - 0x5F6];        // [0x5F6-0x5FB] Reserved (padding)
    uint16_t tx_frame_status;               // [0x5FC] TX frame status/flags
    uint8_t  rsv_5fe[0x630 - 0x5FE];        // [0x5FE-0x62F] Reserved (padding)
    uint32_t cca_control_status;            // [0x630] CCA observation control/status
    uint32_t cca_result_0;                  // [0x634] CCA observation result 0
    uint32_t cca_result_1;                  // [0x638] CCA observation result 1
    uint32_t cca_result_2;                  // [0x63C] CCA observation result 2
    uint32_t cca_result_3;                  // [0x640] CCA observation result 3
    uint32_t cca_result_4;                  // [0x644] CCA observation result 4
    uint32_t tx_queue_wstate;               // [0x648] TX packet queue write state (alternate)
    uint32_t tx_packet_state;               // [0x64C] TX packet descriptor state
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
    uint8_t  rsv_6d6[2];                    // [0x6D6-0x6D7] Reserved (padding)
    uint32_t decode_error_count;            // [0x6D8] Decode/FCS error counter
    uint32_t crc_error_count;               // [0x6DC] CRC error counter
    uint32_t fcs_fail_count;                // [0x6E0] FCS failure counter
    uint32_t rx_underrun_count;             // [0x6E4] RX buffer underrun counter
    uint32_t rx_overflow_count;             // [0x6E8] RX buffer overflow counter
    uint8_t  rsv_6ec[4];                    // [0x6EC-0x6EF] Reserved (padding)
    uint32_t corruption_error_count;        // [0x6F0] Corruption/integrity error counter
    uint32_t channel_err_count;             // [0x6F4] Channel/decode error counter
    uint32_t frame_sync_error_count;        // [0x6F8] Frame sync error counter
    uint32_t plcp_error_count;              // [0x6FC] PLCP error counter
    uint32_t rx_fifo_error_count;           // [0x700] RX FIFO error counter
    uint32_t tx_fifo_error_count;           // [0x704] TX FIFO error counter
    uint8_t  phy_error_flags;               // [0x708] PHY error/status flags (bit field)
    uint8_t  rsv_709[3];                    // [0x709-0x70B] Reserved (padding)
    uint8_t  rx_state_error_count;          // [0x70C] RX state machine error count
    uint8_t  tx_state_error_count;          // [0x70D] TX state machine error count
    uint8_t  mac_timeout_count;             // [0x70E] MAC timeout counter
    uint8_t  rsv_70f;                       // [0x70F] Reserved
    uint8_t  collision_detect_count;        // [0x710] Collision detection counter
    uint8_t  rsv_711;                       // [0x711] Reserved (padding)
    int16_t  last_rssi_raw;                 // [0x712] Last raw RSSI measurement
    int16_t  last_cfo_raw;                  // [0x714] Last raw CFO measurement
    uint8_t  rsv_716[2];                    // [0x716-0x717] Reserved (padding)
    uint32_t rx_ampdu_count;                // [0x718] RX A-MPDU counter
    uint32_t rx_mpdu_success_count;         // [0x71C] RX MPDU success counter
    uint32_t rx_mpdu_error_count;           // [0x720] RX MPDU error counter
    uint32_t tx_ampdu_success_count;        // [0x724] TX A-MPDU success counter
    uint32_t tx_ampdu_error_count;          // [0x728] TX A-MPDU error counter
    uint32_t block_ack_timeout_count;       // [0x72C] Block Ack timeout counter
    uint32_t block_ack_error_count;         // [0x730] Block Ack error counter
    uint32_t ack_timeout_count;             // [0x734] ACK timeout counter
    uint32_t ack_error_count;               // [0x738] ACK error counter
    uint32_t cts_timeout_count;             // [0x73C] CTS timeout counter
    uint32_t rts_failure_count;             // [0x740] RTS failure counter
    uint32_t retry_exceeded_count;          // [0x744] Retry limit exceeded counter
    uint32_t qos_null_tx_count;             // [0x748] QoS Null frame TX counter
    uint32_t pspoll_tx_count;               // [0x74C] PS-Poll TX counter
    uint32_t probe_request_count;           // [0x750] Probe request frame counter
    uint32_t failed_frame_count;            // [0x754] TX failed frame counter
    uint32_t error_frame_count;             // [0x758] RX error frame counter
    uint32_t rsv_758_stat1;                 // [0x75C] RX statistics counter 1
    uint32_t rsv_760_stat2;                 // [0x760] RX statistics counter 2
    uint32_t rsv_764_stat3;                 // [0x764] RX statistics counter 3
    uint32_t rsv_768_stat4;                 // [0x768] RX statistics counter 4 (stored from RX path)
    uint32_t rsv_76c_stat5;                 // [0x76C] RX statistics counter 5
    uint32_t rsv_770_stat6;                 // [0x770] RX statistics counter 6
    uint32_t rsv_774_stat7;                 // [0x774] RX statistics counter 7
    uint32_t rsv_778_stat8;                 // [0x778] RX statistics counter 8
    uint32_t rsv_77c_stat9;                 // [0x77C] RX comparison result / threshold crossing
    uint32_t rsv_780_stat10;                // [0x780] RX statistics counter 10
    uint32_t rsv_784_adc;                   // [0x784] ADC/sensor value from RX processing
    uint32_t phy_error_count;               // [0x788] PHY error counter
    uint32_t phy_error_code;                // [0x78C] Last PHY error code
    uint8_t  rsv_790[0x798 - 0x790];        // [0x790-0x797] Reserved (8 bytes)
    uint32_t rx_error_counter;              // [0x798] RX error/event counter (incremented on frame error)
    uint8_t  rsv_79c[0x7A0 - 0x79C];        // [0x79C-0x79F] Reserved (4 bytes)
    uint32_t rssi_peak_calib;               // [0x7A0] RSSI peak value for calibration
    uint32_t phy_stat_count1;               // [0x7A4] PHY statistics counter 1
    uint32_t phy_stat_count2;               // [0x7A8] PHY statistics counter 2
    uint32_t phy_stat_count3;               // [0x7AC] PHY statistics counter 3
    uint32_t phy_stat_count4;               // [0x7B0] PHY statistics counter 4
    uint32_t phy_stat_count5;               // [0x7B4] PHY statistics counter 5
    uint32_t phy_stat_count6;               // [0x7B8] PHY statistics counter 6
    uint32_t phy_stat_count7;               // [0x7BC] PHY statistics counter 7
    uint32_t phy_stat_count8;               // [0x7C0] PHY statistics counter 8
    uint32_t phy_stat_count9;               // [0x7C4] PHY statistics counter 9 (for averaging)
    uint32_t phy_stat_count10;              // [0x7C8] PHY statistics counter 10
    uint32_t phy_stat_count11;              // [0x7CC] PHY statistics counter 11
    uint32_t phy_stat_count12;              // [0x7D0] PHY statistics counter 12
    uint32_t phy_stat_count13;              // [0x7D4] PHY statistics counter 13 (TX total)
    uint32_t phy_stat_count14;              // [0x7D8] PHY statistics counter 14 (RX total)
    uint32_t phy_stat_count15;              // [0x7DC] PHY statistics counter 15 (RX good)
    uint32_t rssi_sum;                      // [0x7E0] RSSI accumulator
    uint16_t rssi_peak;                     // [0x7E4] Peak RSSI
    uint16_t rssi_sample_count;             // [0x7E6] RSSI sample count
    uint16_t rssi_avg_count;                // [0x7E8] RSSI average count
    uint8_t  rsv_7ea[0x804 - 0x7EA];        // [0x7EA-0x803] Reserved (26 bytes)
    uint16_t avg_power_zero_count;          // [0x804] Avg power = 0 counter
    uint16_t avg_power_neg128_count;        // [0x806] Avg power = -128 counter
    uint32_t tx_success_count_low;          // [0x808] TX success counter (64-bit low)
    uint32_t tx_success_count_high;         // [0x80C] TX success counter (64-bit high)
    uint32_t rx_success_count_low;          // [0x810] RX success counter (64-bit low)
    uint32_t rx_success_count_high;         // [0x814] RX success counter (64-bit high)
    uint8_t  rsv_818[0x81C - 0x818];        // [0x818-0x81B] Reserved (padding)
    uint32_t last_jiffies_low;              // [0x81C] Last jiffies timestamp (64-bit low)
    uint32_t last_jiffies_high;             // [0x820] Last jiffies timestamp (64-bit high)
    uint8_t  rsv_824[0x82C - 0x824];        // [0x824-0x82B] Reserved (padding)
    uint32_t frame_error_count;             // [0x82C] Frame error counter
    uint32_t retry_count;                   // [0x830] Retry counter
    uint32_t timeout_count;                 // [0x834] Timeout counter
    uint16_t cca_busy_time;                 // [0x838] CCA busy time counter
    uint8_t  rsv_83a[0x83D - 0x83A];        // [0x83A-0x83C] Reserved (padding)
    uint8_t  thermal_sensor_value;          // [0x83D] Thermal sensor reading
    uint8_t  power_monitor_value;           // [0x83E] Power monitor reading
    uint8_t  rsv_83f;                       // [0x83F] Reserved (padding)
    uint32_t phy_reset_metric_storage;      // [0x840] PHY reset metric storage
    uint8_t  phy_reset_metric;              // [0x841] PHY reset metric / PCF period (CS_NUM)
    uint8_t  rsv_842[3];
    uint32_t hw_tx_power;                   // [0x844] Hardware TX power setting
    uint32_t rsv_848;
    uint32_t tx_status_counter;             // [0x84C] TX completion counter
    uint16_t cca_observ[7];                 // [0x850-0x85E] CCA observation values (7x 16-bit)
    uint8_t  rsv_860[0x864 - 0x860];
    uint32_t reg_864_config;                // [0x864] RF register configuration (width 2)
    uint16_t state_866;                     // [0x866] RF register state
    uint8_t  rsv_868[0x870 - 0x868];
    uint16_t state_870;                     // [0x870] State
    uint8_t  rsv_872[0x875 - 0x872];
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
    uint8_t  rsv_8af[0x8C2 - 0x8AF];        // [0x8AF-0x8C1] Reserved (includes fields at 0x8e1)
    uint8_t  rf_temp_calib[6];              // [0x8C2-0x8C7] RF temperature calibration
    uint8_t  rsv_8c8[0x8CC - 0x8C8];        // [0x8C8-0x8CB] Reserved
    void    *dsleep_cfg;                    // [0x8CC]
    uint8_t  rsv_8d0[0x8d8 - 0x8D0];
    uint32_t beacon_interval_snapshot;      // [0x8D8] Beacon interval snapshot (saved before TDMA ops)
    uint32_t tdma_aux_timing;               // [0x8DC] TDMA auxiliary timing value
    uint8_t  rsv_8e0[0x8e6 - 0x8E0];
    uint16_t ba_resp_timeout;               // [0x8E6] Block Ack response timeout (calculated from frame durations)
    uint8_t  rsv_8e7[0x8f6 - 0x8E7];
    uint16_t ba_timeout_counter;            // [0x8F6] BA/ACK timeout counter
    uint8_t  rsv_8f8[0x906 - 0x8F8];
    uint16_t tx_vec_hdr_dur;                // [0x906] TX vector - header duration (lmac_hdr_dur_calc result)
    uint16_t tx_vec_buff[2];                // [0x908-0x90B] TX vector buffer area
    uint16_t tx_vec_info;                   // [0x90E] TX vector info field
    uint32_t tx_vec_flags;                  // [0x910] TX vector flags/control (bit flags)
    uint32_t tx_vec_config[2];              // [0x914-0x91B] TX vector config registers
    uint32_t tx_power_idx;                  // [0x91C] TX power index configuration
    uint32_t mcs_rate_info[4];              // [0x920-0x92F] MCS/rate info registers (4x 32-bit)
    uint8_t  rsv_938[0x969 - 0x938];
    uint8_t  tx_control_flags;              // [0x969] TX control flags (bit field)
    uint8_t  rsv_96a[0x979 - 0x96A];
    uint8_t  tx_mode_flags;                 // [0x979] TX mode flags (bit field)
    uint8_t  rsv_97a[0x994 - 0x97A];
    uint32_t frame_rx_state;                // [0x994] RX frame handler state (0-7 state machine)
    uint32_t rx_frame_counter;              // [0x998] RX frame counter (reset between frames)
    uint32_t state;                         // [0x99C]
    struct os_task main_task;               // [0x9A0] Main LMAC OS task structure (16B)
    uint8_t  rsv_9b0[0x9B8 - 0x9B0];        // [0x9B0-0x9B7] Reserved (padding after task)
    uint32_t print_buf_ptr;                 // [0x9B8] Print task buffer pointer
    struct os_semaphore print_sem;          // [0x9BC] Print task semaphore
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
    struct os_timer tick_timer;             // [0xA14] Ticker/periodic timer object
    uint8_t  rsv_a2c[0xA53 - 0xA2C];        // [0xA2C-0xA52] Reserved
    uint8_t  phy_watchdog_flags;            // [0xA53] PHY watchdog state flags (shifted +4)
    uint32_t scan_duration_ms;              // [0xA54] Scan duration or timeout counter (shifted +4)
    uint8_t  rsv_a58[0xa63 - 0xA58];
    uint8_t  scan_ie_cfg;                   // [0xa63] Scan IE configuration
    uint8_t  rsv_a64[0xA67 - 0xA64];        // [0xa64-0xA66] Reserved (shifted +4)
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
    struct os_task      tx_task;            // [0x02C] TX task (20 bytes)
    struct os_task      tx_status_task;     // [0x040] TX status task (20 bytes)
    struct os_semaphore tx_sem;             // [0x054] TX semaphore (8 bytes)
    struct os_semaphore tx_status_sem;      // [0x05C] TX status semaphore (8 bytes)
    uint8_t             rsv_064[4];       // [0x064] Padding to align with #defines

    struct skb_list     txq;               // [0x068] TX queue (from AH_TXQ_OFS=0x64)
    struct skb_list     txsq;              // [0x070] TX status queue (from AH_TXSQ_OFS=0x70)
    uint8_t             rsv_078[0x088 - 0x078]; // Padding to ACQ offset
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
