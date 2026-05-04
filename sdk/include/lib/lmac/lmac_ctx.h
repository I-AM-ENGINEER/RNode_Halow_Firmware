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

typedef struct lmac_ctx {
    //lmac_ops_t *ops;                        // [0x000] Ops vtable pointer
    uint8_t rsv[0xbc4];
    // uint32_t config_word;                   // [0x004] Configuration/init value
    // uint32_t init_state_flags;              // [0x008] Initialization state and flags
    // uint32_t init_control;                  // [0x00C] Init control register
    // uint32_t init_marker_10;                // [0x010] Init marker/timer
    // uint32_t init_marker_14;                // [0x014] Init marker/timer
    // uint32_t init_marker_18;                // [0x018] Init marker/timer value
    // uint32_t init_base_param_1c;            // [0x01C] Base parameter 1
    // uint32_t init_base_param_20;            // [0x020] Base parameter 2
    // uint32_t init_base_param_24;            // [0x024] Base parameter 3
    // uint32_t init_base_param_28;            // [0x028] Base parameter 4
    // uint32_t init_base_param_2c;            // [0x02C] Base parameter 5
    // uint32_t init_base_param_30;            // [0x030] Base parameter 6
    // uint32_t init_base_param_34;            // [0x034] Base parameter 7
    // uint32_t init_base_param_38;            // [0x038] Base parameter 8
    // uint32_t init_base_param_3c;            // [0x03C] Base parameter 9
    // uint32_t param_40;                      // [0x040] Parameter/state
    // uint32_t param_44;                      // [0x044] Parameter/state
    // uint32_t dma_init_param1;               // [0x048] DMA initialization parameter
    // uint32_t dma_init_param2;               // [0x04C] DMA initialization parameter
    // uint32_t dma_config_50;                 // [0x050] DMA configuration
    // uint32_t dma_config_54;                 // [0x054] DMA configuration
    // uint32_t dma_config_58;                 // [0x058] DMA configuration
    // uint32_t dma_config_5c;                 // [0x05C] DMA configuration
    // uint32_t dma_status_60;                 // [0x060] DMA status/control
    // uint32_t dma_status_64;                 // [0x064] DMA status/control
    // uint32_t dma_status_68;                 // [0x068] DMA status/control
    // uint32_t dma_status_6c;                 // [0x06C] DMA status/control
    // uint32_t hw_state_70;                   // [0x070] Hardware state
    // uint32_t hw_state_74;                   // [0x074] Hardware state
    // uint32_t hw_state_78;                   // [0x078] Hardware state
    // uint32_t hw_state_7c;                   // [0x07C] Hardware state
    // uint32_t hw_state_80;                   // [0x080] Hardware state
    // uint8_t  phy_config_084;                // [0x084] PHY configuration
    // uint8_t  phy_config_085;                // [0x085] PHY configuration
    // uint8_t  phy_config_086;                // [0x086] PHY configuration
    // uint8_t  phy_config_087;                // [0x087] PHY configuration
    // uint8_t  phy_ctrl_flags;                // [0x088] PHY control flags
    // uint8_t  rsv_089[0x090 - 0x089];        // [0x089-0x08F] Reserved (padding)
    // uint16_t phy_param_90;                  // [0x090] PHY parameter
    // uint16_t phy_param_92;                  // [0x092] PHY parameter
    // uint16_t phy_param_94;                  // [0x094] PHY parameter
    // uint16_t phy_param_96;                  // [0x096] PHY parameter
    // uint16_t phy_state_98;                  // [0x098] PHY state
    // uint16_t rsv_09a;                       // [0x09A] Reserved (padding)
    // uint16_t lo_freq_threshold_a0;          // [0x0A0] LO frequency threshold
    // uint16_t lo_freq_threshold_a2;          // [0x0A2] LO frequency threshold
    // uint16_t lo_freq_threshold_a4;          // [0x0A4] LO frequency threshold
    // uint16_t lo_freq_threshold_a6;          // [0x0A6] LO frequency threshold
    // uint16_t rsv_0a8;                       // [0x0A8] Alignment/reserved
    // uint32_t phy_config_ac;                 // [0x0AC] PHY config
    // uint32_t phy_config_b0;                 // [0x0B0] PHY config
    // uint32_t phy_config_b4;                 // [0x0B4] PHY config
    // uint32_t phy_config_b8;                 // [0x0B8] PHY config
    // uint32_t phy_config_bc;                 // [0x0BC] PHY config
    // uint32_t phy_config_c0;                 // [0x0C0] PHY config
    // uint32_t phy_config_c4;                 // [0x0C4] PHY config
    // uint32_t phy_config_c8;                 // [0x0C8] PHY config
    // uint32_t phy_config_cc;                 // [0x0CC] PHY config
    // uint32_t phy_config_d0;                 // [0x0D0] PHY config
    // uint32_t phy_config_d4;                 // [0x0D4] PHY config
    // uint32_t phy_config_d8;                 // [0x0D8] PHY config
    // uint32_t phy_config_dc;                 // [0x0DC] PHY config
    // uint32_t phy_config_e0;                 // [0x0E0] PHY config
    // uint32_t phy_config_e4;                 // [0x0E4] PHY config
    // uint32_t phy_config_e8;                 // [0x0E8] PHY config
    // uint32_t phy_config_ec;                 // [0x0EC] PHY config
    // uint32_t phy_config_f0;                 // [0x0F0] PHY config
    // uint32_t phy_config_f4;                 // [0x0F4] PHY config
    // uint32_t phy_config_f8;                 // [0x0F8] PHY config
    // uint32_t param_fc;                      // [0x0FC] Parameter/state
    // uint32_t rx_frame_tsf;                  // [0x100] RX frame timestamp (TSF)
    // uint16_t rx_frame_length;               // [0x104] RX frame length
    // uint16_t rx_frame_info;                 // [0x106] RX frame info (MCS, rate, bandwidth)
    // uint32_t rx_rssi_value;                 // [0x108] RX RSSI value
    // uint16_t rx_cfo;                        // [0x10A] RX carrier frequency offset
    // uint16_t rx_phase_offset;               // [0x10C] RX phase offset
    // uint32_t rx_evm;                        // [0x10E] RX EVM (Error Vector Magnitude)
    // uint32_t rx_snr;                        // [0x110] RX SNR value
    // uint8_t  rsv_114[0x116 - 0x114];
    // uint8_t  rx_status_flags;               // [0x116] RX status flags (bit field)
    // uint16_t rx_seq_ctrl;                   // [0x118] RX sequence control from frame
    // uint8_t  rsv_11a[0x11c - 0x11A];
    // uint32_t rx_cipher_param;               // [0x11C] RX cipher parameters
    // uint32_t rx_timestamp_adj;              // [0x120] RX timestamp adjustment/auxiliary
    // uint32_t rx_frame_duration;             // [0x124] RX frame duration calculation
    // uint32_t rx_subframe_info;              // [0x128] RX subframe/MPDU info
    // uint32_t rx_agg_param;                  // [0x12C] RX aggregation parameters
    // uint32_t rx_ampdu_len;                  // [0x130] RX A-MPDU length
    // uint8_t  rsv_134[0x138 - 0x134];
    // uint32_t rx_descriptor;                 // [0x138] RX frame descriptor
    // uint16_t rx_descriptor_ext;             // [0x13C] RX descriptor extension
    // uint8_t  rsv_13e[0x140 - 0x13E];
    // uint32_t rx_buffer_ptr;                 // [0x140] RX buffer/SKB pointer
    // uint32_t rx_processing_state;           // [0x144] RX frame processing state
    // uint32_t rx_hw_state_148;               // [0x148] RX hardware state register
    // uint32_t rx_hw_state_14c;               // [0x14C] RX hardware state register
    // uint32_t rx_hw_state_150;               // [0x150] RX hardware state register
    // uint32_t rx_hw_state_154;               // [0x154] RX hardware state register
    // uint32_t rx_hw_state_158;               // [0x158] RX hardware state register
    // uint32_t rx_hw_state_15c;               // [0x15C] RX hardware state register
    // uint32_t rx_interrupt_status;           // [0x160] RX interrupt/event status
    // uint8_t  rsv_164[0x1B8 - 0x164];        // [0x164-0x1B7] Reserved (RX buffer/descriptor area)
    // uint32_t rx_frame_vector;               // [0x1B8] RX frame vector / descriptor
    // uint8_t  rsv_1bc[0x1C4 - 0x1BC];        // [0x1BC-0x1C3] Reserved (padding)
    // uint16_t rx_frame_count;                // [0x1C4] RX frame counter / valid count
    // uint16_t rx_max_frame_count;            // [0x1C6] RX max frame count threshold
    // uint8_t  rsv_1c8[0x1D0 - 0x1C8];        // [0x1C8-0x1CF] Reserved (padding)
    // uint32_t rx_dma_param;                  // [0x1D0] RX DMA parameter / descriptor address
    // uint16_t rx_frame_length_threshold;     // [0x1D4] RX frame length threshold
    // uint8_t  rsv_1d6[0x1D8 - 0x1D6];        // [0x1D6-0x1D7] Reserved (padding)
    // uint32_t rx_buffer_threshold;           // [0x1D8] RX buffer threshold / level
    // uint16_t rx_frame_timeout;              // [0x1DC] RX frame timeout value
    // uint8_t  rsv_1de[0x1E0 - 0x1DE];        // [0x1DE-0x1DF] Reserved (padding)
    // uint16_t rx_good_count;                 // [0x1E0] RX good frame count
    // uint16_t rx_bad_count;                  // [0x1E2] RX bad frame count
    // uint8_t  rsv_1e4[0x1E8 - 0x1E4];        // [0x1E4-0x1E7] Reserved (padding)
    // uint32_t rx_total_frames;               // [0x1E8] RX total frames processed
    // uint32_t rx_frame_body;                 // [0x1EC] RX frame body descriptor
    // uint32_t phy_tx_vector_h;               // [0x1F0] PHY TX vector header
    // uint32_t phy_tx_vector_l;               // [0x1F4] PHY TX vector lower
    // uint8_t  rsv_1f8[0x208 - 0x1F8];        // [0x1F8-0x207] Reserved (final padding)
    // uint32_t phy_tx_config;                 // [0x208] PHY TX configuration (packed register)
    // uint32_t phy_tx_ctrl;                   // [0x20C] PHY TX control
    // uint32_t phy_rx_config;                 // [0x210] PHY RX configuration (packed register)
    // uint32_t phy_rx_ctrl_214;               // [0x214] PHY RX control
    // uint32_t phy_rx_ctrl_218;               // [0x218] PHY RX control
    // uint32_t phy_rx_ctrl_21c;               // [0x21C] PHY RX control
    // uint32_t phy_rx_ctrl_220;               // [0x220] PHY RX control
    // uint32_t phy_control_flags;             // [0x224] PHY control/status flags
    // uint8_t  rsv_228[0x257 - 0x228];        // [0x228-0x256] Reserved
    // uint8_t  dsleep_control;                // [0x257] Deep-sleep control byte (written value 4)
    // uint8_t  dsleep_pmu_flags;              // [0x258] Deep-sleep PMU flags (bits 6:0 used for PMU control)
    // uint8_t  rsv_259[0x25C - 0x259];        // [0x259-0x25B] Reserved (3B)
    // uint32_t hw_register_20_backup;         // [0x25C-0x25F] Backup of hardware register 0x20 (masked 0x0bf807f7)
    // uint8_t  rsv_260[0x2C0 - 0x260];        // [0x260-0x2BF] Reserved (96B, includes padding)
    // uint32_t dsleep_wakeup_timer;           // [0x2C0-0x2C3] Deep-sleep wakeup timer
    // uint8_t  dsleep_status_byte;            // [0x2C4] Deep-sleep status control
    // uint8_t  rsv_2c5[0x2CC - 0x2C5];        // [0x2C5-0x2CB] Reserved (7B)
    // uint32_t dsleep_state_read_0;           // [0x2CC] Deep-sleep state read 0
    // uint32_t dsleep_state_read_1;           // [0x2D0] Deep-sleep state read 1
    // uint32_t dsleep_state_read_2;           // [0x2D4] Deep-sleep state read 2
    // uint32_t dsleep_state_read_3;           // [0x2D8] Deep-sleep state read 3
    // uint32_t dsleep_state_write_0;          // [0x2DC] Deep-sleep state write 0
    // uint32_t dsleep_state_write_1;          // [0x2E0] Deep-sleep state write 1
    // uint32_t dsleep_state_write_2;          // [0x2E4] Deep-sleep state write 2
    // uint32_t dsleep_state_write_3;          // [0x2E8] Deep-sleep state write 3 / OBSS field
    // uint8_t  obss_scan_count;               // [0x2EC] OBSS scan counter (part of state_write_3)
    // uint8_t  rsv_2ed[0x307 - 0x2ED];        // [0x2ED-0x306] Reserved (padding, 26B)
    // int8_t   obss_threshold;                // [0x307] OBSS detection threshold
    // uint8_t  obss_state;                    // [0x308] OBSS state byte
    // uint8_t  self_mac[6];                   // [0x309-0x30E]
    // uint8_t  bss_bw;                        // [0x30F] BSS bandwidth
    // uint8_t  pri_chan_cfg;                  // [0x310]
    // uint8_t  rsv_311[2];                    // [0x311-0x312]
    // uint8_t  txq_thresh0;                   // [0x313]
    // uint8_t  txq_thresh1;                   // [0x314]
    // uint8_t  txq_thresh2;                   // [0x315]
    // uint8_t  txq_thresh3;                   // [0x316]
    // uint8_t  rsv_317;                       // [0x317]
    // uint8_t  rate_mode;                     // [0x318]
    // uint8_t  tx_power_levels;               // [0x319]
    // uint8_t  rate_fallback_limit;           // [0x31A]
    // uint8_t  rsv_31b;                       // [0x31B]
    // uint8_t  max_agg_frames;                // [0x31C]
    // uint8_t  phy_mode;                      // [0x31D]
    // uint8_t  sta_priv_len;                  // [0x31E]
    // uint8_t  psm_state;                     // [0x31F]
    // uint8_t  sleep_flags;                   // [0x320]
    // uint8_t  sleep_gpio_shift;              // [0x321]
    // uint8_t  sleep_gpio_mask;               // [0x322]
    // int8_t   rssi_threshold_low;            // [0x323]
    // int8_t   rssi_threshold_high;           // [0x324]
    // int8_t   cal_temp_offset;               // [0x325]
    // int8_t   cal_voltage_offset;            // [0x326]
    // int8_t   cal_rssi_offset;               // [0x327]
    // int8_t   bknoise_agc_offsets[6];        // [0x328-0x32D]
    // int8_t   bknoise_base_offset;           // [0x32E]
    // int8_t   cca_threshold_base;            // [0x32F]
    // int8_t   cca_threshold_min;             // [0x330]
    // int8_t   sta_event_state;               // [0x331]
    // uint8_t  rsv_32b;                       // [0x332]
    // uint16_t rssi_lower_threshold;          // [0x334]
    // uint16_t rssi_upper_threshold;          // [0x336]
    // uint16_t aid;                           // [0x338]
    // uint8_t  rx_buff_addr_state;            // [0x33A]
    // uint8_t  rx_buff_addr_ctrl;             // [0x33B]
    // uint16_t rx_buff_info;                  // [0x33C]
    // uint16_t partial_aid_pack;              // [0x33E]
    // uint32_t chan_cfg_param;                // [0x340]
    // uint8_t  meas_report_flags;             // [0x344]
    // uint8_t  meas_state;                    // [0x345]
    // uint16_t rsv_33e;                       // [0x346-0x347]
    // uint8_t  lo_cfg_byte_340;               // [0x348]
    // uint8_t  lo_cfg_byte_341;               // [0x349]
    // uint8_t  lo_cfg_byte_342;               // [0x34A]
    // uint8_t  lo_cfg_byte_343;               // [0x34B]
    // uint32_t lo_freq_value;                 // [0x34C]
    // uint8_t  lo_status_348;                 // [0x350]
    // uint8_t  lo_freq_flags;                 // [0x351]
    // uint16_t lo_freq_table_idx;             // [0x352]
    // uint16_t lo_control_34c;                // [0x354]
    // uint16_t rsv_34e;                       // [0x356]
    // uint32_t tx_config_350;                 // [0x358]
    // uint32_t tx_config_354;                 // [0x35C]
    // uint32_t tx_config_358;                 // [0x360]
    // uint32_t tx_config_35c;                 // [0x364]
    // uint16_t tx_max_syms_config;            // [0x368]
    // uint16_t beacon_timestamp_high;         // [0x36A]
    // uint8_t  chan_info_364;                 // [0x36C]
    // uint8_t  chan_info_365;                 // [0x36D]
    // uint8_t  rsv_36e;                       // [0x36E]
    // uint8_t  rsv_36f;                       // [0x36F]
    // uint32_t chan_setup_param;              // [0x370]
    // uint32_t rf_cfg;                        // [0x374]
    // uint32_t event_payload;                 // [0x378]
    // uint32_t misc_ctrl_word;                // [0x37C]
    // uint8_t  nav_mgmt_state;                // [0x380]
    // uint8_t  ap_state_flags;                // [0x381]
    // uint8_t  flags_37a;                     // [0x382]
    // uint8_t  rsv_37b;                       // [0x383]
    // uint8_t  flags_37c;                     // [0x384]
    // uint8_t  flags_37d;                     // [0x385]
    // uint8_t  flags_37e;                     // [0x386]
    // uint8_t  flags_37f;                     // [0x387]
    // uint8_t  beacon_fsm_state;              // [0x388]
    // uint8_t  rsv_381[3];                    // [0x389-0x38B]
    // uint32_t fsm_timeout_counter;           // [0x38C]
    // uint32_t rx_active_time_ms;             // [0x390] RX channel active time (milliseconds)
    // uint32_t tx_active_time_ms;             // [0x394] TX channel active time (milliseconds)
    // uint32_t beacon_timer_reload;           // [0x398] Beacon timer reload/countdown value
    // uint32_t beacon_interval_scaled;        // [0x39C] Beacon interval * 1024
    // uint32_t beacon_interval_next;          // [0x3A0] Next beacon interval
    // uint32_t rsv_3a4;                       // [0x3A4] Reserved
    // uint32_t beacon_interval_current;       // [0x3A8] Current beacon interval (TU)
    // uint8_t  rsv_3ac[0x3B4 - 0x3AC];        // [0x3AC-0x3B3] Reserved (8 bytes)
    // uint32_t beacon_timer_control;          // [0x3B4] Beacon timer control register
    // uint32_t antenna_probe_flag;            // [0x3B8] Rate control / antenna probe flag
    // uint32_t dsleep_countdown;              // [0x3BC] Deep-sleep duration countdown
    // uint32_t flags_3c0;                     // [0x3C0] Debug/control flags
    // uint8_t  rsv_3c4[0x3C8 - 0x3C4];        // [0x3C4-0x3C7] Reserved (4 bytes)
    // uint32_t ap_sleep_state;                // [0x3C8] AP sleep state
    // uint32_t beacon_event_counter;          // [0x3CC] Beacon event counter / beacon processing state
    // uint16_t beacon_drift_adj;              // [0x3D0] Beacon drift adjustment (half-word field)
    // uint16_t beacon_timing_param;           // [0x3D2] Beacon timing parameter
    // uint32_t tsf_adjustment_factor;         // [0x3D4] TSF adjustment factor
    // uint32_t beacon_miss_counter;           // [0x3D8] Beacon miss/detection counter
    // uint32_t hw_tsf_estimate;               // [0x3DC] Hardware TSF estimate / timing estimate
    // uint16_t beacon_offset;                 // [0x3E0] Beacon offset / timing correction
    // uint8_t  rx_state_flags2;               // [0x3E2] RX state flags (part 2)
    // uint8_t  rx_filter_flags2;              // [0x3E3] RX filter flags (part 2)
    // int8_t   rssi_adjustment;               // [0x3E4] RSSI value adjustment/calibration
    // uint8_t  ba_window_param;               // [0x3E5] Block Ack window parameter
    // uint8_t  ampdu_density;                 // [0x3E6] A-MPDU density setting
    // uint8_t  tx_retry_count;                // [0x3E7] TX retry counter / limit
    // uint8_t  rate_control_flags;            // [0x3E8] Rate control flags
    // uint8_t  rsv_3e9[0x3EC - 0x3E9];        // [0x3E9-0x3EB] Reserved (3 bytes)
    // uint32_t beacon_int_counter;            // [0x3EC] Beacon interval counter
    // uint32_t rx_buffer_usage;               // [0x3F0] RX buffer usage/threshold tracking
    // uint32_t tx_queue_state;                // [0x3F4] TX queue state / counter
    // uint8_t  rsv_3f8[0x409 - 0x3F8];        // [0x3F8-0x408] Reserved (0x11 bytes)
    // uint8_t  tx_frame_prep_state;           // [0x409] TX frame preparation state
    // uint8_t  rsv_40a[0x51A - 0x40A];        // [0x40A-0x519] Reserved (0x110 bytes)
    // uint8_t  chan_cfg_51a;                  // [0x51A] Channel configuration
    // uint8_t  chan_cfg_51b;                  // [0x51B] Channel configuration
    // uint8_t  rsv_51c[0x51E - 0x51C];        // [0x51C-0x51D] Reserved
    // uint8_t  chan_cfg_51e;                  // [0x51E] Channel configuration
    // uint8_t  chan_cfg_51f;                  // [0x51F] Channel configuration
    // uint8_t  rsv_520[0x522 - 0x520];        // [0x520-0x521] Reserved
    // uint8_t  chan_cfg_522;                  // [0x522] Channel configuration
    // uint8_t  chan_cfg_523;                  // [0x523] Channel configuration
    // uint8_t  rsv_524[0x528 - 0x524];        // [0x524-0x527] Reserved
    // uint8_t  bssid[6];                      // [0x528] BSSID
    // uint8_t  rsv_52e[0x550 - 0x52E];        // [0x52E-0x54F] Reserved
    // uint32_t probe_req_elem;                // [0x550] Probe request element info
    // uint8_t  probe_resp_type;               // [0x554] Probe response type/subtype
    // uint8_t  probe_resp_flags;              // [0x555] Probe response flags
    // uint8_t  ie_element_index;              // [0x556] IE element index / position
    // uint8_t  ie_type_field;                 // [0x557] IE type identifier field
    // uint32_t ie_info_558;                   // [0x558] IE info field
    // uint8_t  rsv_55c;                       // [0x55C] Reserved
    // uint16_t s1g_compat_values;             // [0x55E] S1G compatibility field
    // uint16_t tx_aifs_slots;                 // [0x560] Per-attempt AIFS slot count
    // uint16_t tx_backoff_slots;              // [0x562] Per-attempt random/backoff slot count
    // uint8_t  rsv_564[0x568 - 0x564];        // [0x564-0x567] Reserved
    // lmac_txvec_slot_t ndp_txvec_slots[5];   // [0x568-0x5B7] NDP TX vector slots
    // lmac_txvec_slot_t pv0_ctrl_txvec_slots[8]; // [0x5B8-0x637] PV0 control TX vector slots
    // lmac_txvec_slot_t beacon_txvec;         // [0x638-0x647] Beacon/AC-PD TX vector slot
    // uint8_t  rsv_64c[0x64C - 0x648];        // [0x648-0x64B] Reserved
    // uint32_t tx_queue_wstate;               // [0x64C] TX packet queue write state
    // uint32_t tx_packet_state;               // [0x650] TX packet descriptor state
    // lmac_s1g_beacon_state_t s1g_beacon_state; // [0x654-0x667] S1G beacon state
    // lmac_txvec_word_t s1g_short_beacon_cfg; // [0x668-0x66B] Short beacon config
    // lmac_pv0_ctrl_airtime_cache_t pv0_ctrl_airtime; // [0x66C-0x677] PV0 control airtime cache
    // int32_t  calibrated_temp_code;          // [0x678] Calibrated temperature sensor code
    // uint32_t vcc_measurement;               // [0x67C] VCC measurement sample
    // lmac_chip_monitor_gain_cache_t chip_monitor_gain_cache; // [0x680-0x68D] Chip monitor gain cache
    // int8_t   chip_monitor_cfg;              // [0x68E] Chip-monitor configuration
    // int8_t   chip_monitor_offset;           // [0x68F] Chip-monitor signed offset
    // uint8_t  channel_busy_percent;          // [0x690] Channel busy percentage
    // uint8_t  channel_idle_percent;          // [0x691] Channel idle percentage
    // uint8_t  sec_key_index;                 // [0x692] Security key index
    // uint8_t  sec_key_len;                   // [0x693] Security key length
    // uint8_t  sec_key[32];                   // [0x694-0x6B3] Security key material
    // uint8_t  sec_key_index2;                // [0x6B4] Security key index 2
    // uint8_t  sec_key_len2;                  // [0x6B5] Security key length 2
    // uint8_t  sec_key2[32];                  // [0x6B6-0x6D5] Security key material 2
    // uint8_t  rsv_6da[0x6D8 - 0x6D6];        // [0x6D6-0x6D7] Reserved
    // uint32_t vdd13b_measurement;            // [0x6D8] VDD13B measurement sample
    // uint32_t vdd13c_measurement;            // [0x6DC] VDD13C measurement sample
    // uint32_t fcs_fail_count;                // [0x6E0] FCS failure counter
    // uint32_t rx_underrun_count;             // [0x6E4] RX buffer underrun counter
    // uint32_t rx_overflow_count;             // [0x6E8] RX buffer overflow counter
    // uint8_t  rsv_6f0[0x6F0 - 0x6EC];        // [0x6EC-0x6EF] Reserved
    // uint32_t corruption_error_count;        // [0x6F0] Corruption/integrity error counter
    // uint32_t channel_err_count;             // [0x6F4] Channel/decode error counter
    // uint32_t frame_sync_error_count;        // [0x6F8] Frame sync error counter
    // uint32_t plcp_error_count;              // [0x6FC] PLCP error counter
    // uint32_t rx_fifo_error_count;           // [0x700] RX FIFO error counter
    // uint32_t tx_fifo_error_count;           // [0x704] TX FIFO error counter
    // uint8_t  phy_error_flags;               // [0x708] PHY error/status flags
    // uint8_t  rsv_70d[0x70C - 0x709];        // [0x709-0x70B] Reserved
    // uint8_t  rx_state_error_count;          // [0x70C] RX state machine error count
    // uint8_t  tx_state_error_count;          // [0x70D] TX state machine error count
    // uint8_t  mac_timeout_count;             // [0x70E] MAC timeout counter
    // uint8_t  rsv_713;                       // [0x70F] Reserved
    // uint8_t  collision_detect_count;        // [0x710] Collision detection counter
    // uint8_t  rsv_715;                       // [0x711] Reserved
    // int16_t  last_rssi_raw;                 // [0x712] Last raw RSSI measurement
    // int16_t  last_cfo_raw;                  // [0x714] Last raw CFO measurement
    // uint8_t  rsv_71a[0x718 - 0x716];        // [0x716-0x717] Reserved
    // uint32_t rx_ampdu_count;                // [0x718] RX A-MPDU counter
    // uint32_t rx_mpdu_success_count;         // [0x71C] RX MPDU success counter
    // uint32_t rx_mpdu_error_count;           // [0x720] RX MPDU error counter
    // uint32_t tx_ampdu_success_count;        // [0x724] TX A-MPDU success counter
    // uint32_t tx_ampdu_error_count;          // [0x728] TX A-MPDU error counter
    // uint32_t block_ack_timeout_count;       // [0x72C] Block Ack timeout counter
    // uint32_t block_ack_error_count;         // [0x730] Block Ack error counter
    // uint32_t ack_timeout_count;             // [0x734] ACK timeout counter
    // uint32_t ack_error_count;               // [0x738] ACK error counter
    // uint32_t cts_timeout_count;             // [0x73C] CTS timeout counter
    // uint32_t rts_failure_count;             // [0x740] RTS failure counter
    // uint32_t retry_exceeded_count;          // [0x744] Retry limit exceeded counter
    // uint32_t qos_null_tx_count;             // [0x748] QoS Null frame TX counter
    // uint32_t pspoll_tx_count;               // [0x74C] PS-Poll TX counter
    // uint32_t probe_request_count;           // [0x750] Probe request frame counter
    // uint32_t failed_frame_count;            // [0x754] TX failed frame counter
    // uint32_t error_frame_count;             // [0x758] RX error frame counter
    // uint32_t rsv_760_stat1;                 // [0x75C] RX statistics counter 1
    // uint32_t rsv_764_stat2;                 // [0x760] RX statistics counter 2
    // uint32_t rsv_768_stat3;                 // [0x764] RX statistics counter 3
    // uint32_t rsv_76c_stat4;                 // [0x768] RX statistics counter 4
    // uint32_t rsv_770_stat5;                 // [0x76C] RX statistics counter 5
    // uint32_t rsv_774_stat6;                 // [0x770] RX statistics counter 6
    // uint32_t rsv_778_stat7;                 // [0x774] RX statistics counter 7
    // uint32_t rsv_77c_stat8;                 // [0x778] RX statistics counter 8
    // uint32_t rsv_780_stat9;                 // [0x77C] RX statistics counter 9
    // uint32_t rsv_784_adc;                   // [0x780] ADC/sensor value
    // uint32_t phy_error_count;               // [0x784] PHY error counter
    // uint32_t phy_error_code;                // [0x788] Last PHY error code
    // uint8_t  rsv_790[0x798 - 0x78C];        // [0x78C-0x797] Reserved (12 bytes)
    // uint32_t rx_error_counter;              // [0x798] RX error/event counter
    // uint8_t  rsv_7a0[0x7A0 - 0x79C];        // [0x79C-0x79F] Reserved
    // uint32_t rssi_peak_calib;               // [0x7A0] RSSI peak value for calibration
    // uint32_t phy_stat_count1;               // [0x7A4] PHY statistics counter 1
    // uint32_t phy_stat_count2;               // [0x7A8] PHY statistics counter 2
    // uint32_t phy_stat_count3;               // [0x7AC] PHY statistics counter 3
    // uint32_t phy_stat_count4;               // [0x7B0] PHY statistics counter 4
    // uint32_t phy_stat_count5;               // [0x7B4] PHY statistics counter 5
    // uint32_t phy_stat_count6;               // [0x7B8] PHY statistics counter 6
    // uint32_t phy_stat_count7;               // [0x7BC] PHY statistics counter 7
    // uint32_t phy_stat_count8;               // [0x7C0] PHY statistics counter 8
    // uint32_t phy_stat_count9;               // [0x7C4] PHY statistics counter 9
    // uint32_t phy_stat_count10;              // [0x7C8] PHY statistics counter 10
    // uint32_t phy_stat_count11;              // [0x7CC] PHY statistics counter 11
    // uint32_t phy_stat_count12;              // [0x7D0] PHY statistics counter 12
    // uint32_t phy_stat_count13;              // [0x7D4] PHY statistics counter 13
    // uint32_t phy_stat_count14;              // [0x7D8] PHY statistics counter 14
    // uint32_t phy_stat_count15;              // [0x7DC] PHY statistics counter 15
    // uint32_t rssi_sum;                      // [0x7E0] RSSI accumulator
    // uint16_t rssi_peak;                     // [0x7E4] Peak RSSI
    // uint16_t rssi_sample_count;             // [0x7E6] RSSI sample count
    // uint16_t rssi_avg_count;                // [0x7E8] RSSI average count
    // uint8_t  rsv_7ee[0x804 - 0x7EA];        // [0x7EA-0x803] Reserved (0x1A bytes)
    // uint16_t avg_power_zero_count;          // [0x804] Avg power = 0 counter
    // uint16_t avg_power_neg128_count;        // [0x806] Avg power = -128 counter
    // uint32_t tx_success_count_low;          // [0x808] TX success counter (low)
    // uint32_t tx_success_count_high;         // [0x80C] TX success counter (high)
    // uint32_t rx_success_count_low;          // [0x810] RX success counter (low)
    // uint32_t rx_success_count_high;         // [0x814] RX success counter (high)
    // uint8_t  rsv_81c[0x81C - 0x818];        // [0x818-0x81B] Reserved
    // uint32_t last_jiffies_low;              // [0x81C] Last jiffies timestamp (low)
    // uint32_t last_jiffies_high;             // [0x820] Last jiffies timestamp (high)
    // uint8_t  rsv_828[0x82C - 0x824];        // [0x824-0x82B] Reserved
    // uint32_t frame_error_count;             // [0x82C] Frame error counter
    // uint32_t retry_count;                   // [0x830] Retry counter
    // uint32_t timeout_count;                 // [0x834] Timeout counter
    // uint16_t cca_busy_time;                 // [0x838] CCA busy time
    // uint8_t  rsv_83e[0x83D - 0x83A];        // [0x83A-0x83C] Reserved (3B)
    // uint8_t  thermal_sensor_value;          // [0x83D] Thermal sensor value
    // uint8_t  power_monitor_value;           // [0x83E] Power monitor value
    // uint8_t  rsv_843;                       // [0x83F] Reserved
    // uint8_t  last_tx_power_sel;             // [0x840] Last TX power selection
    // uint8_t  tx_power_track_snapshot;       // [0x841] TX power track snapshot
    // uint8_t  rsv_846[0x844 - 0x842];        // [0x842-0x843] Reserved (2B)
    // uint32_t tx_power_sel_count;            // [0x844] TX power selection count
    // uint32_t tx_power_sel_assoc_id;         // [0x848] TX power selection association ID
    // uint32_t tx_status_counter;             // [0x84C] TX status counter
    // uint16_t cca_observ[7];                 // [0x850-0x85D] CCA observation values
    // uint8_t  cca_observ_mode;               // [0x85E] CCA observation mode
    // uint8_t  rsv_863[0x864 - 0x85F];        // [0x85F-0x863] Reserved (5B)
    // uint32_t reg_864_config;                // [0x864] Register 0x864 config
    // uint8_t  qa_tx_mcs;                     // [0x868] QA TX MCS
    // uint8_t  rsv_86d;                       // [0x869] Reserved
    // uint8_t  mcast_mcs;                     // [0x86A] Multicast MCS
    // uint8_t  mcast_bw_mhz;                  // [0x86B] Multicast bandwidth MHz
    // uint8_t  rsv_870[0x871 - 0x86C];        // [0x86C-0x870] Reserved (5B)
    // uint8_t  rf_control_flags;              // [0x871] RF control flags
    // uint16_t state_876;                     // [0x872-0x873] State at 0x872
    // uint8_t  rsv_878[0x876 - 0x874];        // [0x874-0x875] Reserved (2B)
    // uint8_t  sleep_gpio_state;              // [0x876] Sleep GPIO state
    // uint8_t  rf_reset_flags;                // [0x877] RF reset flags
    // uint8_t  rf_powerdown_flags;            // [0x878] RF powerdown flags
    // uint8_t  rsv_87d[0x87C - 0x879];        // [0x879-0x87B] Reserved (3B)
    // uint8_t  qa_ctrl_flags;                 // [0x87C] QA control flags
    // uint8_t  rsv_881;                       // [0x87D] Reserved
    // uint16_t rsv_882;                       // [0x87E-0x87F] Reserved
    // uint32_t qa_lo_freq;                    // [0x880] QA LO frequency
    // int8_t   qa_bw_mhz;                     // [0x884] QA bandwidth MHz
    // int8_t   qa_mcs;                        // [0x885] QA MCS
    // int8_t   qa_timeout_delta_threshold;    // [0x886] QA timeout delta threshold
    // int8_t   qa_att;                        // [0x887] QA attenuation
    // int8_t   qa_rx_thresholds[8];           // [0x888-0x88F] QA RX thresholds
    // int8_t   qa_tx_thresholds[8];           // [0x890-0x897] QA TX thresholds
    // int8_t   qa_rx_metric_0;                // [0x898] QA RX metric 0
    // int8_t   qa_rx_metric_1;                // [0x899] QA RX metric 1
    // int8_t   qa_rx_metric_2;                // [0x89A] QA RX metric 2
    // int8_t   qa_rx_metric_3;                // [0x89B] QA RX metric 3
    // int8_t   qa_rx_metric_4;                // [0x89C] QA RX metric 4
    // uint8_t  rsv_8a1;                       // [0x89D] Reserved
    // int16_t  qa_rx_metric_5;                // [0x89E-0x89F] QA RX metric 5
    // uint8_t  rsv_8a4[0x8A2 - 0x8A0];        // [0x8A0-0x8A1] Reserved (2B)
    // int8_t   qa_rx_avg_power;               // [0x8A2] QA RX average power
    // int8_t   qa_rx_avg_evm;                 // [0x8A3] QA RX average EVM
    // int8_t   qa_rx_freq_offset;             // [0x8A4] QA RX frequency offset
    // uint8_t  qa_rx_agc_index;               // [0x8A5] QA RX AGC index
    // uint8_t  rsv_8aa[0x8AC - 0x8A6];        // [0x8A6-0x8AB] Reserved (6B)
    // uint8_t  qa_rx_threshold_flags;         // [0x8AC] QA RX threshold flags
    // uint8_t  qa_tx_threshold_flags;         // [0x8AD] QA TX threshold flags
    // uint8_t  rf_temp_calib[6];              // [0x8AE-0x8B3] RF temperature calibration
    // struct lmac_init_param init_param;      // [0x8B4-0x8C7] Init parameters (0x14 bytes)
    // uint32_t tdma_aux_timing;               // [0x8C8] TDMA auxiliary timing
    // uint8_t  rsv_8d0[0x8D2 - 0x8D0];        // [0x8D0-0x8D1] Reserved (2 bytes)
    // uint16_t ba_resp_timeout;               // [0x8D2] Block Ack response timeout
    // uint8_t  rsv_8d8[0x8E4 - 0x8D4];        // [0x8D4-0x8E3] Reserved (0x10 bytes)
    // uint16_t ba_timeout_counter;            // [0x8E4] Block Ack timeout counter
    // uint8_t  rsv_8ea[0x8F4 - 0x8E6];        // [0x8E6-0x8F3] Reserved (0xe bytes)
    // uint16_t tx_vec_hdr_dur;                // [0x8F4] TX vector header duration
    // uint16_t tx_vec_buff[2];                // [0x8F6-0x8F9] TX vector buffer
    // uint16_t tx_vec_info;                   // [0x8FA] TX vector info
    // uint8_t  rsv_8fc[0x900 - 0x8FC];        // [0x8FC-0x8FF] Reserved
    // uint32_t tx_vec_flags;                  // [0x900] TX vector flags
    // uint32_t tx_vec_config[2];              // [0x904-0x90B] TX vector config
    // uint32_t tx_power_idx;                  // [0x908] TX power index
    // uint32_t mcs_rate_info[4];              // [0x90C-0x91B] MCS rate info
    // uint8_t  rsv_920[0x94D - 0x91C];        // [0x91C-0x94C] Reserved (0x31 bytes)
    // uint8_t  tx_control_flags;              // [0x94D] TX control flags
    // uint8_t  rsv_952[0x95D - 0x94E];        // [0x94E-0x95C] Reserved (0xf bytes)
    // uint8_t  tx_mode_flags;                 // [0x95D] TX mode flags
    // uint8_t  rsv_962[0x978 - 0x95E];        // [0x95E-0x977] Reserved (0x1a bytes)
    // uint32_t frame_rx_state;                // [0x978] Frame RX state
    // uint32_t rx_frame_counter;              // [0x97C] RX frame counter
    // uint32_t state;                         // [0x980] MAC state
    // struct os_task      main_task;          // [0x984-0x997] Main task storage
    // uint8_t  rsv_99c[0x99C - 0x998];        // [0x998-0x99B] Reserved
    // uint32_t print_buf_ptr;                 // [0x99C] Print buffer pointer
    // struct os_semaphore print_sem;          // [0x9A0-0x9A7] Print semaphore
    // struct os_task      print_task;         // [0x9A8-0x9BB] Print task storage
    // uint32_t beacon_interval_scaled_backup; // [0x9BC] Beacon interval scaled backup
    // uint32_t beacon_interval_next_backup;   // [0x9C0] Beacon interval next backup
    // uint32_t rsv_9c8;                       // [0x9C4] Reserved
    // uint32_t beacon_interval_current_backup;// [0x9C8] Beacon interval current backup
    // uint8_t  rsv_9d0[0x9D4 - 0x9CC];        // [0x9CC-0x9D3] Reserved (8 bytes)
    // uint32_t beacon_ctrl_backup;            // [0x9D4] Beacon control backup
    // uint32_t flags_backup;                  // [0x9D8] Flags backup
    // void    *sta_list_head;                 // [0x9DC] Station list head pointer
    // void    *sta_list_tail;                 // [0x9E0] Station list tail pointer
    // struct os_mutex     sta_list_mutex;     // [0x9E4-0x9EB] Station list mutex
    // uint16_t sta_total;                     // [0x9EC] Total stations
    // uint16_t sta_psm1;                      // [0x9EE] Station PSM mode 1
    // uint16_t sta_psm2;                      // [0x9F0] Station PSM mode 2
    // uint16_t tick_timer_mode_hint;          // [0x9F2] Tick timer mode hint
    // struct os_timer     tick_timer;         // [0x9F4-0xA0F] Tick timer storage
    // struct os_timer     scan_probe_timer;   // [0xA10-0xA2B] Scan probe timer storage
    // uint32_t evt_wr;                        // [0xA2C] Event write index
    // uint32_t evt_cap;                       // [0xA30] Event capture/count
    // uint32_t evt_ring[64];                  // [0xA34-0xB33] Event ring buffer
    // uint8_t  rsv_b38[0xB74 - 0xB34];        // [0xB34-0xB73] Reserved (0x40 bytes)
    // struct os_semaphore main_sem;           // [0xB74-0xB7B] Main semaphore
    // uint8_t  main_runtime_info[0x18];       // [0xB7C-0xB93] Main runtime info
    // uint32_t free_kb;                       // [0xB94] Free kernel buffers
    // uint8_t  rsv_b9c[0xBC0 - 0xB98];        // [0xB98-0xBBF] Reserved (0x24 bytes)
} lmac_ctx_t;

// _Static_assert(sizeof(lmac_chip_monitor_gain_cache_t) == 0x0E, "lmac_chip_monitor_gain_cache_t size");
// _Static_assert(offsetof(lmac_ctx_t, obss_threshold) == 0x307, "lmac_ctx obss_threshold offset");
// _Static_assert(offsetof(lmac_ctx_t, obss_state) == 0x308, "lmac_ctx obss_state offset");
// _Static_assert(offsetof(lmac_ctx_t, self_mac) == 0x309, "lmac_ctx self_mac offset");
// _Static_assert(offsetof(lmac_ctx_t, bss_bw) == 0x30F, "lmac_ctx bss_bw offset");
// _Static_assert(offsetof(lmac_ctx_t, pri_chan_cfg) == 0x310, "lmac_ctx pri_chan_cfg offset");
// _Static_assert(offsetof(lmac_ctx_t, txq_thresh0) == 0x313, "lmac_ctx txq_thresh0 offset");
// _Static_assert(offsetof(lmac_ctx_t, txq_thresh1) == 0x314, "lmac_ctx txq_thresh1 offset");
// _Static_assert(offsetof(lmac_ctx_t, txq_thresh2) == 0x315, "lmac_ctx txq_thresh2 offset");
// _Static_assert(offsetof(lmac_ctx_t, txq_thresh3) == 0x316, "lmac_ctx txq_thresh3 offset");
// _Static_assert(offsetof(lmac_ctx_t, cca_busy_time) == 0x838, "lmac_ctx cca_busy_time offset");
// _Static_assert(offsetof(lmac_ctx_t, qa_rx_threshold_flags) == 0x8AC, "lmac_ctx qa_rx_threshold_flags offset");
// _Static_assert(offsetof(lmac_ctx_t, qa_tx_threshold_flags) == 0x8AD, "lmac_ctx qa_tx_threshold_flags offset");
// _Static_assert(offsetof(lmac_ctx_t, rf_temp_calib) == 0x8AE, "lmac_ctx rf_temp_calib offset");
// _Static_assert(offsetof(lmac_ctx_t, init_param) == 0x8B4, "lmac_ctx init_param offset");
// _Static_assert(sizeof(((lmac_ctx_t *)0)->init_param) == 0x14, "lmac_ctx init_param size");
// _Static_assert(offsetof(lmac_ctx_t, tdma_aux_timing) == 0x8C8, "lmac_ctx tdma_aux_timing offset");
// _Static_assert(offsetof(lmac_ctx_t, frame_rx_state) == 0x978, "lmac_ctx frame_rx_state offset");
// _Static_assert(offsetof(lmac_ctx_t, rx_frame_counter) == 0x97C, "lmac_ctx rx_frame_counter offset");
// _Static_assert(offsetof(lmac_ctx_t, state) == 0x980, "lmac_ctx state offset");
// _Static_assert(offsetof(lmac_ctx_t, main_task) == 0x984, "lmac_ctx main_task offset");
// _Static_assert(offsetof(lmac_ctx_t, print_sem) == 0x9A0, "lmac_ctx print_sem offset");
// _Static_assert(offsetof(lmac_ctx_t, print_task) == 0x9A8, "lmac_ctx print_task offset");
// _Static_assert(offsetof(lmac_ctx_t, tick_timer) == 0x9F4, "lmac_ctx tick_timer offset");
// _Static_assert(offsetof(lmac_ctx_t, scan_probe_timer) == 0xA10, "lmac_ctx scan_probe_timer offset");
// _Static_assert(offsetof(lmac_ctx_t, evt_wr) == 0xA2C, "lmac_ctx evt_wr offset");
// _Static_assert(offsetof(lmac_ctx_t, evt_cap) == 0xA30, "lmac_ctx evt_cap offset");
// _Static_assert(offsetof(lmac_ctx_t, evt_ring) == 0xA34, "lmac_ctx evt_ring offset");
// _Static_assert(offsetof(lmac_ctx_t, main_sem) == 0xB74, "lmac_ctx main_sem offset");
// _Static_assert(offsetof(lmac_ctx_t, main_runtime_info) == 0xB7C, "lmac_ctx main_runtime_info offset");
// _Static_assert(offsetof(lmac_ctx_t, free_kb) == 0xB94, "lmac_ctx free_kb offset");
// _Static_assert(offsetof(lmac_ctx_t, chip_monitor_gain_cache) == 0x680, "lmac_ctx chip_monitor_gain_cache offset");
_Static_assert(sizeof(lmac_ctx_t) == 0xBC4, "lmac_ctx size");

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
