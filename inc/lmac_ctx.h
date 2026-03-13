/*
 * Updated lmac_ctx structure.
 *
 * This version attempts to name additional fields based on reverse–engineering
 * of the Mars LMAC firmware. Many of the original members were simply
 * unnamed byte arrays (unk_*).  By examining how various offsets are used
 * throughout the assembly listings, the following names and one‑line
 * descriptions were inferred.  Where the purpose remains unclear the field
 * is kept as a reserved placeholder.  Offsets and sizes are preserved so
 * that the ABI remains compatible with the original firmware.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef struct lmac_ops lmac_ops_t;

#define LMAC_PHY_SOFT_RESET_A4F_MASK            0x03U
#define LMAC_PHY_SOFT_RESET_A4F_TRIGGER         0x03U
#define LMAC_PHY_SOFT_RESET_METRIC_THRESHOLD    51
#define LMAC_PHY_SOFT_RESET_ERRCNT_THRESHOLD    101U

#define LMAC_PHY_WD_TX_ACK_PEND   (1U << 0)
#define LMAC_PHY_WD_RX_ACK_PEND   (1U << 1)
#define LMAC_PHY_WD_RX_ACTIVE     (1U << 2)
#define LMAC_PHY_WD_SCAN_TIMER    (1U << 3)

typedef struct lmac_ctx {
    /* 0x000 */
    lmac_ops_t *ops;            // pointer to low‑MAC operation table

    /*
     * 0x004..0x301 – large reserved area.  This region holds assorted
     * configuration, tables and statistics which were not analysed in
     * detail.  Keeping the layout intact ensures ABI compatibility.
     */
    uint8_t     reserved_004[0x302 - 0x004];

    /* 0x302 */
    uint8_t     self_mac[6];    // device MAC address

    /* 0x308 */
    uint8_t     bss_bw;         // BSS bandwidth (e.g. 20/40/80 MHz)

    /* 0x309 */
    uint8_t     pri_chan_cfg;   // primary channel configuration

    /*
     * 0x30c..0x30f – thresholds for selecting transmit AC queue.  These
     * values are compared against the current TX credit to choose which
     * Access Category (AC) queue to service.  They are initialised to
     * 10, 20, 30 and 40 respectively in the firmware.
     */
    uint8_t     txq_thresh0;    // TX AC queue threshold 0
    uint8_t     txq_thresh1;    // TX AC queue threshold 1
    uint8_t     txq_thresh2;    // TX AC queue threshold 2
    uint8_t     txq_thresh3;    // TX AC queue threshold 3

    /* 0x310 */
    uint8_t     reserved_310;   // unused/reserved byte

    /*
     * 0x311 – rate control mode.  The firmware tests this field against
     * values 1 and 2 when determining how aggressively to fall back on
     * lower data rates.
     */
    uint8_t     rate_mode;      // 0: disabled, 1: auto, 2: conservative

    /*
     * 0x312 – number of TX power levels.  In lmac_tx_pwr_sel() this value
     * (initially 20) is decremented and compared to the desired power index.
     */
    uint8_t     tx_power_levels; // transmit power steps available

    /*
     * 0x313 – rate fallback limit.  Used in ah_get_rate() to decide when
     * to reduce the modulation rate.  It limits how many consecutive
     * failures can occur before falling back.
     */
    uint8_t     rate_fallback_limit;

    /* 0x314 */
    uint8_t     reserved_314;   // unused/reserved byte

    /*
     * 0x315 – maximum number of MPDUs in an aggregate.  The default
     * value (16) is used in lmac_gen_tx_agglist() when building A‑MPDUs.
     */
    uint8_t     max_agg_frames;

    /*
     * 0x316 – PHY mode for the hardware.  This byte is passed to
     * lmac_hw_init() along with bss_bw; the firmware initialises it to 3.
     */
    uint8_t     phy_mode;

    /* 0x317 */
    uint8_t     sta_priv_len;   // per‑station private context length (e.g. 22)

    /*
     * 0x318 – power save state.  lmac_psm_enter() clears this byte when
     * entering PSM; it acts as a flag indicating whether the device is
     * currently in a power‑saving mode.
     */
    uint8_t     psm_state;

    /*
     * 0x319 – sleep/wakeup flags.  Individual bits control oscillator
     * enable, IO wakeup and other PMU related behaviour.  The PD timer
     * callback manipulates these bits before entering or leaving sleep.
     */
    uint8_t     sleep_flags;

    /*
     * 0x31a – GPIO shift for sleep control.  Used as a bit shift when
     * configuring the GPIO pin that wakes the MCU from deep sleep.
     */
    uint8_t     sleep_gpio_shift;

    /*
     * 0x31b – GPIO mask for sleep control.  Combined with the shift value
     * this byte selects which GPIO line is used to control AP sleep.
     */
    uint8_t     sleep_gpio_mask;

    /*
     * 0x31c – lower RSSI threshold for rate adaptation.  Signed value
     * (initialised to a firmware‑dependent constant) compared against
     * measured RSSI to select a slower modulation rate.
     */
    int8_t      rssi_threshold_low;

    /*
     * 0x31d – upper RSSI threshold for rate adaptation.  Signed value
     * compared against measured RSSI to select a higher modulation rate.
     */
    int8_t      rssi_threshold_high;

    /* 0x31e..0x320 – calibration offsets used in the RF calibration routine. */
    int8_t      cal_temp_offset;    // calibration offset 1 (e.g. –60)
    int8_t      cal_voltage_offset; // calibration offset 2 (e.g. –84)
    int8_t      cal_rssi_offset;    // calibration offset 3 (e.g. –87)

    /* 0x321..0x329 – reserved area for future use. */
    uint8_t     reserved_321[0x32A - 0x321];

    /* 0x32a */
    int8_t      sta_event_state; // per‑station event/state machine variable

    /* 0x32b */
    uint8_t     reserved_32b;   // unused/reserved byte

    /*
     * 0x32c – lower threshold used by the firmware to drive internal
     * state changes; default value is 50.
     */
    uint16_t    rssi_lower_threshold;

    /*
     * 0x32e – upper threshold used by the firmware to drive internal
     * state changes; also initialised to around 50.
     */
    uint16_t    rssi_upper_threshold;

    /* 0x330 */
    uint16_t    aid;            // association identifier assigned by AP

    /* 0x332..0x335 – reserved. */
    uint8_t     reserved_332[0x336 - 0x332];

    /*
     * 0x336 – partial AID/packing bits.  The low bit is set by
     * lmac_cfg_init() but its broader purpose remains unclear.
     */
    uint16_t    partial_aid_pack;

    /* 0x338..0x36b – miscellaneous configuration and counters. */
    uint8_t     reserved_338[0x36C - 0x338];

    /*
     * 0x36c – RF configuration.  Accessed as a 16‑bit or 8‑bit value
     * depending on context; holds modulation mode and channel flags.
     */
    uint32_t    rf_cfg;

    /* 0x370 */
    uint32_t    event_payload;  // payload or pointer associated with pending event

    /* 0x374 */
    uint32_t    misc_word_374; // miscellaneous word at offset 0x374

    /* 0x378..0x37b – reserved/unknown. */
    uint8_t     reserved_378[0x37C - 0x378];

    /* 0x37c..0x37f – configuration flags used by lmac_cfg_init().
     * Each byte is a bitfield controlling various aspects of the radio.
     */
    uint8_t     flags_37c;
    uint8_t     flags_37d;
    uint8_t     flags_37e;
    uint8_t     flags_37f;

    /* 0x380..0x387 – reserved. */
    uint8_t     reserved_380[0x388 - 0x380];

    /*
     * Tick counters used by the scheduler.  These 32‑bit values store
     * timeouts for various periodic operations (scan, beacon, etc.).
     */
    /* 0x388 */ uint32_t tick_388;
    /* 0x38c */ uint32_t tick_38c;
    /* 0x390 */ uint32_t tick_390;
    /* 0x394 */ uint32_t tick_div_394; // divider for converting ticks to ms
    /* 0x398 */ uint32_t tick_398;
    /* 0x39c */ uint32_t tick_39c;
    /* 0x3a0 */ uint32_t tick_3a0;

    /* 0x3a4..0x3ab – reserved. */
    uint8_t     reserved_3a4[0x3AC - 0x3A4];

    /* Additional tick counters updated in lmac_cfg_init(). */
    /* 0x3ac */ uint32_t tick_3ac;
    /* 0x3b0 */ uint32_t tick_3b0;
    /* 0x3b4 */ uint32_t tick_3b4;

    /* 0x3b8 */
    uint32_t    flags_3b8;      // miscellaneous status/flags register

    /* 0x3bc..0x525 – large reserved area holding tables and logs. */
    uint8_t     reserved_3bc[0x526 - 0x3BC];

    /* 0x526 */
    uint8_t     bssid[6];       // BSSID of the AP when associated

    /* 0x52c..0x68d – reserved area used by test code and debugging. */
    uint8_t     reserved_52c[0x68E - 0x52C];

    /* 0x68e */
    uint8_t     bg_rssi_cfg;    // background RSSI configuration
    /* 0x68f */
    uint8_t     bg_rssi_src;    // background RSSI source selection

    /* 0x690..0x787 – reserved. */
    uint8_t     reserved_690[0x788 - 0x690];

    /* 0x788 */
    uint32_t    wphy_err_count; // incremented on WPHY RX error, soft reset if >= 101

    /* 0x78c */
    uint32_t    last_wphy_err_code;  // last value returned by ah_wphy_err_code_get()

    /* 0x790..0x83c – reserved. */
    uint8_t     reserved_790[0x83D - 0x790];

    /* 0x83d */
    int8_t      phy_reset_metric; // metric checked by lmac_tick_cb(), soft reset if >= 51

    /* 0x83e..0x874 – reserved. */
    uint8_t     reserved_83e[0x875 - 0x83E];

    /* 0x875 */
    uint8_t     rf_flags;       // RF flags/indicators

    /* 0x876..0x891 – reserved. */
    uint8_t     reserved_876[0x892 - 0x876];

    /* 0x892 */
    uint8_t     reset_delay_flags; // bits 3..7 arm delayed reset, bits 0..2 unknown control flags

    /* 0x893..0x8cb – reserved. */
    uint8_t     reserved_893[0x8CC - 0x893];

    /* 0x8cc */
    void       *dsleep_cfg;     // pointer to deep‑sleep configuration

    /* 0x8d0..0x99b – reserved. */
    uint8_t     reserved_8d0[0x99C - 0x8D0];

    /* 0x99c */
    uint32_t    state;          // current LMAC state

    /*
     * 0x9a0..0x9bf – RTOS main task object.  This region stores the
     * task control block used by the real‑time scheduler for the LMAC
     * main loop.
     */
    uint8_t     main_task_obj[0x9BC - 0x9A0];

    /* 0x9bc..0x9c3 – semaphore used by the print task. */
    uint8_t     print_sem[0x9C4 - 0x9BC];

    /* 0x9c4..0x9f7 – task object for the print thread. */
    uint8_t     print_task_obj[0x9F8 - 0x9C4];

    /* 0x9f8 */
    void       *sta_list_head;  // head of linked list of associated stations
    /* 0x9fc */
    void       *sta_list_tail;  // tail of station list

    /* 0xa00..0xa07 – mutex protecting the station list. */
    uint8_t     sta_list_mutex[0xA08 - 0xA00];

    /* 0xa08 */
    uint16_t    sta_total;      // total number of stations associated
    /* 0xa0a */
    uint16_t    sta_psm1;       // stations in PSM 1
    /* 0xa0c */
    uint16_t    sta_psm2;       // stations in PSM 2

    /* 0xa0e..0xa0f – reserved. */
    uint8_t     reserved_a0e[0xA10 - 0xA0E];

    /* 0xa10..0xa2b – OS tick timer structure. */
    uint8_t     tick_timer[0xA2C - 0xA10];

    /* 0xa2c..0xa4e – reserved / timer state. */
    uint8_t     reserved_a2c[0xA4F - 0xA2C];

    /* 0xa4f */
    uint8_t     phy_watchdog_flags;; // low 2 bits participate in lmac_phy_soft_reset trigger

    /* 0xa50..0xa7f – reserved / timer state. */
    uint8_t     reserved_a50[0xA80 - 0xA50];
    
    /* Event ring.  Offsets 0xa80..0xa8b hold indices; 0xa8c..0xb8b hold
     * the ring buffer itself.  Each entry is a 32‑bit handle identifying
     * a pending event to be processed by the LMAC main loop.
     */
    /* 0xa80 */ uint32_t evt_rd;   // read index into event ring
    /* 0xa84 */ uint32_t evt_wr;   // write index into event ring
    /* 0xa88 */ uint32_t evt_cap;  // capacity of the event ring
    /* 0xa8c */ uint32_t evt_ring[64]; // circular buffer of event handles

    /* 0xb8c..0xb8f – reserved. */
    uint8_t     reserved_b8c[0xB90 - 0xB8C];

    /* 0xb90..0xbaf – semaphore used to wake the main loop. */
    uint8_t     main_sem[0xBB0 - 0xB90];

    /* 0xbb0 */
    uint32_t    free_kb;        // remaining heap space in kilobytes

    /* 0xbb4..0xc13 – reserved. */
    uint8_t     reserved_bb4[0xC14 - 0xBB4];
} lmac_ctx_t;

extern lmac_ctx_t ah_lmac;
