#ifndef _MARS_LMAC_TX_H_
#define _MARS_LMAC_TX_H_

#include <stdint.h>
#include "typesdef.h"
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/ieee802_11_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Point-to-point TX timing overrides.
 *
 * bypass_backoff = 1  →  writes CW_min=CW_max=1 for all ACs before each
 *                         lmac_irq_ac_pd_orig dispatch, so the random backoff
 *                         computed in lmac_attempt_tx_orig is always rand()%1=0.
 *                         This saves ~390 µs/frame at 1 MHz CWmin=15.
 *                         Unlike FSM_BO_BYPASS, this does not corrupt the FSM.
 *
 * Future knob (not yet implemented — needs SIFS_INIT bit-layout study):
 *   zero_slot_time   →  write 0 to the slot-time field of SIFS_INIT, collapsing
 *                        DIFS from 264 µs to SIFS (160 µs).
 */
typedef struct {
    uint8_t bypass_backoff;
    uint8_t ignore_cca;
    uint8_t fast_tx;
    uint8_t defer_ac_pd;
    uint8_t cca_enabled;
    uint8_t cca_sensitivity;
    uint16_t cca_force_tx_pct;
    uint16_t duty_limit_pct;
    uint16_t cw_min;
    uint16_t cw_max;
    uint8_t cca_threshold_dynamic;
} lmac_custom_cfg_t;

extern lmac_custom_cfg_t lmac_custom_cfg;


/*
 * TX Queue Management Functions
 */

/**
 * @brief Initialize TX subsystem (queues, tasks, semaphores)
 */
void lmac_tx_init(void);

/**
 * @brief Kick TX task to process pending packets
 */
void lmac_kick_tx_task(void);

/**
 * @brief Get count of packets in TXSQ
 * @return Number of packets in TXSQ
 */
uint32 lmac_txsq_count(void);

/**
 * @brief Get count of packets in STATQ
 * @return Number of packets in STATQ
 */
uint32 lmac_statq_count(void);

/**
 * @brief Get count of packets in TXQ
 * @return Number of packets in TXQ
 */
uint32 lmac_txq_count(void);

/**
 * @brief Get count of packets in AC queue
 * @param ac Access category (0-3)
 * @return Number of packets in AC queue
 */
uint32 lmac_acq_count(uint32 ac);

/**
 * @brief Get count of aggregated packets for AC
 * @param ac Access category (0-3)
 * @return Number of aggregated packets
 */
uint32 lmac_txagg_count(uint32 ac);

/**
 * @brief Reorder TX aggregation list and dispatch completed packets
 * @return Number of completed packets
 */
int32 lmac_reorder_tx_agglist(void);

/**
 * @brief Get first SKB in AC queue
 * @param ac Access category (0-3)
 * @return Pointer to SKB or NULL
 */
struct sk_buff *lmac_get_first_skb(uint32 ac);


/*
 * TX Frame Submission Functions
 */

/**
 * @brief Submit packet to LMAC for transmission
 * @param ops LMAC operations structure
 * @param skb Socket buffer to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_ah_tx(struct lmac_ops *ops, struct sk_buff *skb);

/**
 * @brief Fast TX: fill TXD and inject directly into AC0 queue.
 * Bypasses tx_task, tx_pending_queue and tx_data_reload.
 * The skb must have >= 0x48 bytes headroom (as set by lmac_ah_init).
 * Caller constructs the S1G frame at skb->data (same as halow_tx does).
 * @param skb  Socket buffer with S1G frame at data pointer
 * @return 0 on success, negative on error (skb is freed on error)
 */
int32 lmac_fast_tx(struct sk_buff *skb, uint8_t mcs);

/**
 * @brief Test TX function (bypasses radio check)
 * @param ops LMAC operations structure
 * @param skb Socket buffer to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_ah_test_tx(struct lmac_ops *ops, struct sk_buff *skb);

/**
 * @brief Send management frame
 * @param skb Management frame to send
 * @return 0 on success, negative on error
 */
int32 lmac_send_mgmt_skb(struct sk_buff *skb);

/**
 * @brief Transmit beacon frame
 * @param skb Beacon frame to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_tx_beacon(struct sk_buff *skb);

/**
 * @brief Submit prepared AC frame to PHY and re-arm TX vector.
 * skb is accepted for API compatibility but ignored; AC is read from hardware state.
 */
int32 lmac_tx_frm(struct sk_buff *skb);

/**
 * @brief Transmit block ACK frame
 * @param skb BA frame to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_tx_ba(struct sk_buff *skb);

/**
 * @brief Transmit ACK frame
 * @param skb ACK frame to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_tx_ack(struct sk_buff *skb);

/**
 * @brief Transmit CTS frame
 * @param skb CTS frame to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_tx_cts(struct sk_buff *skb);

/**
 * @brief Transmit RTS frame
 * @param skb RTS frame to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_tx_rts(struct sk_buff *skb);

/**
 * @brief Transmit PV0 null frame
 * @param skb Null frame to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_tx_pv0_null(struct sk_buff *skb);

/**
 * @brief Transmit PV0 PS-Poll frame
 * @param skb PS-Poll frame to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_tx_pv0_pspoll(struct sk_buff *skb);

/**
 * @brief Transmit PV0 CF-Poll frame
 * @param skb CF-Poll frame to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_tx_pv0_cfpoll(struct sk_buff *skb);

/**
 * @brief Transmit PV0 CF-End frame
 * @param skb CF-End frame to transmit
 * @return 0 on success, negative on error
 */
int32 lmac_tx_pv0_cfend(struct sk_buff *skb);

/**
 * @brief Dispatch PV0 frame based on frame type
 * @param skb Frame to dispatch
 * @param fc Frame control field
 * @return 0 on success, negative on error
 */
int32 lmac_tx_dispatch_pv0(struct sk_buff *skb, uint16 fc);

/**
 * @brief Dispatch PV1 frame based on frame type
 * @param skb Frame to dispatch
 * @param fc Frame control field
 * @return 0 on success, negative on error
 */
int32 lmac_tx_dispatch_pv1(struct sk_buff *skb, uint16 fc);

/**
 * @brief Send data to PHY for transmission
 * @param ac Access category
 * @return 0 on success, negative on error
 */
int32 lmac_send_data_to_phy(uint32 ac);

/**
 * @brief Get maximum frame length for current PHY
 * @return Maximum frame length in bytes
 */
uint32 lmac_tx_max_frame_len(void);

/**
 * @brief Calculate aligned length for TX
 * @param len Original length
 * @return Aligned length
 */
uint16 lmac_tx_aligned_len(uint16 len);

/**
 * @brief Calculate duration field for header
 * @param len Frame length
 * @return Duration value
 */
uint32 lmac_hdr_dur_calc(uint32 len);

/**
 * @brief Get current TX AC
 * @return Current access category
 */
uint32 lmac_tx_cur_ac(void);

/**
 * @brief Select TX ACQ based on EDCA parameters
 * @return Selected AC (0-3) or 4 if none
 */
uint32 lmac_select_tx_acq(void);

/**
 * @brief Get TX sequence number fallback
 * @return Next sequence number
 */
uint16 lmac_tx_seq_fallback_next(void);

/**
 * @brief Update partial AID in TX info
 * @param txi TX info pointer
 */
void lmac_partial_aid_update(void *txi);

/**
 * @brief Get ACK policy for frame
 * @param txi TX info pointer
 * @return ACK policy (0 or 1)
 */
uint32 lmac_get_ack_policy(void *txi);

/**
 * @brief Update TX rate for AC
 * @param ac Access category
 * @param rate_out Output: rate index
 * @param bw_out Output: bandwidth
 * @return 0 on success, negative on error
 */
int32 lmac_update_tx_rate(uint32 ac, uint8 *rate_out, uint8 *bw_out);

/**
 * @brief Update TX state on ACK reception
 * @param ok ACK success flag
 * @param arg1 Reserved
 * @param arg2 Reserved
 * @return 0 on success, negative on error
 */
int32 lmac_update_tx_state_ack(uint32 ok, uint32 arg1, uint32 arg2);

/**
 * @brief Update TX state on Block ACK reception
 * @param start_ssn Starting sequence number
 * @param bitmap_lo Lower 32 bits of BA bitmap
 * @param bitmap_hi Upper 32 bits of BA bitmap
 * @return 0 on success, negative on error
 */
int32 lmac_update_tx_state_ba(uint32 start_ssn, uint32 bitmap_lo, uint32 bitmap_hi);

/**
 * @brief Update TX state on CTS reception
 * @param ok CTS success flag
 * @return 0 on success, negative on error
 */
int32 lmac_update_tx_state_cts(uint32 ok);

/**
 * @brief Generate TX vector for frame
 * @param ac Access category
 * @param ac_hint AC hint
 * @param mcs MCS index
 * @return Pointer to TX vector or NULL
 */
void *lmac_gen_txvec(uint32 ac, uint32 ac_hint, uint32 mcs);

/**
 * @brief Configure TX vector part 1 (base configuration)
 * @return 0 on success, negative on error
 */
int32 lmac_cfg_txvec_part1(void);

/**
 * @brief Configure TX vector part 2 (antenna selection)
 * @return 0 on success, negative on error
 */
int32 lmac_cfg_txvec_part2(void);

/**
 * @brief Update TX vector for current frame
 * @return 0 on success, negative on error
 */
int32 lmac_update_frm_tx_vec(void);

/**
 * @brief Update NDP CTS TX vector
 * @param arg0 Argument 0
 * @param arg1 Argument 1
 * @return 0 on success, negative on error
 */
int32 lmac_update_ndp_cts_tx_vec(uint32 arg0, uint32 arg1);

/**
 * @brief Update NDP ACK TX vector
 * @param arg0 Argument 0
 * @param arg1 Argument 1
 * @return 0 on success, negative on error
 */
int32 lmac_update_ndp_ack_tx_vec(uint32 arg0, uint32 arg1);

/**
 * @brief Update NDP BA TX vector
 * @param arg0 Argument 0
 * @param arg1 Argument 1
 * @return 0 on success, negative on error
 */
int32 lmac_update_ndp_ba_tx_vec(uint32 arg0, uint32 arg1);

/**
 * @brief Update PV0 WPBA TX vector
 * @return 0 on success, negative on error
 */
int32 lmac_update_pv0_wpba_tx_vec(void);

/**
 * @brief Update PV0 WPACK TX vector
 * @return 0 on success, negative on error
 */
int32 lmac_update_pv0_wpack_tx_vec(void);

/**
 * @brief Update PV0 WPCTS TX vector
 * @return 0 on success, negative on error
 */
int32 lmac_update_pv0_wpcts_tx_vec(void);

/**
 * @brief Update PV0 CFEND TX vector
 * @return 0 on success, negative on error
 */
int32 lmac_update_pv0_cfend_tx_vec(void);

/**
 * @brief Regenerate TX frame
 * @param ac Access category
 * @param ac_hint AC hint
 * @param mcs MCS index
 * @param arg Additional argument
 * @return 0 on success, negative on error
 */
int32 lmac_tx_frame_regen(uint32 ac, uint32 ac_hint, uint32 mcs, void *arg);

/**
 * @brief Check if TX data is prepared
 * @return 0 if prepared, negative if not
 */
int32 lmac_tx_date_prepared(void);


/*
 * TX Power Control Functions
 */

/**
 * @brief Select TX power for frame
 * @param txi TX info pointer
 * @param mcs MCS index
 * @return Selected TX power
 */
int32 lmac_tx_pwr_sel(void *txi, uint32 mcs);

/**
 * @brief Generate uplink TX power for PV0 control
 * @return TX power
 */
uint32 pv0_ctrl_uplink_txpwr_gen(void);

/**
 * @brief Configure antenna selection
 * @param ant Antenna index (0 or 1)
 */
void lmac_ant_sel(uint32 ant);


/*
 * Beacon and Management Functions
 */

/**
 * @brief Initialize PV0 RTS TX vector
 */
void lmac_pv0_rts_init(void);

/**
 * @brief Initialize PV0 WACK TX vector
 */
void lmac_pv0_wpack_init(void);

/**
 * @brief Initialize PV0 WPCTS TX vector
 */
void lmac_pv0_wpcts_init(void);

/**
 * @brief Initialize PV0 WPBA TX vector
 */
void lmac_pv0_wpba_init(void);

/**
 * @brief Initialize PV0 CFPoll TX vector
 */
void lmac_pv0_cfpoll_init(void);

/**
 * @brief Initialize PV0 PS-Poll TX vector
 */
void lmac_pv0_pspoll_init(void);

/**
 * @brief Initialize PV0 CF-End TX vector
 */
void lmac_pv0_cfend_init(void);

/**
 * @brief Initialize PV0 QoS Null TX vector
 */
void lmac_pv0_qos_null_init(void);

/**
 * @brief Initialize NDP TX vector (single)
 * @param txvec TX vector to initialize
 */
void ndp_tx_vec_init_one(uint8 *txvec);

/**
 * @brief Initialize all NDP TX vectors
 */
void ndp_tx_vec_init(void);

/**
 * @brief Allocate management SKB
 * @param size Size to allocate
 * @return Allocated SKB or NULL
 */
struct sk_buff *lmac_alloc_mgmt_skb(uint32 size);

/**
 * @brief Initialize management header
 * @param skb SKB to use
 * @param fc Frame control
 * @param da Destination address
 * @param sa Source address
 * @param bssid BSSID
 * @return Pointer to management header or NULL
 */
struct ieee80211_mgmt *lmac_mgmt_header_init(struct sk_buff *skb,
    uint16 fc, const uint8 *da, const uint8 *sa, const uint8 *bssid);

/**
 * @brief Send management beacon with S1G compatibility
 * @param skb Beacon SKB
 * @return 0 on success, negative on error
 */
int32 lmac_beacon_add_s1g_beacon_compatibility(struct sk_buff *skb);

/**
 * @brief Build S1G beacon
 * @param skb Source beacon SKB
 * @return 0 on success, negative on error
 */
int32 lmac_beacon_build_s1gbeacon(struct sk_buff *skb);

/**
 * @brief Reset beacon workspace
 * @param skb Beacon SKB
 */
void lmac_beacon_reset_workspace(struct sk_buff *skb);

/**
 * @brief Send management measurement request
 * @return 0 on success, negative on error
 */
int32 lmac_send_mgmt_meas_req(void);

/**
 * @brief Send management measurement report
 * @return 0 on success, negative on error
 */
int32 lmac_send_mgmt_meas_report(void);

/**
 * @brief Send BSS announcement
 * @return 0 on success, negative on error
 */
int32 lmac_send_bss_announcement(void);

/**
 * @brief Send scan probe request
 * @return 0 on success, negative on error
 */
int32 lmac_send_scan_probe(void);

/**
 * @brief Send antenna packet
 * @return 0 on success, negative on error
 */
int32 lmac_send_ant_pkt(void);

/**
 * @brief Send probe response
 * @return 0 on success, negative on error
 */
int32 lmac_send_probe_resp(void);


/*
 * TX Status and Notification Functions
 */

/**
 * @brief Mark TX timeout for AC
 * @param ac Access category
 */
void lmac_tx_mark_timeout_for_ac(uint32 ac);

/**
 * @brief Notify local TX status
 * @param ac Access category
 * @param ok Success flag
 * @param bytes Bytes transmitted
 */
void lmac_tx_status_notify_local(uint32 ac, uint32 ok, uint32 bytes);


/*
 * DTIM and Power Management Functions
 */

/**
 * @brief Get DTIM timer remaining
 * @return Remaining DTIM timer value
 */
uint32 lmac_dtim_timer_rem(void);

/**
 * @brief Check if TX to PM AP is allowed
 * @return 0 if allowed, negative if not
 */
int32 lmac_tx_to_pm_ap(void);

/**
 * @brief Set basic NAV value
 * @param nav NAV value
 */
void lmac_set_basic_nav(uint32 nav);


/*
 * Sequence Number Functions
 */

/**
 * @brief Get sequence number from header
 * @param hdr Header pointer
 * @return Sequence number
 */
uint32 lmac_get_seq_num(void *hdr);

/**
 * @brief Get TID from header
 * @param hdr Header pointer
 * @return TID value
 */
uint32 lmac_get_tid(void *hdr);

/**
 * @brief Get header length for PV0
 * @param hdr Header pointer
 * @return Header length
 */
uint32 lmac_get_hdr_len_pv0(void *hdr);

/**
 * @brief Get header length for PV1
 * @param hdr Header pointer
 * @return Header length
 */
uint32 lmac_get_hdr_len_pv1(void *hdr);

/**
 * @brief Convert SID to MAC address
 * @param sid SID value
 * @return MAC address pointer
 */
uint8 *lmac_convert_sid2mac(uint16 sid);


/*
 * RX Address Functions
 */

/**
 * @brief Get RX address from header
 * @param addr Output address buffer
 * @param hdr Header pointer
 */
void lmac_get_rx_addr(uint8 *addr, uint8 *hdr);


/*
 * CCA and Channel Functions
 */

/**
 * @brief Get CCA remaining time
 * @return CCA remaining time
 */
uint32 lhw_get_cca_remain(void);

/**
 * @brief Start CCA
 * @param bw Bandwidth
 * @param dur Duration
 */
void lhw_start_cca(uint32 bw, uint32 dur);

/**
 * @brief Configure special CCA
 * @param enable Enable flag
 */
void lmac_spec_cca_cfg(uint32 enable);

/**
 * @brief Adjust CCA threshold
 * @param delta Delta value
 */
void lmac_adjust_cca_threshold(int32 delta);

/**
 * @brief Adjust AGC threshold
 * @param level Level value
 */
void lmac_adjust_agc_threshold(int32 level);

/**
 * @brief Select channel
 * @param chan Channel number
 * @return 0 on success, negative on error
 */
int32 lmac_lo_freq_set(uint16 chan);

/**
 * @brief Notify channel switch
 * @param chan Channel number
 */
void lmac_notify_channel_switch(uint8 chan);

/**
 * @brief Perform auto channel selection
 * @return Selected channel number
 */
int32 lmac_auto_channel_select(void);


/*
 * Background Noise Functions
 */

/**
 * @brief Enable background noise calculation
 */
void lmac_bknoise_calc_en(void);

/**
 * @brief Disable background noise calculation
 */
void lmac_bknoise_calc_dis(void);

/**
 * @brief Get background noise valid PD
 * @return Valid PD value
 */
uint32 lmac_bknoise_valid_pd_get(void);

/**
 * @brief Clear background noise valid PD
 */
void lmac_bknoise_valid_pd_clr(void);

/**
 * @brief Get background noise value
 * @return Background noise value
 */
uint32 lmac_bknoise_get(void);

/**
 * @brief Update background RSSI
 */
void lmac_bgrssi_update(void);


/*
 * TDMA Functions
 */

/**
 * @brief Start TDMA
 * @return 0 on success, negative on error
 */
int32 lmac_tdma_start(void);

/**
 * @brief Abort TDMA
 */
void ah_tdma_abort(void);

/**
 * @brief Start TDMA
 */
void ah_tdma_start(void);


/*
 * Hardware Abort Functions
 */

/**
 * @brief Abort FSM
 */
void lhw_abort_fsm(void);

/**
 * @brief Start RX
 * @param flags Flags
 */
void lhw_start_rx(uint32 flags);

/**
 * @brief Start TX
 * @param flags Flags
 */
void lhw_start_tx(uint32 flags);

/**
 * @brief Configure TX subframe
 * @param idx Index
 * @param v0 Value 0
 * @param v1 Value 1
 */
void lhw_cfg_tx_sub_frm(uint32 idx, uint32 v0, uint32 v1);

/**
 * @brief Configure DMA list count
 * @param cnt Count
 */
void lhw_cfg_dma_list_cnt(uint32 cnt);

/**
 * @brief Enable IRQ AC
 */
void lhw_enable_irq_ac(void);

/**
 * @brief TX-start gate from lmac_attempt_tx: FSM MAC idle and RX armed
 */
uint32 lhw_tx_gate_blocked(void);

/**
 * @brief All RF gates (TX/RX/PA/DAC) in COMN_CTRL are off
 */
uint32 lhw_rf_gates_off(void);

/**
 * @brief Abort an armed TX under irq-guard; returns 1 if a TX was aborted
 */
uint32 lhw_abort_armed_tx(void);


/*
 * GPIO Functions
 */

/**
 * @brief Set GPIO direction
 * @param pin Pin number
 * @param direction Direction (0=input, 1=output)
 * @return 0 on success, negative on error
 */
int32 gpio_set_dir(uint32 pin, int32 direction);

/**
 * @brief Set GPIO value
 * @param pin Pin number
 * @param value Value (0 or 1)
 * @return 0 on success, negative on error
 */
int32 gpio_set_val(uint32 pin, int32 value);

/**
 * @brief Set JTAG map
 * @param val Value
 * @return 0 on success, negative on error
 */
int jtag_map_set(uint8 val);


/*
 * Register Access Functions
 */

/**
 * @brief Get LMAC register 32-bit value
 * @param ofs Offset
 * @return Register value
 */
uint32 LMAC_REG32(uint32 ofs);

/**
 * @brief Get hardware register 32-bit value
 * @return Register pointer
 */
volatile uint32 *lmac_hw_regs(void);


/*
 * Delay Functions
 */

/**
 * @brief Delay in microseconds
 * @param us Microseconds to delay
 */
void lmac_delay_us(uint32 us);

/**
 * @brief Sleep in microseconds
 * @param us Microseconds to sleep
 */
void os_sleep_us(int us);


/*
 * IRQ Handler Functions
 */

/**
 * @brief TX end IRQ handler
 */
void lmac_irq_tx_end(void);

/**
 * @brief TX timeout IRQ handler
 */
void lmac_irq_tx_tmo(void);

/**
 * @brief Backoff interrupt handler
 */
void lmac_irq_bo_fns(void);

/**
 * @brief AC power down IRQ handler
 */
void lmac_irq_ac_pd(void);

/**
 * @brief NDP ACK RX handler
 * @param rx0 RX value 0
 * @param rx1 RX value 1
 * @param ext Extended flag
 * @return 0 on success, negative on error
 */
int32 ndp_ack_rx_hdl(uint32 rx0, uint32 rx1, uint32 ext);

/**
 * @brief NDP BA RX handler
 * @param rx0 RX value 0
 * @param rx1 RX value 1
 * @param ext Extended flag
 * @return 0 on success, negative on error
 */
int32 ndp_ba_rx_hdl(uint32 rx0, uint32 rx1, uint32 ext);

/**
 * @brief NDP PS-Poll ACK RX handler
 * @return 0 on success, negative on error
 */
int32 ndp_pspoll_ack_rx_hdl(void);


/*
 * NDP2M Functions
 */

/**
 * @brief Generate PS-PACK NDP2M
 * @return NDP2M value
 */
uint64 lmac_gen_pspack_ndp2m(void);

/**
 * @brief Generate PS-Poll NDP2M
 * @return NDP2M value
 */
uint64 lmac_gen_pspoll_ndp2m(void);

/**
 * @brief Generate PS-Poll ACK NDP2M
 * @return NDP2M value
 */
uint64 lmac_gen_pspoll_ack_ndp2m(void);


/*
 * WPHY Functions
 */

/**
 * @brief Configure WPHY CCA threshold
 * @param cfg Configuration array
 */
void ah_wphy_cca_th_cfg(void *cfg);

/**
 * @brief Configure WPHY OBSS parameters
 * @param a Parameter a
 * @param b Parameter b
 * @param c Parameter c
 * @param d Parameter d
 */
void ah_wphy_obss_para_cfg(int32 a, int32 b, int32 c, int32 d);

/**
 * @brief Get WPHY AGC info
 * @return AGC info
 */
uint32 ah_wphy_agc_info_get(void);

/**
 * @brief Get WPHY RX gain parameter
 * @param idx Index
 * @return RX gain parameter
 */
int32 ah_wphy_rx_gain_para_get(int32 idx);

/**
 * @brief Configure WPHY auto signal error reset disable
 */
void ah_wphy_auto_sig_err_rst_disable(void);

/**
 * @brief Configure WPHY auto signal error reset enable
 */
void ah_wphy_auto_sig_err_rst_enable(void);

/**
 * @brief Configure WPHY primary channel
 * @param cfg Configuration
 */
void ah_wphy_pri_channel_cfg(uint32 cfg);

/**
 * @brief Configure WPHY hardware BK noise
 * @param arg0 Argument 0
 * @param arg1 Argument 1
 */
void ah_rfdigicali_config_hw_bknoise(uint16_t arg0, uint16_t arg1);


/*
 * RF Digital Calibration Functions
 */

/**
 * @brief Configure RF digital calibration TX power
 * @param arg0 Argument 0
 */
void ah_rfdigicali_tx_pwr(uint32 arg0);

/**
 * @brief Enable RF digital calibration BK noise calculation
 */
void ah_rfdigicali_bknoise_calc_en(void);

/**
 * @brief Disable RF digital calibration BK noise calculation
 */
void ah_rfdigicali_bknoise_calc_dis(void);

/**
 * @brief Get RF digital calibration BK noise valid PD
 * @return Valid PD value
 */
uint32 ah_rfdigicali_bknoise_valid_pd_get(void);

/**
 * @brief Clear RF digital calibration BK noise valid PD
 */
void ah_rfdigicali_bknoise_valid_pd_clr(void);

/**
 * @brief Get RF digital calibration BK noise value
 * @return BK noise value
 */
int8 ah_rfdigicali_bknoise_get(void);


/*
 * Utility Functions
 */

/**
 * @brief Check if MAC address is zero
 * @param addr MAC address
 * @return 1 if zero, 0 otherwise
 */
int32 lmac_mac_is_zero(const uint8 *addr);

/**
 * @brief Calculate partial BSSID
 * @param bssid BSSID
 * @return Partial BSSID value
 */
uint16 partial_bssid_calc(uint8 *bssid);

/**
 * @brief Calculate partial AID
 * @param aid AID value
 * @param bssid BSSID
 * @return Partial AID value
 */
uint16 partial_aid_calc(uint16 aid, uint8 *bssid);

/**
 * @brief Get LOD table kick
 * @param id ID value
 */
void lmac_lo_table_kick(uint16 id);

/**
 * @brief Calculate maximum aggregation bytes
 * @param bw Bandwidth
 * @param mcs MCS index
 * @return Maximum aggregation bytes
 */
uint32 calc_max_agg_bytes(uint32 bw, uint32 mcs);

/**
 * @brief Calculate symbol length
 * @param bytes Byte count
 * @param bw Bandwidth
 * @param mcs MCS index
 * @return Symbol length
 */
uint32 calc_symbol_len(uint32 bytes, uint32 bw, uint32 mcs);

/**
 * @brief Configure FT attenuation value
 */
void config_ft_att_val(uint32 val);   /* arg consumed by the binary: att1/att2 split */

/**
 * @brief Print hex dump
 * @param buf Buffer
 * @param len Length
 */
void hgics_print_hex(void *buf, uint32 len);

/**
 * @brief Get dialog token
 * @return Dialog token
 */
uint8 lmac_dialog_token_next(void);


/*
 * SKB Utility Functions (external declarations)
 */

extern int32 os_sema_up(struct os_semaphore *sem);
extern int32 skb_list_init(struct skb_list *list);
extern uint32 skb_list_count(struct skb_list *list);
extern void assert_internal(const char *__function, unsigned int __line, const char *__assertion);
extern int32 _os_task_set_priority(struct os_task *task, uint8 priority);
extern void lmac_sta_put(void *sta);
extern void *lmac_sta_get(uint16 aid, uint8 *addr);
extern void *lmac_sta_search(uint16 aid, uint8 *addr);
extern uint32 lmac_get_tid(void *hdr);
extern uint32 lmac_get_seq_num(void *hdr);
extern uint32 lmac_get_hdr_len_pv0(void *hdr);
extern uint32 lmac_get_hdr_len_pv1(void *hdr);
extern uint8 *lmac_convert_sid2mac(uint16 sid);
extern uint32 calc_max_agg_bytes(uint32 bw, uint32 mcs);
extern uint32 calc_symbol_len(uint32 bytes, uint32 bw, uint32 mcs);
extern void ah_rfdigicali_tx_pwr(uint32 arg0);
extern void config_ft_att_val(uint32 val);   /* arg consumed by the binary: att1/att2 split */
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


/* Return codes */
#ifndef RET_OK
#define RET_OK      0
#endif
#ifndef RET_ERR
#define RET_ERR     (-1)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _MARS_LMAC_TX_H_ */
