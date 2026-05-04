// LMAC context structure - recovered from assembly analysis
// Total size: 3012 bytes (0xbc4)
// Note: tx_power_ctrl_bits may be stored at a different offset than the SDK suggests;
//   the area at 0x370 (880) is occupied by rx_iface_queue/tx_ratio fields.
//   Regmap aliases: 0x311=rate_mode, 0x34a=rc_group_flags, 0x36e=rc_flags, 0x3b8=debug_flags

0    (4) - lmac_ops *ops
4    (184) - struct ah_ce_ctx ce_ctx
              // ah_ce_init(0, ah_lmac.rsv + 4)
188  (4) - uint32_t sta0_added_or_assoc_flag
192  (384) - struct lmac_chan_candidate chan_list[16]
               // stride 24, count 16
               // +0  (4) - uint32_t freq
               // +4  (3) - padding                            // alignment before base_score_or_metric
               // +7  (1) - int8_t   base_score_or_metric
               // +8  (16)- padding                            // unused/reserved space per candidate entry
576  (192) - struct rx_vendor_bss_cache_entry rx_vendor_bss_cache[16]
              // stride 12, count 16
              // +0  (4) - uint32_t key
              // +4  (1) - uint8_t  ie_param0
              // +5  (1) - uint8_t  ie_param1
              // +6  (1) - uint8_t  ie_param2
              // +7  (1) - int8_t   best_rssi_or_metric
              // +8  (1) - uint8_t  ie_param3
               // +9  (3) - padding                            // unused/reserved
768  (1) - uint8_t  obss_threshold
769  (1) - uint8_t  obss_edca_select_flag
770  (6) - uint8_t  mac_addr[6]
776  (1) - uint8_t  bss_bw
777  (1) - uint8_t  pri_channel
778  (2) - padding                                          // alignment before chan_busy_thresholds (u32 at 0x30c)
780  (1) - uint8_t  chan_busy_threshold_0      // 0x30c, init=10 (channel busy % tier 1 boundary)
781  (1) - uint8_t  chan_busy_threshold_1      // 0x30d, init=20 (tier 2 boundary, cumulative: zones 0-10, 10-30)
782  (1) - uint8_t  chan_busy_threshold_2      // 0x30e, init=30 (tier 3 boundary, cumulative: zones 0-10, 10-30, 30-60)
783  (1) - uint8_t  chan_busy_threshold_3      // 0x30f, init=40 (tier 4 boundary, cumulative: 0-10, 10-30, 30-60, 60+)
784  (1) - uint8_t  link_mode_flags            // 0x310, bit1=doze_uplink_en, bit2=obss_cca_mode, bit3=bss_load_en, bit4=agg_en
785  (1) - uint8_t  mcs_encoding_format        // 0x311, init=3; values 1/2/3 select MCS encoding mode
786  (1) - uint8_t  tx_cnt_max_0
              // LMAC_IOCTL_SET_TX_CNT_MAX, ah_lmac.rsv[0x312]
787  (1) - uint8_t  tx_cnt_max_1
              // LMAC_IOCTL_SET_TX_CNT_MAX, ah_lmac.rsv[0x313]
788  (1) - uint8_t  mcast_dup_filter_cfg
              // ah_lmac.rsv[0x314]
              // bits[4:0] - multicast duplicate filter cfg
              // bit5      - SET_MCAST_CLEAR_CHN / clear-channel flag
789  (1) - uint8_t  aggcnt
790  (1) - uint8_t  hw_init_param
791  (1) - uint8_t  sta_priv_alloc_size
792  (1) - uint8_t  ps_timeout_retry_count
              // ah_lmac.rsv[0x318]
              // инкрементируется в tx timeout state 5
              // при превышении 0x1d запускает sleep/AP-lost recovery
793  (1) - uint8_t  sleep_ctrl_flags
              // ah_lmac.rsv[0x319]
              // bit0 clear при истечении bss_rx_activity timeout
              // bit6 выставляется через LMAC_IOCTL_SET_AP_PSMODE_EN
794  (1) - uint8_t  uplink_ctrl_flags0
795  (1) - uint8_t  uplink_ctrl_flags1
796  (1) - int8_t   tx_power_high_threshold
797  (1) - int8_t   tx_power_low_threshold
798  (1) - int8_t   cca_threshold_base
799  (1) - int8_t   agc_threshold_high
800  (1) - int8_t   agc_threshold_low
801  (6) - int8_t   bknoise_gain_ref[6]         // 0x321..0x326, indexed by (ah_wphy_agc_info_get()&0xf) capped at 5
807  (1) - int8_t   bknoise_base_offset          // 0x327, subtracted alongside table entry in lmac_bknoise_get
808  (1) - int8_t   cca_threshold_offset
809  (1) - int8_t   cca_threshold_max
810  (1) - int8_t   s1g_short_beacon_optional_ie_flag
811  (1) - padding                                          // alignment before bgrssi_spur_threshold (int16 at 0x32c)
812  (2) - int16_t  bgrssi_spur_threshold       // 0x32c, init=50; spur count threshold in lmac_bgrssi_update, set via atcmd_bgrssi_spur_hdl
814  (2) - uint16_t rts_threshold
816  (2) - uint16_t ps_heartbeat_period
818  (1) - uint8_t  adc_dump_id               // 0x332; set by atcmd_adc_dump_hdl; lmac_adc_dump fires when (rsv[0x332] == caller_id) and clears to 0
819  (1) - uint8_t  tdma_rx_buff_flags         // 0x333; bit0=TDMA RX buffer adjustment pending (set/cleared in update_rx_buff_addr)
820  (2) - uint16_t tx_bw_len_threshold
822  (2) - uint16_t sta_partial_aid_bits
824  (4) - uint32_t lo_freq_or_channel_bits
828  (1) - uint8_t  lo_table_index
829  (1) - uint8_t  lo_active_freq_b0           // 0x33d, low byte of active channel frequency (kHz), cached on lmac_lo_table_kick
830  (2) - uint16_t lo_active_freq_b1b2         // 0x33e, bits[23:8] of active channel freq (kHz); together with b0 forms 24-bit freq
832  (1) - uint8_t  lo_active_index             // 0x340, current/active LO table channel index; compared to lo_table_index (0x33c) to detect pending LO switch
833  (3) - padding                                          // alignment before s1g_optional_ie_time_value (u32 at 0x344)
836  (4) - uint32_t s1g_optional_ie_time_value
840  (1) - uint8_t  s1g_optional_ie_param
841  (1) - padding                                          // alignment before beacon_s1g_format_flags
842  (1) - uint8_t  beacon_s1g_format_flags                 // 0x34a; also referenced as rc_group_flags in regmap (bit0 used by mars_lmac_rc)
843  (1) - padding                                          // alignment before 0x34c init-zero dword
844  (4) - uint32_t beacon_init_zero_a                      // 0x34c, init=0 in lmac_cfg_init (alongside 0x350)
848  (4) - uint32_t beacon_init_zero_b                      // 0x350, init=0 in lmac_cfg_init (alongside 0x34c)
852  (8) - padding                                          // 0x354-0x35b, gap before acs_sample_count
860  (4) - uint32_t acs_sample_count                        // 0x35c, init=10; ACS noise samples per channel; set via atcmd_acs_start_hdl, used in lmac_auto_channel_select
864  (1) - uint8_t  cca_ctrl_low_byte                       // 0x360, low byte of 32-bit packed CCA/AGC control word (0x360-0x363); bit0=CCA mode flag (checked in lhw_start_cca context)
865  (1) - uint8_t  cca_agc_ctrl_flags
866  (2) - uint16_t rx_gain_cfg_bits
868  (1) - uint8_t  pcf_period                 // 0x364, init=3; PCF CF-Poll period; set via atcmd_pcf_period_hdl (clamped >= 1)
869  (1) - uint8_t  pcf_percent                // 0x365, init=50; PCF airtime percent (0-100); set via atcmd_pcf_percent_hdl (clamped <= 100)
870  (2) - padding                                          // 0x366-0x367, gap before queue indices
872  (4) - uint32_t rx_iface_queue_head                     // 0x368; init=0 in lmac_rx_init; circular buffer head incremented in lmac_iface_task
876  (2) - uint16_t rx_iface_queue_tail                     // 0x36c; init=0 in lmac_rx_init; circular buffer tail incremented in lmac_rx_task
878  (1) - uint8_t  tx_rate_ctrl_flags                      // 0x36e; bit6=tx_rate_fixed_mode (set via atcmd_tx_rate_fixed_hdl, checked in lmac_update_tx_rate)
879  (1) - padding                                          // 0x36f, gap before tx_rx_ratio_statics
880  (4) - uint32_t tx_rx_ratio_statics                     // 0x370; written by lmac_transceive_statics as (TX_time*20)/(RX_time+20); also read as packed freq/channel word in notify case 3
884  (4) - uint32_t tx_freq_or_init_param                   // 0x374, init=0x1000 (4096); written from lmac_cfg_init param; no functional reads found
888  (1) - uint8_t  chan_list_count
889  (1) - uint8_t  bgrssi_chan_index           // 0x379; background RSSI scan index, cycles 0..chan_list_count-1; passed to lmac_lo_table_kick in lmac_bgrssi_update
890  (2) - uint16_t bgrssi_scan_param          // 0x37a, init=20; no functional reads found in .S files
892  (2) - uint16_t auto_chan_switch_flags
894  (2) - uint16_t obss_cca_param_bits
              // bit3      - OBSS CCA / spatial detect enable
              // bits[8:4] - OBSS CCA threshold offset
              // bit10     - BW restore/adapt enable, seen as ah_lmac.rsv[0x37f] & 4
896  (1) - uint8_t txvec_phy_opt;
              // updated on valid NDP CTS RX before lmac_update_frm_tx_vec()
              // bits[1:0] = remapped CTS indication uVar2 via {3,0,1,2}
              // bits[4:2] = parameter from current frame/user context +0xad
              // bits[7:6] preserved
897  (3) - padding                                          // 0x381-0x383, alignment before pv0_ctrl_duration (u32 at 0x384)
900  (4) - uint32_t pv0_ctrl_duration
904  (4) - uint32_t phy_watchdog_period
908  (4) - uint32_t event6_period
912  (4) - uint32_t mode_event_period
916  (4) - uint32_t tick_unit
920  (4) - uint32_t event3_7_period
924  (4) - uint32_t obss_scan_period
928  (4) - uint32_t obss_ap_period
932  (4) - uint32_t hw_scan_interval_us
936  (4) - uint32_t hw_scan_param_3a8
940  (4) - uint32_t periodic_event13_period
944  (4) - uint32_t reset_countdown_period
948  (4) - uint32_t ant_auto_period
952  (4) - uint32_t debug_flags
956  (2) - uint16_t bw_restore_count_threshold;
958  (2) - uint16_t bgr_sample_threshold;
960  (4) - uint32_t ap_sleep_timer_base;       // 0x3c0, set to os_jiffies()
964  (4) - uint32_t ap_sleep_timer_hi_or_mark; // 0x3c4, set to 1, participates in deadline check
968  (2) - uint16_t ap_sleep_timeout_active;   // 0x3c8, added to ap_sleep_timer_base
970  (2) - uint16_t ap_sleep_timeout_reload;   // 0x3ca, copied into active timeout
972  (4) - uint32_t bss_rx_activity_jiffies;   // 0x3cc, set to os_jiffies() on RX/beacon activity
976  (4) - uint32_t bss_rx_activity_ref;       // 0x3d0, RX context / frm_info / beacon timestamp fragment
980  (4)  - uint32_t beacon_timeout_low;
984  (4)  - uint32_t beacon_timeout_high;
988  (2)  - uint16_t ack_timeout_extra
990  (1)  - uint8_t  psconnect_period
991  (1)  - uint8_t  pwr_cca_flags
992  (1)  - uint8_t  rxg_offset
993  (1)  - uint8_t  obss_per
994  (1)  - beacon_misc_flags; // 0x3e2
995  (1)  - unused, init to 0
996  (1)  - txvec_const_phy_opt allways  init to 1
997  (3)  - padding                                          // 0x3e5-0x3e7, alignment before dsleep_target_tsf_low (u32 at 0x3e8)
1000 (4)  - dsleep_target_tsf_low
1004 (4)  - dsleep_target_tsf_high
1008 (259)- struct lmac_ctx_extra_ies extra_ies // буфер для необработанных beacon
1267 (15) - struct lmac_ctx_s1g_capabilities payload S1G Capabilities IE
1282 (18) - struct lmac_ctx_edca_params edca_params
1300 (18) - struct lmac_ctx_edca_params obss_edca_params
1318 (6)  - uint8_t bssid_or_peer_mac[6]
1324 (34) - struct lmac_ctx_ssid
1358 (2)  - padding
1360 (4)  - compressed_ssid
1364 (1)  - uint8_t tim.length
1365 (1)  - uint8_t DTIM Count
1366 (1)  - uint8_t dtim_period
1367 (1)  - uint8_t bitmap_control_bit0
1368 (1)  - uint8_t bitmap_control
1369 (251)- partial_virtual_bitmap[]
1620 (2)  - uint16_t s1g_compat_info
1622 (2)  - uint16_t beacon_interval
1624 (4)  - uint32_t TSF-period value
1628 (4)  - uint32_t beacon counter
1632 (4)  - uint32_t last_beacon_tsf_low
1636 (4)  - uint32_t last_beacon_tsf_high
1640 (2)  - uint16_t s1g_operation_bits
1642 (2)  - padding                                          // 0x66a-0x66b
1644 (2)  - uint16_t tx_time_part0                          // 0x66c
1646 (2)  - uint16_t tx_symbol_duration                     // 0x66e
1648 (2)  - uint16_t tx_time_part2                          // 0x670
1650 (2)  - padding                                          // 0x672-0x673
1652 (2)  - uint16_t beacon_airtime                          // 0x674
1654 (2)  - uint16_t bss_max_idle                            // 0x676
1656 (4)  - int32_t  chip_temp_adj
1660 (4)  - uint32_t vcc_meas_value
1664 (1)  - uint8_t  thermal_pmu_flags
              // bit0      - thermal doze active/requested
              // bits[6:4] - PMU/VREF thermal trim state
1665 (1) - padding                                          // alignment before tx_digi_gain (u16 at 0x682)
1666 (12) - uint16_t tx_digi_gain[6]
              // 0x682..0x68d
              // init читает RF digi gain idx 0..5
              // chip_monitor корректирует idx 0,1,5
              // SET_TXPOWER обновляет idx 3..5

1678 (1)  - uint8_t  tx_power
1679 (1)  - uint8_t  xo_cs_trim_offset
1680 (1) - uint8_t  chan_score_weight_a
1681 (1) - uint8_t  chan_score_weight_b
1682 (34) - struct lmac_ctx_key key0
1716 (34) - struct lmac_ctx_key key1
1750 (2) - padding                                          // 0x6d6-0x6d7, alignment before vdd13b_meas_value (u32 at 0x6d8)
1752 (4)  - uint32_t vdd13b_meas_value
1756 (4)  - uint32_t vdd13c_meas_value
1760 (4) - uint32_t tx_success_pkt_count                   // 0x6e0; TX packet/success counter; copied from 0x744 in lmac_transceive_statics; read in atcmd_tx_pkts_rd_hdl
1764 (4) - uint32_t tx_fail_err_count                      // 0x6e4; TX fail/error counter; copied from 0x758 in lmac_transceive_statics; read in atcmd_tx_fail_rd_hdl; percentage = 100*0x6e4/0x6e0
1768 (4)  - uint32_t last_tx_mcs
1772 (4)  - uint32_t last_tx_bw_sig
1776 (4)  - uint32_t tx_some_counter_6f0                     // 0x6f0; R/W, word
1780 (4)  - uint32_t tx_some_counter_6f4                     // 0x6f4; R/W, word
1784 (8)  - uint32_t padding_6f8_6fb                         // 0x6f8-0x6fb; R/W u32 at 0x6f8, then byte flags at 0x708-0x710
1792 (4)  - uint32_t tx_state_700                             // 0x700; R/W, word
1796 (4)  - uint32_t tx_state_704                             // 0x704; R/W, word
1800 (1)  - uint8_t  tx_flags_708                             // 0x708; R/W, byte
1801 (3)  - padding                                          // 0x709-0x70b
1804 (1)  - uint8_t  tx_write_flags_70c                       // 0x70c; W-only, byte (part of 4-byte write block)
1805 (1)  - uint8_t  tx_write_flags_70d                       // 0x70d; W-only, byte
1806 (1)  - uint8_t  tx_write_flags_70e                       // 0x70e; W-only, byte
1807 (1)  - uint8_t  tx_flags_70f                             // 0x70f; R/W, byte
1808 (1)  - uint8_t  tx_write_only_710                        // 0x710; W-only, byte
1809 (1)  - padding                                          // 0x711
1810 (2)  - int16_t  rx_dcoc_i_offset                         // 0x712; R/W, hword
1812 (2)  - int16_t  rx_dcoc_q_offset                         // 0x714; R/W, hword
1814 (2)  - padding                                          // 0x716-0x717
1816 (4)  - uint32_t ac_pd_irq_tx_attempt_count               // 0x718; R/W
1820 (4)  - uint32_t ac_pd_read_only_71c                      // 0x71c; R-only, word
1824 (4)  - uint32_t ac_pd_read_only_720                      // 0x720; R-only, word
1828 (4)  - uint32_t ac_pd_read_only_724                      // 0x724; R-only, word
1832 (4)  - uint32_t ac_pd_read_only_728                      // 0x728; R-only, word
1836 (4)  - uint32_t tx_queue_state_72c                       // 0x72c; R/W, word
1840 (4)  - uint32_t tx_queue_state_730                       // 0x730; R/W, word
1844 (4)  - uint32_t tx_queue_state_734                       // 0x734; R/W, word; loaded/stored in mars_lmac_tx
1848 (4)  - uint32_t tx_queue_state_738                       // 0x738; R/W, word; loaded/stored in mars_lmac_tx
1852 (4)  - uint32_t tx_queue_state_73c                       // 0x73c; R/W, word
1856 (4)  - uint32_t tx_duration_low                          // 0x740; R/W, word; TX duration low part, used in lmac_transceive_statics
1860 (4)  - uint32_t tx_duration_high                         // 0x744; R/W, word; TX duration high part; copied to tx_success_pkt_count (0x6e0) in lmac_transceive_statics
1864 (4)  - uint32_t tx_state_748                             // 0x748; R/W, word
1868 (4)  - uint32_t tx_queue_state_74c                       // 0x74c; R/W, word; loaded/stored in mars_lmac_tx
1872 (4)  - uint32_t rx_duration_low                          // 0x750; R/W, word; RX duration low part
1876 (4)  - uint32_t rx_queue_state_754                       // 0x754; R/W, word; loaded/stored in mars_lmac_tx/mars_lmac_test
1880 (4)  - uint32_t rx_duration_high                         // 0x758; R/W, word; RX duration high part; copied to tx_fail_err_count (0x6e4) in lmac_transceive_statics
1884 (4)  - uint32_t tx_state_75c                             // 0x75c; R/W, word; loaded/stored in mars_lmac_tx
1888 (4)  - uint32_t tx_state_760                             // 0x760; R/W, word; loaded/stored in mars_lmac_tx
1892 (4)  - uint32_t tx_state_764                             // 0x764; R/W, word; loaded/stored in mars_lmac_tx
1896 (4)  - uint32_t tx_queue_entry_768                       // 0x768; R/W, word; loaded/stored in mars_lmac_tx/mars_lmac_test
1900 (4)  - uint32_t tx_queue_state_76c                       // 0x76c; R/W, word
1904 (4)  - uint32_t tx_queue_state_770                       // 0x770; R/W, word; loaded/stored in mars_lmac_rx
1908 (4)  - uint32_t tx_queue_state_774                       // 0x774; R/W, word; loaded/stored in mars_lmac_rx
1912 (4)  - uint32_t tx_queue_state_778                       // 0x778; R/W, word; loaded/stored in mars_lmac_rx
1916 (4)  - uint32_t tx_write_only_77c                        // 0x77c; W-only, word; set in mars_lmac_rx
1920 (4)  - uint32_t tx_write_only_780                        // 0x780; W-only, word; set in mars_lmac_rx
1924 (4)  - uint32_t tx_state_784                             // 0x784; R/W, word; loaded/stored in mars_lmac_rx
1928 (4)  - uint32_t tx_state_788                             // 0x788; R/W, word; loaded/stored in mars_lmac_rx
1932 (4)  - uint32_t tx_state_78c                             // 0x78c; R/W, word; loaded/stored in mars_lmac_rx
1936 (4)  - uint32_t tx_state_790                             // 0x790; R/W, word; loaded/stored in mars_lmac_rx
1940 (4)  - uint32_t tx_state_794                             // 0x794; R/W, word; loaded/stored in mars_lmac_rx/mars_lmac.S
1944 (4)  - uint32_t tx_state_798                             // 0x798; R/W, word; loaded/stored in mars_lmac_rx
1948 (4)  - uint32_t tx_state_79c                             // 0x79c; R/W, word; loaded/stored in mars_lmac_rx/mars_lmac_test (cleared to 0)
1952 (4)  - uint32_t tx_state_7a0                             // 0x7a0; R/W, word
1956 (4)  - uint32_t tx_state_7a4                             // 0x7a4; R/W, word
1960 (4)  - uint32_t tx_state_7a8                             // 0x7a8; R/W, word
1964 (4)  - uint32_t tx_state_7ac                             // 0x7ac; R/W, word; loaded/stored in mars_lmac_tx
1968 (4)  - uint32_t tx_retry_count_7b0                       // 0x7b0; R/W, word; TX retry counter, loaded/stored in mars_lmac_tx
1972 (4)  - uint32_t tx_retry_limit_7b4                       // 0x7b4; R/W, word; TX retry limit, loaded/stored in mars_lmac_tx
1976 (4)  - uint32_t tx_state_7b8                             // 0x7b8; R/W, word
1980 (4)  - uint32_t tx_state_7bc                             // 0x7bc; R/W, word
1984 (4)  - uint32_t tx_state_7c0                             // 0x7c0; R/W, word
1988 (4)  - uint32_t tx_state_7c4                             // 0x7c4; R/W, word
1992 (4)  - uint32_t tx_state_7c8                             // 0x7c8; R/W, word; loaded/stored in mars_lmac_rx
1996 (4)  - uint32_t tx_state_7cc                             // 0x7cc; R/W, word; loaded/stored in mars_lmac_rx
2000 (4)  - uint32_t tx_state_7d0                             // 0x7d0; R/W, word; loaded/stored in mars_lmac_rx
2004 (4)  - uint32_t tx_state_7d4                             // 0x7d4; R/W, word; loaded/stored in mars_lmac_rx
2008 (4)  - uint32_t tx_state_7d8                             // 0x7d8; R/W, word; loaded/stored in mars_lmac_rx
2012 (4)  - uint32_t tx_state_7dc                             // 0x7dc; R/W, word; loaded/stored in mars_lmac_rx
2016 (4)  - uint32_t tx_state_7e0                             // 0x7e0; R/W, word; loaded/stored in mars_lmac_tx
2020 (2)  - uint16_t tx_state_7e4                             // 0x7e4; R/W, hword/hs; loaded as halfword in mars_lmac_tx
2022 (2)  - uint16_t tx_state_7e6                             // 0x7e6; R/W, hword; loaded/stored in mars_lmac_tx
2024 (2)  - uint16_t tx_state_7e8                             // 0x7e8; R/W, hword; loaded/stored in mars_lmac_tx
2026 (2)  - padding                                          // 0x7ea-0x7eb
2028 (4)  - uint32_t tx_state_7ec                             // 0x7ec; R/W, word; set to 6 in mars_lmac_tx
2032 (4)  - uint32_t tx_state_7f0                             // 0x7f0; R/W, word; set to 7 in mars_lmac_tx
2036 (4)  - uint32_t tx_state_7f4                             // 0x7f4; R/W, word; set in mars_lmac_tx
2040 (4)  - uint32_t tx_state_7f8                             // 0x7f8; R/W, word; loaded/stored in mars_lmac_rx
2044 (4)  - padding                                          // 0x7fc, no assembly access
2048 (4)  - uint32_t tx_channel_state_800                     // 0x800; R/W, word; loaded/stored in mars_lmac.S/mars_lmac_rx
2052 (2)  - uint16_t tx_state_804                             // 0x804; R/W, hword; loaded/stored in mars_lmac_util
2054 (2)  - uint16_t tx_state_806                             // 0x806; R/W, hword; loaded/stored in mars_lmac_util
2056 (4)  - uint32_t tx_state_808                             // 0x808; R/W, word; loaded/stored in mars_lmac.S/mars_lmac_tx
2060 (4)  - uint32_t tx_state_80c                             // 0x80c; R/W, word; loaded/stored in mars_lmac.S/mars_lmac_tx
2064 (4)  - uint32_t tx_state_810                             // 0x810; R/W, word; loaded/stored in mars_lmac.S/mars_lmac_tx
2068 (4)  - uint32_t tx_state_814                             // 0x814; R/W, word; loaded/stored in mars_lmac.S/mars_lmac_tx
2072 (4)  - padding                                          // 0x818-0x81b
2076 (4)  - uint32_t tx_state_81c                             // 0x81c; R/W, word; loaded in mars_lmac.S, stored at end of function
2080 (4)  - uint32_t tx_write_only_820                        // 0x820; W-only, word; set to 1 in mars_lmac.S
2084 (4)  - uint32_t tx_channel_set_824                       // 0x824; R/W, word; loaded/stored in mars_lmac.S
2088 (4)  - uint32_t tx_channel_state_828                     // 0x828; R/W, word; loaded/stored in mars_lmac_rx
2092 (4)  - uint32_t tx_result_82c                            // 0x82c; W-only, word; set from r8 in mars_lmac_rx
2096 (4)  - uint32_t tx_result_830                            // 0x830; W-only, word; set from r2 in mars_lmac_rx
2100 (4)  - uint32_t tx_result_834                            // 0x834; W-only, word; set from r6 in mars_lmac_rx
2104 (2)  - uint16_t rx_dcoc_i_last                           // 0x838; R/W, hword/hs; loaded as signed halfword in mars_lmac.S
2106 (2)  - int16_t  rx_dcoc_q_last                           // 0x83a; R/W, hword/hs; loaded as signed halfword in mars_lmac.S
2108 (1)  - padding                                          // 0x83c
2109 (1)  - uint8_t  tx_byte_83d                              // 0x83d; R/W, byte; signed byte load in mars_lmac.S/mars_lmac_tx/mars_lmac_rx; cleared to 0 in mars_lmac.S
2110 (1)  - uint8_t  tx_write_byte_83e                        // 0x83e; W-only, byte; set from r5 in mars_lmac_tx
2111 (1)  - padding                                          // 0x83f
2112 (1)  - uint8_t  tx_byte_840                              // 0x840; R/W, byte
2113 (1)  - uint8_t  tx_write_byte_841                        // 0x841; W-only, byte
2114 (2)  - padding                                          // 0x842-0x843
2116 (4)  - uint32_t tx_state_844                             // 0x844; R/W, word; loaded in mars_lmac.S/mars_lmac_tx
2120 (4)  - uint32_t tx_write_word_848                        // 0x848; W-only, word
2124 (2)  - int16_t  chan_scan_rssi[0]                        // 0x84c; R-only, hword; channel scan RSSI entry 0, loaded from lmac_auto_channel_select context
2126 (2)  - int16_t  chan_scan_rssi[1]                        // 0x84e; R-only, hword; channel scan RSSI entry 1
2128 (2)  - int16_t  chan_scan_rssi[2]                        // 0x850; R-only, hword; channel scan RSSI entry 2
2130 (2)  - int16_t  chan_scan_rssi[3]                        // 0x852; R-only, hword; channel scan RSSI entry 3
2132 (2)  - int16_t  chan_scan_rssi[4]                        // 0x854; R-only, hword; channel scan RSSI entry 4
2134 (2)  - int16_t  chan_scan_rssi[5]                        // 0x856; R-only, hword; channel scan RSSI entry 5
2136 (2)  - int16_t  chan_scan_rssi[6]                        // 0x858; R-only, hword; channel scan RSSI entry 6
2138 (2)  - int16_t  chan_scan_rssi[7]                        // 0x85a; R-only, hword; channel scan RSSI entry 7
2140 (2)  - int16_t  chan_scan_rssi[8]                        // 0x85c; R-only, hword; channel scan RSSI entry 8
2142 (2)  - int16_t  chan_scan_rssi[9]                        // 0x85e; R-only, hword; channel scan RSSI entry 9
2144 (1)  - uint8_t  tx_byte_860                              // 0x860; R/W, byte
2145 (3)  - padding                                          // 0x861-0x863
2148 (1)  - uint8_t  tx_mcs_max_limit                         // 0x864
2149 (1)  - uint8_t  tx_mcs_min_limit                        // 0x865
2150 (1)  - uint8_t  tx_mcs                                  // 0x866
2151 (1)  - uint8_t  tx_bw_sig                               // 0x867; also referenced as phy_rate_byte in regmap
2152 (1)  - uint8_t  mcast_tx_rate                           // 0x868
2153 (1)  - uint8_t  mcast_txbw                              // 0x869
2154 (11) - padding                                          // 0x86a-0x874, gap before tx_bw_ctrl_flags at 0x875
2165 (1)  - uint8_t  tx_bw_ctrl_flags                        // 0x875
2166 (1)  - uint8_t  gpio0_pin_flags                          // 0x876
2167 (1)  - uint8_t  gpio1_pin_flags                          // 0x877
2168 (1)  - uint8_t  cfend_or_cfp_active_flags                // 0x878
2169 (3)  - padding                                          // 0x879-0x87b, gap before cfpoll_duration_calc
2172 (2)  - uint16_t cfpoll_duration_calc                     // 0x87c
2174 (2)  - uint16_t tx_timestamp_disable_or_reset_flag       // 0x87e
2176 (16) - padding                                          // 0x880-0x88f, gap before qa_tx_thresholds at 0x890
2192 (1)  - uint8_t  qa_tx_thresholds[0]                     // 0x890; QA TX threshold byte 0; stored in mars_lmac_tx timeout path
2193 (1) - uint8_t  qa_tx_thresholds[1]                     // 0x891; QA TX threshold byte 1; stored/cleared in mars_lmac_tx/mars_lmac_rx
2194 (1) - uint8_t  qa_freq_hop_flags                       // 0x892; QA frequency hopping flags; heavily read/written across mars_lmac_tx, mars_lmac_rx, mars_lmac_test, mars_lmac_util
2195 (1) - padding                                          // 0x893, gap between qa_freq_hop_flags and qa_tx_thresholds[2]
2196 (4) - uint32_t qa_tx_params_word0                      // 0x894-0x897; set as word+bytes in mars_lmac_test; qa_tx_thresholds[2..5] may be packed here
2200 (1) - uint8_t  qa_tx_thresholds[6]                     // 0x898; QA RX metric 0 per SDK; accessed in mars_lmac_test
2201 (1) - uint8_t  qa_tx_thresholds[7]                     // 0x899; QA RX metric 1 per SDK; compared/loaded in mars_lmac_test
2202 (1) - int8_t   qa_rx_metric_2                          // 0x89a; QA RX metric 2; compared in mars_lmac_tx timeout path, loaded in mars_lmac_test/mars_lmac.S
2203 (1) - int8_t   qa_rx_metric_3                          // 0x89b; QA RX metric 3; stored/cleared in mars_lmac_test
2204 (1) - int8_t   qa_rx_metric_4                          // 0x89c; QA RX metric 4; loaded/compared in mars_lmac_rx/mars_lmac_util, stored in mars_lmac_test
2205 (1) - uint8_t  qa_rx_metric_reserved                   // 0x89d; reserved per SDK; stored from r0 in mars_lmac_test
2206 (2) - int16_t  qa_rx_metric_5                          // 0x89e-0x89f; QA RX metric 5 (halfword); signed byte loads in mars_lmac.S/mars_lmac_test
2208 (2) - padding                                          // 0x8a0-0x8a1, reserved per SDK
2210 (1) - int8_t   qa_rx_avg_power                          // 0x8a2; QA RX average power; stored in mars_lmac_test
2211 (1) - int8_t   qa_rx_avg_evm                            // 0x8a3; QA RX average EVM; stored in mars_lmac_test
2212 (1) - int8_t   qa_rx_freq_offset                        // 0x8a4; QA RX frequency offset; stored in mars_lmac_test, loaded in mars_lmac_util
2213 (1) - uint8_t  qa_rx_agc_index                          // 0x8a5; QA RX AGC index; stored in mars_lmac_test, loaded as signed in mars_lmac.S/mars_lmac_util
2214 (2) - padding                                          // 0x8a6-0x8a7, reserved
2216 (1) - int8_t   qa_rx_metric_6                           // 0x8a8; stored in mars_lmac_test
2217 (1) - int8_t   qa_rx_metric_7                           // 0x8a9; stored in mars_lmac_test
2218 (1) - int8_t   qa_rx_metric_8                           // 0x8aa; stored in mars_lmac_test
2219 (1) - int8_t   qa_rx_metric_9                           // 0x8ab; stored in mars_lmac_test
2220 (1) - uint8_t  qa_rx_threshold_flags                    // 0x8ac; QA RX threshold flags; stored/loaded across mars_lmac_tx, mars_lmac_rx, mars_lmac_test, mars_lmac.S
2221 (1) - uint8_t  qa_tx_threshold_flags                    // 0x8ad; QA TX threshold flags; stored/loaded in mars_lmac_tx/mars_lmac_rx/mars_lmac_test; loaded as signed in mars_lmac.S
2222 (1) - uint8_t  rf_temp_calib[0]                         // 0x8ae; RF temp calibration byte 0; stored/compared in mars_lmac_tx/mars_lmac_test, loaded as signed in mars_lmac.S
2223 (1) - uint8_t  rf_temp_calib[1]                         // 0x8af; RF temp calibration byte 1; stored in mars_lmac_tx/mars_lmac_test
2224 (1) - uint8_t  rf_temp_calib[2]                         // 0x8b0; RF temp calibration byte 2; stored from r0/r2 in mars_lmac_tx/mars_lmac_rx; used in timeout calc
2225 (1) - uint8_t  rf_temp_calib[3]                         // 0x8b1; RF temp calibration byte 3; stored as hword low byte in mars_lmac_tx
2226 (2) - uint16_t rf_temp_calib[4]                         // 0x8b2-0x8b3; RF temp calibration hword; stored as word in mars_lmac_tx; loaded as hword in mars_lmac_test/mars_lmac.S
2228 (2) - uint16_t init_param_rxbuf_size                    // 0x8b4-0x8b5; lmac_init_param.rxbuf_size (u16); init_param starts at 0x8b4
2230 (4) - void    *init_param_rxbuf                          // 0x8b6-0x8b9; lmac_init_param.rxbuf (pointer); stored/loaded in mars_lmac_tx
2234 (4) - void    *init_param_tdma_buff                     // 0x8ba-0x8bd; lmac_init_param.tdma_buff (pointer)
2238 (4) - uint32_t init_param_rxbuf_size2                   // 0x8be-0x8c1; possibly duplicate or tdma_buff_size
2242 (1) - uint8_t  init_param_uart_tx_io                    // 0x8c2; lmac_init_param.uart_tx_io; compared against frame bytes in lmac_rx_pv0_ctrl_ba
2243 (1) - uint8_t  init_param_dual_ant                      // 0x8c3; lmac_init_param.dual_ant flag; compared against frame bytes
2244 (1) - uint8_t  init_param_field_8c4                     // 0x8c4; init_param byte; compared against frame bytes; read in lmac_transceive_statics
2245 (1) - uint8_t  init_param_field_8c5                     // 0x8c5; compared against frame bytes; read in lmac_transceive_statics
2246 (1) - uint8_t  init_param_field_8c6                     // 0x8c6; compared against frame bytes; read in lmac_transceive_statics
2247 (1) - uint8_t  init_param_field_8c7                     // 0x8c7; compared against frame bytes; read in lmac_transceive_statics (as r8)
2248 (1) - uint8_t  tdma_aux_timing_b0                     // 0x8c8; TDMA timing byte 0; bit[4:0] updated in lmac_rx_pv0_ctrl_ba
2249 (1) - uint8_t  tdma_aux_timing_b1                     // 0x8c9; TDMA timing byte 1; stored from frame byte[1]; read as signed in lmac_transceive_statics
2250 (2) - padding                                          // 0x8ca-0x8cb, gap
2252 (4) - uint32_t qa_rx_channel_map                       // 0x8cc; widely read as word across mars_lmac, mars_lmac_cfg, mars_lmac_rx, mars_lmac_tx, mars_lmac_test
2256 (8) - padding                                          // 0x8d0-0x8d7, gap
2264 (4) - uint32_t ba_resp_timeout_or_tdma                 // 0x8d8; TDMA/BA timeout word
2268 (80) - padding                                         // 0x8dc-0x92b, gap
2348 (4) - uint32_t tx_vec_hdr_config                       // 0x92c; TX vector header config
2352 (40) - padding                                         // 0x930-0x957, gap before pv0_cfend_frame at 0x958
2392 (16) - struct pv0_cfend_frame pv0_cfend
              // ah_lmac.rsv + 0x958
              // lhw_cfg_tx_sub_frm(..., ah_lmac.rsv + 0x958, 0x10)
              // +0  (2) - uint16_t frame_control
              // +2  (2) - uint16_t duration
              // +4  (6) - uint8_t  receiver_mac[6]
              // +10 (6) - uint8_t  bssid_or_self_mac[6]
2408 (16) - struct pv0_pspoll_frame pv0_pspoll
                // ah_lmac.rsv + 0x968
                // lhw_cfg_tx_sub_frm(..., ah_lmac.rsv + 0x968, 0x10)
                // +0  (2) - uint16_t frame_control
                // +2  (2) - uint16_t aid
                // +4  (6) - uint8_t  bssid[6]
                // +10 (6) - uint8_t  self_mac[6]
2424 (1)  - uint8_t  mac_state_978                            // 0x978; R/W, byte; accessed in mars_lmac_tx (bit manipulation with ins instruction, bits 3-4 used)
2425 (3)  - padding                                          // 0x979-0x97b
2428 (20) - padding                                          // 0x97c-0x98f, no assembly access
2448 (4)  - uint32_t frame_rx_state                          // 0x990; R/W, word; set to 0 in mars_lmac_tx/rx, set/loaded in mars_lmac_tx (state machine counter for frame RX)
2452 (4)  - uint32_t rx_frame_counter                        // 0x994; R/W, word; set to 0 in mars_lmac_rx incrementing counter, read in mars_lmac_tx
2456 (4)  - uint32_t rx_frame_byte_count                     // 0x998; R/W, word; loaded in mars_lmac_tx/rx, stored with RX byte data
2460 (4)  - uint32_t rx_frame_info                           // 0x99c; R/W, word; loaded/stored in mars_lmac_tx/rx, set to 0 in mars_lmac_test
2464 (20) - padding                                          // 0x9a0-0x9b3, no assembly access
2484 (4)  - uint32_t tx_active_flags                         // 0x9b4
2488 (12) - padding                                          // 0x9b8-0x9c3
2500 (1)  - uint8_t  tx_write_only_9c4                       // 0x9c4; W-only byte; set from r3 in mars_lmac
2501 (3)  - padding                                          // 0x9c5-0x9c7
2504 (2)  - uint16_t tx_state_9c8                            // 0x9c8
2506 (2)  - padding                                          // 0x9ca-0x9cb
2508 (4)  - padding                                          // 0x9cc-0x9cf
2512 (20) - struct os_task main_task                        // 0x9d0-0x9e3
2532 (4) - uint32_t                                         // 0x9e4
2536 (4) - uint32_t                                         // 0x9e8
2540 (8) - struct os_semaphore                               // 0x9ec-0x9f3
2548 (20) - struct os_task print_task                        // 0x9f4-0xa07
2568 (1) - uint8_t  tx_ac_state_flags                        // 0xa08
               // ah_lmac.rsv[0xa08]
               // signed < 0 означает active/timeout-sensitive TX state
               // bits[3:0] = AC index / queue index
2569 (1) - uint8_t  beacon_pending_state_flags               // 0xa09
2570 (1) - padding                                          // 0xa0a, gap
2571 (1) - uint8_t  beacon_obss_slot_flags                   // 0xa0b
2572 (1) - uint8_t  irq_ac_control_flags                     // 0xa0c; bit0: если set, не вызывается lhw_enable_irq_ac()
2573 (1) - padding                                          // 0xa0d, gap
2574 (1) - uint8_t  tx_global_flags                          // 0xa0e; bit1 используется в tx-rate path / special TX mode
2575 (1) - padding                                          // 0xa0f, gap before tdma_buff
2576 (4) - void    *tdma_buff                                // 0xa10
2580 (4) - uint32_t tdma_buff_size                           // 0xa14
2584 (8) - padding                                          // 0xa18-0xa1f
2592 (8) - struct os_mutex sta_list_mutex                     // 0xa20-0xa27
2600 (28) - struct os_timer tick_timer                        // 0xa28-0xa43
2628 (28) - struct os_timer scan_timer                        // 0xa44-0xa5f
2656 (4) - uint32_t last_rx_pv0_ctrl_info                     // 0xa60; R/W word/hword
2660 (28) - padding                                          // 0xa64-0xa7f; gap
2688 (4) - uint32_t evt_queue_head                            // 0xa80; event queue write pointer
2692 (4) - uint32_t evt_queue_tail                            // 0xa84; event queue read pointer (cleared in lmac_init, consumed by lmac_chip_monitor)
2696 (4) - uint32_t evt_queue_capacity                        // 0xa88; event queue capacity (set to 0x40=64 in lmac_init)
2700 (4) - uint32_t evt_write_index                           // 0xa8c; current write index into evt_ring (used as index for event slot assignment)
2704 (4) - uint32_t evt_slot_count                           // 0xa90; event slot counter or related index
2708 (116) - uint32_t evt_ring[29]                            // 0xa94-0xb07; event ring buffer entries (29×4=116 bytes); events 0x06/0x0a/0x0b written here
2824 (28) - padding                                          // 0xb08-0xb23; gap after evt_ring
2852 (8) - struct os_semaphore main_sem                       // 0xb24-0xb2b; main semaphore (SDK: main_sem)
2860 (24) - uint8_t main_runtime_info[24]                     // 0xb2c-0xb43; main runtime info block (SDK: main_runtime_info[0x18])
2884 (16) - padding                                          // 0xb44-0xb53; gap
2900 (4) - uint32_t free_kb                                  // 0xb54; free kernel buffer count (SDK: free_kb)
2904 (68) - padding                                         // 0xb58-0xb9b; gap
2972 (4) - uint32_t tsf_low_at_sleep                          // 0xb9c; TSF64 low snapshot
2976 (4) - uint32_t tsf_high_at_sleep                         // 0xba0; TSF64 high snapshot; read in sleep/wakeup path
2980 (4) - uint32_t tsf_last_beacon_low                       // 0xba4; TSF64 low from last beacon (R-only)
2984 (4) - uint32_t tsf_last_beacon_high                      // 0xba8; TSF64 high from last beacon (R-only)
2988 (4) - uint32_t tsf_target_low                            // 0xbac; TSF64 low target for next scheduled event (R-only)
2992 (4) - uint32_t skbpool_free_units                        // 0xbb0; R/W word; free skb pool count (skbpool_freesize(1)>>0xb, checked for pool exhaustion)
2996 (1) - uint8_t  rx_frame_flag                             // 0xbb4; RX frame active flag (bit0=set in lmac_rx_frm_hdl, cleared in lmac_rx_cleanup_info)
2997 (11) - padding                                          // 0xbb5-0xbbf
3008 (4) - padding                                           // 0xbc0-0xbc3; end padding
3012 (0)  - padding                                            // end, total structure size = 3012 bytes (0xbc4)

