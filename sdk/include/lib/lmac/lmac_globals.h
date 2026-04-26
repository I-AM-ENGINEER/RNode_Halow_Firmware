#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "lmac_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

// LMAC ops/vtable (20 fn pointers, 80 bytes) @ 0x20063734
extern lmac_ops_t ah_ops;

// Main LMAC context (3012 bytes) @ 0x20063784
extern lmac_ctx_t ah_lmac;

// TX subsystem context (1748 bytes) @ 0x20055710
extern lmac_ah_tx_ctx_t ah_lmac_tx;

// RX subsystem context (1416 bytes, opaque) @ 0x20054f68
typedef struct { uint8_t _opaque[0x588]; } lmac_ah_rx_ctx_t;
extern lmac_ah_rx_ctx_t ah_lmac_rx;

// Factory-test/calibration context (76 bytes) @ 0x20064348
typedef struct {
    uint8_t  rsv_000[0x20];
    void    *tx_skb;        // 0x20 — test TX SKB
    uint8_t  rsv_024[0x10];
    void    *tx_payload;    // 0x34 — TX frame payload pointer
    uint8_t  rsv_038[0x0a];
    uint8_t  ctrl_flags;    // 0x42
    uint8_t  rsv_043;
    uint32_t lo_freq;       // 0x44 — LO frequency (kHz)
    uint8_t  rsv_048[0x04];
} lmac_test_ctx_t;
extern lmac_test_ctx_t lmactest;

// RF register shadow (56 × uint16_t, 112 bytes) @ 0x20064394
extern uint16_t rf_regs[56];

// Calibration results
extern int32_t  tx_dcoc_res;           // TX DC-offset cal @ 0x20064404
extern int16_t  rx_dcoc_res[48];       // RX DC-offset cal per gain step @ 0x20064408
extern int16_t  tx_epa_imb_res_pm;     // TX EPA IQ-imbalance phase @ 0x20064468
extern int16_t  min_qdc;               // min Q DC-offset target @ 0x2006446a
extern int16_t  rx_imb_gain_comp[6];   // RX IQ-imbalance gain comp @ 0x2006446c
extern int16_t  tx_epa_imb_res_gm;     // TX EPA IQ-imbalance gain @ 0x20064478
extern int16_t  min_idc;               // min I DC-offset target @ 0x2006447a
extern int16_t  dpd_epa_phase_comp;    // DPD EPA phase comp @ 0x2006447c
extern int16_t  dpd_epa_gain_comp;     // DPD EPA gain comp @ 0x2006447e
extern int32_t  dpd_epa_trx_dcoc_res;  // DPD EPA transceiver DCOC @ 0x20064480
extern int16_t  rx_imb_phase_comp[6];  // RX IQ-imbalance phase comp @ 0x20064484

// Cipher engine context pointer @ 0x20054f54
extern void *ah_cipher;

// Rate control quality sample table (9 bytes) @ 0x20054f5d
extern uint8_t q_sample_tbl[9];

// RX frame-info descriptor queue (512 bytes, opaque) @ 0x200554f8
extern uint8_t frm_info_dq[0x200];

// TX statics
extern uint32_t ft_att_pre;    // prev factory-test attenuation @ 0x20055dec
extern uint64_t pn_num;        // CCMP packet number (48-bit) @ 0x20055df4
extern uint32_t sys_con8_bak;  // saved SYS_CON8 register @ 0x20055e04

// LMAC MAC hardware register base pointer @ 0x20006d1c
extern uint32_t LMAC;

// Deep-sleep context (300 bytes, opaque) @ 0x20005504
typedef struct { uint8_t _opaque[0x12c]; } lmac_dsleep_ctx_t;
extern lmac_dsleep_ctx_t ah_dsleep;

// PHY power/config state (88 bytes, opaque) @ 0x20050e28
extern uint8_t pwphy[0x58];

// DPD coefficient RAM (432 × uint32_t) @ 0x20050e80
extern uint32_t dpd_ram[432];

// RF parameter tables (initialised at boot)
extern uint16_t rf_agc_reg_hw_val[144];  // AGC register shadow @ 0x20006d20
extern uint16_t rf_agcbw_reg_hw_val[128]; // AGC BW register shadow @ 0x20006e40
extern uint16_t rf_reg_hw_val[136];      // general RF register shadow @ 0x20006f40

// Misc data tables
extern int16_t  xo_cs_comp_1[7];    // XO temperature compensation @ 0x20050d28
extern uint32_t rate_tbl[16];        // MCS→PHY rate descriptor table @ 0x20050d36
extern uint8_t  max_byte_table[176]; // max MPDU length per MCS×BW @ 0x20050d78

#ifdef __cplusplus
}
#endif
