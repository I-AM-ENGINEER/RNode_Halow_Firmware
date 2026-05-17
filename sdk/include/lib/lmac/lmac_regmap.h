#pragma once

#include "typesdef.h"

/* Hardware MMIO bases for LMAC peripheral blocks */
#define LMAC_HW_BASE_ADDR           0x40008000UL /* MAC/LMAC FSM, timing, IRQ, RF gate registers. */
#define LMAC_TDMA_BASE_ADDR         0x40001000UL /* First TDMA capture/playback DMA engine. */
#define LMAC_TDMA2_BASE_ADDR        0x4000b000UL /* Second TDMA capture/playback DMA engine. */
#define LMAC_RFSPI_BASE_ADDR        0x4001b000UL /* RF serial peripheral interface controller. */
#define LMAC_RFDIGICALI_BASE_ADDR   0x4001d000UL /* RF digital calibration engine. */

#define LMAC_WRITE_REG(reg_, val_) ((reg_) = (val_))
#define LMAC_SET_BIT(reg_, mask_) ((reg_) |= (mask_))
#define LMAC_CLEAR_BIT(reg_, mask_) ((reg_) &= ~(mask_))
#define LMAC_REG_IS_SET(reg_, mask_) (((reg_) & (mask_)) != 0U)
#define LMAC_REG_IS_CLEAR(reg_, mask_) (((reg_) & (mask_)) == 0U)
#define LMAC_CLEAR_BITS_RMW(reg_, clear_mask_) \
    do { \
        uint32 val = (reg_); \
        val &= (clear_mask_); \
        (reg_) = val; \
    } while (0)
#define LMAC_SET_BITS_RMW(reg_, set_mask_) \
    do { \
        uint32 val = (reg_); \
        val |= (set_mask_); \
        (reg_) = val; \
    } while (0)

typedef struct {
    volatile uint32 CTRL;            /* 0x000: TDMA Control register */
    volatile uint32 STATUS;          /* 0x004: TDMA Status register */
    volatile uint32 STADDR;          /* 0x008: TDMA Start Address register */
    volatile uint32 LEN;             /* 0x00C: TDMA data Length register */
    volatile uint32 REM;             /* 0x010: TDMA REM register */
    volatile uint32 TRLEN;           /* 0x014: TDMA Transmit Length register */
    volatile uint32 TRADDR;          /* 0x018: TDMA Target Address register */
} LMAC_TDMA_t;

typedef struct {
    volatile uint32 CFG;             /* 0x000: Clock/divider/mode configuration */
    volatile uint32 CTRL;            /* 0x004: Transaction mode/delay control */
    volatile uint32 RESERVED_008;    /* 0x008 */
    volatile uint32 STATUS;          /* 0x00C: Done/pending status */
    volatile uint32 CMD;             /* 0x010: Packed RF register address/data command word */
    volatile uint32 RDATA;           /* 0x014: Read result word */
    volatile uint32 RESERVED_018[2]; /* 0x018..0x01C */
    volatile uint32 SETUP0;          /* 0x020: Transaction setup word 0 */
    volatile uint32 SETUP1;          /* 0x024: Transaction setup word 1 */
} LMAC_RFSPI_t;

typedef struct {
    volatile uint32 MACADDRL;        /* 0x000: MAC address low */
    volatile uint32 MACADDRH;        /* 0x004: MAC address high */
    volatile uint32 AID;             /* 0x008: Association ID */
    volatile uint32 RESERVED_00C;    /* 0x00c */
    volatile uint32 TSFL;           /* 0x010: TSF low word */
    volatile uint32 TSFH;           /* 0x014: TSF high word */
    volatile uint32 NAV_CNT;         /* 0x018: NAV counter */
    volatile uint32 SIFS_INIT;      /* 0x01c: SIFS/slot/EIFS timing */
    volatile uint32 BO_CNT0;        /* 0x020: Backoff counter 0 / CCA control */
    volatile uint32 BO_CNT1;         /* 0x024: Backoff counter 1 */
    volatile uint32 RESERVED_028;    /* 0x028 */
    volatile uint32 FSM_TSF;         /* 0x02c: FSM TSF */
    volatile uint32 FSM_CFG;        /* 0x030: FSM configuration/control */
    volatile uint32 FSM_STAT;       /* 0x034: FSM status */
    volatile uint32 FSM_TSF1;        /* 0x038: FSM TSF1 */
    volatile uint32 RAND_GEN;        /* 0x03c: Random number generator */
    volatile uint32 COMN_CTRL;      /* 0x040: Common control */
    volatile uint32 IRQ_EN;          /* 0x044: Interrupt enable */
    volatile uint32 IRQ_PD;         /* 0x048: Interrupt pending/clear */
    volatile uint32 AC_PD;           /* 0x04c: AC pending */
    volatile uint32 RESERVED_050;    /* 0x050 */
    volatile uint32 FCS_RES;         /* 0x054: FCS result */
    volatile uint32 AGGR_CTRL;      /* 0x058: Aggregation/TX control */
    volatile uint32 END_TO_LIMIT;    /* 0x05c: End-to limit */
    volatile uint32 RESERVED_060;    /* 0x060 */
    volatile uint32 TXVEC1;          /* 0x064: TX vector 1 */
    volatile uint32 TXVEC2;          /* 0x068: TX vector 2 */
    volatile uint32 TXVEC3;          /* 0x06c: TX vector 3 */
    volatile uint32 TXVEC4;          /* 0x070: TX vector 4 */
    volatile uint32 TX_STAT;         /* 0x074: TX status */
    volatile uint32 TX_DLY1;        /* 0x078: TX delay 1 */
    volatile uint32 TX_BYTCNT;       /* 0x07c: TX byte count */
    volatile uint32 TX_EOFBYT;       /* 0x080: TX end-of-byte */
    volatile uint32 TX_DLY2;        /* 0x084: TX delay 2 */
    volatile uint32 TX_PRBS_GEN;     /* 0x088: TX PRBS generator */
    volatile uint32 TX_DLY3;        /* 0x08c: TX delay 3 */
    volatile uint32 RESERVED_090[4]; /* 0x090..0x09f */
    volatile uint32 RX_CTRL;        /* 0x0a0: RX control */
    volatile uint32 RXVEC1;         /* 0x0a4: RX vector 1 */
    volatile uint32 RXVEC2;         /* 0x0a8: RX vector 2 */
    volatile uint32 RXVEC3;          /* 0x0ac: RX vector 3 */
    volatile uint32 RXVEC4;          /* 0x0b0: RX vector 4 */
    volatile uint32 RX_STAT;        /* 0x0b4: RX status */
    volatile uint32 RESERVED_0B8;    /* 0x0b8 */
    volatile uint32 CCA_STAT;        /* 0x0bc: CCA status */
    volatile uint32 HF_TIMER1;       /* 0x0c0: HF timer 1 */
    volatile uint32 HF_TIMER2;       /* 0x0c4: HF timer 2 */
    volatile uint32 LF_TIMER;        /* 0x0c8: LF timer */
    volatile uint32 TIMER_CTL;       /* 0x0cc: Timer control */
    volatile uint32 HF_TIMER3;       /* 0x0d0: HF timer 3 */
    volatile uint32 HF_TIMER4;       /* 0x0d4: HF timer 4 */
    volatile uint32 HF_TIMER5;       /* 0x0d8: HF timer 5 */
    volatile uint32 HF_TIMER6;       /* 0x0dc: HF timer 6 */
    volatile uint32 RESERVED_0E0[6]; /* 0x0e0..0x0f7 */
    volatile uint32 TEST_CTRL;       /* 0x0f8: Test control */
    volatile uint32 DBG_CTRL;        /* 0x0fc: Debug control */
    volatile uint32 TXDMACTL;       /* 0x100: TX DMA control */
    volatile uint32 CURTXDMACNT;     /* 0x104: Current TX DMA count */
    volatile uint32 TXDMASTAT;       /* 0x108: TX DMA status/start address */
    volatile uint32 RESERVED_10C[5]; /* 0x10c..0x11f */
    volatile uint32 TX_SUB_FRM[16];  /* 0x120..0x15f: TX sub-frame descriptors */
    volatile uint32 RESERVED_160[168]; /* 0x160..0x3ff */
    volatile uint32 RXDMACTL;        /* 0x400: RX DMA control */
    volatile uint32 RXFSTADDR;       /* 0x404: RX start address */
    volatile uint32 RXFENADDR;       /* 0x408: RX end address */
    volatile uint32 RESERVED_40C;    /* 0x40c */
    volatile uint32 CURRXDMACNT;     /* 0x410: Current RX DMA count */
    volatile uint32 RXDMASTAT;       /* 0x414: RX DMA status */
    volatile uint32 RXFCS1;          /* 0x418: RX FCS 1 */
    volatile uint32 RXFCS2;          /* 0x41c: RX FCS 2 */
    volatile uint32 RESERVED_420[128]; /* 0x420..0x61f */
    volatile uint32 RXFSTADDR_SEC;   /* 0x620: Secondary RX start address */
    volatile uint32 RXFENADDR_SEC;   /* 0x624: Secondary RX end address */
    volatile uint32 RESERVED_628[2]; /* 0x628..0x62f */
    volatile uint32 CCADBGCTL;      /* 0x630: CCA debug control */
    volatile uint32 CCAINFO[5];     /* 0x634..0x644: CCA info */
    volatile uint32 DUMMY[2];        /* 0x648..0x64f */
} LMAC_HW_t;

typedef struct {
    volatile uint32 RFDCOCCON0;      /* 0x000: RF DCOC control register 0 */
    volatile uint32 RFDCOCCON1;      /* 0x004: RF DCOC control register 1 */
    volatile uint32 RFDCOCCON2;      /* 0x008: RF DCOC control register 2 */
    volatile uint32 RFDCOCCON3;      /* 0x00c: RF DCOC control register 3 */
    volatile uint32 RFDCOCCON4;      /* 0x010: RF DCOC control register 4 */
    volatile uint32 RFPWRCON0;       /* 0x014: RF Power control register 0 */
    volatile uint32 RFPWRCON1;       /* 0x018: RF Power control register 1 */
    volatile uint32 RFPWRCON2;       /* 0x01c: RF Power control register 2 */
    volatile uint32 XOSCDFMCON0;     /* 0x020: XOSC DFM control register 0 */
    volatile uint32 XOSCDFMCON1;     /* 0x024: XOSC DFM control register 1 */
    volatile uint32 XOSCDFMCON2;     /* 0x028: XOSC DFM control register 2 */
    volatile uint32 TXPWRIDX;        /* 0x02c: TX power index */
    volatile uint32 TXDC0;           /* 0x030: TX DC register 0 */
    volatile uint32 TXDC1;           /* 0x034: TX DC register 1 */
    volatile uint32 TXDC2;           /* 0x038: TX DC register 2 */
    volatile uint32 TXDC3;           /* 0x03c: TX DC register 3 */
    volatile uint32 TXDC4;           /* 0x040: TX DC register 4 */
    volatile uint32 TXDC5;           /* 0x044: TX DC register 5 */
    volatile uint32 TXIMB0;          /* 0x048: TX IMB register 0 */
    volatile uint32 TXIMB1;          /* 0x04c: TX IMB register 1 */
    volatile uint32 TXIMB2;          /* 0x050: TX IMB register 2 */
    volatile uint32 TXIMB3;          /* 0x054: TX IMB register 3 */
    volatile uint32 TXIMB4;          /* 0x058: TX IMB register 4 */
    volatile uint32 TXIMB5;          /* 0x05c: TX IMB register 5 */
    volatile uint32 RXPWRIDX;        /* 0x060: RX power index */
    volatile uint32 RX1MDC0;         /* 0x064: RX 1M DC register 0 */
    volatile uint32 RX1MDC1;         /* 0x068: RX 1M DC register 1 */
    volatile uint32 RX1MDC2;         /* 0x06c: RX 1M DC register 2 */
    volatile uint32 RX1MDC3;         /* 0x070: RX 1M DC register 3 */
    volatile uint32 RX1MDC4;         /* 0x074: RX 1M DC register 4 */
    volatile uint32 RX1MDC5;         /* 0x078: RX 1M DC register 5 */
    volatile uint32 RX1MIMB0;        /* 0x07c: RX 1M IMB register 0 */
    volatile uint32 RX1MIMB1;        /* 0x080: RX 1M IMB register 1 */
    volatile uint32 RX1MIMB2;        /* 0x084: RX 1M IMB register 2 */
    volatile uint32 RX1MIMB3;        /* 0x088: RX 1M IMB register 3 */
    volatile uint32 RX1MIMB4;        /* 0x08c: RX 1M IMB register 4 */
    volatile uint32 RX1MIMB5;        /* 0x090: RX 1M IMB register 5 */
    volatile uint32 RX2MDC0;         /* 0x094: RX 2M DC register 0 */
    volatile uint32 RX2MDC1;         /* 0x098: RX 2M DC register 1 */
    volatile uint32 RX2MDC2;         /* 0x09c: RX 2M DC register 2 */
    volatile uint32 RX2MDC3;         /* 0x0a0: RX 2M DC register 3 */
    volatile uint32 RX2MDC4;         /* 0x0a4: RX 2M DC register 4 */
    volatile uint32 RX2MDC5;         /* 0x0a8: RX 2M DC register 5 */
    volatile uint32 RX2MIMB0;        /* 0x0ac: RX 2M IMB register 0 */
    volatile uint32 RX2MIMB1;        /* 0x0b0: RX 2M IMB register 1 */
    volatile uint32 RX2MIMB2;        /* 0x0b4: RX 2M IMB register 2 */
    volatile uint32 RX2MIMB3;        /* 0x0b8: RX 2M IMB register 3 */
    volatile uint32 RX2MIMB4;        /* 0x0bc: RX 2M IMB register 4 */
    volatile uint32 RX2MIMB5;        /* 0x0c0: RX 2M IMB register 5 */
    volatile uint32 RX4MDC0;         /* 0x0c4: RX 4M DC register 0 */
    volatile uint32 RX4MDC1;         /* 0x0c8: RX 4M DC register 1 */
    volatile uint32 RX4MDC2;         /* 0x0cc: RX 4M DC register 2 */
    volatile uint32 RX4MDC3;         /* 0x0d0: RX 4M DC register 3 */
    volatile uint32 RX4MDC4;         /* 0x0d4: RX 4M DC register 4 */
    volatile uint32 RX4MDC5;         /* 0x0d8: RX 4M DC register 5 */
    volatile uint32 RX4MIMB0;        /* 0x0dc: RX 4M IMB register 0 */
    volatile uint32 RX4MIMB1;        /* 0x0e0: RX 4M IMB register 1 */
    volatile uint32 RX4MIMB2;        /* 0x0e4: RX 4M IMB register 2 */
    volatile uint32 RX4MIMB3;        /* 0x0e8: RX 4M IMB register 3 */
    volatile uint32 RX4MIMB4;        /* 0x0ec: RX 4M IMB register 4 */
    volatile uint32 RX4MIMB5;        /* 0x0f0: RX 4M IMB register 5 */
    volatile uint32 RX8MDC0;         /* 0x0f4: RX 8M DC register 0 */
    volatile uint32 RX8MDC1;         /* 0x0f8: RX 8M DC register 1 */
    volatile uint32 RX8MDC2;         /* 0x0fc: RX 8M DC register 2 */
    volatile uint32 RX8MDC3;         /* 0x100: RX 8M DC register 3 */
    volatile uint32 RX8MDC4;         /* 0x104: RX 8M DC register 4 */
    volatile uint32 RX8MDC5;         /* 0x108: RX 8M DC register 5 */
    volatile uint32 RX8MIMB0;        /* 0x10c: RX 8M IMB register 0 */
    volatile uint32 RX8MIMB1;        /* 0x110: RX 8M IMB register 1 */
    volatile uint32 RX8MIMB2;        /* 0x114: RX 8M IMB register 2 */
    volatile uint32 RX8MIMB3;        /* 0x118: RX 8M IMB register 3 */
    volatile uint32 RX8MIMB4;        /* 0x11c: RX 8M IMB register 4 */
    volatile uint32 RX8MIMB5;        /* 0x120: RX 8M IMB register 5 */
    volatile uint32 RXFBDC0;         /* 0x124: RX feedback DC register 0 */
    volatile uint32 RXFBDC1;         /* 0x128: RX feedback DC register 1 */
    volatile uint32 RXFBDC2;         /* 0x12c: RX feedback DC register 2 */
    volatile uint32 RXFBDC3;         /* 0x130: RX feedback DC register 3 */
    volatile uint32 RXFBDC4;         /* 0x134: RX feedback DC register 4 */
    volatile uint32 RXFBDC5;         /* 0x138: RX feedback DC register 5 */
    volatile uint32 RXFBIMB0;        /* 0x13c: RX feedback IMB register 0 */
    volatile uint32 RXFBIMB1;        /* 0x140: RX feedback IMB register 1 */
    volatile uint32 RXFBIMB2;        /* 0x144: RX feedback IMB register 2 */
    volatile uint32 RXFBIMB3;        /* 0x148: RX feedback IMB register 3 */
    volatile uint32 RXFBIMB4;        /* 0x14c: RX feedback IMB register 4 */
    volatile uint32 RXFBIMB5;        /* 0x150: RX feedback IMB register 5 */
    volatile uint32 RXFILTER;        /* 0x154: RX filter */
    volatile uint32 TXDIGPWR01;      /* 0x158: TX digital power register 0/1 */
    volatile uint32 TXDIGPWR23;      /* 0x15c: TX digital power register 2/3 */
    volatile uint32 TXDIGPWR45;      /* 0x160: TX digital power register 4/5 */
} LMAC_RFDIGICALI_t;

#define LMAC_HW ((LMAC_HW_t *)LMAC_HW_BASE_ADDR)
#define LMAC_TDMA ((LMAC_TDMA_t *)LMAC_TDMA_BASE_ADDR)
#define LMAC_TDMA2 ((LMAC_TDMA_t *)LMAC_TDMA2_BASE_ADDR)
#define LMAC_RFSPI ((LMAC_RFSPI_t *)LMAC_RFSPI_BASE_ADDR)
#define LMAC_RFDIGICALI ((LMAC_RFDIGICALI_t *)LMAC_RFDIGICALI_BASE_ADDR)

#define LMAC_RFDIGI_BKNOISE_IS_VALID() LMAC_REG_IS_SET(LMAC_RFDIGICALI->RFPWRCON0, LMAC_RFDIGI_BKNOISE_VALID)
#define LMAC_RFDIGI_RX_IS_BUSY() LMAC_REG_IS_SET(LMAC_RFDIGICALI->RXPWRIDX, LMAC_RFDIGI_BUSY)
#define LMAC_RFDIGI_TX_IS_BUSY() LMAC_REG_IS_SET(LMAC_RFDIGICALI->TXPWRIDX, LMAC_RFDIGI_BUSY)
#define LMAC_RFDIGI_DCOC_I_IS_RUNNING() LMAC_REG_IS_SET(LMAC_RFDIGICALI->RFDCOCCON0, LMAC_RFDIGI_DCOC_EN_I)
#define LMAC_RFDIGI_DCOC_Q_IS_RUNNING() LMAC_REG_IS_SET(LMAC_RFDIGICALI->RFDCOCCON0, LMAC_RFDIGI_DCOC_EN_Q)
#define LMAC_RFDIGI_WAIT_RX_READY() do { while (LMAC_RFDIGI_RX_IS_BUSY()) {} } while (0)
#define LMAC_RFDIGI_WAIT_TX_READY() do { while (LMAC_RFDIGI_TX_IS_BUSY()) {} } while (0)

#define LMAC_FSM_BUSY_MASK          0x00f000f0U /* Non-zero means RX start should be skipped. */
#define LMAC_FSM_START              (1U << 0)  /* Kick selected TX/RX FSM. */
#define LMAC_FSM_ABORT              (1U << 1)  /* Abort/reset current FSM state. */
#define LMAC_FSM_TX_SEL             (1U << 4)  /* Select TX path for FSM start. */
#define LMAC_FSM_RX_SEL             (1U << 5)  /* Select RX path for FSM start. */
#define LMAC_FSM_BO_BYPASS          (1U << 8)  /* Backoff bypass control. */
#define LMAC_FSM_RX_POST_CLEAR      (1U << 13) /* Cleared after RX start sequence. */

#define LMAC_RF_EN                  (1U << 8)  /* RF frontend enable. */
#define LMAC_RF_SW_CTRL             (1U << 9)  /* 1 = software RF control, 0 = hardware control. */
#define LMAC_RF_TX_EN               (1U << 10) /* RF TX enable gate. */
#define LMAC_RF_RX_EN               (1U << 11) /* RF RX enable gate. */
#define LMAC_RF_PA_EN               (1U << 16) /* Power amplifier enable gate. */
#define LMAC_RF_DAC_EN              (1U << 17) /* TX DAC enable gate. */

#define LMAC_TDMA_MAX_LEN           ((1U << 20) - 1U) /* Hardware accepts 20-bit lengths. */

#define LMAC_TDMA_START             (1U << 0) /* Start TDMA transfer. */
#define LMAC_TDMA_ABORT             (1U << 1) /* Abort TDMA transfer. */
#define LMAC_TDMA_MODE              (1U << 2) /* Mode selector bit. */
#define LMAC_TDMA_IRQ_EN            (1U << 3) /* Enable TDMA interrupt. */
#define LMAC_TDMA_MODE_EN           (1U << 4) /* Enable selected TDMA mode. */
#define LMAC_TDMA_PD_BIT            (1U << 0) /* Pending/done bit. */

#define LMAC_RFSPI_PD               (1U << 10) /* Transaction done/pending status and clear bit. */
#define LMAC_RFSPI_WRITE_FLAG       (1U << 31) /* Command word write marker. */
#define LMAC_RFSPI_ADDR_MASK        0x7fff0000U /* RF register address field in command word. */
#define LMAC_RFSPI_DATA_MASK        0x7fffffffU /* Payload bits before setting write marker. */

#define LMAC_RFDIGI_BUSY            (1U << 3)  /* Commit/busy bit for RX/TX gain writes. */
#define LMAC_RFDIGI_DCOC_EN_I       (1U << 0)  /* Enable/start DCOC I path. */
#define LMAC_RFDIGI_DCOC_EN_Q       (1U << 1)  /* Enable/start DCOC Q path. */
#define LMAC_RFDIGI_DCOC_STOP       (1U << 3)  /* Stop/commit TX calibration state. */
#define LMAC_RFDIGI_DCOC_KICK       (1U << 6)  /* Kick DCOC estimator. */
#define LMAC_RFDIGI_IMB_FB_COMP_GATE (1U << 25) /* IMB control feedback-compensation gate. */
#define LMAC_RFDIGI_RX_GAIN_IDX_SRC (1U << 4)  /* RX gain index source selector. */
#define LMAC_RFDIGI_RX_FB_COMP_EN   (1U << 10) /* RX feedback compensation enable. */
#define LMAC_RFDIGI_RX_FILTER_MANUAL (1U << 0) /* RX filter manual/fb-comp enable bit. */
#define LMAC_RFDIGI_RX_FILTER_AUTO  (1U << 4)  /* RX filter automatic/fb-comp bit. */
#define LMAC_RFDIGI_TX_GAIN_IDX_SRC (1U << 15) /* TX gain index source selector. */
#define LMAC_RFDIGI_BKNOISE_EN      (1U << 0)  /* Enable background-noise calculation. */
#define LMAC_RFDIGI_BKNOISE_VALID   (1U << 13) /* Background-noise valid/pending bit. */
#define LMAC_RFDIGI_BKNOISE_CLR     0x6000U    /* Write bits13/14 to clear valid/pending. */
#define LMAC_RFDIGI_BKNOISE_HW_TRIG (1U << 15) /* Enable background-noise hardware trigger. */
#define LMAC_RFDIGI_RX_DCOC_HW_TRIG (1U << 25) /* Enable RX DCOC hardware trigger. */
#define LMAC_RFDIGI_DCOC_RESULT_MASK 0x0fffU   /* One signed 12-bit DCOC result lane. */
#define LMAC_RFDIGI_DCOC_RESULT_SIGN 0x0800U   /* Sign bit for a 12-bit DCOC result. */
#define LMAC_RFDIGI_DCOC_RESULT_BIAS 0x1000U   /* Subtract to sign-extend 12-bit DCOC result. */
#define LMAC_RFDIGI_RX_DCOC_MASK    0x03ffU    /* One packed 10-bit RX DCOC lane. */
#define LMAC_RFDIGI_RX_DCOC_Q_SHIFT 10U        /* Packed RX DCOC Q lane shift. */
#define LMAC_RFDIGI_RX_IMB_GAIN_SHIFT 20U      /* Packed RX IQ gain-comp lane shift. */
#define LMAC_RFDIGI_TX_DIGI_GAIN_MASK 0x07ffU  /* One 11-bit TX digital gain lane. */
#define LMAC_RFDIGI_TX_DIGI_GAIN_HI_MASK 0x07ff0000U /* Upper 11-bit TX digital gain lane. */
#define LMAC_RFDIGI_TX_DIGI_GAIN_HI_SHIFT 16U  /* Upper TX digital gain lane shift. */
#define LMAC_RFDIGI_HW_BKNOISE_VALID_MASK LMAC_RFDIGI_BKNOISE_VALID /* Power-calc wait mask aliases BKNOISE valid. */
#define LMAC_RFDIGI_TX_GAIN_LOW_MASK 0x00000007U /* Low TX power field in TX_GAIN_CTRL. */

