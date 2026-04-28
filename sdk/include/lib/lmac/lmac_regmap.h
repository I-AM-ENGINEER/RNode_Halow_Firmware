#pragma once

#include <stddef.h>
#include "typesdef.h"

/* Hardware MMIO bases for LMAC peripheral blocks */
#define LMAC_CE_BASE_ADDR           0x40010000UL /* Cipher Engine: AES/GHASH crypto operations. */
#define LMAC_HW_BASE_ADDR           0x40008000UL /* MAC/LMAC FSM, timing, IRQ, RF gate registers. */
#define LMAC_DBGPATH_BASE_ADDR      0x40005000UL /* Debug-path DMA and external SPI debug controls. */
#define LMAC_TDMA_BASE_ADDR         0x40001000UL /* First TDMA capture/playback DMA engine. */
#define LMAC_TDMA2_BASE_ADDR        0x4000b000UL /* Second TDMA capture/playback DMA engine. */
#define LMAC_RFSPI_BASE_ADDR        0x4001b000UL /* RF serial peripheral interface controller. */
#define LMAC_RFDIGICALI_BASE_ADDR   0x4001d000UL /* RF digital calibration engine. */
#define LMAC_SYS_CON_BASE_ADDR      0x40026000UL /* System-control register block used for pin mux/clock gates. */

#define LMAC_MMIO_PTR(base_) ((volatile uint32 *)(base_))

/* Register access macros */
#define LMAC_REG_IDX(offset_) ((offset_) / 4U)
#define LMAC_REG(base_, offset_) (LMAC_MMIO_PTR(base_)[LMAC_REG_IDX(offset_)])
#define LMAC_READ_REG(reg_) (reg_)
#define LMAC_WRITE_REG(reg_, val_) ((reg_) = (val_))
#define LMAC_READ_BIT(reg_, mask_) ((reg_) & (mask_))
#define LMAC_SET_BIT(reg_, mask_) ((reg_) |= (mask_))
#define LMAC_CLEAR_BIT(reg_, mask_) ((reg_) &= ~(mask_))
#define LMAC_MODIFY_REG(reg_, clear_mask_, set_mask_) \
    ((reg_) = (((reg_) & ~(clear_mask_)) | (set_mask_)))
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
    volatile uint32 CFG;             /* 0x000: Debug Path Configuration register */
    volatile uint32 RESERVED_004[2]; /* 0x004..0x008 */
    volatile uint32 COUNTER;         /* 0x00C: Debug Path Counter register */
    volatile uint32 EXTSPI_TX_PWR;   /* 0x010: External SPI TX Power Command register */
    volatile uint32 RFSPI_TX_POWER;  /* 0x014: RF SPI TX Power Command register */
    volatile uint32 RFSPI_RX_POWER;  /* 0x018: RF SPI RX Power Command register */
    volatile uint32 RFENCTL0;        /* 0x01C: RF enable control register 0 */
    volatile uint32 RFENCTL1;        /* 0x020: RF enable control register 1 */
    volatile uint32 RFENCTL2;        /* 0x024: RF enable control register 2 */
    volatile uint32 DBG_OUT0;        /* 0x028: Debug output register 0 */
    volatile uint32 DBG_OUT1;        /* 0x02C: Debug output register 1 */
    volatile uint32 MIPICTL0;        /* 0x030: MIPI Control 0 */
    volatile uint32 MIPIWDATA0;      /* 0x034: MIPI Write Data 0 */
    volatile uint32 MIPICTL1;        /* 0x038: MIPI Control 1 */
    volatile uint32 MIPIWDATA1;      /* 0x03C: MIPI Write Data 1 */
    volatile uint32 MIPICTL2;        /* 0x040: MIPI Control 2 */
    volatile uint32 MIPIWDATA2;      /* 0x044: MIPI Write Data 2 */
    volatile uint32 MIPICTL3;        /* 0x048: MIPI Control 3 */
    volatile uint32 MIPIWDATA3;      /* 0x04C: MIPI Write Data 3 */
    volatile uint32 MIPICTL4;        /* 0x050: MIPI Control 4 */
    volatile uint32 MIPIWDATA4;      /* 0x054: MIPI Write Data 4 */
    volatile uint32 MIPICTL5;        /* 0x058: MIPI Control 5 */
    volatile uint32 MIPIWDATA5;      /* 0x05C: MIPI Write Data 5 */
    volatile uint32 RESERVED_060[4]; /* 0x060..0x06C */
    volatile uint32 RFSPIWDATA;      /* 0x070: RF SPI Write Data */
    volatile uint32 RESERVED_074[13];/* 0x074..0x0A4 */
    volatile uint32 STOP_POS;        /* 0x0A8: DMA stop position register */
    volatile uint32 RESERVED_0AC[6]; /* 0x0AC..0x0C4 */
    volatile uint32 ENABLE_ERR;      /* 0x0C8: Enable/error register */
    volatile uint32 RESERVED_0CC[13];/* 0x0CC..0x0FC */
    volatile uint32 TDMA2_CTRL;      /* 0x100: TDMA2 control register */
} LMAC_DBGPATH_t;

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
    volatile uint32 KEY[8];          /* 0x000..0x01c: Primary AES key words KEY[1-8] */
    volatile uint32 IV[2];           /* 0x020..0x024: IV[1-2] */
    volatile uint32 PN[2];           /* 0x028..0x02c: PN (Packet Number) PN[1-2] */
    volatile uint32 AAD[8];          /* 0x030..0x04c: AAD words AAD[1-8] */
    volatile uint32 ENC_DATA_LEN;    /* 0x050: Encryption data length */
    volatile uint32 ENC_SADDR;       /* 0x054: Encryption source address */
    volatile uint32 ENC_DADDR;       /* 0x058: Encryption destination address */
    volatile uint32 RESERVED_05C[1]; /* 0x05c */
    volatile uint32 CIPHER_CTRL[2];  /* 0x060..0x064: CIPHER_CTRL[1-2] */
    volatile uint32 CIPHER_STATUS;   /* 0x068: Cipher status */
    volatile uint32 RESERVED_06C[2]; /* 0x06c..0x06f */
    volatile uint32 MIC[4];          /* 0x070..0x07c: MIC[1-4] result words */
} LMAC_CE_t;

typedef struct {
    volatile uint32 RESERVED_000[4]; /* 0x000..0x00c: Reserved area */
    volatile uint32 TSF_LO;          /* 0x010: TSF low word */
    volatile uint32 TSF_HI;          /* 0x014: TSF high word */
    volatile uint32 RESERVED_018[2]; /* 0x018..0x01c */
    volatile uint32 TIMING_CTRL;     /* 0x01c: SIFS/slot/EIFS + TX/RX flags */
    volatile uint32 CCA_CTRL;        /* 0x020: CCA control */
    volatile uint32 RESERVED_024[3]; /* 0x024..0x02f */
    volatile uint32 FSM_CTRL;        /* 0x030: FSM start/abort, TX/RX select */
    volatile uint32 FSM_STATE;       /* 0x034: FSM state/busy flags */
    volatile uint32 RESERVED_038[2]; /* 0x038..0x03f */
    volatile uint32 RF_CTRL;         /* 0x040: RF switch, TX/RX, PA, DAC */
    volatile uint32 IRQ_EN;          /* 0x044: Interrupt enable mask */
    volatile uint32 IRQ_CLR;         /* 0x048: Interrupt clear */
    volatile uint32 RESERVED_04C[4]; /* 0x04c..0x05b */
    volatile uint32 END_TO_LIMIT;    /* 0x05c: End-timeout limit */
    volatile uint32 RESERVED_060[6]; /* 0x060..0x077 */
    volatile uint32 TX_DELAY_BEFORE; /* 0x078: Three 5-bit TX pre-delay lanes */
    volatile uint32 RESERVED_07C[2]; /* 0x07c..0x083 */
    volatile uint32 TX_DELAY_AFTER;  /* 0x084: Four 6-bit TX post-delay lanes */
    volatile uint32 RESERVED_088[1]; /* 0x088..0x08b */
    volatile uint32 TX_DAC_RF_DELAY; /* 0x08c: DAC/RF/PA TX delays */
    volatile uint32 RESERVED_090[4]; /* 0x090..0x09f */
    volatile uint32 PHY_RX_DELAY;    /* 0x0a0: PHY RX delay */
    volatile uint32 NDP2M_LO;        /* 0x0a4: NDP2M low word */
    volatile uint32 NDP2M_HI;        /* 0x0a8: NDP2M high word */
    volatile uint32 RESERVED_0AC[2]; /* 0x0ac..0x0b3 */
    volatile uint32 RX_FRM_TYPE;     /* 0x0b4: RX frame type status */
    volatile uint32 RESERVED_0B8[18];/* 0x0b8..0x0ff */
    volatile uint32 DMA_LIST_CNT;    /* 0x100: DMA list count */
    volatile uint32 RESERVED_104[8]; /* 0x104..0x123 */
    volatile uint32 TX_SUB_FRM[16];  /* 0x124..0x163: TX sub-frame descriptors */
    volatile uint32 RESERVED_164[371]; /* 0x164..0x62f: Large gap to CCA observation */
    volatile uint32 CCA_OBSERV_CTRL; /* 0x630: CCA observation control */
    volatile uint32 CCA_OBSERV[5];   /* 0x634..0x644: Five CCA observation results */
} LMAC_HW_t;

typedef struct {
    volatile uint32 DCOC_CTRL;       /* 0x000: DCOC enable/start/kick/HW-trigger control. */
    volatile uint32 DCOC_CFG0;       /* 0x004: DCOC estimation config word 0. */
    volatile uint32 DCOC_CFG1;       /* 0x008: DCOC estimation config word 1. */
    volatile uint32 DCOC_RESULT;     /* 0x00c: signed I/Q DCOC result, 12 bits each. */
    volatile uint32 IMB_CTRL;        /* 0x010: DCOC/IQ imbalance control and fb-comp gate. */
    volatile uint32 BKNOISE_CTRL;    /* 0x014: background-noise calc/status/HW-trigger control. */
    volatile uint32 BKNOISE_RESULT;  /* 0x018: background-noise/power result. */
    volatile uint32 RESERVED_01C[4]; /* 0x01c..0x028 */
    volatile uint32 TX_GAIN_CTRL;    /* 0x02c: TX power/gain index source and commit/busy bit. */
    volatile uint32 TX_SLOT[12];     /* 0x030..0x05c: TX DCOC/IQ compensation slots. */
    volatile uint32 RX_GAIN_CTRL;    /* 0x060: RX gain/source/fb-comp and commit/busy control. */
    volatile uint32 RX_SLOT_LO[60];  /* 0x064..0x150: RX slots for gain index 0..3 and related data. */
    volatile uint32 RX_FILTER_CTRL;  /* 0x154: RX filter and fb-comp mode control. */
    volatile uint32 TX_DIGI_GAIN[3]; /* 0x158..0x160: packed TX digital gain entries. */
} LMAC_RFDIGICALI_t;

#define LMAC_CE ((LMAC_CE_t *)LMAC_CE_BASE_ADDR)
#define LMAC_HW ((LMAC_HW_t *)LMAC_HW_BASE_ADDR)
#define LMAC_TDMA ((LMAC_TDMA_t *)LMAC_TDMA_BASE_ADDR)
#define LMAC_TDMA2 ((LMAC_TDMA_t *)LMAC_TDMA2_BASE_ADDR)
#define LMAC_DBGPATH ((LMAC_DBGPATH_t *)LMAC_DBGPATH_BASE_ADDR)
#define LMAC_RFSPI ((LMAC_RFSPI_t *)LMAC_RFSPI_BASE_ADDR)
#define LMAC_RFDIGICALI ((LMAC_RFDIGICALI_t *)LMAC_RFDIGICALI_BASE_ADDR)

#define LMAC_RFDIGI_BKNOISE_IS_VALID() LMAC_REG_IS_SET(LMAC_RFDIGICALI->BKNOISE_CTRL, LMAC_RFDIGI_BKNOISE_VALID)
#define LMAC_RFDIGI_RX_IS_BUSY() LMAC_REG_IS_SET(LMAC_RFDIGICALI->RX_GAIN_CTRL, LMAC_RFDIGI_BUSY)
#define LMAC_RFDIGI_TX_IS_BUSY() LMAC_REG_IS_SET(LMAC_RFDIGICALI->TX_GAIN_CTRL, LMAC_RFDIGI_BUSY)
#define LMAC_RFDIGI_DCOC_I_IS_RUNNING() LMAC_REG_IS_SET(LMAC_RFDIGICALI->DCOC_CTRL, LMAC_RFDIGI_DCOC_EN_I)
#define LMAC_RFDIGI_DCOC_Q_IS_RUNNING() LMAC_REG_IS_SET(LMAC_RFDIGICALI->DCOC_CTRL, LMAC_RFDIGI_DCOC_EN_Q)
#define LMAC_RFDIGI_WAIT_RX_READY() do { while (LMAC_RFDIGI_RX_IS_BUSY()) {} } while (0)
#define LMAC_RFDIGI_WAIT_TX_READY() do { while (LMAC_RFDIGI_TX_IS_BUSY()) {} } while (0)

/* LMAC MAC register offsets */
#define LMAC_REG_TSF_LO             0x010U /* TSF low word written by lhw_set_tsf(). */
#define LMAC_REG_TSF_HI             0x014U /* TSF high word written by lhw_set_tsf(). */
#define LMAC_REG_TIMING_CTRL        0x01cU /* SIFS/slot/EIFS plus TX/RX start flags. */
#define LMAC_REG_CCA_CTRL           0x020U /* CCA duration/remain, BW selector, and CCA start bit. */
#define LMAC_REG_FSM_CTRL           0x030U /* MAC FSM start/abort and TX/RX path selection. */
#define LMAC_REG_FSM_STATE          0x034U /* MAC FSM state/busy flags. */
#define LMAC_REG_RF_CTRL            0x040U /* RF switch, TX/RX, PA, and DAC enables. */
#define LMAC_REG_IRQ_EN             0x044U /* MAC interrupt enable mask. */
#define LMAC_REG_IRQ_CLR            0x048U /* MAC interrupt/status clear register. */
#define LMAC_REG_END_TO_LIMIT       0x05cU /* End-timeout/limit value; init writes 25000. */
#define LMAC_REG_TX_DELAY_BEFORE    0x078U /* Three 5-bit TX pre-delay lanes. */
#define LMAC_REG_TX_DELAY_AFTER     0x084U /* Four 6-bit TX post-delay lanes. */
#define LMAC_REG_TX_DAC_RF_DELAY    0x08cU /* RF/DAC/PA TX delay fields. */
#define LMAC_REG_PHY_RX_DELAY       0x0a0U /* PHY RX delay in bits 28..31. */
#define LMAC_REG_NDP2M_LO           0x0a4U /* NDP2M low word; bit25 is NDP indicator for frame type 0. */
#define LMAC_REG_NDP2M_HI           0x0a8U /* NDP2M high word; bit5 is NDP indicator for frame type 1. */
#define LMAC_REG_RX_FRM_TYPE        0x0b4U /* RX frame-type status: present/type bits. */
#define LMAC_REG_DMA_LIST_CNT       0x100U /* DMA list count, low 7 bits. */
#define LMAC_REG_TX_SUB_FRM_BASE    0x124U /* TX sub-frame descriptor register area. */
#define LMAC_REG_CCA_OBSERV_CTRL    0x630U /* CCA observation start/mode/valid register. */
#define LMAC_REG_CCA_OBSERV0        0x634U /* First of five CCA observation result words. */

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

/* Cipher Engine register offsets (from txw4002a.svc CIPHER_ENGINE) */
#define LMAC_CE_KEY0                0x000U /* KEY[1] - Primary key word 0 */
#define LMAC_CE_KEY1                0x004U /* KEY[2] - Primary key word 1 */
#define LMAC_CE_KEY2                0x008U /* KEY[3] - Primary key word 2 */
#define LMAC_CE_KEY3                0x00cU /* KEY[4] - Primary key word 3 */
#define LMAC_CE_KEY4                0x010U /* KEY[5] - Primary key word 4 */
#define LMAC_CE_KEY5                0x014U /* KEY[6] - Primary key word 5 */
#define LMAC_CE_KEY6                0x018U /* KEY[7] - Primary key word 6 */
#define LMAC_CE_KEY7                0x01cU /* KEY[8] - Primary key word 7 */
#define LMAC_CE_IV0                 0x020U /* IV[1] - IV word 0 */
#define LMAC_CE_IV1                 0x024U /* IV[2] - IV word 1 */
#define LMAC_CE_PN0                 0x028U /* PN[1] - Packet Number / Nonce word 0 */
#define LMAC_CE_PN1                 0x02cU /* PN[2] - Packet Number / Nonce word 1 */
#define LMAC_CE_AAD0                0x030U /* AAD[1] - Additional Authenticated Data word 0 */
#define LMAC_CE_AAD1                0x034U /* AAD[2] - Additional Authenticated Data word 1 */
#define LMAC_CE_AAD2                0x038U /* AAD[3] */
#define LMAC_CE_AAD3                0x03cU /* AAD[4] */
#define LMAC_CE_AAD4                0x040U /* AAD[5] */
#define LMAC_CE_AAD5                0x044U /* AAD[6] */
#define LMAC_CE_AAD6                0x048U /* AAD[7] */
#define LMAC_CE_AAD7                0x04cU /* AAD[8] */
#define LMAC_CE_DATA_LEN            0x050U /* ENC_DATA_LEN - Payload length */
#define LMAC_CE_SRC_ADDR            0x054U /* ENC_SADDR - Source buffer address */
#define LMAC_CE_DST_ADDR            0x058U /* ENC_DADDR - Destination buffer address */
#define LMAC_CE_CTRL0               0x060U /* CIPHER_CTRL[1] - Control register 0 */
#define LMAC_CE_CTRL1               0x064U /* CIPHER_CTRL[2] - Control register 1 */
#define LMAC_CE_STATUS              0x068U /* CIPHER_STATUS - Done/MIC-error status */
#define LMAC_CE_MIC0                0x070U /* MIC[1] - First MIC result word */
#define LMAC_CE_MIC1                0x074U /* MIC[2] */
#define LMAC_CE_MIC2                0x078U /* MIC[3] */
#define LMAC_CE_MIC3                0x07cU /* MIC[4] */

#define LMAC_CE_CTRL_START          (1U << 0)  /* Start one CE operation. */
#define LMAC_CE_CTRL_ENABLE_IRQ     (1U << 1)  /* Enable CE/CE interrupt path. */
#define LMAC_CE_STATUS_DONE         (1U << 0)  /* Completion IRQ/status bit. */
#define LMAC_CE_STATUS_MIC_ERR      (1U << 1)  /* Decrypt MIC/error status bit. */
#define LMAC_CE_CFG_DECRYPT         (1U << 0)  /* 1 = decrypt, 0 = encrypt. */
#define LMAC_CE_CFG_MODE_BIT12      (1U << 12) /* Cipher-mode selector bit. */
#define LMAC_CE_CFG_MODE_BIT13      (1U << 13) /* Cipher-mode selector bit. */

/* DBGPATH register offsets and bits */
#define LMAC_DBGPATH_CFG            0x000U /* Debug Path Configuration register. */
#define LMAC_DBGPATH_COUNTER        0x00cU /* Debug Path Counter register. */
#define LMAC_DBGPATH_EXTSPI_TX_PWR  0x010U /* External SPI TX Power Command register. */
#define LMAC_DBGPATH_RFSPI_TX_POWER 0x014U /* External SPI RX Power Command register. */
#define LMAC_DBGPATH_RFSPI_RX_POWER 0x018U /* External SPI RX DPD Power Command register. */
#define LMAC_DBGPATH_RFENCTL0       0x01cU /* RF enable control register 0. */
#define LMAC_DBGPATH_RFENCTL1       0x020U /* RF enable control register 1. */
#define LMAC_DBGPATH_RFENCTL2       0x024U /* RF enable control register 2 (TDMA2 enable in bit31). */
#define LMAC_DBGPATH_DBGOUT_CTL0    0x028U /* Debug Path Output Control 0. */
#define LMAC_DBGPATH_DBGOUT_CTL1    0x02cU /* Debug Path Output Control 1. */
#define LMAC_DBGPATH_MIPICTL0       0x030U /* MIPI Control 0. */
#define LMAC_DBGPATH_MIPIWDATA0     0x034U /* MIPI Write Data 0. */
#define LMAC_DBGPATH_MIPICTL1       0x038U /* MIPI Control 1. */
#define LMAC_DBGPATH_MIPIWDATA1     0x03cU /* MIPI Write Data 1. */
#define LMAC_DBGPATH_MIPICTL2       0x040U /* MIPI Control 2. */
#define LMAC_DBGPATH_MIPIWDATA2     0x044U /* MIPI Write Data 2. */
#define LMAC_DBGPATH_MIPICTL3       0x048U /* MIPI Control 3. */
#define LMAC_DBGPATH_MIPIWDATA3     0x04cU /* MIPI Write Data 3. */
#define LMAC_DBGPATH_MIPICTL4       0x050U /* MIPI Control 4. */
#define LMAC_DBGPATH_MIPIWDATA4     0x054U /* MIPI Write Data 4. */
#define LMAC_DBGPATH_MIPICTL5       0x058U /* MIPI Control 5. */
#define LMAC_DBGPATH_MIPIWDATA5     0x05cU /* MIPI Write Data 5. */
#define LMAC_DBGPATH_RFSPIWDATA     0x070U /* RF SPI Write Data. */

#define LMAC_DBGPATH_DMA_TRIG       (1U << 4)  /* Trigger debug-path DMA. */
#define LMAC_DBGPATH_DMA_ABORT      (1U << 5)  /* Abort debug-path DMA. */
#define LMAC_DBGPATH_EXT_PATH0      (1U << 20) /* Enable external debug path, low control bit. */
#define LMAC_DBGPATH_EXT_PATH1      (1U << 21) /* Enable external path/DPD-gain source. */
#define LMAC_DBGPATH_DMA2_TRIG      (1U << 22) /* Trigger second debug-path DMA. */
#define LMAC_DBGPATH_DMA2_ABORT     (1U << 23) /* Abort second debug-path DMA. */
#define LMAC_DBGPATH_TDMA2_EN       (1U << 31) /* Enable TDMA2 in DBGPATH register 0x24. */
#define LMAC_DBGPATH_RFMIPI_CLR     (1U << 10) /* Toggle to clear RFMIPI error info. */
#define LMAC_DBGPATH_RFMIPI_MASK    0x0fffU    /* Low 12 bits contain RFMIPI error info. */

/* TDMA register offsets */
#define LMAC_TDMA_CTRL              0x000U /* TDMA mode/start/abort/IRQ enable control. */
#define LMAC_TDMA_PD                0x004U /* TDMA pending/done status; bit0 is write-one clear. */
#define LMAC_TDMA_BUF_ADDR          0x008U /* DMA buffer address. */
#define LMAC_TDMA_BUF_LEN           0x00cU /* DMA buffer length, max 20 bits. */
#define LMAC_TDMA_TRIG_LEN          0x014U /* Trigger length, max 20 bits. */
#define LMAC_TDMA_MAX_LEN           ((1U << 20) - 1U) /* Hardware accepts 20-bit lengths. */

#define LMAC_TDMA_START             (1U << 0) /* Start TDMA transfer. */
#define LMAC_TDMA_ABORT             (1U << 1) /* Abort TDMA transfer. */
#define LMAC_TDMA_MODE              (1U << 2) /* Mode selector bit. */
#define LMAC_TDMA_IRQ_EN            (1U << 3) /* Enable TDMA interrupt. */
#define LMAC_TDMA_MODE_EN           (1U << 4) /* Enable selected TDMA mode. */
#define LMAC_TDMA_PD_BIT            (1U << 0) /* Pending/done bit. */

/* RFSPI register offsets */
#define LMAC_RFSPI_CFG              0x000U /* Clock/divider/open configuration. */
#define LMAC_RFSPI_CTRL             0x004U /* Transaction mode/delay control. */
#define LMAC_RFSPI_STATUS           0x00cU /* Done/pending status. */
#define LMAC_RFSPI_CMD              0x010U /* Packed RF register address/data command word. */
#define LMAC_RFSPI_RDATA            0x014U /* Read result word. */
#define LMAC_RFSPI_SETUP0           0x020U /* Transaction setup word 0; current code writes 1. */
#define LMAC_RFSPI_SETUP1           0x024U /* Transaction setup word 1; current code writes 0. */

#define LMAC_RFSPI_PD               (1U << 10) /* Transaction done/pending status and clear bit. */
#define LMAC_RFSPI_WRITE_FLAG       (1U << 31) /* Command word write marker. */
#define LMAC_RFSPI_ADDR_MASK        0x7fff0000U /* RF register address field in command word. */
#define LMAC_RFSPI_DATA_MASK        0x7fffffffU /* Payload bits before setting write marker. */

/* RFDIGICALI register offsets */
#define LMAC_RFDIGI_DCOC_CTRL       0x000U /* DCOC enable/start/kick/HW-trigger control. */
#define LMAC_RFDIGI_DCOC_CFG0       0x004U /* DCOC estimation config word 0. */
#define LMAC_RFDIGI_DCOC_CFG1       0x008U /* DCOC estimation config word 1. */
#define LMAC_RFDIGI_DCOC_RESULT     0x00cU /* Signed I/Q DCOC result, 12 bits each. */
#define LMAC_RFDIGI_IMB_CTRL        0x010U /* DCOC/IQ imbalance control and fb-comp gate. */
#define LMAC_RFDIGI_BKNOISE_CTRL    0x014U /* Background-noise calc/status/HW-trigger control. */
#define LMAC_RFDIGI_BKNOISE_RESULT  0x018U /* Background-noise/power result. */
#define LMAC_RFDIGI_TX_GAIN_CTRL    0x02cU /* TX power/gain index source and commit/busy bit. */
#define LMAC_RFDIGI_TX_DCOC_BASE    0x030U /* TX DCOC/IQ compensation slot base. */
#define LMAC_RFDIGI_RX_GAIN_CTRL    0x060U /* RX gain/source/fb-comp and commit/busy control. */
#define LMAC_RFDIGI_RX_LO_BASE      0x064U /* RX DCOC/IQ slots for gain index 0..3. */
#define LMAC_RFDIGI_RX_LO_PHASE_BASE 0x07cU /* RX IQ phase slots for gain index 0..3. */
#define LMAC_RFDIGI_RX_HI_BASE      0x124U /* RX DCOC/IQ slots for gain index 4+. */
#define LMAC_RFDIGI_RX_HI_PHASE_BASE 0x13cU /* RX IQ phase slots for gain index 4+. */
#define LMAC_RFDIGI_RX_FILTER_CTRL  0x154U /* RX filter and fb-comp mode control. */
#define LMAC_RFDIGI_TX_DIGI_GAIN0   0x158U /* TX digital gain entries 0 and 1. */
#define LMAC_RFDIGI_TX_DIGI_GAIN1   0x15cU /* TX digital gain entries 2 and 3. */
#define LMAC_RFDIGI_TX_DIGI_GAIN2   0x160U /* TX digital gain entries 4 and 5. */

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

typedef struct {
    uint32 cfg;
    uint32 extspi_tx_pwr;
    uint32 rfspi_tx_power;
    uint32 rfspi_rx_power;
    uint32 rfenctl0;
    uint32 rfenctl1;
    uint32 rfenctl2;
    uint32 dbg_out0;
    uint32 dbg_out1;
    uint32 mipictl0;
    uint32 mipiwdata0;
    uint32 mipictl1;
    uint32 mipiwdata1;
    uint32 mipictl2;
    uint32 mipiwdata2;
    uint32 mipictl3;
    uint32 mipiwdata3;
    uint32 mipictl4;
    uint32 mipiwdata4;
    uint32 mipictl5;
    uint32 mipiwdata5;
    uint32 rfspiwdata;
} LMAC_DBGPATH_CFG_t;

/* Structure layout verification */
_Static_assert(offsetof(LMAC_TDMA_t, CTRL) == LMAC_TDMA_CTRL, "TDMA CTRL offset");
_Static_assert(offsetof(LMAC_TDMA_t, STATUS) == LMAC_TDMA_PD, "TDMA STATUS offset");
_Static_assert(offsetof(LMAC_TDMA_t, STADDR) == LMAC_TDMA_BUF_ADDR, "TDMA STADDR offset");
_Static_assert(offsetof(LMAC_TDMA_t, LEN) == LMAC_TDMA_BUF_LEN, "TDMA LEN offset");
_Static_assert(offsetof(LMAC_TDMA_t, TRLEN) == LMAC_TDMA_TRIG_LEN, "TDMA TRLEN offset");

_Static_assert(offsetof(LMAC_DBGPATH_t, CFG) == LMAC_DBGPATH_CFG, "DBGPATH CFG offset");
_Static_assert(offsetof(LMAC_DBGPATH_t, COUNTER) == LMAC_DBGPATH_COUNTER, "DBGPATH COUNTER offset");
_Static_assert(offsetof(LMAC_DBGPATH_t, EXTSPI_TX_PWR) == LMAC_DBGPATH_EXTSPI_TX_PWR, "DBGPATH EXTSPI_TX_PWR offset");
_Static_assert(offsetof(LMAC_DBGPATH_t, RFSPIWDATA) == LMAC_DBGPATH_RFSPIWDATA, "DBGPATH RFSPIWDATA offset");

_Static_assert(offsetof(LMAC_RFSPI_t, CFG) == LMAC_RFSPI_CFG, "RFSPI CFG offset");
_Static_assert(offsetof(LMAC_RFSPI_t, CTRL) == LMAC_RFSPI_CTRL, "RFSPI CTRL offset");
_Static_assert(offsetof(LMAC_RFSPI_t, STATUS) == LMAC_RFSPI_STATUS, "RFSPI STATUS offset");
_Static_assert(offsetof(LMAC_RFSPI_t, CMD) == LMAC_RFSPI_CMD, "RFSPI CMD offset");
_Static_assert(offsetof(LMAC_RFSPI_t, RDATA) == LMAC_RFSPI_RDATA, "RFSPI RDATA offset");
_Static_assert(offsetof(LMAC_RFSPI_t, SETUP0) == LMAC_RFSPI_SETUP0, "RFSPI SETUP0 offset");
_Static_assert(offsetof(LMAC_RFSPI_t, SETUP1) == LMAC_RFSPI_SETUP1, "RFSPI SETUP1 offset");

_Static_assert(offsetof(LMAC_RFDIGICALI_t, DCOC_CTRL) == LMAC_RFDIGI_DCOC_CTRL, "RFDIGICALI DCOC_CTRL offset");
_Static_assert(offsetof(LMAC_RFDIGICALI_t, IMB_CTRL) == LMAC_RFDIGI_IMB_CTRL, "RFDIGICALI IMB_CTRL offset");
_Static_assert(offsetof(LMAC_RFDIGICALI_t, BKNOISE_CTRL) == LMAC_RFDIGI_BKNOISE_CTRL, "RFDIGICALI BKNOISE_CTRL offset");
_Static_assert(offsetof(LMAC_RFDIGICALI_t, TX_GAIN_CTRL) == LMAC_RFDIGI_TX_GAIN_CTRL, "RFDIGICALI TX_GAIN_CTRL offset");
_Static_assert(offsetof(LMAC_RFDIGICALI_t, RX_GAIN_CTRL) == LMAC_RFDIGI_RX_GAIN_CTRL, "RFDIGICALI RX_GAIN_CTRL offset");
_Static_assert(offsetof(LMAC_RFDIGICALI_t, RX_SLOT_LO) == LMAC_RFDIGI_RX_LO_BASE, "RFDIGICALI RX_SLOT_LO offset");
_Static_assert(offsetof(LMAC_RFDIGICALI_t, RX_FILTER_CTRL) == LMAC_RFDIGI_RX_FILTER_CTRL, "RFDIGICALI RX_FILTER_CTRL offset");
_Static_assert(offsetof(LMAC_RFDIGICALI_t, TX_DIGI_GAIN) == LMAC_RFDIGI_TX_DIGI_GAIN0, "RFDIGICALI TX_DIGI_GAIN offset");

/* Verified ah_lmac offsets. Prefer these until lmac_ctx_t is corrected. */
#define LMAC_CTX_BSS_BW             0x308U /* BSS/channel bandwidth byte used by rate-control checks. */
#define LMAC_CTX_RATE_MODE          0x311U /* Rate-control mode byte. */
#define LMAC_CTX_FALLBACK_LIMIT     0x313U /* Retry/fallback limit byte used by rate control. */
#define LMAC_CTX_RC_GROUP_FLAGS     0x34aU /* RC group/channel flag byte; bit0 is used by mars_lmac_rc.o. */
#define LMAC_CTX_RC_FLAGS_36E       0x36eU /* RC/control flags; bit6 is used by mars_lmac_rc.o. */
#define LMAC_CTX_DEBUG_FLAGS        0x3b8U /* Debug/control flags; RC checks bit1, antenna debug checks bit8. */
#define LMAC_CTX_PHY_RATE_BYTE      0x867U /* PHY/rate-related byte consumed by RC. Name still tentative. */
#define LMAC_CTX_RF_CONTROL_FLAGS   0x875U /* RF/antenna control flags; bits1..4 are used by RC/antenna logic. */
