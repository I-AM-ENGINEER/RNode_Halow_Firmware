// Auto-reconstructed: mars_rfspi.c
#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_MARS_RFSPI
#include "lib/logc/log.h"

#include "lib/lmac/mars_rfspi.h"
#include "lib/lmac/lmac_regmap.h"
#include "chip/txw4002ack803/io_function.h"
#include "chip/txw4002ack803/sysctrl.h"
#include "dev.h"
#include "hal/gpio.h"

void ah_rfspi_clear_pd(void) {
    log_debug("ah_rfspi_clear_pd called\n");
    LMAC_SET_BIT(LMAC_RFSPI->STATUS, LMAC_RFSPI_PD);
}

void ah_rfspi_close(void) {
    log_debug("ah_rfspi_close called\n");
    LMAC_CLEAR_BIT(LMAC_RFSPI->CFG, (1U << 8) | (1U << 9));
    LMAC_CLEAR_BIT(LMAC_RFSPI->CTRL, 0x07U);
    rfspi_pin_func(0);
}

uint32_t ah_rfspi_get_pd(void) {
    log_debug("ah_rfspi_get_pd called\n");
    return LMAC_READ_BIT(LMAC_RFSPI->STATUS, LMAC_RFSPI_PD);
}

int ah_rfspi_open(int arg0, uint32_t arg1, uint32_t arg2) {
    log_debug("ah_rfspi_open called with arg0=%d, arg1=%u, arg2=%u\n", arg0, arg1, arg2);

    LMAC_SET_BIT(SYSCTRL->CLK_CON2, CLK_CON2_ZHRF_SYS_SPI_CLK_EN_MSK);
    LMAC_CLEAR_BIT(SYSCTRL->SYS_CON1, SYS_CON1_ZHRF_SPI_SOFT_RST_MSK);
    LMAC_SET_BIT(SYSCTRL->SYS_CON1, SYS_CON1_ZHRF_SPI_SOFT_RST_MSK);

    LMAC_RFSPI->CFG = (arg0 != 0) ? 0x040f03ccU : 0x040f038cU;
    LMAC_SET_BIT(LMAC_RFSPI->CTRL, 4U);

    rfspi_pin_func(arg2);

    int result = ah_rfspi_set_clk((uint8_t)arg1);

    uint32_t apbclk = sys_get_apbclk();
    uint32_t half   = ((apbclk >> 31) + apbclk) >> 1;
    int rx_dly_arg  = (arg1 * 1000000U != half) ? 0 : 1;
    ah_rfspi_set_rx_dly((uint32_t)rx_dly_arg);

    return result;
}

uint16_t ah_rfspi_read(uint16_t reg_addr) {
    log_debug("ah_rfspi_read called with reg_addr=0x%x\n", reg_addr);

    LMAC_CLEAR_BIT(LMAC_RFSPI->CTRL, 1U << 3);
    LMAC_SET_BIT(LMAC_RFSPI->CTRL, 3U);

    LMAC_RFSPI->SETUP0 = 1U;
    LMAC_RFSPI->SETUP1 = 0U;
    LMAC_RFSPI->CMD    = ((uint32_t)reg_addr << 16) & LMAC_RFSPI_ADDR_MASK;

    while (LMAC_REG_IS_CLEAR(LMAC_RFSPI->STATUS, LMAC_RFSPI_PD)) {}
    ah_rfspi_clear_pd();

    LMAC_SET_BIT(LMAC_RFSPI->CTRL, 1U << 3);

    uint16_t val = (uint16_t)LMAC_RFSPI->RDATA;
    log_debug("ah_rfspi_read reg=0x%x -> 0x%x\n", reg_addr, val);
    return val;
}

int ah_rfspi_set_clk(uint8_t clk_div) {
    log_debug("ah_rfspi_set_clk called with clk_div=%u\n", clk_div);
    uint32_t apb_clk = sys_get_apbclk();
    uint32_t div     = apb_clk / (62500U * 32U * (uint32_t)clk_div);
    div = (div & 0xFFU) - 1U;
    LMAC_MODIFY_REG(LMAC_RFSPI->CFG, 0x00FF0000U, div << 16);
    return 0;
}

int32_t ah_rfspi_set_rx_dly(uint32_t delay) {
    log_debug("ah_rfspi_set_rx_dly called with delay=%u\n", delay);
    if (delay >= 8) {
        return -1;
    }
    LMAC_MODIFY_REG(LMAC_RFSPI->CFG, 0x07000000U, delay << 24);
    return 0;
}

int ah_rfspi_set_trig_mode(uint32_t mode) {
    log_debug("ah_rfspi_set_trig_mode called with mode=%u\n", mode);
    LMAC_MODIFY_REG(LMAC_RFSPI->CFG, 1U << 1, mode << 1);
    return 0;
}

void ah_rfspi_write(uint16_t addr, uint32_t data) {
    log_debug("ah_rfspi_write called with addr=0x%x, data=0x%x\n", addr, data);

    LMAC_CLEAR_BIT(LMAC_RFSPI->CTRL, 1U << 3);
    LMAC_CLEAR_BIT(LMAC_RFSPI->CTRL, (1U << 0) | (1U << 1));
    LMAC_SET_BIT(LMAC_RFSPI->CTRL, 1U << 1);

    LMAC_RFSPI->SETUP0 = 1U;
    LMAC_RFSPI->SETUP1 = 0U;

    data &= LMAC_RFSPI_DATA_MASK;
    data |= LMAC_RFSPI_WRITE_FLAG;
    data |= ((uint32_t)addr << 16) & LMAC_RFSPI_ADDR_MASK;
    LMAC_RFSPI->CMD = data;

    uint32_t timeout = 128U << 9;
    while (!LMAC_REG_IS_SET(LMAC_RFSPI->STATUS, LMAC_RFSPI_PD) && timeout != 0) {
        timeout--;
    }
    ah_rfspi_clear_pd();

    LMAC_SET_BIT(LMAC_RFSPI->CTRL, 1U << 3);
}

uint16_t ah_rfspi_write_and_read(uint32_t addr, uint32_t data) {
    log_debug("ah_rfspi_write_and_read called with addr=0x%x, data=0x%x\n", addr, data);
    ah_rfspi_write((uint16_t)addr, data);
    return ah_rfspi_read((uint16_t)addr);
}

void rfspi_pin_func(uint32_t mode) {
    log_debug("rfspi_pin_func called with mode=%u\n", mode);

    if (mode == 1) {
        LMAC_SET_BIT(SYSCTRL->IO_MAP, IO_MAP_RF_SPI_MASTER_MAP0_MSK);
        LMAC_CLEAR_BIT(SYSCTRL->IO_MAP, IO_MAP_RF_SPI_SLAVE_MAP0_MSK);
        gpio_set_altnt_func(22, 3);
        gpio_set_altnt_func(23, 3);
        gpio_set_altnt_func(24, 3);
        gpio_set_altnt_func(25, 3);
        return;
    }

    LMAC_CLEAR_BIT(SYSCTRL->IO_MAP, IO_MAP_RF_SPI_MASTER_MAP0_MSK);

    if (mode == 2) {
        LMAC_CLEAR_BIT(SYSCTRL->IO_MAP, IO_MAP_RF_SPI_SLAVE_MAP0_MSK);
        gpio_set_altnt_func(22, 4);
        gpio_set_altnt_func(23, 4);
        gpio_set_altnt_func(24, 4);
        gpio_set_altnt_func(25, 4);
        return;
    }

    if (mode == 3) {
        LMAC_SET_BIT(SYSCTRL->IO_MAP, IO_MAP_RF_SPI_SLAVE_MAP0_MSK);
        gpio_set_altnt_func(22, 1);
        gpio_set_altnt_func(23, 1);
        gpio_set_altnt_func(24, 1);
        gpio_set_altnt_func(25, 1);
        return;
    }

    LMAC_CLEAR_BIT(SYSCTRL->IO_MAP, IO_MAP_RF_SPI_SLAVE_MAP0_MSK);
    gpio_set_dir(22, 0);
    gpio_set_dir(23, 0);
    gpio_set_dir(24, 0);
    gpio_set_dir(25, 0);
}
