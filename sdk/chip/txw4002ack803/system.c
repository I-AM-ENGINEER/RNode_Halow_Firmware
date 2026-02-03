#include "sys_config.h"
#include "csi_config.h"
#include "soc.h"
#include "csi_core.h"
#include "csi_kernel.h"
#include "txw4002ack803/ticker.h"
#include "osal/irq.h"
#include "osal/string.h"
#include "osal/task.h"
#include "osal/work.h"
#include "lib/heap/sysheap.h"
#include "lib/common/common.h"
#include "lib/common/dsleepdata.h"

int32 sysctrl_err_resp_disable(void);

extern void  main(void);
extern void board_init(void);
extern int  dev_init(void);
extern void device_init(void);
extern int32_t g_top_irqstack;
extern uint32_t __heap_start;
extern uint32_t __heap_end;
extern struct os_workqueue main_wkq;
extern uint32 *sysvar_mgr;
extern uint8_t assert_holdup;

uint32 srampool_start = 0;
uint32 srampool_end   = 0;

k_task_handle_t main_task_hdl;

#ifndef SYS_FACTORY_PARAM_SIZE
#define SYS_FACTORY_PARAM_SIZE 4
#endif
const uint16_t __used sys_factory_param[SYS_FACTORY_PARAM_SIZE/2] __at_section("SYS_PARAM") = {SYS_FACTORY_PARAM_SIZE};

__weak void dsleep_wakeup(void){}

void cpu_clk_sel_hosc(void)
{
    *(volatile uint32 *)0x4002602c = 0x3fac87e4;
    *(volatile uint32 *)0x4002600C = 0x00000001;// sel hosc
}

void boot_reload(void)
{
    CORE_SEC_OPT_B(PWRDMCTL->CORE_PMUCON7, PWRDMCTL->CORE_PMUCON7 & 0xFFFFFFFE);
}

/**
  * @brief  initialize the system
  *         Initialize the psr and vbr.
  * @param  None
  * @return None
  */
__init void SystemInit(void)
{
    __set_VBR((uint32_t) & (__Vectors));
    srampool_start = (uint32)&__heap_start;
    srampool_end   = (uint32)&__heap_end;
    
    SYSCTRL_REG_OPT_INIT();
    if (pmu_get_boot_direct_run_pending()) {
        pmu_set_direct_run_pengding2();
    } else {
        pmu_clr_direct_run_pengding2();
    }
    sysctrl_err_resp_disable();
#ifndef FPGA_SUPPORT
#if (DAC_BUG_FIXED==0)
    sysctrl_dac_init();//en dac for ldo bug
#endif
    //pmu cfg
    pmu_vdd_limit_cur_disable();
    pd_reg_sec_opt_en();
    pd_hxosc_en_sec(TRUE);
    adkey_init();
    tsensor_ref_get_from_efuse();
    
    sysctrl_unlock();
    SYSCTRL->IO_MAP &= ~(IO_MAP_RF_SPI_SLAVE_MAP0_MSK | IO_MAP_EXT_PHY_DEBUG_MAP0_MSK);
    sysctrl_crc_clk_close();
    if (0 || (pmu_get_boot_direct_run_pending2())) {
        sysctrl_sddev_clk_close();
        sysctrl_usb11_clk_close();
    }
    sysctrl_sysaes_clk_close();
    sysctrl_iic_clk_close();
    //sysctrl_uart0_clk_close();
    //sysctrl_uart1_clk_close();
    //sysctrl_spi0_clk_close();
    sysctrl_spi1_clk_close();
    sysctrl_spi3_clk_close();
    sysctrl_gmac_clk_close();
    
    //sysctrl_adcpll_set(int enable,int plla_ref_div,int plla_ref_sel_div,int plla_fb_div)
    sysctrl_adcpll_set(1, 0, 0, 8); //using PB9 or internal 32M to calib adcpll

    if (sys_set_sysclk(DEFAULT_SYS_CLK) == RET_ERR) {
        while (1);
    }
#endif
    sysctrl_lf_clk_cfg(); //from HOSC/1024 = 31.25k
    
#if defined(CONFIG_SEPARATE_IRQ_SP) && !defined(CONFIG_KERNEL_NONE)
    /* 801 not supported */
    __set_Int_SP((uint32_t)&g_top_irqstack);
    __set_CHR(__get_CHR() | CHR_ISE_Msk);
    VIC->TSPR = 0xFF;
#endif

    /* Clear active and pending IRQ */
    csi_vic_clear_all_pending_irq();
    csi_vic_clear_all_active();

#ifdef CONFIG_KERNEL_NONE
    __enable_excp_irq();
#endif

    csi_coret_config(DEFAULT_SYS_CLK / CONFIG_SYSTICK_HZ, CORET_IRQn);    //1ms
#ifndef CONFIG_KERNEL_NONE
    csi_vic_enable_irq(CORET_IRQn);
#endif

    request_irq(LVD_IRQn, lvd_irq_handler, 0);
    irq_enable(LVD_IRQn);
    
    CORE_SEC_OPT(WKCON, PWRDMCTL->CORE_WKCON | CORE_WKCON_WK_MCLR_RST_EN_MSK | CORE_WKCON_WK_LVD_INT_EN_MSK | CORE_WKCON_WK_LVD_RST_EN_MSK);
    
    sysctrl_set_xo_fx2(1);
}

__init uint8 lvd_detect(void)
{
    uint32 tmp;
    
    tmp = PWRDMCTL->LVD_CON;
    if ((tmp & 0xff000000) != 0) {
        if (tmp & LVD_CON_LVD13A_PD_MSK) {
            os_printf("VDD13A LVD occured!\r\n");
        }
        if (tmp & LVD_CON_LVD13D_PD_MSK) {
            os_printf("VDD13D LVD occured!\r\n");
        }
        if (tmp & LVD_CON_LVDVCC_PD_MSK) {
            os_printf("VCC LVD occured!\r\n");
        }
        if (tmp & LVD_CON_LVDVDD_PD_MSK) {
            os_printf("VDD LVD occured!\r\n");
        }
        if (tmp & LVD_CON_VDDOC_PD_MSK) {
            os_printf("VDD OC LVD occured!\r\n");
        }
        if (tmp & LVD_CON_13BOC_PD_MSK) {
            //os_printf("VDD13B OC LVD occured!\r\n");
        }
        if (tmp & LVD_CON_13COC_PD_MSK) {
            //os_printf("VDD13C OC LVD occured!\r\n");
        }
        if (tmp & LVD_CON_MIPIOC_PD_MSK) {
            os_printf("MIPI OC LVD occured!\r\n");
        }
        CORE_SEC_OPT(LVDCON, tmp & 0xffffff);
    }

    if (PWRDMCTL->CORE_WKCON & CORE_WKCON_WK_MCLR_RST_PNDS_MSK) {
        os_printf("MCLR occured!\r\n");
        CORE_SEC_OPT(WKCON, PWRDMCTL->CORE_WKCON | CORE_WKCON_CLEAR_MCLR_PND_MSK);
    }
    if (PWRDMCTL->CORE_WKCON & CORE_WKCON_WK_LVD_INT_PNDS_MSK) {
        CORE_SEC_OPT(WKCON, PWRDMCTL->CORE_WKCON | CORE_WKCON_CLEAR_LVD_INT_PND_MSK);
    }
    if (PWRDMCTL->CORE_WKCON & CORE_WKCON_WK_LVD_RST_PNDS_MSK) {
        CORE_SEC_OPT(WKCON, PWRDMCTL->CORE_WKCON | CORE_WKCON_CLEAR_LVD_RST_PND_MSK);
    }
    
    return (tmp>>24);
}

__init void malloc_init(void)
{
    uint32 flags = 0;
#ifdef MEM_TRACE
    flags |= SYSHEAP_FLAGS_MEM_LEAK_TRACE | SYSHEAP_FLAGS_MEM_OVERFLOW_CHECK;
#endif
    sysheap_init(&sram_heap, (void *)SYS_HEAP_START, SYS_HEAP_SIZE, flags);
#ifdef PSRAM_HEAP
    sysheap_init(&psram_heap, (void *)psrampool_start, psrampool_end - psrampool_start, flags);
#endif
}


__init void pre_main(void)
{
    assert_holdup = ASSERT_HOLDUP;
    malloc_init();
    csi_kernel_init();
    dev_init();
    device_init();
#ifdef CONFIG_SLEEP
    sys_sleepcb_init();
#endif
//#ifdef CONFIG_SLEEP
    sys_sleepdata_init();
//#endif
    VERSION_SHOW();
    module_version_show();
    lvd_detect();
    os_workqueue_init(&main_wkq, "MAIN", OS_TASK_PRIORITY_NORMAL, 2048);
    mainwkq_monitor_init();
    os_run_func((os_run_func_t)main, 0, 0, 0);
    csi_kernel_start();
}

