#include "sys_config.h"
#include "typesdef.h"
#include "list.h"
#include "dev.h"
#include "devid.h"
#include "osal/string.h"
#include "osal/semaphore.h"
#include "osal/mutex.h"
#include "osal/timer.h"
#include "osal/task.h"

//#include "ahrf.h"
#include "hal/uart.h"
#include "hal/i2c.h"
#include "hal/timer_device.h"
#include "hal/dma.h"
#include "hal/netdev.h"
#include "hal/spi.h"
#include "hal/spi_nor.h"
#include "hal/sysaes.h"
#include "lib/syscfg/syscfg.h"
#include "lib/net/ethphy/eth_mdio_bus.h"
#include "lib/net/ethphy/eth_phy.h"

#ifdef ETHERNET_IP101G
#include "lib/net/ethphy/phy/ip101g.h"
#endif
#ifdef ETHERNET_RTL8201F
#include "lib/net/ethphy/phy/rtl8201f.h"
#endif
#ifdef ETHERNET_SZ18201
#include "lib/net/ethphy/phy/sz18201.h"
#endif
#ifdef AUTO_ETHERNET_PHY
#include "lib/net/ethphy/phy/auto_phy.h"
#endif

#include "lib/ota/fw.h"

#include "dev/uart/hguart.h"
#include "dev/i2c/hgi2c_dw.h"
#include "dev/sdio/hgsdio20_slave.h"
#include "dev/dma/dw_dmac.h"
#include "dev/gpio/hggpio_v2.h"
#include "dev/timer/hgtimer_v2.h"
#include "dev/dma/hg_m2m_dma.h"
#include "dev/usb/hgusb11_dev_api.h"
#include "dev/spi/hgspi_dw.h"
#include "dev/crc/hg_crc.h"
#include "dev/sysaes/hg_sysaes.h"

#include "device.h"
#include "syscfg.h"

extern const struct hgwphy_ah_cfg nphyahcfg;
extern union _dpd_ram dpd_ram;
extern const uint32 rx_imb_iq_normal[6];
extern const union hgdbgpath_cfg ndbgpathcfg;
extern const union hgrfmipi_cfg nrfmipicfg;
extern struct dma_device *m2mdma;

struct hgusb11_dev usb_dev = {
    .usb_hw = (struct hgusb11_dev_hw *)HG_USB11_DEVICE_BASE,
    .irq_num = USB_CTL_IRQn,
    .sof_irq_num = USB_SOF_IRQn,
};

struct hgsdio20_slave sdioslave = {
    .hw = (struct hgsdio20_slave_hw *)HG_SDIO20_SLAVE_BASE,
    .irq_num = HGSDIO20_IRQn,
    .rst_irq_num = HGSDIO20_RST_IRQn,
};

struct hg_crc crc32_module = {
    .hw = (struct hg_crc_hw *)HG_CRC32_BASE,
    .irq_num = CRC_IRQn,
};

struct hguart uart0 = {
    .hw = (struct hguart_hw *) HG_UART0_BASE,
    .irq_num = UART0_IRQn,
    .tx_dma_id = DMA_CH_UART0_TX,
    .rx_dma_id = DMA_CH_UART0_RX,
};
struct hguart uart1 = {
    .hw = (struct hguart_hw *) HG_UART1_BASE,
    .irq_num = UART1_IRQn,
    .tx_dma_id = DMA_CH_UART1_TX,
    .rx_dma_id = DMA_CH_UART1_RX,
    
};

struct hggpio_v2 gpioa = {
    .hw = (struct hggpio_v2_hw *)HG_GPIOA_BASE,
    .irq_num = GPIOA_IRQn,
    .pin_num = {0, 31},
};

struct hggpio_v2 gpiob = {
    .hw = (struct hggpio_v2_hw *)HG_GPIOB_BASE,
    .irq_num = GPIOB_IRQn,
    .pin_num = {32, 50},
};

struct hgi2c_dw hgi2c0 = {
    .hw = (struct hgi2c_dw_reg *)IIC0_BASE,
    .irq_num = IIC0_IRQn,
};

struct hgdma_dw dmac = {
    .hw = (struct hgdma_dw_hw *)DMAC_BASE,
    .irq_num = DMAC_IRQn,
};

#ifndef SYS_IRQ_STAT
struct hgtimer_v2 timer0 = {
    .hw      = (struct hgtimer_v2_hw *)HG_TIMER0_BASE,
    .irq_num = TIM0_IRQn,
};
#endif
struct hgtimer_v2 timer2 = {
    .hw      = (struct hgtimer_v2_hw *)HG_TIMER2_BASE,
    .irq_num = TIM2_IRQn,
};

struct mem_dma_dev mem_dma = {
    .hw      = (struct mem_dma_hw *)M2M_DMA0_BASE,
};


struct hg_sysaes sysaes = {
    .hw = (struct hg_sysaes_hw *)SYS_AES_BASE,
    .irq_num = SYS_AES_IRQn,
};

struct hgspi_dw spi0 = {
    .hw      = (struct hgspi_dw_hw *)SPI0_BASE,
    .irq_num = SPI0_IRQn,
    .tx_dma_id = DMA_CH_SPI0_TX,
    .rx_dma_id = DMA_CH_SPI0_RX,
    .cs_pin  = {1, PIN_SPI0_CS},
};

struct hgspi_dw spi1 = {
    .hw      = (struct hgspi_dw_hw *)SPI1_BASE,
    .irq_num = SPI1_IRQn,
    .cs_pin  = {1, PIN_SPI1_CS},
};

struct spi_nor_flash flash0 = {
    .spidev      = (struct spi_device *)&spi0,
    .spi_config  = {12000000, SPI_CLK_MODE_3, SPI_WIRE_NORMAL_MODE, 0},
    .vendor_id   = 0,
    .product_id  = 0,
    .size        = 0x100000,
    .sector_size = 0x1000,
    .page_size   = 256,
    .mode        = SPI_NOR_NORMAL_SPI_MODE,
};

struct ethernet_mdio_bus mdio_bus0;

#ifdef ETHERNET_IP101G
struct ethernet_phy_device ethernet_phy0 = {
    .addr = 0x01,
    .drv  = &ip101g_driver,
};
#endif
#ifdef ETHERNET_RTL8201F
struct ethernet_phy_device ethernet_phy0 = {
    .addr = 0x01,
    .drv  = &rtl8201f_driver,
};
#endif
#ifdef ETHERNET_SZ18201
struct ethernet_phy_device ethernet_phy0 = {
    .addr = ETHERNET_PHY_ADDR,
    .drv  = &sz18201_driver,
};
#endif
#ifdef AUTO_ETHERNET_PHY
struct ethernet_phy_device ethernet_phy0 = {
    .addr = ETHERNET_PHY_ADDR,
    .drv  = &auto_phy_driver,
};
#endif

__init void device_init(void)
{
    extern void *console_handle;

    hggpio_v2_attach(HG_GPIOA_DEVID, &gpioa);
    hggpio_v2_attach(HG_GPIOB_DEVID, &gpiob);
    
    hguart_attach(HG_UART0_DEVID, &uart0);
    hguart_attach(HG_UART1_DEVID, &uart1);
    
#ifdef MACBUS_SDIO
    hgsdio20_slave_attach(HG_SDIOSLAVE_DEVID, &sdioslave);
#endif
#ifdef MACBUS_USB
    hgusb11_dev_attach(HG_USBDEV_DEVID, &usb_dev);
#endif

#ifndef SYS_IRQ_STAT
    hgtimer_v2_attach(HG_TIMER0_DEVID, &timer0);
#endif
    hgtimer_v2_attach(HG_TIMER2_DEVID, &timer2);
    
    hg_m2m_dma_dev_attach(HG_M2MDMA_DEVID, &mem_dma);
    m2mdma = (struct dma_device *)&mem_dma;

    dw_dmac_attach(HG_DMAC_DEVID, &dmac);
    
    hg_sysaes_attach(HG_HWAES0_DEVID, &sysaes);
    
    //spi_nor_master
    hgspi_dw_attach(HG_SPI0_DEVID, &spi0);
    spi_nor_attach(&flash0, HG_FLASH0_DEVID);
    hg_crc_attach(HG_CRC_DEVID, &crc32_module);

    hgspi_dw_attach(HG_SPI1_DEVID, &spi1);

//cfg print
#ifdef MACBUS_USB
    uart_open((struct uart_device *)&uart0, HGUART_DEFAULT_BAUDRATE);
    console_handle = &uart0;
#else
    uart_open((struct uart_device *)&uart1, HGUART_DEFAULT_BAUDRATE);
    console_handle = &uart1;
#endif
}

struct gpio_device *gpio_get(uint32 pin)
{
    if (pin >= gpioa.pin_num[0] && pin <= gpioa.pin_num[1]) {
        return (struct gpio_device *)&gpioa;
    }
    if (pin >= gpiob.pin_num[0] && pin <= gpiob.pin_num[1]) {
        return (struct gpio_device *)&gpiob;
    }
    return NULL;
}

int32 syscfg_info_get(struct syscfg_info *pinfo)
{
#ifdef SYSCFG_ENABLE
    if(flash0.product_id == 0)
        return -1;
    pinfo->flash1 = &flash0;
    pinfo->flash2 = &flash0;
    pinfo->size  = pinfo->flash1->sector_size;
    pinfo->addr1 = pinfo->flash1->size - (2 * pinfo->size);
    pinfo->addr2 = pinfo->flash1->size - pinfo->size;
    ASSERT((pinfo->addr1 & ~(pinfo->flash1->sector_size - 1)) == pinfo->addr1);
    ASSERT((pinfo->addr2 & ~(pinfo->flash2->sector_size - 1)) == pinfo->addr2);
    ASSERT((pinfo->size >= sizeof(struct sys_config)) && 
           (pinfo->size == (pinfo->size & ~(pinfo->flash1->sector_size - 1))));
    return 0;
#else
    return -1;
#endif
}

int32 ota_fwinfo_get(struct ota_fwinfo *pinfo)
{
    if(flash0.product_id == 0)
        return -1;
    pinfo->flash0 = &flash0;
    pinfo->flash1 = &flash0;
    pinfo->addr0  = 0;
    pinfo->addr1  = 0x00080000;
    return 0;
}

