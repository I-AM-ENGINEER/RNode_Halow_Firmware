#ifndef __SYS_CONFIG_H__
#define __SYS_CONFIG_H__

#define PROJECT_TYPE PRO_TYPE_WNB

#define IP_SOF_BROADCAST 1
#define LWIP_NETIF_HOSTNAME        1
#define TCPIP_THREAD_STACKSIZE      2048
#define HALOW_MTU               (512)
//#define TCP_MSS                 (HALOW_MTU)              // Smaller packets -> less latency
#define CFG_SERVER_PORT         (8002)
#define TCP_SERVER_PORT         (8001)
#define TCP_SERVER_MTU          (TCP_MSS)
//#define TCP_SND_BUF             (2*TCP_MSS)         // Near realtime
//#define TCP_SNDLOWAT            (TCP_MSS)
//#define TCP_SNDQUEUELOWAT       2
//#define TCP_SND_QUEUELEN        4

#define SYS_FACTORY_PARAM_SIZE 2048

// #define SYS_CACHE_ENABLE                1

#ifndef TDMA_BUFF_SIZE
#define TDMA_BUFF_SIZE (100 * 1024)
#endif

#define SYS_HEAP_SIZE (60 * 1024)

#define WIFI_RX_BUFF_SIZE (80 * 1024) //(17*1024)

#define SRAM_POOL_START   (srampool_start)
#define SRAM_POOL_SIZE    (srampool_end - srampool_start)
#define TDMA_BUFF_ADDR    (SRAM_POOL_START)
#define SYS_HEAP_START    (TDMA_BUFF_ADDR + TDMA_BUFF_SIZE)
#define WIFI_RX_BUFF_ADDR (SYS_HEAP_START + SYS_HEAP_SIZE)
#define SKB_POOL_ADDR     (WIFI_RX_BUFF_ADDR + WIFI_RX_BUFF_SIZE)
#define SKB_POOL_SIZE     (SRAM_POOL_START + SRAM_POOL_SIZE - SKB_POOL_ADDR)

#define DEFAULT_SYS_CLK 144000000UL // options: 32M/48M/72M/144M, and 16*N from 64M to 128M

#define GMAC_ENABLE 1

#define AUTO_ETHERNET_PHY

#define ETHERNET_PHY_ADDR -1

/*! Use GPIO to simulate the MII management interface */
#define HG_GMAC_IO_SIMULATION
#ifndef HG_GMAC_MDIO_PIN
#define HG_GMAC_MDIO_PIN PA_10
#endif
#ifndef HG_GMAC_MDC_PIN
#define HG_GMAC_MDC_PIN PA_11
#endif

#define LWIP_RAW 1 // support at+ping
#define TX_PWR_SUPER_EN 1
#define WNB_TX_POWER 20

//#define ANT_CTRL_PIN PB_1 // 网桥用PB1来做双天线选择

#endif
