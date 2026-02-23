#ifndef __SYS_CONFIG_H__
#define __SYS_CONFIG_H__

#define PROJECT_TYPE           PRO_TYPE_WNB
#define FW_VERSION              "1.2.0"
#define FW_FULL_VERSION         FW_VERSION " (" __DATE__ " " __TIME__ ")"

#define IP_SOF_BROADCAST       1
#define LWIP_RAW               1
#define LWIP_NETIF_HOSTNAME    1

// LWIP debug

//#define TCPIP_MBOX_SIZE              32
//#define DEFAULT_TCP_RECVMBOX_SIZE    32
//#define DEFAULT_ACCEPTMBOX_SIZE      8
//#define MEMP_NUM_TCP_PCB         16
//#define MEMP_NUM_TCP_PCB_LISTEN  16
//#define DEFAULT_RAW_RECVMBOX_SIZE 8
//#define MEMP_NUM_NETBUF 8
#define LWIP_SO_RCVTIMEO 1
//#define LWIP_DEBUG                  1
//#define MEM_SIZE (8*1024)
//#define PBUF_POOL_SIZE  16
//#define LWIP_DBG_MIN_LEVEL          LWIP_DBG_LEVEL_ALL
//#define LWIP_DBG_TYPES_ON           LWIP_DBG_ON

// #define TCP_MSS                 (HALOW_MTU)

// #define TCP_SND_BUF             (2*TCP_MSS) 
// #define TCP_SNDLOWAT            (TCP_MSS)
// #define TCP_SNDQUEUELOWAT       2
// #define TCP_SND_QUEUELEN        4

#define TDMA_BUFF_SIZE 0

#define SYS_HEAP_SIZE     (256 * 1024)

#define WIFI_RX_BUFF_SIZE (40 * 1024) //(17*1024)

#define SRAM_POOL_START   (srampool_start)
#define SRAM_POOL_SIZE    (srampool_end - srampool_start)
#define TDMA_BUFF_ADDR    (SRAM_POOL_START)
#define SYS_HEAP_START    (TDMA_BUFF_ADDR + TDMA_BUFF_SIZE)
#define WIFI_RX_BUFF_ADDR (SYS_HEAP_START + SYS_HEAP_SIZE)
#define SKB_POOL_ADDR     (WIFI_RX_BUFF_ADDR + WIFI_RX_BUFF_SIZE)
#define SKB_POOL_SIZE     (SRAM_POOL_START + SRAM_POOL_SIZE - SKB_POOL_ADDR)

#define DEFAULT_SYS_CLK   128000000UL // options: 32M/48M/72M/144M, and 16*N from 64M to 128M

#define GMAC_ENABLE       1

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

#define NET_IP_CONFIG_MODE_DEF        (NET_IP_MODE_DHCP)
#define NET_IP_CONFIG_IP_DEF          PP_HTONL(LWIP_MAKEU32(192, 168, 42, 42))
#define NET_IP_CONFIG_MASK_DEF        PP_HTONL(LWIP_MAKEU32(255, 255, 255, 0))
#define NET_IP_CONFIG_GW_DEF          PP_HTONL(LWIP_MAKEU32(0, 0, 0, 0))

#define HALOW_MTU                     (512)
#define HALOW_CONFIG_CENTRAL_FREQ_DEF (8665)
#define HALOW_CONFIG_POWER_DEF        (17)
#define HALOW_CONFIG_BANDWIDTH_DEF    (1)
#define HALOW_CONFIG_MCS_DEF          (0)
#define HALOW_CONFIG_SPOWER_EN_DEF    (false)

#define HALOW_LBT_CONFIG_EN_DEF                 (true)
#define HALOW_LBT_CONFIG_NSWS_DEF               (256)
#define HALOW_LBT_CONFIG_NLWS_DEF               (256)
#define HALOW_LBT_CONFIG_NLLP_DEF               (20)
#define HALOW_LBT_CONFIG_NRO_DEF                (10)
#define HALOW_LBT_CONFIG_NAB_DEF                (-75)
#define HALOW_LBT_CONFIG_TX_SKIP_US_DEF         (2000)
#define HALOW_LBT_CONFIG_TX_MAX_MS_DEF          (100)
#define HALOW_LBT_CONFIG_BO_MIN_US_DEF          (3000)
#define HALOW_LBT_CONFIG_BO_MAX_US_DEF          (10000)
#define HALOW_LBT_CONFIG_UTIL_EN_DEF            (true)
#define HALOW_LBT_CONFIG_UTIL_MAX_DEF           (50)
#define HALOW_LBT_CONFIG_UTIL_REFILL_MS_DEF     (1000)
#define HALOW_LBT_CONFIG_UTIL_BUCKET_MS_DEF     (200)

#define TCP_SERVER_PORT               (8001)
#define TCP_SERVER_MTU                (TCP_MSS)

#define TCP_SERVER_CONFIG_ENABLED_DEF               (true)
#define TCP_SERVER_CONFIG_PORT_DEF                  (8001)
#define TCP_SERVER_CONFIG_WHITELIST_IP_DEF          PP_HTONL(LWIP_MAKEU32(0, 0, 0, 0))
#define TCP_SERVER_CONFIG_WHITELIST_MASK_DEF        PP_HTONL(LWIP_MAKEU32(0, 0, 0, 0))

#define OTA_FAL_PART_NAME "ota_slot0"

#define CONFIG_PAGE_TASK_PRIO    (3)
#define CONFIG_PAGE_TASK_STACK   (10*1024)

#define STATISTICS_TASK_PRIO    (2)
#define STATISTICS_TASK_STACK   (2*1024)

#define HALOW_LBT_LISTEN_TASK_PRIO    (OS_TASK_PRIORITY_IDLE)
#define HALOW_LBT_LISTEN_TASK_STACK   (2*1024)

// #define ANT_CTRL_PIN PB_1 // 网桥用PB1来做双天线选择

#endif
