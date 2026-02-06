#ifndef __SYS_CONFIG_H__
#define __SYS_CONFIG_H__
#include "project_config.h"

#define PROJECT_TYPE PRO_TYPE_WNB

#ifndef SYSCFG_ENABLE
#define SYSCFG_ENABLE 0
#endif

#define USING_TX_SQ
#define TDMA_DEBUG
#define RXSUBFRAME_EN     1
#define RXSUBFRAME_PERIOD (5)

#define IP_SOF_BROADCAST 1
#define LWIP_NETIF_HOSTNAME        1
// #define SYS_IRQ_STAT

#define SYS_FACTORY_PARAM_SIZE 2048

// #define SYS_CACHE_ENABLE                1

#ifndef TDMA_BUFF_SIZE
#define TDMA_BUFF_SIZE (100 * 1024)
#endif

#ifndef SYS_STA_MAX
#define SYS_STA_MAX (8)
#endif

#ifndef SYS_HEAP_SIZE
#if SYS_STA_MAX <= 8
#define SYS_HEAP_SIZE (60 * 1024)
#else
#define SYS_HEAP_SIZE (60 * 1024 + 64 * 1024)
#endif
#endif

#ifndef WIFI_RX_BUFF_SIZE
#define WIFI_RX_BUFF_SIZE (80 * 1024) //(17*1024)
#endif

#define SRAM_POOL_START   (srampool_start)
#define SRAM_POOL_SIZE    (srampool_end - srampool_start)
#define TDMA_BUFF_ADDR    (SRAM_POOL_START)
#define SYS_HEAP_START    (TDMA_BUFF_ADDR + TDMA_BUFF_SIZE)
#define WIFI_RX_BUFF_ADDR (SYS_HEAP_START + SYS_HEAP_SIZE)
#define SKB_POOL_ADDR     (WIFI_RX_BUFF_ADDR + WIFI_RX_BUFF_SIZE)
#define SKB_POOL_SIZE     (SRAM_POOL_START + SRAM_POOL_SIZE - SKB_POOL_ADDR)

#ifndef K_iPA
#define K_EXT_PA
#endif

#define K_SWITCH_PWR_PA22
#define K_SINGLE_PIN_SWITCH

#define RF_PARA_FROM_NOR // if open it to read parameter from nor in case efuse is not ready
// when efuse data is ready, close it

#ifndef TRV_PILOT
#define TRV_PILOT 1
#endif

#define WIFI_SINGLE_DEV 1

#ifndef SYS_NETWORK_SUPPORT
#define SYS_NETWORK_SUPPORT 1
#endif

#ifndef DEFAULT_SYS_CLK
#define DEFAULT_SYS_CLK 144000000UL // options: 32M/48M/72M/144M, and 16*N from 64M to 128M
#endif

#ifndef ATCMD_UARTDEV
#define ATCMD_UARTDEV HG_UART1_DEVID
#endif

#ifndef WIFI_RTS_THRESHOLD
#define WIFI_RTS_THRESHOLD 2304
#endif

#ifndef WIFI_RTS_MAX_RETRY
#define WIFI_RTS_MAX_RETRY 2
#endif

#ifndef WIFI_TX_MAX_RETRY
#define WIFI_TX_MAX_RETRY 7
#endif

#ifndef WIFI_MULICAST_RETRY
#define WIFI_MULICAST_RETRY 0 // 组播帧传输次数
#endif

#ifndef WIFI_MAX_PS_CNT
#define WIFI_MAX_PS_CNT 10 // 底层为休眠sta缓存的帧最大数量。0代表sta休眠由umac全程管理，底层不缓存
#endif

#ifndef GMAC_ENABLE
#define GMAC_ENABLE 1
#endif

#ifndef WIFI_BRIDGE_EN
#define WIFI_BRIDGE_EN 1
#endif

#ifndef WIFI_BRIDGE_DEV1
#define WIFI_BRIDGE_DEV1 HG_GMAC_DEVID
#endif

#ifndef WIFI_AP_SUPPORT
#define WIFI_AP_SUPPORT 1
#endif

#ifndef WIFI_STA_SUPPORT
#define WIFI_STA_SUPPORT 1
#endif

#ifndef WIFI_WNBAP_SUPPORT
#define WIFI_WNBAP_SUPPORT 0 // 支持私有协议的AP
#endif

#ifndef WIFI_WNBSTA_SUPPORT
#define WIFI_WNBSTA_SUPPORT 0 // 支持私有协议的STA
#endif

#ifndef WNB_PSALIVE_SUPPORT
#define WNB_PSALIVE_SUPPORT 0 // 支持私有协议的psmode2
#endif

#ifndef SYS_APP_DHCPD
#define SYS_APP_DHCPD 0
#endif

#ifndef SYS_APP_WNBOTA
#define SYS_APP_WNBOTA 1
#endif

#ifndef SYS_APP_NETAT
#define SYS_APP_NETAT 0
#endif

#ifndef SYS_APP_PAIR
#define SYS_APP_PAIR 1
#endif

#ifndef WNB_ROLEKEY_IO
#define WNB_ROLEKEY_IO PA_8
#endif

#ifndef WNB_PAIRKEY_IO
#define WNB_PAIRKEY_IO PA_7
#endif

#ifndef WNB_CONN_IO
#define WNB_CONN_IO PA_6
#endif

#ifndef WNB_RSSI_IO1
#define WNB_RSSI_IO1 PA_9
#endif

#ifndef WNB_RSSI_IO2
#define WNB_RSSI_IO2 PA_31
#endif

#ifndef WNB_RSSI_IO3
#define WNB_RSSI_IO3 PA_30
#endif

#ifndef SYS_APP_NETLOG
#define SYS_APP_NETLOG 0
#endif

#ifndef SYS_APP_SNTP
#define SYS_APP_SNTP 0
#endif

#ifndef SYS_APP_UHTTPD
#define SYS_APP_UHTTPD 0
#endif

#ifndef SYS_DISABLE_PRINT
#define SYS_DISABLE_PRINT (0)
#endif

#ifndef SYS_DEV_DOMAIN
#define SYS_DEV_DOMAIN 0
#endif

#ifndef WNB_DEV_DOMAIN
#define WNB_DEV_DOMAIN "tx"
#endif

#ifndef WIFI_SSID_PREFIX
#define WIFI_SSID_PREFIX "HALOW_"
#endif

#ifndef SYS_DHCPD_EN
#define SYS_DHCPD_EN 0
#endif

#ifndef SYS_DHCPC_EN
#define SYS_DHCPC_EN 1
#endif

#ifndef SYS_APP_POWER_CTRL
#define SYS_APP_POWER_CTRL 0
#endif

#ifndef SYS_SAVE_PAIRSTA
#define SYS_SAVE_PAIRSTA 1
#endif

#ifndef WIFI_PAIR_MAGIC
#define WIFI_PAIR_MAGIC 0x1234
#endif

#ifndef AUTO_ETHERNET_PHY
#define AUTO_ETHERNET_PHY
#endif

#ifndef ETHERNET_PHY_ADDR
#define ETHERNET_PHY_ADDR -1
#endif

/*! Use GPIO to simulate the MII management interface */
#define HG_GMAC_IO_SIMULATION
#ifndef HG_GMAC_MDIO_PIN
#define HG_GMAC_MDIO_PIN PA_10
#endif
#ifndef HG_GMAC_MDC_PIN
#define HG_GMAC_MDC_PIN PA_11
#endif

#ifndef WIFI_PSALIVE_SUPPORT
#define WIFI_PSALIVE_SUPPORT 0
#endif

#ifndef WIFI_MGR_CMD
#define WIFI_MGR_CMD 0
#endif

#ifndef ROLE_KEY_EN
#define ROLE_KEY_EN 1
#endif

#ifndef LWIP_RAW
#define LWIP_RAW 1 // support at+ping
#endif

#ifndef WIFI_REPEATER_SUPPORT
#define WIFI_REPEATER_SUPPORT 0
#endif

#ifndef TX_PWR_SUPER_EN
#define TX_PWR_SUPER_EN 1
#endif

#ifndef WNB_TX_POWER
#define WNB_TX_POWER 20
#endif

#define ANT_CTRL_PIN PB_1 // 网桥用PB1来做双天线选择

#endif
