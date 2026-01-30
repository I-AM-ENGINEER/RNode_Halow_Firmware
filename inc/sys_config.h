#ifndef __SYS_CONFIG_H__
#define __SYS_CONFIG_H__
#include "project_config.h"

#define PROJECT_TYPE PRO_TYPE_FMAC

#ifndef SYSCFG_ENABLE
#define SYSCFG_ENABLE 1
#endif

#ifndef K_iPA
#define K_EXT_PA
#endif

#define K_SWITCH_PWR_PA22

#define K_SINGLE_PIN_SWITCH
#define RF_PARA_FROM_NOR   //if open it to read parameter from nor in case efuse is not ready
//when efuse data is ready, close it

#ifndef TRV_PILOT
#define TRV_PILOT 1
#endif

#define USING_TX_SQ
#define TDMA_DEBUG
#define RXSUBFRAME_EN       1
#define RXSUBFRAME_PERIOD   (5)

//#define SYS_IRQ_STAT

//bgrssi calc
#ifndef TDMA_BUFF_SIZE
#define TDMA_BUFF_SIZE    (32*4*80)
#endif

#ifndef SYS_STA_MAX
#define SYS_STA_MAX (8)
#endif

#ifndef SYS_HEAP_SIZE
#if SYS_STA_MAX <= 8
#define SYS_HEAP_SIZE     (50*1024)
#else
#define SYS_HEAP_SIZE     (50*1024+64*1024)
#endif
#endif

#ifndef WIFI_RX_BUFF_SIZE
#define WIFI_RX_BUFF_SIZE (100*1024)
#endif

#define SRAM_POOL_START   (srampool_start)
#define SRAM_POOL_SIZE    (srampool_end - srampool_start)
#define TDMA_BUFF_ADDR    (SRAM_POOL_START)
#define SYS_HEAP_START    (TDMA_BUFF_ADDR+TDMA_BUFF_SIZE)
#define WIFI_RX_BUFF_ADDR (SYS_HEAP_START+SYS_HEAP_SIZE)
#define SKB_POOL_ADDR     (WIFI_RX_BUFF_ADDR+WIFI_RX_BUFF_SIZE)
#define SKB_POOL_SIZE     (SRAM_POOL_START+SRAM_POOL_SIZE-SKB_POOL_ADDR)


#if defined(MACBUS_SDIO)
#define FMAC_MAC_BUS MAC_BUS_TYPE_SDIO
#elif defined(MACBUS_USB)
#define FMAC_MAC_BUS MAC_BUS_TYPE_USB
#elif defined(MACBUS_UART)
#define FMAC_MAC_BUS MAC_BUS_TYPE_UART
#else
#error "FMAC_MAC_BUS is not defined"
#endif

#ifndef DEFAULT_SYS_CLK
#define DEFAULT_SYS_CLK   64000000UL //options: 32M/48M/72M/144M, and 16*N from 64M to 128M
#endif

#ifndef ATCMD_UARTDEV
#ifdef MACBUS_USB
#define ATCMD_UARTDEV HG_UART0_DEVID
#else
#define ATCMD_UARTDEV HG_UART1_DEVID
#endif
#endif

#ifndef SYS_WIFI_MODE
#define SYS_WIFI_MODE WIFI_MODE_AP
#endif

#ifndef LED_INIT_BLINK
#define LED_INIT_BLINK 1
#endif

#ifndef DSLEEP_PAPWRCTL_DIS
#define DSLEEP_PAPWRCTL_DIS 0
#endif

#ifndef TX_POWER
#define TX_POWER 20
#endif

#ifndef DC_DC_1_3V
#define DC_DC_1_3V 0
#endif

#ifndef SYS_NETWORK_SUPPORT
#define SYS_NETWORK_SUPPORT 0
#endif

#ifndef WIFI_AP_SUPPORT
#define WIFI_AP_SUPPORT 1
#endif

#ifndef WIFI_STA_SUPPORT
#define WIFI_STA_SUPPORT 1
#endif

#ifndef WIFI_WNBAP_SUPPORT
#define WIFI_WNBAP_SUPPORT 0  //支持私有协议的AP
#endif

#ifndef WIFI_WNBSTA_SUPPORT
#define WIFI_WNBSTA_SUPPORT 0  //支持私有协议的STA
#endif

#ifndef WNB_PSALIVE_SUPPORT
#define WNB_PSALIVE_SUPPORT 0  //支持私有协议的psmode2
#endif

#ifndef WIFI_PSALIVE_SUPPORT
#define WIFI_PSALIVE_SUPPORT 0
#endif

#ifndef WIFI_PSCONNECT_SUPPORT
#define WIFI_PSCONNECT_SUPPORT 0
#endif

#ifndef WIFI_REPEATER_SUPPORT
#define WIFI_REPEATER_SUPPORT 0
#endif

#ifndef WIFI_DHCPC_SUPPORT
#define WIFI_DHCPC_SUPPORT 1
#endif

#ifndef SYS_APP_DSLEEP_TEST
#define SYS_APP_DSLEEP_TEST 0
#endif

#ifndef DSLEEP_TEST_SVR
#define DSLEEP_TEST_SVR NULL
#endif

#ifndef SYS_APP_PAIR
#define SYS_APP_PAIR 1
#endif

#ifndef SYS_APP_WNBOTA
#define SYS_APP_WNBOTA 0
#endif

#ifndef WNB_PAIRKEY_IO
#define WNB_PAIRKEY_IO PA_9
#endif

#ifndef WNB_RSSI_IO1
#define WNB_RSSI_IO1   PA_7
#endif

#ifndef WNB_RSSI_IO2
#define WNB_RSSI_IO2   PA_6
#endif

#ifndef WIFI_SSID_PREFIX
#define WIFI_SSID_PREFIX "HALOW_"
#endif

#ifndef SYS_SAVE_PAIRSTA
#define SYS_SAVE_PAIRSTA 1
#endif

#ifndef WIFI_MGR_CMD
#define WIFI_MGR_CMD 1
#endif

#ifndef WIFI_PAIR_MAGIC
#define WIFI_PAIR_MAGIC 0x1234
#endif

#ifndef DRV_AGGSIZE
#define DRV_AGGSIZE (0)
#endif

#ifndef SYS_APP_NETLOG
#define SYS_APP_NETLOG 0
#endif

#ifndef WIFIMGR_FRM_TYPE
#define WIFIMGR_FRM_TYPE WIFIMGR_FRM_TYPE_HGIC
#endif

#define ANT_CTRL_PIN PA_31        //FMAC用PA31来做双天线选择


#endif
