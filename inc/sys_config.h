#ifndef __SYS_CONFIG_H__
#define __SYS_CONFIG_H__

#define PROJECT_TYPE           PRO_TYPE_WNB
#define FW_VERSION              "2.3.0"

#define IP_SOF_BROADCAST       1
#define LWIP_RAW               1
#define LWIP_NETIF_HOSTNAME    1

// LWIP debug

//#define TCPIP_MBOX_SIZE              32
#define DEFAULT_TCP_RECVMBOX_SIZE    16
//#define DEFAULT_ACCEPTMBOX_SIZE      8
/* 4*MSS: the RF link tops out ~0.5 Mbps; a 10*MSS window let the single TCP
 * client legally pin ~14 pool pbufs and forced PBUF_POOL_SIZE=48 (72 KiB of
 * the RAM-resident firmware). 4*MSS (~5.8 KB) still saturates the link
 * (5.8 KB / 100 ms RTT > 460 kbps) and frees the pool pressure below. */
#define TCP_WND                     (TCP_MSS*4)
#define MEMP_NUM_TCP_PCB            16
#define MEMP_NUM_TCP_PCB_LISTEN     8
/* 24 pbufs (~36 KiB) are enough NOW that TCP_WND is 4*MSS: the client can
 * hold ~5-6 pbufs + recvmbox + web UI. (With the old 10*MSS window 24 starved
 * the pool under bidir load and the GMAC RX path dropped silently on
 * pbuf_alloc NULL -- that is why this was 48.) Verify with a TCP blast. */
#define PBUF_POOL_SIZE              48
//#define DEFAULT_RAW_RECVMBOX_SIZE 8
//#define MEMP_NUM_NETBUF 8
#define TCP_LISTEN_BACKLOG 1
#define LWIP_SO_RCVTIMEO 1
#define LWIP_SO_SNDTIMEO 1
#define MQTT_OUTPUT_RINGBUF_SIZE 1024

// LWIP debug
// #define LWIP_DEBUG                  1
// #define LWIP_DBG_MIN_LEVEL          LWIP_DBG_LEVEL_ALL
// #define LWIP_DBG_TYPES_ON           LWIP_DBG_ON

// #define TCP_INPUT_DEBUG      LWIP_DBG_ON
// #define TCP_OUTPUT_DEBUG     LWIP_DBG_ON
// #define TCP_RST_DEBUG        LWIP_DBG_ON
// #define TCP_RTO_DEBUG        LWIP_DBG_ON
// #define API_LIB_DEBUG        LWIP_DBG_ON
// #define API_MSG_DEBUG        LWIP_DBG_ON
// #define TCP_WND_DEBUG        LWIP_DBG_ON
// #define TCP_QLEN_DEBUG       LWIP_DBG_ON

/* RNS stream decoder frame buffer: sized for the actual link MTU (500 B
 * reticulum) with headroom. RNS_MAX_MTU (8 KB) is the protocol ceiling, but
 * real frames are ~519 B (header + payload). 2048 covers any single RNS frame
 * on this link and frees ~8 KB vs the original 10 KB default. */
#ifndef RNS_STREAM_MAX_FRAME_SIZE
#define RNS_STREAM_MAX_FRAME_SIZE       (1024*2)
#endif

#define TDMA_BUFF_SIZE 0

/*
 * Auto-sized malloc heap
 * ----------------------
 * The malloc heap takes ALL free SRAM that is not reserved for the WiFi DMA RX
 * buffer or the TX skb pool.  The pool boundaries come from the linker symbols
 * __heap_start (= end of .bss) and __heap_end (= top of SRAM), so the heap
 * grows / shrinks automatically as firmware size changes — no manual tuning.
 *
 * SKB_POOL_RESERVE is the minimum kept back for the TX skb free-list.  The skb
 * pool is a software free-list: exhaustion causes graceful -5 TX drops (no
 * crash).  48 KB comfortably covers the TX_BUFFER_SIZE (29 200 B) in-flight
 * budget for full-size frames with headroom for LMAC mgmt skbs.
 */
#define SKB_POOL_RESERVE  (48 * 1024)

#define WIFI_RX_BUFF_SIZE (40 * 1024) //(17*1024)

#define SRAM_POOL_START   (srampool_start)
#define SRAM_POOL_SIZE    (srampool_end - srampool_start)
#define SYS_HEAP_SIZE     (SRAM_POOL_SIZE - TDMA_BUFF_SIZE - WIFI_RX_BUFF_SIZE - SKB_POOL_RESERVE)
#define TDMA_BUFF_ADDR    (SRAM_POOL_START)
#define SYS_HEAP_START    (TDMA_BUFF_ADDR + TDMA_BUFF_SIZE)
#define WIFI_RX_BUFF_ADDR (SYS_HEAP_START + SYS_HEAP_SIZE)
#define SKB_POOL_ADDR     (WIFI_RX_BUFF_ADDR + WIFI_RX_BUFF_SIZE)
#define SKB_POOL_SIZE     (SRAM_POOL_START + SRAM_POOL_SIZE - SKB_POOL_ADDR)

#define DEFAULT_SYS_CLK   (128000000UL) // options: 32M/48M/72M/144M, and 16*N from 64M to 128M

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



#define MQTT_RETRIES                            (3)
#define MQTT_DNS_TO_MS                          (5000)
#define MQTT_CONN_TO_MS                         (8000)
#define MQTT_PUB_TO_MS                          (8000)
#define MQTT_RETRY_MS                           (500)

// SLIP static ip only
#define SLIP_RX_FROM_ISR                        (0)
#define SLIP_USE_RX_THREAD                      (0)
#define UART_SLIP_DEVICE                        (uart1)
#define UART_SLIP_RB_SIZE                       (2048)
#define UART_SLIP_CONFIG_ENABLE_DEF             (true)
#define UART_SLIP_CONFIG_BAUD_DEF               (2000000)
#define UART_SLIP_CONFIG_IP_ADDR_DEF            PP_HTONL(LWIP_MAKEU32(192,168,7,2))
#define UART_SLIP_CONFIG_IP_MASK_DEF            PP_HTONL(LWIP_MAKEU32(255,255,255,255))
#define UART_SLIP_CONFIG_IP_GW_DEF              PP_HTONL(LWIP_MAKEU32(192,168,7,1))

#define NET_IP_CONFIG_MODE_DEF                  (NET_IP_MODE_DHCP)
#define NET_IP_CONFIG_IP_DEF                    PP_HTONL(LWIP_MAKEU32(192, 168, 42, 42))
#define NET_IP_CONFIG_MASK_DEF                  PP_HTONL(LWIP_MAKEU32(255, 255, 255, 0))
#define NET_IP_CONFIG_GW_DEF                    PP_HTONL(LWIP_MAKEU32(0, 0, 0, 0))

#define NET_LOG_CONFIG_EN_DEF                   (true)
#define NET_LOG_CONFIG_IP_DEF                   PP_HTONL(LWIP_MAKEU32(192,168,7,1))
#define NET_LOG_CONFIG_PORT_DEF                 (5000)

#define LOG_OUTPUT_TARGET_NET                   (0)
#define LOG_OUTPUT_TARGET_UART                  (1)
#define LOG_OUTPUT_TARGET                       LOG_OUTPUT_TARGET_UART

/* Default channel = 920 MHz. The deployed nodes use 915 MHz ISM-band antennas
 * (resonant ~905-925 MHz). At 864.5 MHz the balcony node's RX antenna is
 * off-resonance and decodes only ~40% of frames regardless of power/MCS; at
 * 920 MHz both directions are <1% (measured). This is a hardware fact, so it
 * belongs in the default. Runtime /api/halow_cfg still overrides it. */
#define HALOW_CONFIG_CENTRAL_FREQ_DEF           (9200)
#define HALOW_CONFIG_POWER_DEF                  (14)
#define HALOW_CONFIG_BANDWIDTH_DEF              (1)
#define HALOW_CONFIG_MCS_DEF                    (0)
#define HALOW_CONFIG_SPOWER_EN_DEF              (false)
#define HALOW_LBT_IGNORE_CCA_DEF                (false)
#define HALOW_LBT_CCA_ENABLED_DEF               (true)
#define HALOW_LBT_CCA_SENSITIVITY_DEF            (5)
#define HALOW_LBT_CCA_FORCE_TX_PCT_DEF          (1)
#define HALOW_LBT_DUTY_LIMIT_PCT_DEF            (1000)
#define HALOW_LBT_CW_MIN_DEF                    (63)
#define HALOW_LBT_CW_MAX_DEF                    (1023)
#define HALOW_LBT_CCA_THRESHOLD_DYNAMIC_DEF     (0)

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

#define TCP_SERVER_PORT                         (8001)
#define TCP_SERVER_MTU                          (TCP_MSS)

#define TCP_SERVER_CONFIG_ENABLED_DEF           (true)
#define TCP_SERVER_CONFIG_PORT_DEF              (4242)
#define TCP_SERVER_CONFIG_WHITELIST_IP_DEF      PP_HTONL(LWIP_MAKEU32(0, 0, 0, 0))
#define TCP_SERVER_CONFIG_WHITELIST_MASK_DEF    PP_HTONL(LWIP_MAKEU32(0, 0, 0, 0))

#define CONFIG_PAGE_TASK_PRIO                   (OS_TASK_PRIORITY_ABOVE_NORMAL)
#define CONFIG_PAGE_TASK_STACK                  (4*1024)

#define TCP_SERVER_TASK_PRIO                    (OS_TASK_PRIORITY_ABOVE_NORMAL + 2)
#define TCP_SERVER_TASK_STACK                   (4*1024)

#define STATISTICS_TASK_PRIO                    (OS_TASK_PRIORITY_LOW)
#define STATISTICS_TASK_STACK                   (2*1024)

#define LINK_DB_SWEEP_TASK_PRIO                 (OS_TASK_PRIORITY_LOW)
#define LINK_DB_SWEEP_TASK_STACK                (1*1024)
#define LINK_DB_SWEEP_PERIOD_S                  (60)

#define HALOW_LBT_LISTEN_TASK_PRIO              (OS_TASK_PRIORITY_IDLE)
#define HALOW_LBT_LISTEN_TASK_STACK             (2*1024)

#define TCPIP_THREAD_PRIO                       (OS_TASK_PRIORITY_ABOVE_NORMAL + 5)
#define TCPIP_THREAD_STACKSIZE                  (2*1024)

#define UART_SLIP_TASK_PRIO                     (OS_TASK_PRIORITY_ABOVE_NORMAL + 4)
#define UART_SLIP_TASK_STACK                    (2*1024)

#define NET_LOG_TASK_PRIO                       (OS_TASK_PRIORITY_ABOVE_NORMAL + 3)
#define NET_LOG_TASK_STACK                      (2*1024)

#define TELEMETRY_WORK_PRIO                     (OS_TASK_PRIORITY_BELOW_NORMAL)

#define LOG_LEVEL_CONFIGDB                      (LOG_NONE)
#define LOG_LEVEL_LITTLEFS                      (LOG_NONE)
#define LOG_LEVEL_OTA_LFS                       (LOG_NONE)
#define LOG_LEVEL_OTA                           (LOG_NONE)
#define LOG_LEVEL_NET_IP                        (LOG_NONE)
#define LOG_LEVEL_CONFIG_API_CALLS              (LOG_NONE)
#define LOG_LEVEL_CONFIG_API_DISPATCH           (LOG_NONE)
#define LOG_LEVEL_CONFIG_API_OTA                (LOG_NONE)
#define LOG_LEVEL_CONFIG_PAGE                   (LOG_NONE)
#define LOG_LEVEL_TFTP_SERVER                   (LOG_NONE)
#define LOG_LEVEL_STATISTICS                    (LOG_NONE)
#define LOG_LEVEL_TCP_SERVER                    (LOG_WARN)
#define LOG_LEVEL_TELEMETRY                     (LOG_NONE)
#define LOG_LEVEL_RNS_STREAM_PARSER             (LOG_NONE)
#define LOG_LEVEL_RNS_LINK_DB                   (LOG_WARN)
#define LOG_LEVEL_FAL_PORT                      (LOG_INFO)
#define LOG_LEVEL_RNS_LINK_PARSER               (LOG_NONE)
#define LOG_LEVEL_UART_SLIP                     (LOG_NONE)
#define LOG_LEVEL_HALOW_PKG_HANDLER             (LOG_NONE)
#define LOG_LEVEL_HALOW                        (LOG_WARN)
#define LOG_LEVEL_MARS_LMAC_HW                  (LOG_NONE)
#define LOG_LEVEL_MARS_LMAC_TX                  (LOG_WARN)
#define LOG_LEVEL_MARS_RFSPI                    (LOG_NONE)
#define LOG_LEVEL_MARS_TDMA                     (LOG_NONE)
#define LOG_LEVEL_LMAC_RXQ                      (LOG_NONE)

#define RNS_STREAM_PARSER_LOG_LEVEL LOG_LEVEL_RNS_STREAM_PARSER
#define RNS_LINK_PARSER_LOG_LEVEL LOG_LEVEL_RNS_LINK_PARSER

#endif
