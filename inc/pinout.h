#ifndef __PINOUT_H__
#define __PINOUT_H__

// PA30/31 - SWIO/SWCLK pins and should be disabled when debug
#define SWITCH_ROLE_PIN                 PA_8    // Unused
#define BUTTON_PAIR_PIN                 PA_7    // Factory reset & recovery
#define INDICATION_LED_CONNECT_PIN      PA_6    // Heartbeat
#define INDICATION_LED_RSSI1_PIN        PA_9    // Unused
#define INDICATION_LED_RSSI2_PIN        PA_31   // TX indication
#define INDICATION_LED_RSSI3_PIN        PA_30   // RX indication

/*! Use GPIO to simulate the MII management interface */
#define HG_GMAC_IO_SIMULATION
#define HG_GMAC_MDIO_PIN                PA_10
#define HG_GMAC_MDC_PIN                 PA_11

// #define ANT_CTRL_PIN PB_1 // 网桥用PB1来做双天线选择     // Unused

#endif //__PINOUT_H__
