#ifndef __SYS_PROJECT_CONFIG_H__

#define __SYS_PROJECT_CONFIG_H__

#define MACBUS_SDIO
//#define MACBUS_USB
//#define MACBUS_UART

#ifdef MACBUS_UART
#define UART_BUS_TIMER      HG_TIMER2_DEVID
#define UARTBUS_DEV         HG_UART0_DEVID
#define UARTBUS_DEV_BAUDRATE   115200            //波特率范围57600~400k
#define WIFIMGR_FRM_TYPE    WIFIMGR_FRM_TYPE_RAW //串口默认用RAW数据类型，如果需要用Nonos驱动接口，注释掉这个宏
#define WIFI_DHCPC_SUPPORT  0                    //如果串口用RAW,就把DHCPC关掉，否现串口会有乱码出现
#endif

#define CONFIG_SLEEP             //默认支持SLEEP
#define WIFI_PSALIVE_SUPPORT 1   //默认支持标准协议的psmode2（服务器保活）
#define WIFI_PSCONNECT_SUPPORT 1 //默认支持PSCONNECT（不连接状态时休眠和发起连接周期进行）

#define WIFI_REPEATER_SUPPORT 0  //中继模式默认关掉的

/* fmac enable lwip */
//#define SYS_NETWORK_SUPPORT 1  //用LWIP的话需要打开
//#define LWIP_RAW            1  //LWIP默认关掉的

//#define SYS_STA_MAX (31)       //不打开这个宏，最大支持8sta，打开则最大支持31 sta，不支持更多sta了

//#define SKB_TRACE

//二次开发相关
//#define UART_TX_PA31           //如果要用PA12做ADKEY，就打开这个宏，把调试串口切到：Tx PA31，Rx PA13
//#define MULTI_WAKEUP           //多唤醒源的示例代码
//#define LOW_BAT_WAKEUP         //低电唤醒的示例代码

//#define DUAL_ANT_OPT           //使能双天线，串口透传的固件要开双天线的话，要开这个宏；
                                 //对于sdio和usb等接口，可以通过驱动打开，就不用开这个宏；




#endif

