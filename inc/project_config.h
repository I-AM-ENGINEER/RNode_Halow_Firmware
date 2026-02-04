#ifndef __SYS_PROJECT_CONFIG_H__

#define __SYS_PROJECT_CONFIG_H__

#define SYS_WIFI_MODE         WIFI_MODE_AP
#define SYS_APP_DHCPD         1
#define SYS_APP_WNBOTA        1
#define SYS_APP_NETAT         1
#define SYS_APP_NETLOG        1
#define SYS_DHCPD_EN          1

#define WIFI_REPEATER_SUPPORT 0 // 默认不支持中继

#define WIFI_PSALIVE_SUPPORT  1 // 支持标准协议的psmode2（服务器保活）

// #define SKB_TRACE

// #define SYS_STA_MAX (31)       //最大支持31 sta
// #define DUAL_ANT_OPT           //使能双天线
// #define ROLE_KEY_EN  0         //不需要角色IO的时候，打开这个宏

#endif
