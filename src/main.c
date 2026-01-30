#include "basic_include.h"
#include "lib/lmac/lmac.h"
#include "lib/skb/skb.h"
#include "lib/skb/skb_list.h"
#include "lib/bus/macbus/mac_bus.h"
#include "lib/atcmd/libatcmd.h"
#include "lib/bus/xmodem/xmodem.h"
#include "lib/net/skmonitor/skmonitor.h"
#include "lib/net/dhcpd/dhcpd.h"
#include "lib/net/utils.h"
#include "lib/umac/ieee80211.h"
#include "lib/umac/wifi_mgr.h"
#include "lib/umac/wifi_cfg.h"
#include "lib/common/atcmd.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/sys.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "netif/ethernetif.h"
#include "lib/net/skmonitor/skmonitor.h"
#include "pairled.h"
#include "syscfg.h"
#include "lib/lmac/lmac_def.h"
#ifdef MULTI_WAKEUP
#include "lib/common/sleep_api.h"
#include "hal/gpio.h"
#include "lib/lmac/lmac.h"
#include "lib/common/dsleepdata.h"
#endif

static struct os_work main_wk;
extern uint32_t srampool_start;
extern uint32_t srampool_end;
struct system_status  sys_status=
{
    .dbg_lmac=2,
};

void *lmacops;

extern void sys_check_wkreason(uint8 type);
extern void lmac_transceive_statics(uint8 en);
extern sysevt_hdl_res sys_event_hdl(uint32 event_id, uint32 data, uint32 priv);
int32 sys_ieee80211_event_cb(uint8 ifidx, uint16 evt, uint32 param1, uint32 param2);

#ifdef MULTI_WAKEUP
//这个示例实现了4个唤醒源的情况
//1，按键唤醒，跟PIR唤醒通过“逻辑或”电路连到IOB4；无论是保活休眠/断线休眠，都可以唤醒；唤醒后查询到原因是DSLEEP_WK_REASON_IO
//2，PIR唤醒，连到IOB2，同时通过“逻辑或”电路连到IOB4；无论是保活休眠/断线休眠，都可以唤醒；唤醒后查询到原因是DSLEEP_WK_REASON_PIR
//3，BAT低电唤醒，用IOA12连到BAT分压采样电路（因为IOA12满幅度1.1v）；只有保活休眠可以唤醒，断线休眠无法唤醒；唤醒后查询到原因是DSLEEP_WK_REASON_LOW_BAT
//4，其他IO唤醒，连到IOB3；只有保活休眠可以唤醒，断线休眠无法唤醒；唤醒后查询到原因是DSLEEP_WK_REASON_OTHER（用户要自定义这个唤醒原因），扩展用

#ifdef LOW_BAT_WAKEUP
//注意，用了IOA12做BAT检测，需要将打印串口切一下：将UART_TX_PA31宏打开
__at_section(".dsleep_data") uint32 *bat_vol_chk_interval;
#endif

__at_section(".dsleep_text") void system_sleep_enter_hook(void){
    //软件pir检测demo代码
    //注意首先要通过接口设置唤醒IO，这个例子是PB4，上升沿唤醒
    //按键和PIR逻辑或后连到PB4，PIR再单独连到PB2，如果有更多唤醒源，也可以用其他IO照样设置
    system_sleep_config(SLEEP_SETCFG_GPIOB_RESV, BIT(2)|BIT(3), 0);
    gpio_set_dir(PB_2, GPIO_DIR_INPUT);
    gpio_set_mode(PB_2, GPIO_PULL_DOWN, GPIO_PULL_LEVEL_100K);//可以考虑外部下拉更大电阻省功耗
    gpio_set_dir(PB_3, GPIO_DIR_INPUT);
    gpio_set_mode(PB_3, GPIO_PULL_DOWN, GPIO_PULL_LEVEL_100K);//可以考虑外部下拉更大电阻省功耗

#ifdef LOW_BAT_WAKEUP
    //ADC采样要300uS, 可以每隔几个保活窗口采样一次，避免功耗上升较明显
    bat_vol_chk_interval = (uint32 *)sys_sleepdata_request(SYSTEM_SLEEPDATA_ID_USER, sizeof(uint32));
    *bat_vol_chk_interval = 0;
#endif
};

struct dsleep_cfg *dsleep_cfg_get(void);
__at_section(".dsleep_text") void system_sleep_wakeup_hook(void){
    //注意wakeup_hook里面不能加打印，会影响保活唤醒的窗口时序！！！

    struct dsleep_cfg *cfg = dsleep_cfg_get();

    //按键/pir检测demo代码（由于同时连到唤醒Pin（IOB4），可以在纯休眠的时候唤醒）
    //1，如果拉高PB4，但是不拉高PB2，唤醒reason：DSLEEP_WK_REASON_IO
    //2，如果同时拉高PB4和PB2，唤醒reason：DSLEEP_WK_REASON_PIR
    // 一开始的唤醒原因会是IO，通过查询IOB2再区分是不是PIR
    int32 io_val = 0;

    if (cfg->psdata.wk_reason == DSLEEP_WK_REASON_IO) {
        // 唤醒后只能使用非掉电域函数读取IO
        io_val = dsleep_gpio_get_val(PB_2);

        if (io_val == 1) {
            cfg->psdata.wk_reason = DSLEEP_WK_REASON_PIR; // PIR唤醒原因
        }

        return;
    }

#ifdef LOW_BAT_WAKEUP
    //低电唤醒检测代码（只在保活休眠的场景才检测到这个唤醒，不能在断线休眠的时候唤醒）
    uint16 bat_vol;

    //adc sampling will take about 300uA
    (*bat_vol_chk_interval) ++;
    if(*bat_vol_chk_interval == 3){//由于ADC采样会增加保活窗口时间，这里设置3个保活周期查一次电量，也可以根据需要调更久
        dsleep_gpio_set_val(PA_2, 1);
        adkey_init();
        bat_vol = io_input_meas_mv();

        if (bat_vol < 500) {//可以根据需要来修改判断阈值
            cfg->psdata.wk_reason = DSLEEP_WK_REASON_LOW_BAT;
            system_sleep_reset();
        }
        *bat_vol_chk_interval = 0;
        dsleep_gpio_set_val(PA_2, 0);
    }
#endif

    //其他IO唤醒代码；由于不连到唤醒pin（IOB4），只在保活休眠的场景才检测到这个唤醒，不能在断线休眠的时候唤醒；
    if (dsleep_gpio_get_val(PB_3) == 1) {
        //cfg->psdata.wk_reason = DSLEEP_WK_REASON_OTHER;//原因靠客户扩展
        system_sleep_reset();
    }
}
#endif

int32 wifi_proc_drvcmd_cust(uint16 cmd_id, uint8 *data, uint32 len, void *hdr)
{
    /*
       cmd_id: driver cmd id (from host driver).
       data  : cmd data.
       len   : cmd data length.
       hdr   : cmd info, just used to call host_cmd_resp API.

       1. parse cmd data, do some thing if you need.

       2. send cmd response to host: 
          // has no additional response data.
          host_cmd_resp(return_value, NULL, 0, hdr);
          
          // has some additional response data.
          host_cmd_resp(return_value, reponse_data, response_data_length, hdr);
          
       3. return RET_OK if the driver cmd has been processed, else return -ENOTSUPP.

       you can process any driver cmd in this function.
    */
    return -ENOTSUPP;
}

__init static void sys_cfg_load(void)
{
    if (syscfg_init(&sys_cfgs, sizeof(sys_cfgs)) == RET_OK) {
        return;
    }

    os_printf("use default params.\r\n");
    syscfg_set_default_val();
    syscfg_save();
}

__init static void sys_wifi_ap_init(void)
{
    ieee80211_iface_create_ap(WIFI_MODE_AP, IEEE80211_BAND_S1GHZ);
    ieee80211_pair_enable(WIFI_MODE_AP, WIFI_PAIR_MAGIC);
    wificfg_flush(WIFI_MODE_AP);
}

__init static void sys_wifi_sta_init(void)
{
    ieee80211_iface_create_sta(WIFI_MODE_STA, IEEE80211_BAND_S1GHZ);
    ieee80211_pair_enable(WIFI_MODE_STA, WIFI_PAIR_MAGIC);
    ieee80211_conf_stabr_table(WIFI_MODE_STA, 128, 10 * 60);
    wificfg_flush(WIFI_MODE_STA);
}

__init static void sys_wifi_wnbap_init(void)
{
    ieee80211_iface_create_wnbap(WIFI_MODE_WNBAP, IEEE80211_BAND_S1GHZ);
    ieee80211_pair_enable(WIFI_MODE_WNBAP, WIFI_PAIR_MAGIC);
    wificfg_flush(WIFI_MODE_WNBAP);
}

__init static void sys_wifi_wnbsta_init(void)
{
    ieee80211_iface_create_wnbsta(WIFI_MODE_WNBSTA, IEEE80211_BAND_S1GHZ);
    ieee80211_pair_enable(WIFI_MODE_WNBSTA, WIFI_PAIR_MAGIC);
    ieee80211_wnb_roam_enable(WIFI_MODE_WNBSTA);
    wificfg_flush(WIFI_MODE_WNBSTA);
}

__init static void sys_wifi_start(void)
{
    uint8 ifidx = wificfg_get_ifidx(sys_cfgs.wifi_mode, 0);

    if (ifidx < 0) {
        ieee80211_iface_start(WIFI_MODE_AP);
        ieee80211_iface_start(WIFI_MODE_WNBAP);
    } else {
        ieee80211_iface_start(ifidx);
    }
}

__init static void sys_wifi_start_acs(void *ops)
{
    int32 ret;
    struct lmac_acs_ctl acs_ctl;

    if (sys_cfgs.channel == 0 && MODE_IS_AP(sys_cfgs.wifi_mode)) {
        acs_ctl.enable     = sys_cfgs.acs_enable;
        acs_ctl.scan_ms    = sys_cfgs.acs_tmo;
        acs_ctl.chn_bitmap = ~0;
        ret = lmac_start_acs(ops, &acs_ctl, 1);  //阻塞式扫描
        if (ret != RET_ERR) {
            sys_cfgs.channel = ret;
        }
    }
}

// __init static void sys_wifi_init(void)
// {
//     struct lmac_init_param lparam;
//     struct ieee80211_initparam param;

//     skbpool_init(SKB_POOL_ADDR, (uint32)SKB_POOL_SIZE, 90, 0);
//     os_memset(&lparam, 0, sizeof(lparam));
//     lparam.rxbuf = WIFI_RX_BUFF_ADDR;
//     lparam.rxbuf_size = WIFI_RX_BUFF_SIZE;
//     lparam.tdma_buff = TDMA_BUFF_ADDR;
//     lparam.tdma_buff_size = TDMA_BUFF_SIZE;

// #ifdef MACBUS_USB
//     lparam.uart_tx_io = 1;//pa11
// #else
//     #ifdef UART_TX_PA31
//         lparam.uart_tx_io = 2;//pa31
//     #else
//         lparam.uart_tx_io = 0;//pa13
//     #endif
// #endif
//     //os_printf("uart_tx_io=%d in main\r\n",lparam.uart_tx_io);

// #ifdef DUAL_ANT_OPT
//     lparam.dual_ant = 1;//enable dual ant
// #else
//     lparam.dual_ant = 0;//disable dual ant
// #endif
    
//     struct lmac_ops lmacops = lmac_ah_init(&lparam);

//     struct ieee80211_initparam param;
//     os_memset(&param, 0, sizeof(param));
//     param.vif_maxcnt = 4;
//     param.sta_maxcnt = sys_cfgs.sta_max ? sys_cfgs.sta_max : 8;
//     param.bss_maxcnt = 32;
//     param.bss_lifetime  = 300; //300 seconds
//     param.evt_cb = sys_ieee80211_event_cb;

//     ieee80211_init(&param);
//     ieee80211_support_txw830x(lmacops);
//     wifi_mgr_init(FMAC_MAC_BUS, WIFIMGR_FRM_TYPE, DRV_AGGSIZE, lmacops, NULL);

//     ieee80211_deliver_init(128, 60);

// #if WIFI_AP_SUPPORT
//     sys_wifi_ap_init();
// #endif

// #if WIFI_STA_SUPPORT
//     sys_wifi_sta_init();
// #endif

// #if WIFI_WNBAP_SUPPORT
//     sys_wifi_wnbap_init();
// #endif

// #if WIFI_WNBSTA_SUPPORT
//     sys_wifi_wnbsta_init();
// #endif

// #ifdef CONFIG_SLEEP
// #if WIFI_PSALIVE_SUPPORT
//     wifi_mgr_enable_psalive();
// #endif

// #if WIFI_PSCONNECT_SUPPORT
//     wifi_mgr_enable_psconnect();
// #endif
// #endif

// #if WIFI_MGR_CMD
//     wifi_mgrcmd_enable();
// #endif

// #if WIFI_DHCPC_SUPPORT
//     wifi_mgr_enable_dhcpc();
// #endif
//     sys_wifi_start_acs(lmacops);
//     sys_wifi_start();
// }

__init static void sys_network_init(void)
{
#if SYS_NETWORK_SUPPORT
    ip_addr_t ipaddr, netmask, gw;
    struct netdev *ndev;

    tcpip_init(NULL, NULL);
    sock_monitor_init();

    /*register wifi netif: w0*/
    ndev = (struct netdev *)dev_get(HG_WIFI0_DEVID);
    if (ndev) {
        ipaddr.addr  = sys_cfgs.ipaddr;
        netmask.addr = sys_cfgs.netmask;
        gw.addr      = sys_cfgs.gw_ip;
        lwip_netif_add(ndev, "w0", &ipaddr, &netmask, &gw);
        lwip_netif_set_default(ndev);
        if (sys_cfgs.dhcpc_en) {
            sys_status.dhcpc_done = 0;
            lwip_netif_set_dhcp2("w0", 1);
        }
    }
#endif
}

__init static void sys_app_init(void)
{
#if SYS_APP_SNTP
    sntp_client_init("ntp.aliyun.com", 60);
#endif

#if SYS_APP_PAIR
    //sys_pairled_init();
#endif

#if SYS_APP_DSLEEP_TEST
    dsleep_test_init(DSLEEP_TEST_SVR, 200);
#endif

#if SYS_APP_WNBOTA
    wnb_ota_init();
#endif

#if SYS_APP_NETLOG
    netlog_init(64320);
#endif

}

#if (WIFI_STA_SUPPORT || WIFI_WNBSTA_SUPPORT) && SYS_NETWORK_SUPPORT
static void sys_dhcpc_check(void)
{
    if (sys_cfgs.dhcpc_en && !sys_status.dhcpc_done) {
        ip_addr_t ip = lwip_netif_get_ip2("w0");
        if (ip.addr == 0) {
            lwip_netif_set_dhcp2("w0", 1);
        }
    }
}
#endif

static void sys_dbginfo_print(void)
{
    static uint8 _print_buf[512];
    static int8 print_interval = 0;
    if (print_interval++ >= 5) {
        if (sys_status.dbg_top) {
            cpu_loading_print(sys_status.dbg_top == 2, (struct os_task_info *)_print_buf, sizeof(_print_buf)/sizeof(struct os_task_info));
        }
        if (sys_status.dbg_heap) {
            sysheap_status(&sram_heap, (uint32 *)_print_buf, sizeof(_print_buf)/4, 0);
            skbpool_status((uint32 *)_print_buf, sizeof(_print_buf)/4, 0);
        }
        if (sys_status.dbg_lmac) {
            lmac_transceive_statics(sys_status.dbg_lmac);
        }
        if (sys_status.dbg_umac) {
            ieee80211_status(_print_buf, sizeof(_print_buf));
            wifi_mgr_status();
        }
        if (sys_status.dbg_irq) {
            irq_status();
        }

#if SYS_APP_SNTP //sample code for NTP
        do {
            struct timeval tv;
            gettimeofday(&tv, 0);
            tv.tv_sec  += 8 * 3600; //时区
            os_printf("system time: %s\r\n", ctime((const time_t *)&tv.tv_sec));
        } while (0);
#endif

        print_interval = 0;
    }
}

static int32 sys_main_loop(struct os_work *work)
{
    static uint8 pa7_val = 0;

    //sys_dbginfo_print();

    /* blink PA7 */
    pa7_val = !pa7_val;
    //gpio_set_val(PA_7, pa7_val);

    /* run again after 1000 ms */
    //os_printf("1234\n");
    //uart_putc(uart, int8 value)
    //hgprintf("sys main loop\r\n");
    os_run_work_delay(&main_wk, 100);


    uint8 payload[64];
    for (unsigned i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8)i;
    }
    //sys_wifi_start_acs(lmacops);
    //ah_ce_start()
    //(void)lmac_raw_tx_once(ops, payload, sizeof(payload));
    return 0;
}

__init static void sys_wifi_init(void)
{
    struct lmac_init_param lparam;
    struct ieee80211_initparam param;

    sys_cfgs.wifi_mode = WIFI_MODE_AP;
    skbpool_init(SKB_POOL_ADDR, (uint32)SKB_POOL_SIZE, 90, 0);
    os_memset(&lparam, 0, sizeof(lparam));
    lparam.rxbuf = WIFI_RX_BUFF_ADDR;
    lparam.rxbuf_size = WIFI_RX_BUFF_SIZE;
    lparam.tdma_buff = TDMA_BUFF_ADDR;
    lparam.tdma_buff_size = TDMA_BUFF_SIZE;

#ifdef DUAL_ANT_OPT
    lparam.dual_ant = 1;//enable dual ant
#else
    lparam.dual_ant = 0;//disable dual ant
#endif

    lmacops = lmac_ah_init(&lparam); 
    os_memset(&param, 0, sizeof(param));
    param.vif_maxcnt = 4;
    param.sta_maxcnt = SYS_STA_MAX;
    param.bss_maxcnt = 4;
    param.bss_lifetime = 300; //300 seconds
    param.evt_cb = sys_ieee80211_event_cb;
    ieee80211_init(&param);
    ieee80211_support_txw830x(lmacops);

    ieee80211_deliver_init(128, 60);
    wificfg_set_beacon_int(500);

    ieee80211_iface_create_ap(WIFI_MODE_AP, IEEE80211_BAND_S1GHZ);
    ieee80211_pair_enable(WIFI_MODE_AP, WIFI_PAIR_MAGIC);
    wificfg_flush(WIFI_MODE_AP);
    //sys_wifi_ap_init();
    //os_sleep(1);
    //sys_wifi_sta_init();
    //sys_wifi_wnbap_init();
    //sys_wifi_wnbsta_init();

//#if WIFI_PSALIVE_SUPPORT
//    wifi_mgr_enable_psalive();
//#endif
    sys_wifi_start_acs(lmacops);
    //sys_wifi_start();
    
    ieee80211_iface_start(WIFI_MODE_AP);
    ieee80211_iface_start(WIFI_MODE_WNBAP);
    //sys_wifi_
}

__init int main(void)
{
    extern uint32 __sinit, __einit;
    mcu_watchdog_timeout(0);
    
    

    //sys_cfg_load();
    //syscfg_check();
	
	//gpio_set_dir(PA_7, GPIO_DIR_OUTPUT);
    //gpio_set_val(PA_7, 0);
	
    sys_event_init(32);
    sys_event_take(0xffffffff, sys_event_hdl, 0);
    
    sys_cfg_load();
    //syscfg_set_default_val();
    syscfg_check();
    sys_cfgs.super_pwr_set = 1;
    sys_wifi_init();
    
	OS_WORK_INIT(&main_wk, sys_main_loop, 0);
    os_run_work_delay(&main_wk, 1000);
    sysheap_collect_init(&sram_heap, (uint32)&__sinit, (uint32)&__einit);
    os_printf("use default params.\r\n");
    return 0;

    //sys_check_wkreason(WKREASON_START_UP);

    return 0;


    

    struct lmac_init_param lparam;

    skbpool_init(SKB_POOL_ADDR, (uint32)SKB_POOL_SIZE, 90, 0);
    os_memset(&lparam, 0, sizeof(lparam));
    lparam.rxbuf = WIFI_RX_BUFF_ADDR;
    lparam.rxbuf_size = WIFI_RX_BUFF_SIZE;
    lparam.tdma_buff = TDMA_BUFF_ADDR;
    lparam.tdma_buff_size = TDMA_BUFF_SIZE;

    lparam.uart_tx_io = 0;//pa13
    os_printf("uart_tx_io=%d in main\r\n",lparam.uart_tx_io);

    //struct lmac_ops *
    lmacops = (struct lmac_ops*)lmac_ah_init(&lparam);
    if (lmacops == NULL) {
        return 0;
    }

    lmac_radio_onoff(lmacops, 1);
    lmac_set_pri_chan(lmacops, 3);
    lmac_set_bss_bw(lmacops, 2);
    lmac_set_tx_bw(lmacops, 2);
    lmac_set_txpower(lmacops, 8);


    struct ieee80211_initparam param;
     os_memset(&param, 0, sizeof(param));
     param.vif_maxcnt = 4;
     param.sta_maxcnt = sys_cfgs.sta_max ? sys_cfgs.sta_max : 8;
     param.bss_maxcnt = 32;
     param.bss_lifetime  = 300; //300 seconds
     param.evt_cb = sys_ieee80211_event_cb;

    ieee80211_init(&param);
    ieee80211_support_txw830x(lmacops);
    wifi_mgr_init(FMAC_MAC_BUS, WIFIMGR_FRM_TYPE, DRV_AGGSIZE, lmacops, NULL);

    ieee80211_deliver_init(128, 60);

// #if WIFI_AP_SUPPORT

    ieee80211_iface_create_ap(WIFI_MODE_AP, IEEE80211_BAND_S1GHZ);
    ieee80211_pair_enable(WIFI_MODE_AP, WIFI_PAIR_MAGIC);
    wificfg_flush(WIFI_MODE_AP);

    //sys_atcmd_init();
    
    //sys_wifi_init();
    //sys_network_init();
    //sys_app_init();
	OS_WORK_INIT(&main_wk, sys_main_loop, 0);
    os_run_work_delay(&main_wk, 1000);
    //sys_check_wkreason(WKREASON_START_UP);
    sysheap_collect_init(&sram_heap, (uint32)&__sinit, (uint32)&__einit);
    return 0;
}

