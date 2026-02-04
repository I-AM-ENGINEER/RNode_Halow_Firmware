#include "sys_config.h"
#include "typesdef.h"
#include "list.h"
#include "dev.h"
#include "devid.h"
#include "osal/string.h"
#include "osal/semaphore.h"
#include "osal/mutex.h"
#include "osal/irq.h"
#include "osal/work.h"
#include "osal/sleep.h"
#include "osal/timer.h"
#include "hal/gpio.h"
#include "hal/uart.h"
#include "lib/common/common.h"
#include "lib/common/sysevt.h"
#include "lib/heap/sysheap.h"
#include "lib/syscfg/syscfg.h"
#include "lib/lmac/lmac.h"
#include "lib/skb/skbpool.h"
#include "lib/atcmd/libatcmd.h"
#include "lib/bus/xmodem/xmodem.h"
#include "lib/net/skmonitor/skmonitor.h"
#include "lib/net/dhcpd/dhcpd.h"
#include "lib/umac/ieee80211.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/sys.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "netif/ethernetif.h"
#include "syscfg.h"
//#include "pairled.h"

static struct os_task tcptest_task;
static in_addr_t tcptest_ip = 0;
static uint16    tcptest_port = 0;
static int32     tcpmode = 0;

static void tcp_test_client(void *arg)
{
    int sock = -1;
    int ret  = -1;
    //int optval = 1;
    struct sockaddr_in server_addr;
    uint8 *txbuf = os_malloc(1400);

    os_memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = tcptest_ip;
    server_addr.sin_port        = htons(tcptest_port);

    ASSERT(txbuf);
    os_printf("tcp client test start ...\r\n");
    while (1) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            os_printf("create socket fail\n");
            os_sleep(1);
            continue;
        }

        //ret = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
        ret = connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
        if (ret < 0) {
            os_printf("connect fail, ret:<%d>!\n", ret);
            os_sleep(1);
            closesocket(sock);
            continue;
        }

        while (1) {
            ret = send(sock, txbuf, 1400, 0);
            if (ret < 0) {
                os_printf("send fail, ret:<%d>!\n", ret);
                break;
            }
        }
        closesocket(sock);
    }
}

static void tcp_test_server(void *arg)
{
    int s = -1;
    int sock = -1;
    int ret  = -1;
    int addrlen = 16;
    struct sockaddr_in addr;
    uint8 *tcpbuf = os_malloc(1500);
    uint32 rxlen  = 0;
    uint32 lasttick;

    os_memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(tcptest_port);

    ASSERT(tcpbuf);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        os_printf("create socket fail\n");
        os_sleep(1);
        return;
    }

    ret = bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    if (ret < 0) {
        os_printf("bind fail, ret:<%d>!\n", ret);
        closesocket(sock);
        return;
    }

    if (listen(sock, 20) < 0) {
        os_printf("tcp listen error\n");
        closesocket(sock);
        return;
    }

    os_printf("tcp server test start, port:%d ...\r\n", tcptest_port);
    while (1) {
        s = accept(sock, (struct sockaddr *)&addr, (socklen_t *)&addrlen);
        if (s != -1) {
            os_printf("accept new client from %s:%d\r\n", inet_ntoa(addr.sin_addr.s_addr), os_ntohs(addr.sin_port));
            rxlen = 0;
            lasttick = os_jiffies();
            while (1) {
                ret = recv(s, tcpbuf, 1500, 0);
                if (ret < 0) {
                    os_printf("recv fail, close socket <%d>!\n", ret);
                    break;
                }
                rxlen += ret;
                if(TIME_AFTER(os_jiffies(), lasttick+os_msecs_to_jiffies(1000))){
                    os_printf("tcp test: %dKB/s\r\n", rxlen/1024);
                    rxlen = 0;
                    lasttick = os_jiffies();
                }
            }
            closesocket(s);
        }
    }
    closesocket(sock);
}

static int32 tcp_test_atcmd_hdl(const char *cmd, char *argv[], uint32 count)
{
    if (count >= 2) {
        if(tcptest_ip){
            atcmd_printf("+ERROR: tcp test busy\r\n");
            return 0;
        }

        tcpmode      = (count==3?(os_strcmp(argv[2],"s")==0):0);
        tcptest_ip   = inet_addr(argv[0]);
        tcptest_port = os_atoi(argv[1]);
        if (tcptest_port == 0) { 
            tcptest_port = 60001; 
        }
        
        os_printf("tcp test: %s:%s, mode:%s\r\n", argv[0], argv[1], tcpmode?"Server":"Client");
        if(tcpmode){
            OS_TASK_INIT("tcptest", &tcptest_task, tcp_test_server, 0, OS_TASK_PRIORITY_LOW, 1024);
        }
        else{
            if (tcptest_ip == IPADDR_NONE) {
                atcmd_error;
                return 0;
            }
            OS_TASK_INIT("tcptest", &tcptest_task, tcp_test_client, 0, OS_TASK_PRIORITY_LOW, 1024);
        }
        atcmd_ok;
    } else {
        atcmd_error;
    }
    return 0;
}


__init void sys_tcptest_init(void)
{
    atcmd_register("AT+TCPTEST", tcp_test_atcmd_hdl);
}
