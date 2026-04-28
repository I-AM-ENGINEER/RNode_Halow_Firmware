#include "basic_include.h"
#include "net_log.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "configdb.h"
#include "lwip/api.h"
#include "lwip/ip_addr.h"
#include "lib/lwrb/lwrb.h"
#include "osal/semaphore.h"
#include "osal/task.h"
#include "port.h"
#include "sys_config.h"

#define NET_LOG_CONFIG_PREFIX               CONFIGDB_ADD_MODULE("net_log")
#define NET_LOG_CONFIG_ADD_CONFIG(name)     NET_LOG_CONFIG_PREFIX "." name

#define NET_LOG_CONFIG_EN_NAME              NET_LOG_CONFIG_ADD_CONFIG("enable")
#define NET_LOG_CONFIG_IP_NAME              NET_LOG_CONFIG_ADD_CONFIG("ip")
#define NET_LOG_CONFIG_PORT_NAME            NET_LOG_CONFIG_ADD_CONFIG("port")

#define NET_LOG_MAX_ALLOC   (16384u)
#define NET_LOG_PTR_SLOTS   (64u)

static net_log_config_t g_net_log_cfg;

typedef struct {
    uint16_t len;
    uint8_t  data[];
} net_log_msg_t;

static lwrb_t  g_rb;
static uint8_t g_rb_data[NET_LOG_PTR_SLOTS * sizeof(net_log_msg_t *) + 1];

static size_t              g_alloc_total;
static struct os_semaphore g_sem;
static struct os_task      g_task;
static bool                g_task_ready;

static bool net_log_send_udp( const void *data, uint16_t len ){
    struct netconn *conn;
    struct netbuf  *buf;
    ip_addr_t       dst;
    err_t           err;

    conn = netconn_new(NETCONN_UDP);
    if( conn == NULL ){
        return false;
    }

    buf = netbuf_new();
    if( buf == NULL ){
        netconn_delete(conn);
        return false;
    }

    err = netbuf_ref(buf, data, len);
    if( err != ERR_OK ){
        netbuf_delete(buf);
        netconn_delete(conn);
        return false;
    }

    IP_SET_TYPE_VAL(dst, IPADDR_TYPE_V4);
    ip4_addr_copy(*ip_2_ip4(&dst), g_net_log_cfg.ip);

    err = netconn_sendto(conn, buf, &dst, g_net_log_cfg.port);

    netbuf_delete(buf);
    netconn_delete(conn);

    return (err == ERR_OK) ? true : false;
}

static void net_log_task_fn( void *arg ){
    net_log_msg_t *msg;
    size_t psr;
    (void)arg;

    for( ;; ){
        os_sema_down(&g_sem, osWaitForever);
        while( lwrb_read(&g_rb, &msg, sizeof(msg)) == sizeof(msg) ){
            net_log_send_udp(msg->data, msg->len);
            psr = cpu_intrpt_save();
            g_alloc_total -= sizeof(*msg) + msg->len;
            cpu_intrpt_restore(psr);
            free(msg);
        }
    }
}

bool net_log_send( const void *data, uint16_t len ){
    net_log_msg_t *msg;
    size_t alloc_sz = sizeof(*msg) + len;
    size_t psr;
    bool   ok;

    if( data == NULL || len == 0 || !g_net_log_cfg.enable || !g_task_ready ){
        return false;
    }

    /* reserve space atomically — check both heap budget and slot count */
    psr = cpu_intrpt_save();
    ok = (g_alloc_total + alloc_sz <= NET_LOG_MAX_ALLOC) &&
         (lwrb_get_free(&g_rb) >= sizeof(msg));
    if( ok ){
        g_alloc_total += alloc_sz;
    }
    cpu_intrpt_restore(psr);

    if( !ok ){
        return false;
    }

    msg = malloc(alloc_sz);
    if( msg == NULL ){
        psr = cpu_intrpt_save();
        g_alloc_total -= alloc_sz;
        cpu_intrpt_restore(psr);
        return false;
    }

    msg->len = len;
    memcpy(msg->data, data, len);

    psr = cpu_intrpt_save();
    lwrb_write(&g_rb, &msg, sizeof(msg));
    cpu_intrpt_restore(psr);

    os_sema_up(&g_sem);
    return true;
}

static bool net_log_config_is_valid( const net_log_config_t *cfg ){
    if( cfg == NULL ){
        return false;
    }
    if( cfg->port == 0 ){
        return false;
    }
    return true;
}

void net_log_config_set_default( net_log_config_t *cfg ){
    if( cfg == NULL ){
        return;
    }
    cfg->enable   = NET_LOG_CONFIG_EN_DEF;
    cfg->ip.addr  = NET_LOG_CONFIG_IP_DEF;
    cfg->port     = NET_LOG_CONFIG_PORT_DEF;
}

void net_log_config_load( net_log_config_t *cfg ){
    int32_t en;
    int32_t ip;
    int32_t port;

    if( cfg == NULL ){
        return;
    }

    en   = NET_LOG_CONFIG_EN_DEF ? 1 : 0;
    ip   = (int32_t)NET_LOG_CONFIG_IP_DEF;
    port = (int32_t)NET_LOG_CONFIG_PORT_DEF;

    configdb_get_i32(NET_LOG_CONFIG_EN_NAME, &en);
    configdb_get_i32(NET_LOG_CONFIG_IP_NAME, &ip);
    configdb_get_i32(NET_LOG_CONFIG_PORT_NAME, &port);

    cfg->enable  = (en != 0) ? true : false;
    cfg->ip.addr = (uint32_t)ip;
    cfg->port    = (uint16_t)port;
}

void net_log_config_save( const net_log_config_t *cfg ){
    int32_t en;
    int32_t ip;
    int32_t port;

    if( cfg == NULL ){
        return;
    }
    if( !net_log_config_is_valid(cfg) ){
        return;
    }

    en   = cfg->enable ? 1 : 0;
    ip   = (int32_t)cfg->ip.addr;
    port = (int32_t)cfg->port;

    configdb_set_i32(NET_LOG_CONFIG_EN_NAME, &en);
    configdb_set_i32(NET_LOG_CONFIG_IP_NAME, &ip);
    configdb_set_i32(NET_LOG_CONFIG_PORT_NAME, &port);
}

void net_log_config_apply( const net_log_config_t *cfg ){
    if( cfg == NULL ){
        return;
    }
    if( !net_log_config_is_valid(cfg) ){
        return;
    }
    memcpy(&g_net_log_cfg, cfg, sizeof(g_net_log_cfg));
}

void net_log_init_early( void ){
    net_log_config_t cfg;
    net_log_config_set_default(&cfg);
    net_log_config_apply(&cfg);
}

void net_log_init( void ){
    net_log_config_t cfg;
    lwrb_init(&g_rb, g_rb_data, sizeof(g_rb_data));
    os_sema_init(&g_sem, 0);
    g_task_ready = true;

    net_log_config_load(&cfg);
    if( !net_log_config_is_valid(&cfg) ){
        net_log_config_set_default(&cfg);
    }
    net_log_config_save(&cfg);
    net_log_config_apply(&cfg);
    
    OS_TASK_INIT("net_log", &g_task, net_log_task_fn, NULL, NET_LOG_TASK_PRIO, NET_LOG_TASK_STACK);
}
