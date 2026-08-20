#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_HALOW_PKG_HANDLER
#include "basic_include.h"
#include <stdio.h>
#include "halow_ack.h"
#include "halow.h"
#include "utils.h"
#include "statistics.h"
#include "configdb.h"
#include "chip/txw4002ack803/sysctrl.h"
#include "../../src/halow_ack.c"

#define RAM_LIMIT (50u * 1024u)

int main( void ){
    size_t bufs  = sizeof(g_bufs);
    size_t peers = sizeof(g_peers);
    size_t pend  = sizeof(g_pend_buf) + sizeof(g_pend_len) + sizeof(g_pend_mac);
    size_t misc  = sizeof(g_ack_cfg) + sizeof(g_ack_stats) + sizeof(g_pend_tries);
    size_t total = bufs + peers + pend + misc;

    printf("ack static RAM: bufs=%zu peers=%zu pend=%zu misc=%zu total=%zu limit=%u\n",
           bufs, peers, pend, misc, total, RAM_LIMIT);
    if( total > RAM_LIMIT ){
        printf("FAIL: over budget by %zu B\n", total - RAM_LIMIT);
        return 1;
    }
    printf("ok: %zu B headroom\n", RAM_LIMIT - total);
    return 0;
}
