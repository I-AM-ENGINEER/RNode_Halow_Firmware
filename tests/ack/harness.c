#include "basic_include.h"
#include "halow.h"
#include "utils.h"
#include "statistics.h"
#include "configdb.h"
#include "harness.h"

#include <stdarg.h>

const uint8_t mac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

halow_tx_dbg_t g_tx_dbg;

/* link_db links with live log_warn calls -- swallow them in tests */
void log_log( int level, const char *file, int line, const char *fmt, ... ){
    (void)level; (void)file; (void)line; (void)fmt;
}

static uint64_t g_jiff;
static uint32_t g_vacancy = 100000;
static uint8_t  g_dflt_mcs = 7;

uint64_t os_jiffies(void){ return g_jiff; }
uint64_t os_msecs_to_jiffies(uint32_t ms){ return (uint64_t)ms; }
uint32_t os_jiffies_to_msecs(uint64_t j){ return (uint32_t)j; }

void test_time_reset(void){ g_jiff = 1000; }
void test_advance_ms(uint32_t ms){ g_jiff += ms; }

int32_t os_sema_down(struct os_semaphore *s, int32_t tmo_ms){
    (void)tmo_ms;
    if( s->count > 0 ){
        s->count--;
        return 0;
    }
    return -1;
}
void os_sema_up(struct os_semaphore *s){ s->count++; }
void os_sema_init(struct os_semaphore *s, int32_t count){ s->count = count; }

int32_t os_mutex_init(struct os_mutex *m){ (void)m; return 0; }
int32_t os_mutex_lock(struct os_mutex *m, int32_t tmo_ms){ (void)m; (void)tmo_ms; return 0; }
void os_mutex_unlock(struct os_mutex *m){ (void)m; }

static int g_task_inits;
void os_task_init(const uint8_t *name, struct os_task *t, void (*fn)(void *), void *arg){
    (void)name; (void)t; (void)fn; (void)arg;
    g_task_inits++;
}
void os_task_set_stacksize(struct os_task *t, uint32_t sz){ (void)t; (void)sz; }
void os_task_set_priority(struct os_task *t, uint8_t prio){ (void)t; (void)prio; }
void os_task_run(struct os_task *t){ (void)t; }
int test_task_inits(void){ return g_task_inits; }

/* os_malloc with an 8-byte header: exact live-block/live-byte accounting and
 * deterministic fault injection for the heap-frame paths. */
static int      g_fail_next;
static uint32_t g_live_blocks;
static uint32_t g_live_bytes;

void test_malloc_reset(void){ g_fail_next = 0; }
void test_malloc_fail_next(int n){ g_fail_next = n; }
uint32_t test_malloc_live_blocks(void){ return g_live_blocks; }
uint32_t test_malloc_live_bytes(void){ return g_live_bytes; }

void *os_malloc(uint32_t size){
    if( g_fail_next > 0 ){
        g_fail_next--;
        return NULL;
    }
    uint8_t *p = (uint8_t *)malloc((size_t)size + 8u);
    if( p == NULL ) return NULL;
    *(uint32_t *)(void *)p       = size;
    *(uint32_t *)(void *)(p + 4) = 0xC0DEBA5Fu;
    g_live_blocks++;
    g_live_bytes += size;
    return p + 8;
}

void os_free(void *pv){
    if( pv == NULL ) return;
    uint8_t *p = (uint8_t *)pv - 8;
    if( *(uint32_t *)(void *)(p + 4) != 0xC0DEBA5Fu ) return;
    g_live_blocks--;
    g_live_bytes -= *(uint32_t *)(void *)p;
    free(p);
}

static uint32_t g_sleep_calls;
void os_sleep_ms(uint32_t ms){ (void)ms; g_sleep_calls++; }
void os_sleep(int sec){ (void)sec; g_sleep_calls++; }
uint32_t test_sleep_calls(void){ return g_sleep_calls; }
uint64_t test_time_jiff(void){ return g_jiff; }

void halow_config_load(halow_config_t *cfg){ cfg->mcs = g_dflt_mcs; }

static test_tx_cap_t g_tx[TEST_TX_CAP_N];
static test_tx_cap_t g_tx_last;
static int g_txn;

void test_tx_reset(void){ g_txn = 0; memset(&g_tx_last, 0, sizeof(g_tx_last)); }
int test_tx_count(void){ return g_txn; }
const test_tx_cap_t *test_tx_at(int i){
    return (i >= 0 && i < g_txn && i < TEST_TX_CAP_N) ? &g_tx[i] : NULL;
}
const test_tx_cap_t *test_tx_last(void){ return &g_tx_last; }

static int g_tx_fail_next;
void test_tx_fail_next(int n){ g_tx_fail_next = n; }

static void tx_capture(const uint8_t *buf, uint16_t len, const uint8_t mac[6], uint8_t mcs){
    g_tx_last.len = len;
    memcpy(g_tx_last.mac, mac, 6);
    g_tx_last.mcs = mcs;
    memset(g_tx_last.buf, 0, sizeof(g_tx_last.buf));
    if( len <= TEST_TX_CAP_LEN ) memcpy(g_tx_last.buf, buf, len);

    if( g_txn < TEST_TX_CAP_N && len <= TEST_TX_CAP_LEN ){
        memcpy(g_tx[g_txn].buf, buf, len);
        g_tx[g_txn].len = len;
        memcpy(g_tx[g_txn].mac, mac, 6);
        g_tx[g_txn].mcs = mcs;
    }
    g_txn++;
}

int32_t halow_tx(const uint8_t *buf, uint16_t len, const uint8_t dest_mac[6], uint8_t mcs){
    if( g_tx_fail_next > 0 ){
        g_tx_fail_next--;
        return -5;
    }
    tx_capture(buf, len, dest_mac, mcs);
    return 0;
}

int32_t halow_tx_p(const uint8_t *buf, uint16_t len, const uint8_t dest_mac[6],
                   uint8_t mcs, uint8_t bw){
    if( g_tx_fail_next > 0 ){
        g_tx_fail_next--;
        return -5;
    }
    (void)bw;
    tx_capture(buf, len, dest_mac, mcs);
    return 0;
}

uint32_t halow_get_tx_vacancy(void){ return g_vacancy; }
void test_vacancy_set(uint32_t v){ g_vacancy = v; }
void halow_tx_vacancy_watchdog(void){}

static uint32_t g_mtu_row[8] = {700, 1450, 2200, 3000, 4500, 6050, 6800, 7600};

uint32_t halow_get_mtu(uint8_t mcs){
    return (mcs <= 7u) ? g_mtu_row[mcs] : 700u;
}

void test_mtu_row_set(const uint32_t row[8]){
    memcpy(g_mtu_row, row, sizeof(g_mtu_row));
}

uint8_t halow_cfg_mcs_get_cached(void){ return g_dflt_mcs; }

/* RF->TCP delivered frames (tcp_server_send) */
static test_tcp_cap_t g_tcp[TEST_TCP_CAP_N];
static int g_tcpn;
static int g_tcp_full;

void test_tcp_reset(void){ g_tcpn = 0; g_tcp_full = 0; }
int test_tcp_count(void){ return g_tcpn; }
const test_tcp_cap_t *test_tcp_at(int i){
    return (i >= 0 && i < g_tcpn && i < TEST_TCP_CAP_N) ? &g_tcp[i] : NULL;
}
void test_tcp_full_set(int full){ g_tcp_full = full; }

int32_t tcp_server_send(const uint8_t *data, uint32_t len){
    if( g_tcp_full ) return -1;
    if( len == 0u || len > TEST_TCP_CAP_LEN ) return -2;
    if( g_tcpn < TEST_TCP_CAP_N ){
        memcpy(g_tcp[g_tcpn].buf, data, len);
        g_tcp[g_tcpn].len = (uint16_t)len;
        g_tcp[g_tcpn].at_jiff = g_jiff;
    }
    g_tcpn++;
    return 0;
}

/* Mirrors the firmware contract: the ring takes ownership of the os_malloc'd
 * buffer and frees it on every exit path (the real tcps task frees it after
 * netconn_write; the harness has no async writer, so free right after the
 * capture copy). */
int32_t tcp_server_send_owned(uint8_t *os_buf, uint32_t len){
    int32_t r;

    if( os_buf == NULL ) return -2;
    r = tcp_server_send(os_buf, len);
    os_free(os_buf);
    return r;
}

static uint32_t g_stat_tx_pkgs;
void statistics_radio_register_tx_package(uint16_t len){ (void)len; g_stat_tx_pkgs++; }

static uint32_t g_wd_feeds;
void mcu_watchdog_feed(void){ g_wd_feeds++; }
uint32_t test_watchdog_feeds(void){ return g_wd_feeds; }

#define KV_MAX 64
static struct { char k[40]; int16_t v; int used; } g_kv[KV_MAX];

static int kv_find(const char *key){
    for( int i = 0; i < KV_MAX; i++ )
        if( g_kv[i].used && strcmp(g_kv[i].k, key) == 0 ) return i;
    return -1;
}

void configdb_reset(void){
    memset(g_kv, 0, sizeof(g_kv));
}

int test_kv_get(const char *key, int16_t *val){
    int i = kv_find(key);
    if( i < 0 ) return -1;
    *val = g_kv[i].v;
    return 0;
}

void test_kv_set(const char *key, int16_t val){
    int i = kv_find(key);
    if( i < 0 ){
        for( i = 0; i < KV_MAX && g_kv[i].used; i++ );
        if( i >= KV_MAX ) return;
        g_kv[i].used = 1;
        strncpy(g_kv[i].k, key, sizeof(g_kv[i].k) - 1);
    }
    g_kv[i].v = val;
}

int configdb_get_i8(const char *key, int8_t *val){
    int16_t t;
    if( test_kv_get(key, &t) != 0 ) return -1;
    *val = (int8_t)t;
    return 0;
}
int configdb_get_i16(const char *key, int16_t *val){ return test_kv_get(key, val); }
int configdb_set_i8(const char *key, const int8_t *val){ test_kv_set(key, *val); return 0; }
int configdb_set_i16(const char *key, const int16_t *val){ test_kv_set(key, *val); return 0; }
