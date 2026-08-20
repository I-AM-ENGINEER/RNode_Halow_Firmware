#include "basic_include.h"
#include "halow.h"
#include "utils.h"
#include "statistics.h"
#include "configdb.h"
#include "harness.h"

const uint8_t mac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

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

void *os_malloc(uint32_t size){ return malloc((size_t)size); }
void os_free(void *p){ free(p); }
void os_sleep_ms(uint32_t ms){ (void)ms; }

void halow_config_load(halow_config_t *cfg){ cfg->mcs = g_dflt_mcs; }

static test_tx_cap_t g_tx[TEST_TX_CAP_N];
static int g_txn;

void test_tx_reset(void){ g_txn = 0; }
int test_tx_count(void){ return g_txn; }
const test_tx_cap_t *test_tx_at(int i){ return (i >= 0 && i < g_txn) ? &g_tx[i] : NULL; }

static void tx_capture(const uint8_t *buf, uint16_t len, const uint8_t mac[6], uint8_t mcs){
    if( g_txn < TEST_TX_CAP_N && len <= TEST_TX_CAP_LEN ){
        memcpy(g_tx[g_txn].buf, buf, len);
        g_tx[g_txn].len = len;
        memcpy(g_tx[g_txn].mac, mac, 6);
        g_tx[g_txn].mcs = mcs;
    }
    g_txn++;
}

int32_t halow_tx(const uint8_t *buf, uint16_t len, const uint8_t dest_mac[6], uint8_t mcs){
    tx_capture(buf, len, dest_mac, mcs);
    return 0;
}

int32_t halow_tx_p(const uint8_t *buf, uint16_t len, const uint8_t dest_mac[6],
                   uint8_t mcs, uint8_t bw){
    (void)bw;
    tx_capture(buf, len, dest_mac, mcs);
    return 0;
}

uint32_t halow_get_tx_vacancy(void){ return g_vacancy; }
void test_vacancy_set(uint32_t v){ g_vacancy = v; }
void halow_tx_vacancy_watchdog(void){}

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
