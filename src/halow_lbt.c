// halow_lbt.c
#include "basic_include.h"
#include "halow_lbt.h"

#include <string.h>
#include <stdlib.h>

#include "lib/lmac/ieee802_11_defs.h"
#include "lib/lmac/lmac_def.h"
#include "lib/lmac/hgic.h"
#include "lib/skb/skb.h"
#include "lib/skb/skbuff.h"
#include "lib/lwrb/lwrb.h"
#include "osal/semaphore.h"
#include "osal/mutex.h"
#include "osal/string.h"
#include "utils.h"
#include "configdb.h"
#include "halow.h"

#define HALOW_LBT_DEBUG

#define HALOW_LBT_CONFIG_PREFIX                 CONFIGDB_ADD_MODULE("hlbt")
#define HALOW_LBT_CONFIG_ADD_CONFIG(name)       HALOW_LBT_CONFIG_PREFIX "." name

#define HALOW_LBT_CONFIG_EN_NAME                HALOW_LBT_CONFIG_ADD_CONFIG("en")
#define HALOW_LBT_CONFIG_NSWS_NAME              HALOW_LBT_CONFIG_ADD_CONFIG("nsws")
#define HALOW_LBT_CONFIG_NLWS_NAME              HALOW_LBT_CONFIG_ADD_CONFIG("nlws")
#define HALOW_LBT_CONFIG_NLLP_NAME              HALOW_LBT_CONFIG_ADD_CONFIG("nllp")
#define HALOW_LBT_CONFIG_NRO_NAME               HALOW_LBT_CONFIG_ADD_CONFIG("nro")
#define HALOW_LBT_CONFIG_NAB_NAME               HALOW_LBT_CONFIG_ADD_CONFIG("nab")
#define HALOW_LBT_CONFIG_TX_SKIP_US_NAME        HALOW_LBT_CONFIG_ADD_CONFIG("tx_skp")
#define HALOW_LBT_CONFIG_TX_MAX_MS_NAME         HALOW_LBT_CONFIG_ADD_CONFIG("tx_max")
#define HALOW_LBT_CONFIG_BO_MIN_US_NAME         HALOW_LBT_CONFIG_ADD_CONFIG("bo_min")
#define HALOW_LBT_CONFIG_BO_MAX_US_NAME         HALOW_LBT_CONFIG_ADD_CONFIG("bo_max")
#define HALOW_LBT_CONFIG_UTIL_EN_NAME           HALOW_LBT_CONFIG_ADD_CONFIG("u_en")
#define HALOW_LBT_CONFIG_UTIL_MAX_NAME          HALOW_LBT_CONFIG_ADD_CONFIG("u_max")
#define HALOW_LBT_CONFIG_UTIL_REFILL_MS_NAME    HALOW_LBT_CONFIG_ADD_CONFIG("u_ref")
#define HALOW_LBT_CONFIG_UTIL_BUCKET_MS_NAME    HALOW_LBT_CONFIG_ADD_CONFIG("u_bkt")

#define HALOW_LBT_AIRTIME_ACCUMULATOR_S 10

#ifdef HALOW_LBT_DEBUG
#define hlbt_debug(fmt, ...)  os_printf("[HLBT] " fmt "\r\n", ##__VA_ARGS__)
#else
#define hlbt_debug(fmt, ...)  do { } while (0)
#endif

typedef struct {
    halow_lbt_config_t cfg;

    int32_t       short_sum;
    uint_fast16_t short_i;

    int8_t        noise_short;
    int8_t        noise_floor;
    uint32_t      noise_floor_ts_ms;

    int64_t       last_tx_us;
    int64_t       last_lbt_us;

    uint16_t      short_n;
    uint16_t      long_n;

    uint8_t       floor_pct;

    int8_t       *short_samples;
    int8_t       *long_rb_data;
    int8_t       *tmp_sort;

    int64_t       time_last_cycle_update_us;
    int64_t       airtime_time_last_tx_started;
    int32_t       airtime_time_tx_from_last_cycle_update_us;
    bool          airtime_tx_active;
    float         airtime_rb[HALOW_LBT_AIRTIME_ACCUMULATOR_S];
    int8_t         airtime_rb_idx;

    lwrb_t        long_rb;
} halow_lbt_ctx_t;

static halow_lbt_ctx_t *g_lbt_ctx;
static struct os_task g_lbt_task;
static struct os_mutex g_lbt_ctx_mutex;

extern void     ah_rfdigicali_bknoise_valid_pd_clr( void );
extern uint32_t ah_rfdigicali_bknoise_valid_pd_get( void );
extern void     ah_rfdigicali_config_hw_bknoise( uint32_t n, uint32_t en );

extern void     lmac_bknoise_calc_en( void );
extern void     lmac_bknoise_calc_dis( void );
extern int32_t  lmac_bknoise_get( void );

static void halow_lbt_rand_init_from_bknoise( void ){
    uint32_t seed = 0xA5A5A5A5u;
    uint32_t cnt  = 0;
    int64_t t0_ms;

    t0_ms = get_time_ms();

    ah_rfdigicali_bknoise_valid_pd_clr();
    lmac_bknoise_calc_en();

    while (cnt < 1000u) {
        if (ah_rfdigicali_bknoise_valid_pd_get() == 0) {
            if ((get_time_ms() - t0_ms) > 2000) {
                break;
            }
            os_sleep_us(10);
            continue;
        }

        int32_t v = lmac_bknoise_get();
        lmac_bknoise_calc_en();

        seed ^= (uint32_t)((int8_t)v);
        seed = (seed << 5) | (seed >> 27);
        seed += (cnt * 0x9E3779B1u);

        cnt++;
    }

    lmac_bknoise_calc_dis();

    if (cnt == 0u) {
        hlbt_debug("bknoise seed timeout");
    }

    if (seed == 0u) {
        seed = 1u;
    }

    os_srand(seed);
}

float halow_lbt_ch_util_get(void){
    halow_lbt_ctx_t *ctx;
    uint32_t busy;
    lwrb_sz_t n;
    int8_t floor;
    int rel_thr;
    int abs_thr;

    busy = 0;
    if(g_lbt_ctx_mutex.hdl == NULL){
        return 0.0f;
    }
    (void)os_mutex_lock(&g_lbt_ctx_mutex, -1);

    ctx = g_lbt_ctx;
    if (ctx == NULL) {
        (void)os_mutex_unlock(&g_lbt_ctx_mutex);
        return 0.0f;
    }

    n = (lwrb_sz_t)ctx->long_n;
    if (n == 0) {
        (void)os_mutex_unlock(&g_lbt_ctx_mutex);
        return 0.0f;
    }

    floor   = halow_lbt_background_long_dbm_get();
    rel_thr = (int)floor + (int)ctx->cfg.noise_relative_offset_dbm;
    abs_thr = (int)ctx->cfg.noise_absolute_busy_dbm;

    (void)lwrb_peek(&ctx->long_rb, 0, ctx->tmp_sort, n);

    for (lwrb_sz_t i = 0; i < n; i++){
        int v = (int)ctx->tmp_sort[i];
        if (v >= abs_thr || v > rel_thr){
            busy++;
        }
    }

    (void)os_mutex_unlock(&g_lbt_ctx_mutex);

    return ((float)busy) / (float)n;
}


float halow_lbt_airtime_get(void){
    if(g_lbt_ctx_mutex.hdl == NULL){
        return 0.0f;
    }
    os_mutex_lock(&g_lbt_ctx_mutex, -1);

    if (g_lbt_ctx == NULL) {
        os_mutex_unlock(&g_lbt_ctx_mutex);
        return 0.0f;
    }
    float airtime = 0;
    for(uint32_t i = 0; i < HALOW_LBT_AIRTIME_ACCUMULATOR_S; i++){
        airtime += g_lbt_ctx->airtime_rb[i];
    }
    airtime /= HALOW_LBT_AIRTIME_ACCUMULATOR_S;
    os_mutex_unlock(&g_lbt_ctx_mutex);
    return airtime;
}

int8_t halow_lbt_noise_dbm_now( int64_t sample_time_us ){
    if(g_lbt_ctx_mutex.hdl == NULL){
        return 0.0f;
    }
    int64_t time_start = get_time_us();
    int64_t time_end = time_start + sample_time_us;

    ah_rfdigicali_config_hw_bknoise(384, 1);
    ah_rfdigicali_bknoise_valid_pd_clr();
    lmac_bknoise_calc_en();

    int64_t acc = 0;
    uint32_t cnt = 0;
    while (get_time_us() < time_end) {
        if (ah_rfdigicali_bknoise_valid_pd_get() == 0) {
            os_sleep_us(10);
            continue;
        }
        int32_t v = lmac_bknoise_get();
        lmac_bknoise_calc_en();
        acc += (int8_t)v;
        cnt++;
    }
    lmac_bknoise_calc_dis();

    if (cnt == 0) {
        return (int8_t)-128;
    }

    int64_t avg = (acc >= 0) ? (acc + (int64_t)(cnt / 2)) : (acc - (int64_t)(cnt / 2));
    avg /= (int64_t)cnt;

    if (avg > 127)  { avg = 127; }
    if (avg < -128) { avg = -128; }

    return (int8_t)avg;
}

static int cmp_i8( const void *a, const void *b ){
    int ia = (int)*(const int8_t *)a;
    int ib = (int)*(const int8_t *)b;
    return (ia > ib) - (ia < ib);
}

static int8_t noise_pxx_from_rb( halow_lbt_ctx_t *ctx ){
    lwrb_sz_t n;
    uint8_t pct;
    uint32_t k;
    lwrb_sz_t idx;
    int8_t r;

    if (ctx == NULL) {
        return 0;
    }

    n = (lwrb_sz_t)ctx->long_n;
    if (n == 0) {
        return 0;
    }

    (void)lwrb_peek(&ctx->long_rb, 0, ctx->tmp_sort, n);

    qsort(ctx->tmp_sort, (size_t)n, sizeof(ctx->tmp_sort[0]), cmp_i8);

    pct = ctx->floor_pct;
    if (pct > 100u) {
        pct = 100u;
    }

    k = ((((uint32_t)n) * (uint32_t)pct) + 99u) / 100u;
    if (k == 0u) {
        k = 1u;
    }

    idx = (lwrb_sz_t)(k - 1u);
    if (idx >= n) {
        idx = n - 1;
    }

    r = ctx->tmp_sort[idx];
    return r;
}

int8_t halow_lbt_background_short_dbm_get( void ){
    if(g_lbt_ctx_mutex.hdl == NULL){
        return 0.0f;
    }
    halow_lbt_ctx_t *ctx;
    int8_t v = 0;

    (void)os_mutex_lock(&g_lbt_ctx_mutex, -1);
    ctx = g_lbt_ctx;
    if (ctx != NULL) {
        v = ctx->noise_short;
    }
    (void)os_mutex_unlock(&g_lbt_ctx_mutex);

    return v;
}

int8_t halow_lbt_background_long_dbm_get( void ){
    if(g_lbt_ctx_mutex.hdl == NULL){
        return 0.0f;
    }
    halow_lbt_ctx_t *ctx;
    int64_t now;
    uint64_t ts;
    int8_t floor;

    now = get_time_ms();

    (void)os_mutex_lock(&g_lbt_ctx_mutex, -1);

    ctx = g_lbt_ctx;
    if (ctx == NULL) {
        (void)os_mutex_unlock(&g_lbt_ctx_mutex);
        return 0;
    }

    ts = ctx->noise_floor_ts_ms;
    floor = ctx->noise_floor;

    if ((uint64_t)now - ts >= 100u) {
        floor = noise_pxx_from_rb(ctx);
        ctx->noise_floor = floor;
        ctx->noise_floor_ts_ms = (uint64_t)now;
    }

    (void)os_mutex_unlock(&g_lbt_ctx_mutex);
    return floor;
}


void halow_lbt_task( void *arg ){
    (void)arg;

    while (1) {
        halow_lbt_ctx_t *ctx;

        (void)os_mutex_lock(&g_lbt_ctx_mutex, -1);
        ctx = g_lbt_ctx;
        if (ctx == NULL) {
            (void)os_mutex_unlock(&g_lbt_ctx_mutex);
            os_sleep_ms(1);
            continue;
        }

        int8_t noise_dbm = halow_lbt_noise_dbm_now(100);

        ctx->short_samples[ctx->short_i++] = noise_dbm;
        ctx->short_sum += noise_dbm;

        if (ctx->short_i >= ctx->short_n) {
            int8_t short_avg = (int8_t)(ctx->short_sum / (int32_t)ctx->short_n);

            ctx->noise_short = short_avg;

            if (lwrb_get_free(&ctx->long_rb) == 0) {
                int8_t evict;
                (void)lwrb_read(&ctx->long_rb, &evict, (lwrb_sz_t)sizeof(evict));
            }

            (void)lwrb_write(&ctx->long_rb, &short_avg, (lwrb_sz_t)sizeof(short_avg));

            ctx->short_i = 0;
            ctx->short_sum = 0;
        }

        
        int64_t current_time_ms = get_time_ms();
        static int64_t airtime_cycle_timetamp;
        if((current_time_ms - airtime_cycle_timetamp) >= 1000){
            airtime_cycle_timetamp = current_time_ms;
            // Airtime
            int64_t now_us  = get_time_us();
            int64_t last_us = ctx->time_last_cycle_update_us;
            int64_t cycle_us = now_us - last_us;
            int32_t airtime_us = ctx->airtime_time_tx_from_last_cycle_update_us;

            if (ctx->airtime_tx_active) {
                int64_t start_us = ctx->airtime_time_last_tx_started;

                int64_t dt = now_us - start_us;
                int64_t acc = (int64_t)airtime_us + dt;
                
                airtime_us = (int32_t)acc;
                ctx->airtime_time_last_tx_started = now_us;
            } else {
                ctx->airtime_time_last_tx_started = 0;
            }

            float current_airtime = (float)airtime_us / (float)cycle_us;
            ctx->airtime_rb[ctx->airtime_rb_idx++] = current_airtime;
            if(ctx->airtime_rb_idx >= HALOW_LBT_AIRTIME_ACCUMULATOR_S){
                ctx->airtime_rb_idx = 0;
            }

            ctx->airtime_time_tx_from_last_cycle_update_us = 0;
            ctx->time_last_cycle_update_us = now_us;
        }
#ifdef HALOW_LBT_DEBUG
        static uint16_t dbg_tick;
        if (++dbg_tick >= 1000) {
            dbg_tick = 0;
            hlbt_debug(
                "ccur=%d floor=%d util=%.1f%% airtime=%.1f%%",
                (int32_t)halow_lbt_background_short_dbm_get(),
                (int32_t)halow_lbt_background_long_dbm_get(),
                halow_lbt_ch_util_get() * 100.0f,
                halow_lbt_airtime_get() * 100.0f
            );
        }
#endif

        (void)os_mutex_unlock(&g_lbt_ctx_mutex);
    }
}

static halow_lbt_ctx_t *halow_lbt_ctx_alloc( const halow_lbt_config_t *cfg ){
    halow_lbt_ctx_t *ctx;
    uint8_t pct;

    if (cfg == NULL) {
        return NULL;
    }

    ctx = (halow_lbt_ctx_t *)os_calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->cfg = *cfg;

    ctx->short_n = (uint16_t)cfg->noise_short_window_samples;
    ctx->long_n  = (uint16_t)cfg->noise_long_window_samples;

    if (ctx->short_n == 0) { ctx->short_n = 1; }
    if (ctx->long_n  == 0) { ctx->long_n  = 1; }

    pct = cfg->noise_long_low_percent;
    if (pct > 100u) {
        pct = 100u;
    }
    ctx->floor_pct = pct;

    ctx->short_samples = (int8_t *)os_malloc(ctx->short_n);
    ctx->long_rb_data  = (int8_t *)os_malloc(ctx->long_n);
    ctx->tmp_sort      = (int8_t *)os_malloc(ctx->long_n);

    if (ctx->short_samples == NULL ||
        ctx->long_rb_data  == NULL ||
        ctx->tmp_sort      == NULL) {

        os_free(ctx->short_samples);
        os_free(ctx->long_rb_data);
        os_free(ctx->tmp_sort);
        os_free(ctx);
        return NULL;
    }

    lwrb_init(&ctx->long_rb, ctx->long_rb_data, (lwrb_sz_t)ctx->long_n);

    return ctx;
}

static void halow_lbt_ctx_free( halow_lbt_ctx_t *ctx ){
    if (ctx == NULL) {
        return;
    }

    os_free(ctx->short_samples);
    os_free(ctx->long_rb_data);
    os_free(ctx->tmp_sort);
    os_free(ctx);
}

void halow_lbt_set_tx_as_active( void ){
    if (g_lbt_ctx_mutex.hdl == NULL) { 
        return; 
    }
    if (os_mutex_lock(&g_lbt_ctx_mutex, 10) != 0) { 
        return; 
    }
    if (g_lbt_ctx == NULL) { os_mutex_unlock(&g_lbt_ctx_mutex); 
        return; 
    }

    if (!g_lbt_ctx->airtime_tx_active) {
        g_lbt_ctx->airtime_tx_active = true;
        g_lbt_ctx->airtime_time_last_tx_started = get_time_us();
        hlbt_debug("SET TX");
    }

    os_mutex_unlock(&g_lbt_ctx_mutex);
}

void halow_lbt_set_tx_as_deactive( void ){
    if (g_lbt_ctx_mutex.hdl == NULL) {
        return;
    }
    if (os_mutex_lock(&g_lbt_ctx_mutex, 10) != 0) {
        return;
    }
    if (g_lbt_ctx == NULL) {
        os_mutex_unlock(&g_lbt_ctx_mutex);
        return;
    }

    if (g_lbt_ctx->airtime_tx_active) {
        hlbt_debug("RESET TX");
        int64_t now_us = get_time_us();
        int64_t start_us = g_lbt_ctx->airtime_time_last_tx_started;

        if (start_us == 0) {
            start_us = g_lbt_ctx->time_last_cycle_update_us;
        }

        int64_t dt = now_us - start_us;
        if (dt > 0) {
            int64_t acc = (int64_t)g_lbt_ctx->airtime_time_tx_from_last_cycle_update_us + dt;
            if (acc > INT32_MAX) { acc = INT32_MAX; }
            g_lbt_ctx->airtime_time_tx_from_last_cycle_update_us = (int32_t)acc;
        }

        g_lbt_ctx->airtime_time_last_tx_started = 0;
        g_lbt_ctx->airtime_tx_active = false;
    }

    os_mutex_unlock(&g_lbt_ctx_mutex);
}

void halow_lbt_config_apply( const halow_lbt_config_t *cfg ){
    int32_t ret;
    halow_lbt_ctx_t *old;
    halow_lbt_ctx_t *ctx;

    if (cfg == NULL) {
        return;
    }

    (void)os_mutex_lock(&g_lbt_ctx_mutex, -1);
    old = g_lbt_ctx;
    g_lbt_ctx = NULL;

    if (old != NULL) {
        ret = os_task_stop(&g_lbt_task);
        hlbt_debug("os_task_stop -> %d", (int)ret);

        ret = os_task_del(&g_lbt_task);
        hlbt_debug("os_task_del -> %d", (int)ret);

        halow_lbt_ctx_free(old);
    }

    ctx = halow_lbt_ctx_alloc(cfg);
    if (ctx == NULL) {
        (void)os_mutex_unlock(&g_lbt_ctx_mutex);
        hlbt_debug("ctx OOM");
        return;
    }

    ret = os_task_init((const uint8 *)"lbt", &g_lbt_task, halow_lbt_task, (uint32)ctx);
    hlbt_debug("os_task_init -> %d", (int)ret);
    if (ret != 0) {
        halow_lbt_ctx_free(ctx);
        (void)os_mutex_unlock(&g_lbt_ctx_mutex);
        return;
    }

    (void)os_task_set_stacksize(&g_lbt_task, HALOW_LBT_LISTEN_TASK_STACK);
    (void)os_task_set_priority(&g_lbt_task, HALOW_LBT_LISTEN_TASK_PRIO);

    g_lbt_ctx = ctx;
    (void)os_mutex_unlock(&g_lbt_ctx_mutex);

    (void)os_task_run(&g_lbt_task);
}

void halow_lbt_config_save( const halow_lbt_config_t *cfg ){
    if (cfg == NULL) {
        return;
    }
    halow_lbt_config_apply(cfg);
    configdb_set_i8 (HALOW_LBT_CONFIG_EN_NAME,             (int8_t*)&cfg->lbt_enabled);
    configdb_set_i16(HALOW_LBT_CONFIG_NSWS_NAME,           (int16_t*)&cfg->noise_short_window_samples);
    configdb_set_i16(HALOW_LBT_CONFIG_NLWS_NAME,           (int16_t*)&cfg->noise_long_window_samples);
    configdb_set_i8 (HALOW_LBT_CONFIG_NLLP_NAME,           (int8_t*)&cfg->noise_long_low_percent);
    configdb_set_i8 (HALOW_LBT_CONFIG_NRO_NAME,            (int8_t*)&cfg->noise_relative_offset_dbm);
    configdb_set_i8 (HALOW_LBT_CONFIG_NAB_NAME,            (int8_t*)&cfg->noise_absolute_busy_dbm);
    configdb_set_i16(HALOW_LBT_CONFIG_TX_SKIP_US_NAME,     (int16_t*)&cfg->tx_skip_check_time_us);
    configdb_set_i16(HALOW_LBT_CONFIG_TX_MAX_MS_NAME,      (int16_t*)&cfg->tx_max_continuous_time_ms);
    configdb_set_i16(HALOW_LBT_CONFIG_BO_MIN_US_NAME,      (int16_t*)&cfg->backoff_random_min_us);
    configdb_set_i16(HALOW_LBT_CONFIG_BO_MAX_US_NAME,      (int16_t*)&cfg->backoff_random_max_us);
    configdb_set_i8 (HALOW_LBT_CONFIG_UTIL_EN_NAME,        (int8_t*)&cfg->util_enabled);
    configdb_set_i8 (HALOW_LBT_CONFIG_UTIL_MAX_NAME,       (int8_t*)&cfg->util_max_percent);
    configdb_set_i32(HALOW_LBT_CONFIG_UTIL_REFILL_MS_NAME, (int32_t*)&cfg->util_refill_window_ms);
    configdb_set_i16(HALOW_LBT_CONFIG_UTIL_BUCKET_MS_NAME, (int16_t*)&cfg->util_bucket_capacity_ms);
}

static void halow_lbt_config_set_default( halow_lbt_config_t *cfg ){
    if (cfg == NULL) {
        return;
    }
    cfg->lbt_enabled               = HALOW_LBT_CONFIG_EN_DEF ? 1 : 0;
    cfg->noise_short_window_samples= HALOW_LBT_CONFIG_NSWS_DEF;
    cfg->noise_long_window_samples = HALOW_LBT_CONFIG_NLWS_DEF;
    cfg->noise_long_low_percent    = HALOW_LBT_CONFIG_NLLP_DEF;
    cfg->noise_relative_offset_dbm = HALOW_LBT_CONFIG_NRO_DEF;
    cfg->noise_absolute_busy_dbm   = HALOW_LBT_CONFIG_NAB_DEF;
    cfg->tx_skip_check_time_us     = HALOW_LBT_CONFIG_TX_SKIP_US_DEF;
    cfg->tx_max_continuous_time_ms = HALOW_LBT_CONFIG_TX_MAX_MS_DEF;
    cfg->backoff_random_min_us     = HALOW_LBT_CONFIG_BO_MIN_US_DEF;
    cfg->backoff_random_max_us     = HALOW_LBT_CONFIG_BO_MAX_US_DEF;
    cfg->util_enabled              = HALOW_LBT_CONFIG_UTIL_EN_DEF ? 1 : 0;
    cfg->util_max_percent          = HALOW_LBT_CONFIG_UTIL_MAX_DEF;
    cfg->util_refill_window_ms     = HALOW_LBT_CONFIG_UTIL_REFILL_MS_DEF;
    cfg->util_bucket_capacity_ms   = HALOW_LBT_CONFIG_UTIL_BUCKET_MS_DEF;
}

void halow_lbt_config_load( halow_lbt_config_t *cfg ){
    if (cfg == NULL) {
        return;
    }

    halow_lbt_config_set_default(cfg);
    configdb_get_i8 (HALOW_LBT_CONFIG_EN_NAME,             (int8_t*)&cfg->lbt_enabled);
    configdb_get_i16(HALOW_LBT_CONFIG_NSWS_NAME,           (int16_t*)&cfg->noise_short_window_samples);
    configdb_get_i16(HALOW_LBT_CONFIG_NLWS_NAME,           (int16_t*)&cfg->noise_long_window_samples);
    configdb_get_i8 (HALOW_LBT_CONFIG_NLLP_NAME,           (int8_t*)&cfg->noise_long_low_percent);
    configdb_get_i8 (HALOW_LBT_CONFIG_NRO_NAME,            (int8_t*)&cfg->noise_relative_offset_dbm);
    configdb_get_i8 (HALOW_LBT_CONFIG_NAB_NAME,            (int8_t*)&cfg->noise_absolute_busy_dbm);
    configdb_get_i16(HALOW_LBT_CONFIG_TX_SKIP_US_NAME,     (int16_t*)&cfg->tx_skip_check_time_us);
    configdb_get_i16(HALOW_LBT_CONFIG_TX_MAX_MS_NAME,      (int16_t*)&cfg->tx_max_continuous_time_ms);
    configdb_get_i16(HALOW_LBT_CONFIG_BO_MIN_US_NAME,      (int16_t*)&cfg->backoff_random_min_us);
    configdb_get_i16(HALOW_LBT_CONFIG_BO_MAX_US_NAME,      (int16_t*)&cfg->backoff_random_max_us);
    configdb_get_i8 (HALOW_LBT_CONFIG_UTIL_EN_NAME,        (int8_t*)&cfg->util_enabled);
    configdb_get_i8 (HALOW_LBT_CONFIG_UTIL_MAX_NAME,       (int8_t*)&cfg->util_max_percent);
    configdb_get_i32(HALOW_LBT_CONFIG_UTIL_REFILL_MS_NAME, (int32_t*)&cfg->util_refill_window_ms);
    configdb_get_i16(HALOW_LBT_CONFIG_UTIL_BUCKET_MS_NAME, (int16_t*)&cfg->util_bucket_capacity_ms);
}

int32_t halow_lbt_init( void ){
    os_mutex_init(&g_lbt_ctx_mutex);

    halow_lbt_rand_init_from_bknoise();

    halow_lbt_config_t cfg;
    halow_lbt_config_set_default(&cfg);
    halow_lbt_config_load(&cfg);
    halow_lbt_config_save(&cfg);

    return 0;
}
