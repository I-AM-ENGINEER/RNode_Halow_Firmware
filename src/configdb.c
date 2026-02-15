#include "basic_include.h"
#include "configdb.h"
#include "lib/flashdb/flashdb.h"
#include "lib/fal/fal.h"
#include "osal/mutex.h"
#include <string.h>

//#define CONFIGDB_DEBUG

#ifdef CONFIGDB_DEBUG
#define cdb_debug(fmt, ...)  os_printf("[CDB] " fmt "\r\n", ##__VA_ARGS__)
#else
#define cdb_debug(fmt, ...)  do { } while (0)
#endif

static struct fdb_kvdb g_cfg_db;
static struct os_mutex g_cfg_db_access_mutex;

#ifdef CONFIGDB_DEBUG
static inline void configdb_debug_i32( const char *tag,
                                      const char *key,
                                      int32_t v,
                                      int32_t rc ){
    cdb_debug("%s key=%s v=%ld rc=%ld",
              tag ? tag : "CDB",
              key ? key : "(null)",
              (long)v,
              (long)rc);
}
#else
#define configdb_debug_i32(tag, key, v, rc) do { } while (0)
#endif

static int16_t clamp_i16(int32_t v){
    if (v < INT16_MIN) {
        printf("[CDB] Clamp i16 min!\r\n");
        return INT16_MIN;
    }
    if (v > INT16_MAX) {
        printf("[CDB] Clamp i16 max!\r\n");
        return INT16_MAX;
    }
    return (int16_t)v;
}

static int8_t clamp_i8(int32_t v){
    if (v < INT8_MIN) {
        printf("[CDB] Clamp i8 min!\r\n");
        return INT8_MIN;
    }
    if (v > INT8_MAX) {
        printf("[CDB] Clamp i8 max!\r\n");
        return INT8_MAX;
    }
    return (int8_t)v;
}

static fdb_kvdb_t configdb_grab(void){
    os_mutex_lock(&g_cfg_db_access_mutex, OS_MUTEX_WAIT_FOREVER);
    return &g_cfg_db;
}

static void configdb_release(void){
    os_mutex_unlock(&g_cfg_db_access_mutex);
}

int32_t configdb_init(void){
    int32_t res = fal_init();
    if (res <= 0) {
        return -1;
    }

    res = (int32_t)fdb_kvdb_init(&g_cfg_db, "cfg", "fdb_kvdb1", NULL, 0);
    if (res != FDB_NO_ERR) {
        return -2;
    }

    res = os_mutex_init(&g_cfg_db_access_mutex);
    if(res != 0){
        return -3;
    }
    os_mutex_unlock(&g_cfg_db_access_mutex);
    return 0;
}

int32_t configdb_set_i32(const char* key, int32_t* paramp){
    struct fdb_blob blob;
    int32_t current_param;
    int32_t res;
    if(paramp == NULL){
        return -1;
    }

    fdb_kvdb_t dbp = configdb_grab();
    if(dbp == NULL){
        return -2;
    }

    res = configdb_get_i32(key, &current_param);
    if ((res == 0) && (current_param == *paramp)) {
        return 0;
    }

    
    blob.buf = (void*)paramp;
    blob.size = sizeof(int32_t);

    res = (int32_t)fdb_kv_set_blob(dbp, key, &blob);
    configdb_release();
    configdb_debug_i32("SET_I32", key, *paramp, res);
    if(res != 0){
        return -3;
    }
    return 0;
}

int32_t configdb_get_i32(const char* key, int32_t* paramp){
    int32_t param;
    struct fdb_blob blob;
    struct fdb_kvdb* dbp = configdb_grab();
    if(dbp == NULL){
        return -1;
    }
    
    blob.buf  = &param;
    blob.size = sizeof(param);
    size_t rd = fdb_kv_get_blob(dbp, key, &blob);
    configdb_release();
    if(rd != sizeof(param)){
        configdb_debug_i32("GET_I32", key, param, -2);
        return -2;
    }
    configdb_debug_i32("GET_I32", key, param, 0);
    *paramp = param;
    return 0;
}

int32_t configdb_get_set_i32(const char* key, int32_t* paramp){
    configdb_get_i32(key, paramp);
    return configdb_set_i32(key, paramp);
}

int32_t configdb_get_i16(const char *key, int16_t *paramp){
    int32_t tmp;
    int32_t rc;

    rc = configdb_get_i32(key, &tmp);
    if (rc != 0) {
        return rc;
    }

    *paramp = clamp_i16(tmp);
    return 0;
}

int32_t configdb_set_i16(const char *key, const int16_t *paramp){
    int32_t tmp = (int32_t)(*paramp);
    return configdb_set_i32(key, &tmp);
}

int32_t configdb_get_set_i16(const char *key, int16_t *paramp){
    int32_t tmp = (int32_t)(*paramp);

    configdb_get_i32(key, &tmp);
    tmp = (int32_t)clamp_i16(tmp);
    *paramp = (int16_t)tmp;

    return configdb_set_i32(key, &tmp);
}

int32_t configdb_get_i8(const char *key, int8_t *paramp){
    int32_t tmp;
    int32_t rc;

    rc = configdb_get_i32(key, &tmp);
    if (rc != 0) {
        return rc;
    }

    *paramp = clamp_i8(tmp);
    return 0;
}

int32_t configdb_set_i8(const char *key, const int8_t *paramp){
    int32_t tmp = (int32_t)(*paramp);
    return configdb_set_i32(key, &tmp);
}

int32_t configdb_get_set_i8(const char *key, int8_t *paramp){
    int32_t tmp = (int32_t)(*paramp);

    configdb_get_i32(key, &tmp);
    tmp = (int32_t)clamp_i8(tmp);
    *paramp = (int8_t)tmp;

    return configdb_set_i32(key, &tmp);
}
