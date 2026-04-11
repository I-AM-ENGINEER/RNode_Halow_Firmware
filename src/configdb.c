#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_CONFIGDB

#include "basic_include.h"
#include "configdb.h"
#include "lib/flashdb/flashdb.h"
#include "lib/fal/fal.h"
#include "lib/logc/log.h"
#include "osal/mutex.h"

#include <string.h>
#include <limits.h>

static struct fdb_kvdb g_cfg_db;
static struct os_mutex g_cfg_db_access_mutex;

static inline void configdb_log_get_i32( const char *key, int32_t v, int32_t rc ){
    log_trace("GET_I32 key=%s v=%ld rc=%ld",
              key ? key : "(null)",
              (long)v,
              (long)rc);
}

static inline void configdb_log_set_i32( const char *key, int32_t v, int32_t rc ){
    log_debug("SET_I32 key=%s v=%ld rc=%ld",
              key ? key : "(null)",
              (long)v,
              (long)rc);
}

static inline void configdb_log_get_blob( const char *key, size_t size, int32_t rc ){
    log_trace("GET_BLOB key=%s size=%lu rc=%ld",
              key ? key : "(null)",
              (unsigned long)size,
              (long)rc);
}

static inline void configdb_log_set_blob( const char *key, size_t size, int32_t rc ){
    log_debug("SET_BLOB key=%s size=%lu rc=%ld",
              key ? key : "(null)",
              (unsigned long)size,
              (long)rc);
}

static int16_t clamp_i16( int32_t v ){
    if( v < INT16_MIN ){
        log_warn("Clamp i16 min");
        return INT16_MIN;
    }
    if( v > INT16_MAX ){
        log_warn("Clamp i16 max");
        return INT16_MAX;
    }
    return (int16_t)v;
}

static int8_t clamp_i8( int32_t v ){
    if( v < INT8_MIN ){
        log_warn("Clamp i8 min");
        return INT8_MIN;
    }
    if( v > INT8_MAX ){
        log_warn("Clamp i8 max");
        return INT8_MAX;
    }
    return (int8_t)v;
}

static fdb_kvdb_t configdb_grab( void ){
    os_mutex_lock(&g_cfg_db_access_mutex, OS_MUTEX_WAIT_FOREVER);
    return &g_cfg_db;
}

static void configdb_release( void ){
    os_mutex_unlock(&g_cfg_db_access_mutex);
}

int32_t configdb_init( void ){
    int32_t res;

    res = (int32_t)fdb_kvdb_init(&g_cfg_db, "cfg", FAL_PART_NAME_KVDB, NULL, 0);
    if( res != FDB_NO_ERR ){
        log_error("fdb_kvdb_init failed rc=%ld", (long)res);
        return -2;
    }

    res = os_mutex_init(&g_cfg_db_access_mutex);
    if( res != 0 ){
        log_error("os_mutex_init failed rc=%ld", (long)res);
        return -3;
    }

    os_mutex_unlock(&g_cfg_db_access_mutex);
    log_info("configdb init ok");
    return 0;
}

int32_t configdb_set_i32( const char *key, const int32_t *paramp ){
    struct fdb_blob blob;
    int32_t current_param;
    int32_t res;
    fdb_kvdb_t dbp;

    if( paramp == NULL ){
        return -1;
    }

    res = configdb_get_i32(key, &current_param);
    if( (res == 0) && (current_param == *paramp) ){
        return 0;
    }

    dbp = configdb_grab();
    if( dbp == NULL ){
        return -2;
    }

    blob.buf = (void *)paramp;
    blob.size = sizeof(int32_t);

    res = (int32_t)fdb_kv_set_blob(dbp, key, &blob);
    configdb_release();

    configdb_log_set_i32(key, *paramp, res);

    if( res != 0 ){
        return -3;
    }

    return 0;
}

int32_t configdb_get_i32( const char *key, int32_t *paramp ){
    int32_t param;
    struct fdb_blob blob;
    fdb_kvdb_t dbp;
    size_t rd;

    if( paramp == NULL ){
        return -1;
    }

    dbp = configdb_grab();
    if( dbp == NULL ){
        return -1;
    }

    blob.buf = &param;
    blob.size = sizeof(param);

    rd = fdb_kv_get_blob(dbp, key, &blob);
    configdb_release();

    if( rd != sizeof(param) ){
        configdb_log_get_i32(key, 0, -2);
        return -2;
    }

    configdb_log_get_i32(key, param, 0);
    *paramp = param;
    return 0;
}

int32_t configdb_get_set_i32( const char *key, int32_t *paramp ){
    configdb_get_i32(key, paramp);
    return configdb_set_i32(key, paramp);
}

int32_t configdb_get_i16( const char *key, int16_t *paramp ){
    int32_t tmp;
    int32_t rc;

    rc = configdb_get_i32(key, &tmp);
    if( rc != 0 ){
        return rc;
    }

    *paramp = clamp_i16(tmp);
    return 0;
}

int32_t configdb_set_i16( const char *key, const int16_t *paramp ){
    int32_t tmp;

    if( paramp == NULL ){
        return -1;
    }

    tmp = (int32_t)(*paramp);
    return configdb_set_i32(key, &tmp);
}

int32_t configdb_get_set_i16( const char *key, int16_t *paramp ){
    int32_t tmp;

    if( paramp == NULL ){
        return -1;
    }

    tmp = (int32_t)(*paramp);

    configdb_get_i32(key, &tmp);
    tmp = (int32_t)clamp_i16(tmp);
    *paramp = (int16_t)tmp;

    return configdb_set_i32(key, &tmp);
}

int32_t configdb_get_i8( const char *key, int8_t *paramp ){
    int32_t tmp;
    int32_t rc;

    rc = configdb_get_i32(key, &tmp);
    if( rc != 0 ){
        return rc;
    }

    *paramp = clamp_i8(tmp);
    return 0;
}

int32_t configdb_set_i8( const char *key, const int8_t *paramp ){
    int32_t tmp;

    if( paramp == NULL ){
        return -1;
    }

    tmp = (int32_t)(*paramp);
    return configdb_set_i32(key, &tmp);
}

int32_t configdb_get_set_i8( const char *key, int8_t *paramp ){
    int32_t tmp;

    if( paramp == NULL ){
        return -1;
    }

    tmp = (int32_t)(*paramp);

    configdb_get_i32(key, &tmp);
    tmp = (int32_t)clamp_i8(tmp);
    *paramp = (int8_t)tmp;

    return configdb_set_i32(key, &tmp);
}

int32_t configdb_set_blob( const char *key, const void *buf, size_t size ){
    struct fdb_blob blob;
    int32_t res;
    fdb_kvdb_t dbp;
    void *tmp;

    if( (key == NULL) || (buf == NULL) || (size == 0u) ){
        return -1;
    }

    tmp = os_malloc(size);
    if( tmp != NULL ){
        if( configdb_get_blob(key, tmp, size) == 0 ){
            if( memcmp(tmp, buf, size) == 0 ){
                os_free(tmp);
                return 0;
            }
        }
        os_free(tmp);
    }

    dbp = configdb_grab();
    if( dbp == NULL ){
        return -2;
    }

    blob.buf = (void *)buf;
    blob.size = size;

    res = (int32_t)fdb_kv_set_blob(dbp, key, &blob);
    configdb_release();

    configdb_log_set_blob(key, size, res);

    if( res != FDB_NO_ERR ){
        return -3;
    }

    return 0;
}

int32_t configdb_get_blob( const char *key, void *buf, size_t size ){
    struct fdb_blob blob;
    size_t rd;
    fdb_kvdb_t dbp;

    if( (key == NULL) || (buf == NULL) || (size == 0u) ){
        return -1;
    }

    dbp = configdb_grab();
    if( dbp == NULL ){
        return -2;
    }

    blob.buf = buf;
    blob.size = size;

    rd = fdb_kv_get_blob(dbp, key, &blob);
    configdb_release();

    if( rd != size ){
        configdb_log_get_blob(key, size, -3);
        return -3;
    }

    configdb_log_get_blob(key, size, 0);
    return 0;
}

int32_t configdb_get_set_blob( const char *key, void *buf, size_t size ){
    configdb_get_blob(key, buf, size);
    return configdb_set_blob(key, buf, size);
}
