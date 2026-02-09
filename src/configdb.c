#include "basic_include.h"
#include "configdb.h"
#include "lib/flashdb/flashdb.h"
#include "lib/fal/fal.h"
#include "osal/mutex.h"
#include <string.h>

static struct fdb_kvdb g_cfg_db;
static struct os_mutex g_cfg_db_access_mutex;

static inline void configdb_param_i32_sanitize(configdb_param_int32_t *p){
    if (p == NULL) {
        return;
    }

    if (p->val < p->min_val) {
        p->val = p->min_val;
    } else if (p->val > p->max_val) {
        p->val = p->max_val;
    }
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

int32_t configdb_set_param_i32(const char* key, configdb_param_int32_t* paramp){
    struct fdb_blob blob;
    if(paramp == NULL){
        return -1;
    }

    configdb_param_i32_sanitize(paramp);

    fdb_kvdb_t dbp = configdb_grab();
    if(dbp == NULL){
        return -2;
    }
    
    blob.buf = (void*)paramp;
    blob.size = sizeof(configdb_param_int32_t);

    int32_t res = (int32_t)fdb_kv_set_blob(dbp, key, &blob);
    configdb_release();
    if(res != 0){
        return -3;
    }
    return 0;
}

int32_t configdb_get_param_i32(const char* key, configdb_param_int32_t* paramp){
    configdb_param_int32_t param;
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
        return -2;
    }
    memcpy(paramp, &param, sizeof(configdb_param_int32_t));
    return 0;
}
