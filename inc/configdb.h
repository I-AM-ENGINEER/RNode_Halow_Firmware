#ifndef __CONFIGDB_H__
#define __CONFIGDB_H__

#include "lib/flashdb/fdb_def.h"
#include <stdint.h>

typedef struct{
    int32_t val;
    int32_t def_val;
    int32_t min_val;
    int32_t max_val;
} configdb_param_int32_t;

int32_t configdb_get_param_i32(const char* key, configdb_param_int32_t* paramp);
int32_t configdb_set_param_i32(const char* key, configdb_param_int32_t* paramp);
int32_t configdb_init(void);

#endif // __CONFIGDB_H__
