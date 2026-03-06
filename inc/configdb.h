#ifndef __CONFIGDB_H__
#define __CONFIGDB_H__

#include "lib/flashdb/fdb_def.h"
#include <stdint.h>

#define CONFIGDB_PREFIX           "cfg"
#define CONFIGDB_ADD_MODULE(name) CONFIGDB_PREFIX "." name

int32_t configdb_get_i32(const char *key, int32_t *paramp);
int32_t configdb_set_i32(const char *key, int32_t *paramp);
int32_t configdb_get_set_i32(const char *key, int32_t *paramp);

int32_t configdb_get_i16(const char *key, int16_t *paramp);
int32_t configdb_set_i16(const char *key, const int16_t *paramp);
int32_t configdb_get_set_i16(const char *key, int16_t *paramp);

int32_t configdb_get_i8(const char *key, int8_t *paramp);
int32_t configdb_set_i8(const char *key, const int8_t *paramp);
int32_t configdb_get_set_i8(const char *key, int8_t *paramp);

int32_t configdb_get_blob(const char *key, void *buf, size_t size);
int32_t configdb_set_blob(const char *key, const void *buf, size_t size);
int32_t configdb_get_set_blob(const char *key, void *buf, size_t size);

int32_t configdb_init(void);

#endif // __CONFIGDB_H__
