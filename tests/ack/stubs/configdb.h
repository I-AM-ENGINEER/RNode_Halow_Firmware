#ifndef TEST_STUB_CONFIGDB_H
#define TEST_STUB_CONFIGDB_H

#include <stdint.h>

#define CONFIGDB_PREFIX           "cfg"
#define CONFIGDB_ADD_MODULE(name) CONFIGDB_PREFIX "." name

int configdb_get_i8(const char *key, int8_t *val);
int configdb_get_i16(const char *key, int16_t *val);
int configdb_set_i8(const char *key, const int8_t *val);
int configdb_set_i16(const char *key, const int16_t *val);

#endif
