
#ifndef __CSKY_TYPESDEF_H_
#define __CSKY_TYPESDEF_H_
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

//typedef enum { FALSE=0, TRUE=1, false=0, true=1} bool;
typedef int8_t     int8;
typedef int16_t    int16;
typedef int32_t    int32;
typedef int64_t    int64;

typedef uint8_t    uint8;
typedef uint16_t   uint16;
typedef uint32_t   uint32;
typedef uint64_t   uint64;

typedef int32_t    ssize_t;

typedef unsigned long ulong;

#ifdef __cplusplus
}
#endif

#include "byteshift.h"
#endif


