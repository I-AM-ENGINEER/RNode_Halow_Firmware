#ifndef _HUGEIC_TYPES_H_
#define _HUGEIC_TYPES_H_

#ifndef GHIDRA_TYPES_FIX_H
#define GHIDRA_TYPES_FIX_H

typedef signed char        int8;
typedef unsigned char      uint8;
typedef signed short       int16;
typedef unsigned short     uint16;
typedef signed int         int32;
typedef unsigned int       uint32;
typedef signed long long   int64;
typedef unsigned long long uint64;

typedef signed char        s8;
typedef unsigned char      u8;
typedef signed short       s16;
typedef unsigned short     u16;
typedef signed int         s32;
typedef unsigned int       u32;
typedef signed long long   s64;
typedef unsigned long long u64;

#define __packed
#define __weak
#define __inline inline
#define __forceinline inline
#define __attribute__(x)
#define __STATIC_INLINE static inline
#define __IO volatile

#endif

#include "sys_config.h"
#include "errno.h"

#ifndef __IO
#define __IO volatile
#endif

#ifndef __I
#define __I volatile const
#endif

#ifndef __O
#define __O volatile
#endif

#ifndef RET_OK
#define RET_OK   0
#endif
#ifndef RET_ERR
#define RET_ERR -1
#endif

#ifndef TRUE
#define TRUE   1
#endif
#ifndef FALSE
#define FALSE  0
#endif

#ifndef ALIGN
#define ALIGN(s,a) (((s)+(a)-1) & ~((a)-1))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef STRUCT_PACKED
#define STRUCT_PACKED __attribute__ ((__packed__))
#endif

#ifdef __MBED__
#include "osal/mbed/typesdef.h"
#endif

#ifdef __CSKY__
#include "osal/csky/typesdef.h"
#endif

typedef struct {
    uint8  *addr;
    uint32  size;
} scatter_data;

#include "tx_platform.h"
#include "version.h"

#ifdef CONFIG_SLEEP
#define __SYS_INIT
#else
#define __SYS_INIT __init
#endif

#endif
