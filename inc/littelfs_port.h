#ifndef __LITTLEFS_PORT_H__
#define __LITTLEFS_PORT_H__

#include <inttypes.h>
#include <stdio.h>

int32_t littlefs_init(void);
int32_t littlefs_reformat(void);

#endif // __LITTLEFS_PORT_H__
