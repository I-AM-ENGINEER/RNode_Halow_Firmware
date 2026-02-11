#ifndef __MONGOOSE_CONFIG_H__
#define __MONGOOSE_CONFIG_H__

#include <ctype.h>
//#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include "lwip/netdb.h"
//#include ""
//#include <netinet/in.h>
//#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define alloca(s) __builtin_alloca((s))

#define MG_ARCH MG_ARCH_CUSTOM
#define MG_ENABLE_SOCKET 1
#define MG_ENABLE_LWIP 1
#define MG_ENABLE_POSIX_FS 0
#define MG_ENABLE_LINES 1
#define MG_ENABLE_POLL 1
#define MG_ENABLE_LOG 0

#endif // __MONGOOSE_CONFIG_H__

