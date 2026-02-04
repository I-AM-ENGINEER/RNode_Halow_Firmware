#ifndef _HUGEIC_BASIC_INCLUDE_H_
#define _HUGEIC_BASIC_INCLUDE_H_

#include "typesdef.h"
#include "list.h"
#include "dev.h"
#include "devid.h"
#include "errno.h"

#include "osal/atomic.h"
#include "osal/ffs.h"
#include "osal/irq.h"
#include "osal/msgqueue.h"
#include "osal/mutex.h"
#include "osal/semaphore.h"
#include "osal/sleep.h"
#include "osal/string.h"
#include "osal/task.h"
#include "osal/timer.h"
#include "osal/time.h"
#include "osal/work.h"

#include "hal/gpio.h"
#include "hal/dma.h"
#include "hal/crc.h"
#include "hal/uart.h"

#include "lib/common/common.h"
#include "lib/common/sysevt.h"
#include "lib/heap/sysheap.h"
#include "lib/syscfg/syscfg.h"

static inline uint16_t __be16(uint16_t v){
    return (uint16_t)((v >> 8) | (v << 8));
}

static inline uint32_t __be32(uint32_t v){
    return ((v & 0x000000FFU) << 24) |
           ((v & 0x0000FF00U) <<  8) |
           ((v & 0x00FF0000U) >>  8) |
           ((v & 0xFF000000U) >> 24);
}

#endif
