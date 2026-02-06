
#include "basic_include.h"
#include "osal/time.h"

static uint64_t os_time_ms(void){
    return (os_jiffies() * NANOSECONDS_PER_TICK) / 1000000ULL;
}
