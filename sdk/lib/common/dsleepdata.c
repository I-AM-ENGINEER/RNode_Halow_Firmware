#include "typesdef.h"
#include "osal/irq.h"
#include "osal/string.h"
#include "lib/common/dsleepdata.h"

//#ifdef CONFIG_SLEEP

struct system_sleepdata {
    uint32 magic1;
    uint32 cur_addr;
    uint32 regions[SYSTEM_SLEEPDATA_ID_MAX];
    uint32 magic2;
};

extern size_t __sleep_data_start;
extern size_t __sleep_data_stop;

__init void sys_sleepdata_init(void)
{
    uint32 flags;
    uint32 start = (uint32)&__sleep_data_start;
    //uint32 end   = (uint32)&__sleep_data_stop;
    struct system_sleepdata *sdata = (struct system_sleepdata *)start;
    flags = disable_irq();
    if (sdata->magic1 != 0x1A2B3C4D || sdata->magic2 != 0xD4C3B2A1) {
        os_printf("sleepdata_init\r\n");
        os_memset(sdata, 0, sizeof(struct system_sleepdata));
        sdata->magic1 = 0x1A2B3C4D;
        sdata->magic2 = 0xD4C3B2A1;
        sdata->cur_addr = start + sizeof(struct system_sleepdata);
    }
    enable_irq(flags);
}

void *sys_sleepdata_request(uint8 id, uint32 size)
{
    void *ptr = NULL;
    uint32 flags;
    uint32 start = (uint32)&__sleep_data_start;
    uint32 end   = (uint32)&__sleep_data_stop;
    struct system_sleepdata *sdata = (struct system_sleepdata *)start;

    size  = ALIGN(size, 4);
    flags = disable_irq();
    if (id < SYSTEM_SLEEPDATA_ID_MAX) {
        os_printf("regions(%d)=0x%x cur_addr=0x%x size=%d end=0x%x\r\n",
                  id, sdata->regions[id], sdata->cur_addr, size, end);
        if (sdata->regions[id] == 0) {
            if (sdata->cur_addr + size < end) {
                os_memset(sdata->cur_addr, 0, size);
                sdata->regions[id] = sdata->cur_addr;
                sdata->cur_addr   += size;
            }
        }
        ptr = (void *)sdata->regions[id];
    }
    enable_irq(flags);
    return ptr;
}

void sys_sleepdata_reset(void)
{
    uint32 flags;
    uint32 *start = (uint32 *)&__sleep_data_start;
    flags = disable_irq();
    *start = 0;
    enable_irq(flags);
}

uint32 sys_sleepdata_freesize(void)
{
    uint32 flags;
    uint32 fsize = 0;
    uint32 start = (uint32)&__sleep_data_start;
    uint32 end   = (uint32)&__sleep_data_stop;
    struct system_sleepdata *sdata = (struct system_sleepdata *)start;

    flags = disable_irq();
    fsize = end - sdata->cur_addr;
    enable_irq(flags);
    return fsize;
}

void *sys_sleepdata_get(uint8 id)
{
    uint32 start = (uint32)&__sleep_data_start;
    struct system_sleepdata *sdata = (struct system_sleepdata *)start;
    if (id < SYSTEM_SLEEPDATA_ID_MAX) {
        return (void *)sdata->regions[id];
    }
    return NULL;
}

//#endif
