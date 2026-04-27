#include <stdlib.h>
#include <stdint.h>

extern int __real_ah_rfspi_write(uint32_t addr, uint32_t val);
extern uint16_t __real_ah_rfspi_read(uint32_t addr);
extern uint16_t __real_ah_rfspi_write_and_read(uint32_t addr, uint32_t data);

volatile uint32_t g_rfspi_last_write_arg0;
volatile uint32_t g_rfspi_last_write_arg1;
volatile uint32_t g_rfspi_last_read_arg0;
volatile uint32_t g_rfspi_last_wr_arg0;

volatile uint32_t g_rfspi_write_count;
volatile uint32_t g_rfspi_read_count;
volatile uint32_t g_rfspi_wr_count;
/*
extern int __real_ah_rf_lo_table_ctrl(uint32_t en);

int __wrap_ah_rf_lo_table_ctrl(uint32_t en)
{
    os_printf("[RF] ah_rf_lo_table_ctrl(%lu)\n", (unsigned long)en);

    //int ret = __real_ah_rf_lo_table_ctrl(en);

    //return ret;
	return 0;
}*/

int __wrap_ah_rfspi_write(uint32_t addr, uint32_t val)
{
    g_rfspi_last_write_arg0 = addr;
    g_rfspi_last_write_arg1 = val;
    g_rfspi_write_count++;

    uint32_t frame =
        ((addr << 16) & 0x7fff0000u) |
        (val | 0x80000000u);

//    os_printf(
//        "[RFSPI WR %lu] addr=0x%04lx val=0x%04lx frame=0x%08lx\n",
//        (unsigned long)g_rfspi_write_count,
//        (unsigned long)addr,
//        (unsigned long)val,
//        (unsigned long)frame
//    );

    int ret = __real_ah_rfspi_write(addr, val);
    return ret;
}

uint16_t __wrap_ah_rfspi_read(uint32_t addr)
{
    g_rfspi_last_read_arg0 = addr;
    g_rfspi_read_count++;

    uint32_t cmd =
        ((addr << 16) & 0x7fff0000u);

//    os_printf(
//        "[RFSPI RD %lu] addr=0x%04lx cmd=0x%08lx\n",
//        (unsigned long)g_rfspi_read_count,
//        (unsigned long)addr,
//        (unsigned long)cmd
//    );

    uint16_t ret = __real_ah_rfspi_read(addr);
    return ret;
}
