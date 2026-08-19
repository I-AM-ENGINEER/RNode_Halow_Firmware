#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_FAL_PORT

#include "basic_include.h"
#include <lib/fal/fal.h>
#include <lib/fal/fal_def.h>

#include "hal/spi_nor.h"
#include "lib/logc/log.h"
#include "chip/txw4002ack803/sysctrl.h"   /* mcu_watchdog_feed() in the erase loop */
#include <stdint.h>
#include <stddef.h>

extern struct spi_nor_flash flash0;
#define FLASH_START_ADDR   0U
#define FLASH_END_ADDR     flash0.size

#define ALIGN_UP(x,a)     (((x)+(a)-1U)/(a)*(a))
#define ALIGN_DOWN(x,a)   ((x)/(a)*(a))

static int init(void);
static int read(long offset, uint8_t *buf, size_t size);
static int write(long offset, const uint8_t *buf, size_t size);
static int erase(long offset, size_t size);

static inline uint32_t sector_size(void){
    return flash0.sector_size ? flash0.sector_size : (4U * 1024U);
}

static inline uint32_t page_size(void){
    return flash0.page_size ? flash0.page_size : 256U;
}

extern struct spi_nor_flash flash0;

static uint32_t spi_nor_size_from_jedec(uint32_t jedec_id){
    uint8_t cap = jedec_id & 0xFF;

    if (cap < 0x10 || cap > 0x1F) {
        return 0;
    }

    return (1UL << cap);
}

static int init(void){
    uint8_t jedec[3];
    uint32_t jedec_id;
    uint32_t size;

    if (spi_nor_open(&flash0) != 0) {
        log_error("spi_nor_open failed");
        return -1;
    }

    spi_nor_standard_read_jedec_id(&flash0, jedec);

    jedec_id = (jedec[0] << 16) | (jedec[1] << 8) | jedec[2];

    log_debug("JEDEC ID: %02X %02X %02X (0x%06X)",
              jedec[0], jedec[1], jedec[2], jedec_id);

    size = spi_nor_size_from_jedec(jedec_id);

    if (size == 0) {
        log_error("Unknown flash size from JEDEC");
        spi_nor_close(&flash0);
        return -1;
    }

    log_info("Flash size detected: %u bytes", size);

    flash0.size        = size;
    flash0.sector_size = 0x1000;
    flash0.page_size   = 256;
    flash0.block_size  = 0x10000;

    nor_flash0.len      = flash0.size;
    nor_flash0.blk_size = flash0.sector_size;

    spi_nor_close(&flash0);
    return 0;
}

static int read(long offset, uint8_t *buf, size_t size){
    uint32_t addr = (uint32_t)offset + FLASH_START_ADDR;

    log_trace("read: addr=0x%08X size=%u", addr, size);

    if (!buf || !size) {
        log_warn("read buff NULL");
        return 0;
    }
    if (addr + size > FLASH_END_ADDR) {
        log_error("read outside sector");
        return -1;
    }

    spi_nor_open(&flash0);
    spi_nor_read(&flash0, addr, buf, (uint32_t)size);
    spi_nor_close(&flash0);

    return (int)size;
}

static int need_erase(const uint8_t *p, uint32_t len){
    for (uint32_t i = 0; i < len; i++) {
        if (p[i] != 0xFF) {
            return 1;
        }
    }
    return 0;
}

static void program_pages(uint32_t addr, const uint8_t *buf, uint32_t size){
    log_trace("program_pages: addr=0x%08X size=%u", addr, size);
    uint32_t page = page_size();

    while (size) {
        uint32_t off   = addr % page;
        uint32_t chunk = page - off;
        if (chunk > size) {
            chunk = size;
        }

        log_trace("write page chunk: addr=0x%08X size=%u", addr, chunk);
        spi_nor_write(&flash0, addr, (uint8_t *)buf, chunk);

        addr += chunk;
        buf  += chunk;
        size -= chunk;
    }
}

static int write_one_sector(uint32_t sector_addr, uint32_t addr,
                            const uint8_t *buf, uint32_t size){
    log_trace("write_one_sector: sect=0x%08X addr=0x%08X size=%u",
              sector_addr, addr, size);
    uint32_t sect = sector_size();
    uint32_t off  = addr - sector_addr;

    static uint8_t sect_buf[4U * 1024U];

    if (sect != sizeof(sect_buf)) {
        log_error("sector size mismatch");
        return -2;
    }
    if (off + size > sect) {
        log_error("write outside sector");
        return -1;
    }

    spi_nor_read(&flash0, sector_addr, sect_buf, sect);

    if (!need_erase(&sect_buf[off], size)) {
        program_pages(addr, buf, size);
        return (int)size;
    }

    for (uint32_t i = 0; i < size; i++) {
        sect_buf[off + i] = buf[i];
    }

    log_debug("erase-before-write sector 0x%08X", sector_addr);
    /* KV/GC writes hold the configdb mutex while the ack tick (the hardware
     * watchdog feeder) may be blocked on it: without feeding here, a GC chain
     * over several sectors outlives the 10 s watchdog -> silent reset MID
     * WRITE, which also dirties the sector and lengthens the next GC (spiral
     * risk -- the boot re-seed already needed the same treatment). */
    mcu_watchdog_feed();
    spi_nor_sector_erase(&flash0, sector_addr);
    program_pages(sector_addr, sect_buf, sect);
    mcu_watchdog_feed();

    return (int)size;
}

static int write(long offset, const uint8_t *buf, size_t size){
    uint32_t addr = (uint32_t)offset + FLASH_START_ADDR;
    uint32_t end  = addr + (uint32_t)size;
    uint32_t sect = sector_size();

    log_trace("write: addr=0x%08X size=%u", addr, size);

    if (!buf || !size) {
        log_warn("write: null buffer or zero size");
        return 0;
    }
    if (end > FLASH_END_ADDR || addr < FLASH_START_ADDR) {
        log_error("write: out of range");
        return -1;
    }

    spi_nor_open(&flash0);

    uint32_t cur = addr;
    while (cur < end) {
        uint32_t sector_addr = ALIGN_DOWN(cur, sect);
        uint32_t next        = sector_addr + sect;
        uint32_t chunk       = (end < next) ? (end - cur) : (next - cur);

        int rc = write_one_sector(sector_addr, cur, buf, chunk);
        if (rc < 0) {
            spi_nor_close(&flash0);
            return rc;
        }

        cur += chunk;
        buf += chunk;
    }

    spi_nor_close(&flash0);
    return (int)size;
}

static int erase(long offset, size_t size){
    log_trace("erase: off=%ld size=%u", offset, size);

    uint32_t addr = (uint32_t)offset + FLASH_START_ADDR;
    uint32_t end  = addr + (uint32_t)size;
    uint32_t sect = sector_size();

    if (!size) {
        log_warn("erase: zero size");
        return 0;
    }
    if (end > FLASH_END_ADDR || addr < FLASH_START_ADDR) {
        log_error("erase: out of range");
        return -1;
    }

    uint32_t cur = ALIGN_DOWN(addr, sect);
    uint32_t end_up = ALIGN_UP(end, sect);

    spi_nor_open(&flash0);

    while (cur < end_up) {
        log_debug("erase sector 0x%08X", cur);
        spi_nor_sector_erase(&flash0, cur);
        cur += sect;
        /* A full-partition OTA erase is up to 200 sectors (tens of seconds,
         * busy-polled): without feeding, the 10 s boot/runtime watchdog resets
         * the node MID-ERASE and bricks it. */
        mcu_watchdog_feed();
    }

    spi_nor_close(&flash0);
    return (int)size;
}

struct fal_flash_dev nor_flash0 = {
    .name       = "nor_flash0",
    .addr       = FLASH_START_ADDR,
    .len        = 0,
    .blk_size   = 0,
    .ops        = { init, read, write, erase },
    .write_gran = 1,
};
