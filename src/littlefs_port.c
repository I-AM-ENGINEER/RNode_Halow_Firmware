/* littlefs_port.c
 *
 * Minimal littlefs block-device port for SPI NOR via your spi_nor_* stack.
 * Uses FAL only to locate partition offset/length (NO fal_partition_write),
 * because littlefs expects prog() to never erase blocks.
 *
 * Requirements:
 *  - FAL already initialized (fal_init()) before littlefs_port_init()
 *  - FAL partition exists (default name: "lfs_www")
 *  - spi_nor_open/close must be called before/after each flash operation
 *
 * Notes:
 *  - prog_size should match NOR page program granularity (usually 256)
 *  - block_size should match erase sector size (usually 4096)
 */
#include "basic_include.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "littelfs_port.h"
#include "lib/littlefs/lfs.h"
#include <lib/fal/fal.h>
#include "littelfs_port.h"

#include "hal/spi_nor.h"

extern struct spi_nor_flash flash0;

#ifndef LFS_PART_NAME
#define LFS_PART_NAME           "littlefs"
#endif

#ifndef LFS_READ_SIZE
#define LFS_READ_SIZE           256U
#endif

#ifndef LFS_PROG_SIZE
#define LFS_PROG_SIZE           256U
#endif

#ifndef LFS_BLOCK_SIZE
#define LFS_BLOCK_SIZE          4096U
#endif

#ifndef LFS_CACHE_SIZE
#define LFS_CACHE_SIZE          256U
#endif

#ifndef LFS_LOOKAHEAD_SIZE
#define LFS_LOOKAHEAD_SIZE      16U
#endif

#ifndef LFS_BLOCK_CYCLES
#define LFS_BLOCK_CYCLES        1000
#endif

static lfs_t g_lfs;
static struct lfs_config g_lfs_cfg;
static const struct fal_partition *g_part;

static inline int lfs_flash_open (void){
    return spi_nor_open(&flash0);
}

static inline void lfs_flash_close (void){
    spi_nor_close(&flash0);
}

static inline uint32_t lfs_phys_addr (const struct lfs_config *c, lfs_block_t block, lfs_off_t off){
    uint32_t rel = (uint32_t)block * (uint32_t)c->block_size + (uint32_t)off;
    return (uint32_t)g_part->offset + rel;
}

static int lfs_bd_read (const struct lfs_config *c,
                        lfs_block_t block, lfs_off_t off,
                        void *buffer, lfs_size_t size){
    (void)c;

    if (g_part == NULL || buffer == NULL) {
        return LFS_ERR_INVAL;
    }

    if (((uint32_t)off + (uint32_t)size) > (uint32_t)c->block_size) {
        return LFS_ERR_INVAL;
    }

    uint32_t addr = lfs_phys_addr(c, block, off);

    if (lfs_flash_open() != 0) {
        return LFS_ERR_IO;
    }

    spi_nor_read(&flash0, addr, (uint8_t *)buffer, (uint32_t)size);

    lfs_flash_close();
    return 0;
}

static int lfs_bd_prog (const struct lfs_config *c,
                        lfs_block_t block, lfs_off_t off,
                        const void *buffer, lfs_size_t size){
    if (g_part == NULL || buffer == NULL) {
        return LFS_ERR_INVAL;
    }

    if ((((uint32_t)off % (uint32_t)c->prog_size) != 0U) ||
        (((uint32_t)size % (uint32_t)c->prog_size) != 0U) ||
        (((uint32_t)off + (uint32_t)size) > (uint32_t)c->block_size)) {
        return LFS_ERR_INVAL;
    }

    uint32_t addr = lfs_phys_addr(c, block, off);

    if (lfs_flash_open() != 0) {
        return LFS_ERR_IO;
    }

    spi_nor_write(&flash0, addr, (uint8_t *)buffer, (uint32_t)size);

    lfs_flash_close();
    return 0;
}

static int lfs_bd_erase (const struct lfs_config *c, lfs_block_t block){
    if (g_part == NULL) {
        return LFS_ERR_INVAL;
    }

    uint32_t addr = lfs_phys_addr(c, block, 0);

    if (lfs_flash_open() != 0) {
        return LFS_ERR_IO;
    }

    spi_nor_sector_erase(&flash0, addr);

    lfs_flash_close();
    return 0;
}

static int lfs_bd_sync (const struct lfs_config *c){
    (void)c;
    return 0;
}

static void lfs_cfg_setup (void){
    memset(&g_lfs_cfg, 0, sizeof(g_lfs_cfg));

    g_lfs_cfg.read  = lfs_bd_read;
    g_lfs_cfg.prog  = lfs_bd_prog;
    g_lfs_cfg.erase = lfs_bd_erase;
    g_lfs_cfg.sync  = lfs_bd_sync;

    g_lfs_cfg.read_size      = LFS_READ_SIZE;
    g_lfs_cfg.prog_size      = LFS_PROG_SIZE;
    g_lfs_cfg.block_size     = LFS_BLOCK_SIZE;
    g_lfs_cfg.block_count    = (lfs_size_t)((uint32_t)g_part->len / (uint32_t)LFS_BLOCK_SIZE);

    g_lfs_cfg.cache_size     = LFS_CACHE_SIZE;
    g_lfs_cfg.lookahead_size = LFS_LOOKAHEAD_SIZE;
    g_lfs_cfg.block_cycles   = LFS_BLOCK_CYCLES;
}

int32_t littlefs_init(void){
    int err;

    g_part = fal_partition_find(LFS_PART_NAME);
    if (g_part == NULL) {
        return -1;
    }
    if (g_part->len < LFS_BLOCK_SIZE) {
        return -1;
    }

    lfs_cfg_setup();

    err = lfs_mount(&g_lfs, &g_lfs_cfg);
    if (err != 0) {
        err = lfs_format(&g_lfs, &g_lfs_cfg);
        if (err != 0) {
            return -1;
        }
        err = lfs_mount(&g_lfs, &g_lfs_cfg);
        if (err != 0) {
            return -1;
        }
    }
    return 0;
}
