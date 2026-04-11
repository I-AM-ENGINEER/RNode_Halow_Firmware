#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_LITTLEFS

#include "basic_include.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "littelfs_port.h"
#include "lib/littlefs/lfs.h"
#include "lib/logc/log.h"
#include <lib/fal/fal.h>
#include "osal/mutex.h"

#include "hal/spi_nor.h"

extern struct spi_nor_flash flash0;

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

lfs_t g_lfs;
static struct os_mutex g_lfs_mutex;
static struct lfs_config g_lfs_cfg;
static const struct fal_partition *g_part;

static inline int lfs_flash_open( void ){
    int rc = spi_nor_open(&flash0);

    if( rc != 0 ){
        log_error("spi_nor_open failed rc=%d", rc);
    }

    return rc;
}

static inline void lfs_flash_close( void ){
    spi_nor_close(&flash0);
}

static inline uint32_t lfs_phys_addr( const struct lfs_config *c, lfs_block_t block, lfs_off_t off ){
    uint32_t rel = (uint32_t)block * (uint32_t)c->block_size + (uint32_t)off;
    return (uint32_t)g_part->offset + rel;
}

static int lfs_bd_read( const struct lfs_config *c,
                        lfs_block_t block, lfs_off_t off,
                        void *buffer, lfs_size_t size ){
    uint32_t addr;

    if( (g_part == NULL) || (buffer == NULL) || (c == NULL) ){
        log_error("read invalid args");
        return LFS_ERR_INVAL;
    }

    if( ((uint32_t)off + (uint32_t)size) > (uint32_t)c->block_size ){
        log_error("read range invalid block=%lu off=%lu size=%lu",
                  (unsigned long)block,
                  (unsigned long)off,
                  (unsigned long)size);
        return LFS_ERR_INVAL;
    }

    addr = lfs_phys_addr(c, block, off);

    if( lfs_flash_open() != 0 ){
        return LFS_ERR_IO;
    }

    spi_nor_read(&flash0, addr, (uint8_t *)buffer, (uint32_t)size);

    lfs_flash_close();
    return 0;
}

static int lfs_bd_prog( const struct lfs_config *c,
                        lfs_block_t block, lfs_off_t off,
                        const void *buffer, lfs_size_t size ){
    uint32_t addr;

    if( (g_part == NULL) || (buffer == NULL) || (c == NULL) ){
        log_error("prog invalid args");
        return LFS_ERR_INVAL;
    }

    if( (((uint32_t)off % (uint32_t)c->prog_size) != 0U) ||
        (((uint32_t)size % (uint32_t)c->prog_size) != 0U) ||
        (((uint32_t)off + (uint32_t)size) > (uint32_t)c->block_size) ){
        log_error("prog align/range invalid block=%lu off=%lu size=%lu prog_size=%lu",
                  (unsigned long)block,
                  (unsigned long)off,
                  (unsigned long)size,
                  (unsigned long)c->prog_size);
        return LFS_ERR_INVAL;
    }

    addr = lfs_phys_addr(c, block, off);

    if( lfs_flash_open() != 0 ){
        return LFS_ERR_IO;
    }

    spi_nor_write(&flash0, addr, (uint8_t *)buffer, (uint32_t)size);

    lfs_flash_close();
    return 0;
}

static int lfs_bd_erase( const struct lfs_config *c, lfs_block_t block ){
    uint32_t addr;

    if( (g_part == NULL) || (c == NULL) ){
        log_error("erase invalid args");
        return LFS_ERR_INVAL;
    }

    addr = lfs_phys_addr(c, block, 0);

    if( lfs_flash_open() != 0 ){
        return LFS_ERR_IO;
    }

    spi_nor_sector_erase(&flash0, addr);

    lfs_flash_close();
    return 0;
}

static int lfs_bd_sync( const struct lfs_config *c ){
    (void)c;
    return 0;
}

static int lfs_lock_cb( const struct lfs_config *c ){
    (void)c;

    if( os_mutex_lock(&g_lfs_mutex, OS_MUTEX_WAIT_FOREVER) != 0 ){
        log_error("mutex lock failed");
        return LFS_ERR_IO;
    }

    return 0;
}

static int lfs_unlock_cb( const struct lfs_config *c ){
    (void)c;

    if( os_mutex_unlock(&g_lfs_mutex) != 0 ){
        log_error("mutex unlock failed");
        return LFS_ERR_IO;
    }

    return 0;
}

static void lfs_cfg_setup( void ){
    memset(&g_lfs_cfg, 0, sizeof(g_lfs_cfg));
    os_mutex_init(&g_lfs_mutex);

    g_lfs_cfg.lock           = lfs_lock_cb;
    g_lfs_cfg.unlock         = lfs_unlock_cb;

    g_lfs_cfg.read           = lfs_bd_read;
    g_lfs_cfg.prog           = lfs_bd_prog;
    g_lfs_cfg.erase          = lfs_bd_erase;
    g_lfs_cfg.sync           = lfs_bd_sync;

    g_lfs_cfg.read_size      = LFS_READ_SIZE;
    g_lfs_cfg.prog_size      = LFS_PROG_SIZE;
    g_lfs_cfg.block_size     = LFS_BLOCK_SIZE;
    g_lfs_cfg.block_count    = (lfs_size_t)((uint32_t)g_part->len / (uint32_t)LFS_BLOCK_SIZE);

    g_lfs_cfg.cache_size     = LFS_CACHE_SIZE;
    g_lfs_cfg.lookahead_size = LFS_LOOKAHEAD_SIZE;
    g_lfs_cfg.block_cycles   = LFS_BLOCK_CYCLES;

    log_info("cfg part=%s off=0x%08lx len=%lu blocks=%lu",
             g_part->name,
             (unsigned long)g_part->offset,
             (unsigned long)g_part->len,
             (unsigned long)g_lfs_cfg.block_count);
}

int32_t littlefs_init( void ){
    int err;

    g_part = fal_partition_find(FAL_PART_NAME_LITTLEFS);
    if( g_part == NULL ){
        log_error("partition not found: %s", FAL_PART_NAME_LITTLEFS);
        return -1;
    }

    if( g_part->len < LFS_BLOCK_SIZE ){
        log_error("partition too small len=%lu block=%u",
                  (unsigned long)g_part->len,
                  (unsigned)LFS_BLOCK_SIZE);
        return -1;
    }

    lfs_cfg_setup();

    err = lfs_mount(&g_lfs, &g_lfs_cfg);
    if( err != 0 ){
        log_warn("mount failed err=%d, formatting", err);

        err = lfs_format(&g_lfs, &g_lfs_cfg);
        if( err != 0 ){
            log_error("format failed err=%d", err);
            return -1;
        }

        err = lfs_mkdir(&g_lfs, "/www");
        if( (err != 0) && (err != LFS_ERR_EXIST) ){
            log_warn("mkdir /www failed err=%d", err);
        }

        err = lfs_mount(&g_lfs, &g_lfs_cfg);
        if( err != 0 ){
            log_error("mount after format failed err=%d", err);
            return -1;
        }
    }

    log_info("littlefs mounted");
    return 0;
}