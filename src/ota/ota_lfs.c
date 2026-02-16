#include "basic_include.h"
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "ota.h"

#include "lib/littlefs/lfs.h"

extern lfs_t g_lfs;

//#define OTA_LFS_DEBUG

#ifdef OTA_LFS_DEBUG
#define otafs_dbg(fmt, ...) os_printf("[OTAFS] " fmt "\r\n", ##__VA_ARGS__)
#else
#define otafs_dbg(fmt, ...) do { } while (0)
#endif

typedef struct {
    bool active;
    uint32_t size;
    uint32_t expect_crc32;
    lfs_file_t file;
} ota_lfs_ctx_t;

static ota_lfs_ctx_t s_ota;

static uint32_t crc32_update_u8( uint32_t crc, const uint8_t *p, uint32_t n ){
    uint32_t c = crc ^ 0xFFFFFFFFu;

    while (n--) {
        c ^= (uint32_t)(*p++);
        for (uint32_t k = 0; k < 8u; k++) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
    }

    return c ^ 0xFFFFFFFFu;
}

static uint32_t crc32_file_u32( const char *path, uint32_t nbytes, uint32_t *out_crc32 ){
    lfs_file_t f;
    uint8_t buf[1024];
    uint32_t left;
    uint32_t crc;

    if (out_crc32 == NULL) {
        otafs_dbg("crc32_file: out_crc32 == NULL");
        return -1;
    }

    if (lfs_file_open(&g_lfs, &f, path, LFS_O_RDONLY) < 0) {
        otafs_dbg("crc32_file: open fail (%s)", path);
        return -2;
    }

    left = nbytes;
    crc  = 0;

    while (left) {
        uint32_t chunk = (left > (uint32_t)sizeof(buf)) ? (uint32_t)sizeof(buf) : left;
        lfs_ssize_t rr = lfs_file_read(&g_lfs, &f, buf, (lfs_size_t)chunk);

        if (rr != (lfs_ssize_t)chunk) {
            otafs_dbg("crc32_file: read fail (rr=%ld)", (long)rr);
            (void)lfs_file_close(&g_lfs, &f);
            return -3;
        }

        crc = crc32_update_u8(crc, buf, chunk);
        left -= chunk;
    }

    (void)lfs_file_close(&g_lfs, &f);
    *out_crc32 = crc;

    otafs_dbg("crc32_file: done crc=0x%08lX", (unsigned long)crc);
    return 0;
}

static uint32_t ota_lfs_abort( void ){
    if (s_ota.active) {
        otafs_dbg("abort: closing active file");
        (void)lfs_file_close(&g_lfs, &s_ota.file);
        s_ota.active = false;
    }

    return 0;
}

uint32_t ota_lfs_begin( uint32_t total_size, uint32_t expect_crc32 ){
    otafs_dbg("begin: size=%lu expect_crc=0x%08lX",
            (unsigned long)total_size,
            (unsigned long)expect_crc32);

    if (total_size == 0) {
        otafs_dbg("begin: invalid size");
        return -1;
    }

    (void)ota_lfs_abort();

    (void)lfs_remove(&g_lfs, OTA_TAR_FILE_PATH);

    if (lfs_file_open(&g_lfs, &s_ota.file, OTA_TAR_FILE_PATH,
        LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC) < 0) {
        otafs_dbg("begin: open fail (%s)", OTA_TAR_FILE_PATH);
        return -2;
    }

    s_ota.active       = true;
    s_ota.size         = total_size;
    s_ota.expect_crc32 = expect_crc32;

    otafs_dbg("begin: file opened");
    return 0;
}

uint32_t ota_lfs_write( uint32_t off, const void *data, uint32_t len ){
    if (!s_ota.active) {
        otafs_dbg("write: not active");
        return -1;
    }

    if (lfs_file_write(&g_lfs, &s_ota.file, data, (lfs_size_t)len) != (lfs_ssize_t)len) {
        otafs_dbg("write: write fail len=%lu", (unsigned long)len);
        return -2;
    }

    otafs_dbg("write: off=%lu len=%lu",
            (unsigned long)off,
            (unsigned long)len);

    return 0;
}

uint32_t ota_lfs_end( void ){
    uint32_t calculated_crc32;
    lfs_soff_t size;
    int32_t res;

    if (!s_ota.active) {
        otafs_dbg("end: not active");
        return -1;
    }

    size = lfs_file_size(&g_lfs, &s_ota.file);
    (void)lfs_file_close(&g_lfs, &s_ota.file);
    s_ota.active = false;

    otafs_dbg("end: size=%ld expected=%lu",
            (long)size,
            (unsigned long)s_ota.size);

    if (size != (lfs_soff_t)s_ota.size) {
        otafs_dbg("end: size mismatch");
        return -2;
    }

    res = crc32_file_u32(OTA_TAR_FILE_PATH, s_ota.size, &calculated_crc32);
    if (res != 0) {
        otafs_dbg("end: crc calc fail (%ld)", (long)res);
        return -3;
    }

    otafs_dbg("end: crc calc=0x%08lX expect=0x%08lX",
            (unsigned long)calculated_crc32,
            (unsigned long)s_ota.expect_crc32);

    if (calculated_crc32 != s_ota.expect_crc32) {
        otafs_dbg("end: crc mismatch");
        return -4;
    }

    otafs_dbg("end: OK");
    return 0;
}
