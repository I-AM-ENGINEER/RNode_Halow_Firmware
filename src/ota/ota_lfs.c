#include "sys_config.h"
#define LOG_LOCAL_LEVEL     LOG_LEVEL_OTA_LFS
#include "lib/logc/log.h"
#include "basic_include.h"
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "ota.h"
#include "lib/littlefs/lfs.h"

extern lfs_t g_lfs;

#define WOTA_PATH_MAX  128

typedef struct {
    bool       active;
    uint32_t   size;
    uint32_t   expect_crc32;
    uint32_t   written;
    uint32_t   crc_running;
    lfs_file_t file;
} wota_ctx_t;

static wota_ctx_t s_wota;

/* True while an OTA file-transfer session is in progress. The TX hard-wedge
 * watchdog consults this before its last-resort reboot. */
bool ota_wota_active( void ){
    return s_wota.active;
}

void ota_wota_session_abort( void ){
    s_wota.active = false;
}

/* Feed bytes into raw (non-finalized) CRC accumulator.
 * Initialize with 0xFFFFFFFF, finalize by XOR with 0xFFFFFFFF. */
static uint32_t crc32_feed( uint32_t c, const uint8_t *p, uint32_t n ){
    while (n--) {
        c ^= (uint32_t)(*p++);
        for (uint32_t k = 0; k < 8u; k++) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
    }
    return c;
}

static int32_t ensure_parent_dirs( const char *fullpath ){
    char tmp[WOTA_PATH_MAX];
    size_t n = strlen(fullpath);

    if (n >= sizeof(tmp)) { return -1; }

    memcpy(tmp, fullpath, n + 1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)lfs_mkdir(&g_lfs, tmp);
            *p = '/';
        }
    }
    return 0;
}

int32_t ota_lfs_file_begin( const char *path, uint32_t total_size, uint32_t expect_crc32 ){
    log_trace("file_begin: path=%s size=%lu crc=0x%08lX",
              path ? path : "NULL",
              (unsigned long)total_size,
              (unsigned long)expect_crc32);

    if (path == NULL || path[0] == '\0') {
        log_trace("file_begin: null/empty path");
        return -1;
    }
    if (total_size == 0) {
        log_trace("file_begin: size=0");
        return -2;
    }
    if (strlen(path) >= WOTA_PATH_MAX) {
        log_trace("file_begin: path too long");
        return -3;
    }

    // close any previously open file
    if (s_wota.active) {
        (void)lfs_file_close(&g_lfs, &s_wota.file);
        s_wota.active = false;
    }

    if (ensure_parent_dirs(path) < 0) {
        log_trace("file_begin: mkdir failed");
        return -4;
    }

    if (lfs_file_open(&g_lfs, &s_wota.file, path,
                      LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC) < 0) {
        log_trace("file_begin: open failed (%s)", path);
        return -5;
    }

    s_wota.active       = true;
    s_wota.size         = total_size;
    s_wota.expect_crc32 = expect_crc32;
    s_wota.written      = 0;
    s_wota.crc_running  = 0xFFFFFFFFu;

    log_trace("file_begin: OK");
    return 0;
}

int32_t ota_wota_file_write( const void *data, uint32_t len ){
    if (!s_wota.active) {
        log_trace("file_write: not active");
        return -1;
    }
    if (data == NULL || len == 0) {
        return -2;
    }
    if (s_wota.written + len > s_wota.size) {
        log_trace("file_write: overflow written=%lu len=%lu size=%lu",
                  (unsigned long)s_wota.written,
                  (unsigned long)len,
                  (unsigned long)s_wota.size);
        return -3;
    }

    if (lfs_file_write(&g_lfs, &s_wota.file, data, (lfs_size_t)len) != (lfs_ssize_t)len) {
        log_trace("file_write: write fail len=%lu", (unsigned long)len);
        return -4;
    }

    s_wota.crc_running = crc32_feed(s_wota.crc_running, (const uint8_t *)data, len);
    s_wota.written    += len;

    log_trace("file_write: len=%lu written=%lu", (unsigned long)len, (unsigned long)s_wota.written);
    return 0;
}

int32_t ota_wota_file_end( void ){
    uint32_t final_crc;

    if (!s_wota.active) {
        log_trace("file_end: not active");
        return -1;
    }

    (void)lfs_file_close(&g_lfs, &s_wota.file);
    s_wota.active = false;

    log_trace("file_end: written=%lu expected_size=%lu",
              (unsigned long)s_wota.written,
              (unsigned long)s_wota.size);

    if (s_wota.written != s_wota.size) {
        log_trace("file_end: size mismatch");
        return -2;
    }

    /* finalise: XOR out */
    final_crc = s_wota.crc_running ^ 0xFFFFFFFFu;

    log_trace("file_end: crc=0x%08lX expected=0x%08lX",
              (unsigned long)final_crc,
              (unsigned long)s_wota.expect_crc32);

    if (final_crc != s_wota.expect_crc32) {
        log_trace("file_end: crc mismatch");
        return -3;
    }

    log_trace("file_end: OK");
    return 0;
}
