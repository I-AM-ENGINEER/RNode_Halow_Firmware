#include "basic_include.h"
#include <stdint.h>
#include <string.h>

#include "ota.h"
#include "lib/littlefs/lfs.h"

extern lfs_t g_lfs;

//#define OTA_UNPACK_DEBUG

#ifdef OTA_UNPACK_DEBUG
#define otau_dbg(fmt, ...) os_printf("[OTAU] " fmt "\r\n", ##__VA_ARGS__)
#else
#define otau_dbg(fmt, ...) do { } while (0)
#endif

#define OTA_UNPACK_TAR_BLK         (512u)
#define OTA_UNPACK_PATH_MAX        (256u)

static int32_t ota_file_exists( const char *path ){
    lfs_file_t f;

    if (lfs_file_open(&g_lfs, &f, path, LFS_O_RDONLY) < 0) {
        return -1;
    }

    (void)lfs_file_close(&g_lfs, &f);
    return 0;
}

static uint32_t oct_u32( const char *p, uint32_t n ){
    uint32_t v = 0;

    while (n-- && *p) {
        if (*p >= '0' && *p <= '7') {
            v = (v << 3) + (uint32_t)(*p - '0');
        }
        p++;
    }

    return v;
}

static uint32_t blk_zero( const uint8_t *b ){
    for (uint32_t i = 0; i < OTA_UNPACK_TAR_BLK; i++) {
        if (b[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int32_t ensure_dir( const char *path ){
    (void)lfs_mkdir(&g_lfs, path);
    return 0;
}

static int32_t ensure_parent_dirs( const char *fullpath ){
    char tmp[OTA_UNPACK_PATH_MAX];
    size_t n = strlen(fullpath);

    if (n >= sizeof(tmp)) {
        return -1;
    }

    memcpy(tmp, fullpath, n + 1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)ensure_dir(tmp);
            *p = '/';
        }
    }

    return 0;
}

static int32_t rm_rf_except( const char *path, const char *keep_fullpath ){
    lfs_dir_t dir;
    struct lfs_info info;

    if (keep_fullpath && strcmp(path, keep_fullpath) == 0) {
        return 0;
    }

    if (lfs_dir_open(&g_lfs, &dir, path) < 0) {
        (void)lfs_remove(&g_lfs, path);
        return 0;
    }

    while (lfs_dir_read(&g_lfs, &dir, &info) > 0) {

        if (!strcmp(info.name, ".") || !strcmp(info.name, "..")) {
            continue;
        }

        char child[OTA_UNPACK_PATH_MAX];

        if (!strcmp(path, "/")) {
            (void)snprintf(child, sizeof(child), "/%s", info.name);
        } else {
            (void)snprintf(child, sizeof(child), "%s/%s", path, info.name);
        }

        if (keep_fullpath && strcmp(child, keep_fullpath) == 0) {
            continue;
        }

        if (info.type == LFS_TYPE_DIR) {
            if (rm_rf_except(child, keep_fullpath) < 0) {
                (void)lfs_dir_close(&g_lfs, &dir);
                return -1;
            }
        } else {
            if (lfs_remove(&g_lfs, child) < 0) {
                (void)lfs_dir_close(&g_lfs, &dir);
                return -2;
            }
        }
    }

    (void)lfs_dir_close(&g_lfs, &dir);

    if (strcmp(path, "/") != 0) {
        (void)lfs_remove(&g_lfs, path);
    }

    return 0;
}


static int32_t fs_wipe_keep_ota( void ){
    return rm_rf_except("/", OTA_TAR_FILE_PATH);
}


static int32_t tar_extract_to_root( const char *tar_path ){
    lfs_file_t tf;
    uint8_t *hdr = NULL;
    uint8_t *buf = NULL;
    char    *full = NULL;
    int32_t rc = 0;

    hdr  = (uint8_t *)malloc(OTA_UNPACK_TAR_BLK);
    buf  = (uint8_t *)malloc(1024u);
    full = (char *)malloc(OTA_UNPACK_PATH_MAX);

    if (hdr == NULL || buf == NULL || full == NULL) {
        rc = -10;
        goto out;
    }

    if (lfs_file_open(&g_lfs, &tf, tar_path, LFS_O_RDONLY) < 0) {
        rc = -1;
        goto out;
    }

    while (1) {

        if (lfs_file_read(&g_lfs, &tf, hdr, (lfs_size_t)OTA_UNPACK_TAR_BLK) != (lfs_ssize_t)OTA_UNPACK_TAR_BLK) {
            rc = -2;
            goto out_tf;
        }

        if (blk_zero(hdr)) {
            break;
        }

        const char *name = (const char *)&hdr[0];
        char typeflag = (char)hdr[156];
        uint32_t size = oct_u32((const char *)&hdr[124], 12);

        (void)snprintf(full, (size_t)OTA_UNPACK_PATH_MAX, "/%.*s", 100, name);

        if (typeflag == '5') {
            (void)ensure_dir(full);
            otau_dbg("dir  %s", full);
            continue;
        }

        if (ensure_parent_dirs(full) < 0) {
            rc = -3;
            goto out_tf;
        }

        otau_dbg("file %s (%lu)", full, (unsigned long)size);

        lfs_file_t of;
        if (lfs_file_open(&g_lfs, &of, full, LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC) < 0) {
            rc = -4;
            goto out_tf;
        }

        uint32_t left = size;

        while (left) {

            uint32_t n = (left > 1024u) ? 1024u : left;

            lfs_ssize_t rr = lfs_file_read(&g_lfs, &tf, buf, (lfs_size_t)n);
            if (rr <= 0) {
                (void)lfs_file_close(&g_lfs, &of);
                rc = -5;
                goto out_tf;
            }

            if (lfs_file_write(&g_lfs, &of, buf, (lfs_size_t)rr) != rr) {
                (void)lfs_file_close(&g_lfs, &of);
                rc = -6;
                goto out_tf;
            }

            left -= (uint32_t)rr;
        }

        (void)lfs_file_close(&g_lfs, &of);

        uint32_t pad =
            (OTA_UNPACK_TAR_BLK - (size % OTA_UNPACK_TAR_BLK)) &
            (OTA_UNPACK_TAR_BLK - 1);

        if (pad) {
            (void)lfs_file_seek(&g_lfs, &tf, (lfs_soff_t)pad, LFS_SEEK_CUR);
        }
    }

out_tf:
    (void)lfs_file_close(&g_lfs, &tf);

out:
    if (full != NULL) {
        free(full);
    }
    if (buf != NULL) {
        free(buf);
    }
    if (hdr != NULL) {
        free(hdr);
    }
    return rc;
}


int32_t ota_lfs_upgrade_from_tar( void ){
    if (ota_file_exists(OTA_TAR_FILE_PATH) != 0) {
        otau_dbg("ota file not found");
        return -1;
    }

    if (fs_wipe_keep_ota() < 0) {
        return -2;
    }

    if (tar_extract_to_root(OTA_TAR_FILE_PATH) != 0) {
        return -3;
    }

    return 0;
}
