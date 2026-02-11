#include "lwip/apps/tftp_server.h"
#include "lwip/pbuf.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "lib/littlefs/lfs.h"
#include "lwip/apps/tftp_server.h"

extern lfs_t     g_lfs;

//#define TFTP_SERVER_DEBUG

#ifdef TFTP_SERVER_DEBUG
#define tftps_debug(fmt, ...)  os_printf("[TFTP] " fmt "\r\n", ##__VA_ARGS__)
#else
#define tftps_debug(fmt, ...)  do { } while (0)
#endif

static lfs_file_t g_tftp_file;
static bool       g_tftp_open;

static void* tftp_lfs_open (const char* fname, const char* mode, u8_t write){
    (void)mode;

    if (g_tftp_open) {
        tftps_debug("open: BUSY");
        return NULL;
    }

    if (fname == NULL) {
        tftps_debug("open: fname is NULL");
        return NULL;
    }

    memset(&g_tftp_file, 0, sizeof(g_tftp_file));

    tftps_debug("open: %s '%s'", write ? "WRQ" : "RRQ", fname);

    int flags = write
              ? (LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC)
              :  LFS_O_RDONLY;

    int err = lfs_file_open(&g_lfs, &g_tftp_file, fname, flags);
    if (err != 0) {
        tftps_debug("open: FAIL err=%d", err);
        memset(&g_tftp_file, 0, sizeof(g_tftp_file));
        return NULL;
    }

    g_tftp_open = true;
    tftps_debug("open: OK");
    return &g_tftp_file;
}

static void tftp_lfs_close (void* handle){
    lfs_file_t *f = (lfs_file_t*)handle;

    if ((f == NULL) || (!g_tftp_open)) {
        tftps_debug("close: BADARGS");
        return;
    }

    (void)lfs_file_close(&g_lfs, f);
    g_tftp_open = false;

    memset(&g_tftp_file, 0, sizeof(g_tftp_file));
    tftps_debug("close: OK");
}

static int tftp_lfs_read (void* handle, void* buf, int bytes){
    lfs_file_t *f = (lfs_file_t*)handle;

    if ((f == NULL) || (!g_tftp_open) || (buf == NULL) || (bytes <= 0)) {
        tftps_debug("read: BADARGS");
        return -1;
    }

    lfs_ssize_t rd = lfs_file_read(&g_lfs, f, buf, (lfs_size_t)bytes);
    if (rd < 0) {
        tftps_debug("read: FAIL rd=%ld", (long)rd);
        return -1;
    }

    return (int)rd;
}

static int tftp_lfs_write (void* handle, struct pbuf* p){
    lfs_file_t *f = (lfs_file_t*)handle;

    if ((f == NULL) || (!g_tftp_open) || (p == NULL)) {
        tftps_debug("write: BADARGS");
        return -1;
    }

    for (struct pbuf *q = p; q; q = q->next) {
        lfs_ssize_t wr = lfs_file_write(&g_lfs, f, q->payload, (lfs_size_t)q->len);
        if ((wr < 0) || ((u16_t)wr != q->len)) {
            tftps_debug("write: FAIL wr=%ld qlen=%u",
                       (long)wr, (unsigned)q->len);
            return -1;
        }
    }

    return 0;
}

static const struct tftp_context g_tftp_ctx = {
    .open  = tftp_lfs_open,
    .close = tftp_lfs_close,
    .read  = tftp_lfs_read,
    .write = tftp_lfs_write,
};

int32_t tftp_server_init(void){
    tftp_init(&g_tftp_ctx);
    return 0;
}
