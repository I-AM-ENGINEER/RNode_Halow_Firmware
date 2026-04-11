#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_LEVEL_TFTP_SERVER

#include "lwip/apps/tftp_server.h"
#include "lwip/pbuf.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "lib/littlefs/lfs.h"
#include "lib/logc/log.h"
#include "lwip/apps/tftp_server.h"

extern lfs_t g_lfs;

static lfs_file_t g_tftp_file;
static bool g_tftp_open;

static void *tftp_lfs_open( const char *fname, const char *mode, u8_t write ){
    int flags;
    int err;

    (void)mode;

    if(g_tftp_open){
        log_warn("open busy");
        return NULL;
    }

    if(fname == NULL){
        log_warn("open fname null");
        return NULL;
    }

    memset(&g_tftp_file, 0, sizeof(g_tftp_file));

    log_debug("open %s '%s'", write ? "WRQ" : "RRQ", fname);

    flags = write
          ? (LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC)
          : LFS_O_RDONLY;

    err = lfs_file_open(&g_lfs, &g_tftp_file, fname, flags);
    if(err != 0){
        log_error("open fail err=%d file='%s'", err, fname);
        memset(&g_tftp_file, 0, sizeof(g_tftp_file));
        return NULL;
    }

    g_tftp_open = true;
    log_trace("open ok");
    return &g_tftp_file;
}

static void tftp_lfs_close( void *handle ){
    lfs_file_t *f = (lfs_file_t *)handle;

    if((f == NULL) || (!g_tftp_open)){
        log_warn("close badargs");
        return;
    }

    (void)lfs_file_close(&g_lfs, f);
    g_tftp_open = false;

    memset(&g_tftp_file, 0, sizeof(g_tftp_file));
    log_trace("close ok");
}

static int tftp_lfs_read( void *handle, void *buf, int bytes ){
    lfs_file_t *f = (lfs_file_t *)handle;
    lfs_ssize_t rd;

    if((f == NULL) || (!g_tftp_open) || (buf == NULL) || (bytes <= 0)){
        log_warn("read badargs");
        return -1;
    }

    rd = lfs_file_read(&g_lfs, f, buf, (lfs_size_t)bytes);
    if(rd < 0){
        log_error("read fail rd=%ld", (long)rd);
        return -1;
    }

    return (int)rd;
}

static int tftp_lfs_write( void *handle, struct pbuf *p ){
    lfs_file_t *f = (lfs_file_t*)handle;

    if((f == NULL) || (!g_tftp_open) || (p == NULL)){
        log_warn("write badargs");
        return -1;
    }

    for(struct pbuf *q = p; q; q = q->next){
        lfs_ssize_t wr = lfs_file_write(&g_lfs, f, q->payload, (lfs_size_t)q->len);
        if((wr < 0) || ((u16_t)wr != q->len)) {
            log_error("write fail wr=%ld qlen=%u",
                      (long)wr,
                      (unsigned)q->len);
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

int32_t tftp_server_init( void ){
    tftp_init(&g_tftp_ctx);
    log_info("tftp init ok");
    return 0;
}
