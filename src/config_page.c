#include "config_page.h"
#include "basic_include.h"

#include "lwip/apps/httpd.h"
#include "lwip/apps/fs.h"
#include "lwip/mem.h"
#include "lwip/err.h"

#include "lib/littlefs/lfs.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "osal/task.h"

#include "lib/net/mongoose/mongoose.h"

#define CFGP_WWW_DIR         "www"

#define CFGP_PAGE_DEBUG
#ifdef CFGP_PAGE_DEBUG
#define cfgp_debug(fmt, ...)  os_printf("[HTTPD] " fmt "\r\n", ##__VA_ARGS__)
#else
#define cfgp_debug(fmt, ...)  do { } while (0)
#endif

extern lfs_t g_lfs;

typedef struct{
    lfs_file_t f;
    bool       open;
} mg_lfs_fd_t;

static struct os_work cfgp_work;
static struct mg_mgr mgr;

static int mg_lfs_st( const char *path, size_t *size, time_t *mtime ){
    struct lfs_info info;

    if (path == NULL) return 0;
    if (lfs_stat(&g_lfs, path, &info) < 0) return 0;

    if (size) {
        *size = (info.type == LFS_TYPE_REG) ? (size_t) info.size : 0;
    }
    if (mtime) {
        *mtime = (time_t) 0;
    }

    if (info.type == LFS_TYPE_DIR) return MG_FS_DIR;
    if (info.type == LFS_TYPE_REG) return MG_FS_READ;
    return 0;
}

static void mg_lfs_ls( const char *path, void (*fn)(const char *, void *), void *param ){
    lfs_dir_t dir;
    struct lfs_info info;

    if ((path == NULL) || (fn == NULL)) return;
    if (lfs_dir_open(&g_lfs, &dir, path) < 0) return;

    for (;;) {
        int r = lfs_dir_read(&g_lfs, &dir, &info);
        if (r <= 0) break;

        if ((strcmp(info.name, ".") == 0) || (strcmp(info.name, "..") == 0)) {
            continue;
        }
        fn(info.name, param);
    }

    lfs_dir_close(&g_lfs, &dir);
}

static void *mg_lfs_op( const char *path, int flags ){
    mg_lfs_fd_t *h;
    int oflags = 0;

    if (path == NULL) return NULL;

    if (flags & MG_FS_WRITE) {
        oflags = LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC;
    } else {
        oflags = LFS_O_RDONLY;
    }

    h = (mg_lfs_fd_t *) mg_calloc(1, sizeof(*h));
    if (h == NULL) return NULL;

    if (lfs_file_open(&g_lfs, &h->f, path, oflags) < 0) {
        mg_free(h);
        return NULL;
    }

    h->open = true;
    return h;
}

static void mg_lfs_cl( void *fd ){
    mg_lfs_fd_t *h = (mg_lfs_fd_t *) fd;
    if (h == NULL) return;

    if (h->open) {
        lfs_file_close(&g_lfs, &h->f);
        h->open = false;
    }
    mg_free(h);
}

static size_t mg_lfs_rd( void *fd, void *buf, size_t len ){
    mg_lfs_fd_t *h = (mg_lfs_fd_t *) fd;
    lfs_ssize_t r;

    if ((h == NULL) || (!h->open) || (buf == NULL) || (len == 0)) return 0;

    r = lfs_file_read(&g_lfs, &h->f, buf, (lfs_size_t) len);
    return (r > 0) ? (size_t) r : 0;
}

static size_t mg_lfs_wr( void *fd, const void *buf, size_t len ){
    mg_lfs_fd_t *h = (mg_lfs_fd_t *) fd;
    lfs_ssize_t w;

    if ((h == NULL) || (!h->open) || (buf == NULL) || (len == 0)) return 0;

    w = lfs_file_write(&g_lfs, &h->f, buf, (lfs_size_t) len);
    return (w > 0) ? (size_t) w : 0;
}

static size_t mg_lfs_sk( void *fd, size_t offset ){
    mg_lfs_fd_t *h = (mg_lfs_fd_t *) fd;
    lfs_soff_t r;

    if ((h == NULL) || (!h->open)) return 0;

    r = lfs_file_seek(&g_lfs, &h->f, (lfs_soff_t) offset, LFS_SEEK_SET);
    return (r >= 0) ? (size_t) r : 0;
}

static bool mg_lfs_mv( const char *from, const char *to ){
    if ((from == NULL) || (to == NULL)) return false;
    return lfs_rename(&g_lfs, from, to) == 0;
}

static bool mg_lfs_rm( const char *path ){
    if (path == NULL) return false;
    return lfs_remove(&g_lfs, path) == 0;
}

static bool mg_lfs_mkd( const char *path ){
    if (path == NULL) return false;
    return lfs_mkdir(&g_lfs, path) == 0;
}

struct mg_fs mg_fs_littlefs = {
    .st  = mg_lfs_st,
    .ls  = mg_lfs_ls,
    .op  = mg_lfs_op,
    .cl  = mg_lfs_cl,
    .rd  = mg_lfs_rd,
    .wr  = mg_lfs_wr,
    .sk  = mg_lfs_sk,
    .mv  = mg_lfs_mv,
    .rm  = mg_lfs_rm,
    .mkd = mg_lfs_mkd,
};

static void ev_handler(struct mg_connection *c, int ev, void *ev_data){
    if (ev == MG_EV_HTTP_MSG) {

        struct mg_http_message *hm = (struct mg_http_message *) ev_data;

        cfgp_debug("%.*s %.*s",
                   (int)hm->method.len, hm->method.buf,
                   (int)hm->uri.len,    hm->uri.buf);

        struct mg_http_serve_opts opts = {
            .root_dir = CFGP_WWW_DIR,
            .fs       = &mg_fs_littlefs
        };

        mg_http_serve_dir(c, hm, &opts);
    }
}

static int32 cfgp_loop(struct os_work *work) {
    mg_mgr_poll(&mgr, 0); // I dont know why poll time work wrong
    os_run_work_delay(&cfgp_work, 5);
    return 0;
}

int32_t config_page_init( void ){
    lfs_mkdir(&g_lfs, CFGP_WWW_DIR);
    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, "http://0.0.0.0:80", ev_handler, NULL);
    OS_WORK_INIT(&cfgp_work, cfgp_loop, 0);
    os_run_work_delay(&cfgp_work, 1000);
    return 0;
}
