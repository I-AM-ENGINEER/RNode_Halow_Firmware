
#include "basic_include.h"

#include "lwip/api.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "osal/task.h"

#include "lib/littlefs/lfs.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "cJSON.h"

#include "config_page/config_api_dispatch.h"

/* extern lfs */
extern lfs_t g_lfs;

#define HTTP_PORT        80
#define HTTP_REQ_MAX     4096
#define HTTP_FILE_CHUNK  1024

#define WWW_DIR          "www"

#define HTTP_CT_TEXT     "text/plain"
#define HTTP_CT_JSON     "application/json"

#define HTTP_JSON_ERR_OOM         "{\"ok\":false,\"rc\":-500,\"err\":\"oom\"}\n"
#define HTTP_JSON_ERR_EMPTY_BODY  "{\"ok\":false,\"rc\":-400,\"err\":\"empty body\"}\n"
#define HTTP_JSON_ERR_BAD_JSON    "{\"ok\":false,\"rc\":-400,\"err\":\"bad json\"}\n"
#define HTTP_JSON_ERR_API_OOM     "{\"error\":\"oom\"}\n"

#define HTTP_SEND_LITERAL(nc, code, ctype, lit) \
    http_send_raw((nc), (code), (ctype), (lit), (sizeof(lit) - 1))

#define HTTP_SEND_TEXT_LITERAL(nc, code, lit) \
    HTTP_SEND_LITERAL((nc), (code), HTTP_CT_TEXT, (lit))

#define HTTP_SEND_JSON_LITERAL(nc, code, lit) \
    HTTP_SEND_LITERAL((nc), (code), HTTP_CT_JSON, (lit))


//#define HTTP_DEBUG

#ifdef HTTP_DEBUG
#define httpd_dbg(fmt, ...) os_printf("[HTTP] " fmt "\r\n", ##__VA_ARGS__)
#else
#define httpd_dbg(fmt, ...) do { } while (0)
#endif

static struct os_task g_http_task;
/* -------------------------------------------------------------------------- */
/* MIME types                                                                 */
/* -------------------------------------------------------------------------- */

static const char *http_content_type( const char *path ){
    const char *ext = strrchr(path, '.');
    if (ext == NULL) {
        return "application/octet-stream";
    }
    ext++;

    if (strcmp(ext, "html") == 0) { return "text/html"; }
    if (strcmp(ext, "htm")  == 0) { return "text/html"; }
    if (strcmp(ext, "css")  == 0) { return "text/css"; }
    if (strcmp(ext, "js")   == 0) { return "application/javascript"; }
    if (strcmp(ext, "json") == 0) { return "application/json"; }
    if (strcmp(ext, "png")  == 0) { return "image/png"; }
    if (strcmp(ext, "jpg")  == 0) { return "image/jpeg"; }
    if (strcmp(ext, "jpeg") == 0) { return "image/jpeg"; }
    if (strcmp(ext, "svg")  == 0) { return "image/svg+xml"; }
    if (strcmp(ext, "ico")  == 0) { return "image/x-icon"; }
    if (strcmp(ext, "txt")  == 0) { return "text/plain"; }

    return "application/octet-stream";
}

static bool http_path_is_safe( const char *p ){
    if (p == NULL) {
        return false;
    }
    if (strstr(p, "..") != NULL) {
        return false;
    }
    if (strchr(p, '\\') != NULL) {
        return false;
    }
    if (strchr(p, ':') != NULL) {
        return false;
    }
    if (strchr(p, '%') != NULL) {
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------- */
/* Send helpers                                                               */
/* -------------------------------------------------------------------------- */

static void http_send_raw( struct netconn *nc,
                           int code,
                           const char *content_type,
                           const void *body,
                           size_t body_len ){
    char hdr[256];

    if (nc == NULL) {
        return;
    }
    if (content_type == NULL) {
        content_type = "application/octet-stream";
    }
    if (body == NULL) {
        body = "";
        body_len = 0;
    }

    snprintf(hdr, sizeof(hdr),
             "HTTP/1.1 %d\r\n"
             "Content-Type: %s\r\n"
             "Cache-Control: no-cache\r\n"
             "Connection: close\r\n"
             "Content-Length: %u\r\n"
             "\r\n",
             code,
             content_type,
             (unsigned)body_len);

    (void)netconn_write(nc, hdr, strlen(hdr), NETCONN_COPY);
    if (body_len > 0) {
        (void)netconn_write(nc, body, body_len, NETCONN_COPY);
    }
}

static void http_send_text( struct netconn *nc, int code, const char *text ){
    if (text == NULL) {
        text = "";
    }
    http_send_raw(nc, code, HTTP_CT_TEXT, text, strlen(text));
}

static void http_send_json_cjson( struct netconn *nc, int code, cJSON *root ){
    char *s;

    if (root == NULL) {
        HTTP_SEND_JSON_LITERAL(nc, 500, HTTP_JSON_ERR_OOM);
        return;
    }

    s = cJSON_PrintUnformatted(root);
    if (s == NULL) {
        HTTP_SEND_JSON_LITERAL(nc, 500, HTTP_JSON_ERR_OOM);
        return;
    }

    http_send_raw(nc, code, HTTP_CT_JSON, s, strlen(s));
    cJSON_free(s);
}

/* -------------------------------------------------------------------------- */
/* HTTP parsing                                                               */
/* -------------------------------------------------------------------------- */

static bool http_parse_request_line( const char *buf,
                                     char *method, size_t method_sz,
                                     char *uri, size_t uri_sz ){
    const char *eol;
    const char *sp1;
    const char *sp2;
    size_t n;

    if (buf == NULL || method == NULL || uri == NULL) {
        return false;
    }

    eol = strstr(buf, "\r\n");
    if (eol == NULL) {
        return false;
    }

    sp1 = memchr(buf, ' ', (size_t)(eol - buf));
    if (sp1 == NULL) {
        return false;
    }
    sp2 = memchr(sp1 + 1, ' ', (size_t)(eol - (sp1 + 1)));
    if (sp2 == NULL) {
        return false;
    }

    n = (size_t)(sp1 - buf);
    if (n == 0 || n >= method_sz) {
        return false;
    }
    memcpy(method, buf, n);
    method[n] = 0;

    n = (size_t)(sp2 - (sp1 + 1));
    if (n == 0 || n >= uri_sz) {
        return false;
    }
    memcpy(uri, sp1 + 1, n);
    uri[n] = 0;

    return true;
}

static bool http_line_starts_with_ci( const char *p, const char *lit, int n ){
    int i;

    for (i = 0; i < n; i++) {
        char a = p[i];
        char b = lit[i];
        if (a == 0 || b == 0) {
            return false;
        }
        a = (char)tolower((unsigned char)a);
        b = (char)tolower((unsigned char)b);
        if (a != b) {
            return false;
        }
    }
    return true;
}


static int http_find_content_length( const char *hdr_start, const char *hdr_end ){
    const char *p;

    if (hdr_start == NULL || hdr_end == NULL || hdr_end <= hdr_start) {
        return 0;
    }

    p = hdr_start;

    while (p < hdr_end) {
        const char *line_end = strstr(p, "\r\n");
        if (line_end == NULL || line_end > hdr_end) {
            line_end = hdr_end;
        }

        if ((line_end - p) >= 15) {
            if (http_line_starts_with_ci(p, "Content-Length:", 15)) {
                const char *v = p + 15;
                while (v < line_end && (*v == ' ' || *v == '\t')) { v++; }
                if (v >= line_end) {
                    return 0;
                }
                {
                    long n = strtol(v, NULL, 10);
                    if (n <= 0) {
                        return 0;
                    }
                    if (n > 1024 * 1024) {  /* clamp: we don't support huge bodies here */
                        return 1024 * 1024;
                    }
                    return (int)n;
                }
            }
        }

        if (line_end == hdr_end) {
            break;
        }
        p = line_end + 2;
    }

    return 0;
}


static int http_recv_request( struct netconn *nc, char *buf, int buf_sz ){
    int total = 0;
    char *hdr_end;
    int need_total = -1; /* unknown */
    int content_len = 0;

    if (nc == NULL || buf == NULL || buf_sz <= 0) {
        return -1;
    }

    while (total < buf_sz - 1) {
        struct netbuf *nb = NULL;
        void *data = NULL;
        u16_t len = 0;
        err_t err;

        err = netconn_recv(nc, &nb);
        if (err != ERR_OK || nb == NULL) {
            if (nb) { netbuf_delete(nb); }
            break;
        }

        if (((buf_sz - 1) - total) > 0) {
            int can = (buf_sz - 1) - total;

            netbuf_first(nb);
            do {
                netbuf_data(nb, &data, &len);
                if (data == NULL || len == 0) {
                    break;
                }

                {
                    int take = can;
                    if ((int)len < take) {
                        take = (int)len;
                    }
                    memcpy(buf + total, data, (size_t)take);
                    total += take;
                    can -= take;
                    buf[total] = 0;
                }

                if (can <= 0) {
                    break;
                }
            } while (netbuf_next(nb) != 0);
        }

        netbuf_delete(nb);

        if (need_total < 0) {
            hdr_end = strstr(buf, "\r\n\r\n");
            if (hdr_end != NULL) {
                const char *headers_start = buf;
                const char *headers_end = hdr_end;
                content_len = http_find_content_length(headers_start, headers_end);
                need_total = (int)((hdr_end - buf) + 4 + content_len);
            }
        }

        if (need_total >= 0 && total >= need_total) {
            break;
        }
    }

    return total;
}

/* -------------------------------------------------------------------------- */
/* Static files                                                               */
/* -------------------------------------------------------------------------- */

static void http_serve_file( struct netconn *nc, const char *uri ){
    char path[256];
    lfs_file_t f;
    lfs_ssize_t r;
    int rc;

    if (nc == NULL || uri == NULL) {
        return;
    }

    if (!http_path_is_safe(uri)) {
        http_send_text(nc, 400, "bad path\n");
        return;
    }

    if (strcmp(uri, "/") == 0) {
        snprintf(path, sizeof(path), "%s/index.html", WWW_DIR);
    } else {
        while (*uri == '/') { uri++; }
        snprintf(path, sizeof(path), "%s/%s", WWW_DIR, uri);
    }

    rc = lfs_file_open(&g_lfs, &f, path, LFS_O_RDONLY);
    if (rc < 0) {
        http_send_text(nc, 404, "not found\n");
        return;
    }

    {
        char hdr[256];
        snprintf(hdr, sizeof(hdr),
                 "HTTP/1.1 200\r\n"
                 "Content-Type: %s\r\n"
                 "Cache-Control: no-cache\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 http_content_type(path));
        (void)netconn_write(nc, hdr, strlen(hdr), NETCONN_COPY);
    }

    {
        uint8_t chunk[HTTP_FILE_CHUNK];
        while (1) {
            r = lfs_file_read(&g_lfs, &f, chunk, sizeof(chunk));
            if (r <= 0) {
                break;
            }
            (void)netconn_write(nc, chunk, (size_t)r, NETCONN_COPY);
        }
    }

    (void)lfs_file_close(&g_lfs, &f);
}

/* -------------------------------------------------------------------------- */
/* API (HTTP glue)                                                            */
/* -------------------------------------------------------------------------- */

static int http_map_api_rc_to_http( int32_t rc ){
    if (rc == WEB_API_RC_NOT_FOUND) {
        return 404;
    }
    if (rc == WEB_API_RC_METHOD_NOT_ALLOWED) {
        return 405;
    }
    if (rc == WEB_API_RC_BAD_REQUEST) {
        return 400;
    }
    if (rc < 0) {
        return 500;
    }
    return 200;
}

static void http_handle_api( struct netconn *nc,
                             const char *method,
                             const char *uri,
                             const char *body,
                             int body_len ){
    cJSON *req = NULL;
    cJSON *out = NULL;
    int32_t rc;
    int http_code;

    if (nc == NULL || method == NULL || uri == NULL) {
        http_send_text(nc, 400, "bad request\n");
        return;
    }

    if (body == NULL) {
        body = "";
        body_len = 0;
    }

    if (strcmp(method, "POST") == 0) {
        if (body_len <= 0) {
            HTTP_SEND_JSON_LITERAL(nc, 400, HTTP_JSON_ERR_EMPTY_BODY);
            return;
        }

        req = cJSON_ParseWithLength(body, (size_t)body_len);
        if (req == NULL || !cJSON_IsObject(req)) {
            if (req) { cJSON_Delete(req); }
            HTTP_SEND_JSON_LITERAL(nc, 400, HTTP_JSON_ERR_BAD_JSON);
            return;
        }
    }

    out = cJSON_CreateObject();
    if (out == NULL) {
        if (req) { cJSON_Delete(req); }
        HTTP_SEND_JSON_LITERAL(nc, 500, HTTP_JSON_ERR_OOM);
        return;
    }

    /* API works ONLY with JSON objects. No ok/rc wrappers here. */
    rc = web_api_dispatch(method, uri, req, out);

    http_code = http_map_api_rc_to_http(rc);

    if (rc != 0) {
        /* Keep error payload minimal, original UI usually expects plain JSON. */
        cJSON_Delete(out);
        out = cJSON_CreateObject();
        if (out == NULL) {
            if (req) { cJSON_Delete(req); }
            HTTP_SEND_JSON_LITERAL(nc, 500, HTTP_JSON_ERR_API_OOM);
            return;
        }

        if (rc == WEB_API_RC_NOT_FOUND) {
            (void)cJSON_AddStringToObject(out, "error", "api not found");
        } else if (rc == WEB_API_RC_METHOD_NOT_ALLOWED) {
            (void)cJSON_AddStringToObject(out, "error", "method not allowed");
        } else if (rc == WEB_API_RC_BAD_REQUEST) {
            (void)cJSON_AddStringToObject(out, "error", "bad request");
        } else {
            (void)cJSON_AddStringToObject(out, "error", "internal error");
        }
        (void)cJSON_AddNumberToObject(out, "rc", (double)rc);
    }

    http_send_json_cjson(nc, http_code, out);

    if (req) { cJSON_Delete(req); }
    if (out) { cJSON_Delete(out); }
}

/* -------------------------------------------------------------------------- */
/* One connection                                                             */
/* -------------------------------------------------------------------------- */

static void http_handle_one( struct netconn *nc ){
    char buf[HTTP_REQ_MAX + 1];
    int n;
    char method[8];
    char uri[128];
    char *hdr_end;
    int header_len;
    int content_len;
    const char *body;
    int body_len;

    if (nc == NULL) {
        return;
    }

    memset(buf, 0, sizeof(buf));
    memset(method, 0, sizeof(method));
    memset(uri, 0, sizeof(uri));

    n = http_recv_request(nc, buf, sizeof(buf));
    if (n <= 0) {
        return;
    }
    buf[n] = 0;

    hdr_end = strstr(buf, "\r\n\r\n");
    if (hdr_end == NULL) {
        http_send_text(nc, 400, "bad request\n");
        return;
    }

    if (!http_parse_request_line(buf, method, sizeof(method), uri, sizeof(uri))) {
        http_send_text(nc, 400, "bad request\n");
        return;
    }

    {
        char *q;

        q = strchr(uri, '?');
        if (q) { *q = 0; }
        q = strchr(uri, '#');
        if (q) { *q = 0; }
    }

    header_len = (int)((hdr_end - buf) + 4);
    content_len = http_find_content_length(buf, hdr_end);

    body = buf + header_len;
    body_len = n - header_len;

    if (content_len > 0 && body_len > content_len) {
        body_len = content_len;
    }

    if (content_len > 0 && body_len < content_len) {
        http_send_text(nc, 400, "incomplete body\n");
        return;
    }
    if (content_len > (HTTP_REQ_MAX - header_len)) {
        http_send_text(nc, 413, "payload too large\n");
        return;
    }

    httpd_dbg("%s %s body=%d", method, uri, body_len);

    if (strncmp(uri, "/api/", 5) == 0) {
        http_handle_api(nc, method, uri, body, body_len);
        return;
    }

    http_serve_file(nc, uri);
}

/* -------------------------------------------------------------------------- */
/* Server task                                                                */
/* -------------------------------------------------------------------------- */
static void http_server_task( void *arg ){
    struct netconn *listen_nc = NULL;

    (void)arg;

    listen_nc = netconn_new(NETCONN_TCP);
    if (listen_nc == NULL) {
        return;
    }

    if (netconn_bind(listen_nc, IP_ADDR_ANY, HTTP_PORT) != ERR_OK) {
        netconn_delete(listen_nc);
        return;
    }

    if (netconn_listen(listen_nc) != ERR_OK) {
        netconn_delete(listen_nc);
        return;
    }

    while (1) {
        struct netconn *client = NULL;

        if (netconn_accept(listen_nc, &client) != ERR_OK || client == NULL) {
            os_sleep_ms(10);
            continue;
        }

        http_handle_one(client);
        netconn_close(client);
        netconn_delete(client);
    }
}

int32_t config_page_init( void ){
    int32_t ret;

    ret = os_task_init((const uint8 *)"httpd", &g_http_task, http_server_task, 0);
    if (ret != 0) {
        return ret;
    }

    ret = os_task_set_stacksize(&g_http_task, CONFIG_PAGE_TASK_STACK);
    if (ret != 0) {
        return ret;
    }

    ret = os_task_set_priority(&g_http_task, CONFIG_PAGE_TASK_PRIO);
    if (ret != 0) {
        return ret;
    }

    ret = os_task_run(&g_http_task);
    return ret;
}
