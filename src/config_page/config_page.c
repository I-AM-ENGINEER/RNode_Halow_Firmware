
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

#define HTTP_PORT           80
#define HTTP_REQ_MAX_LEN    16384
#define HTTP_FILE_CHUNK     1024

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
#define httpd_debug(fmt, ...) os_printf("[HTTP] " fmt "\r\n", ##__VA_ARGS__)
static void http_dbg_dump_text(const char *prefix, const char *data, int len){
    int off = 0;

    httpd_debug("%s len=%d:", prefix ? prefix : "", len);

    while (off < len) {
        int chunk = len - off;
        if (chunk > 64) chunk = 64;

        hgprintf("%.*s", chunk, data + off);

        off += chunk;
    }

    hgprintf("\n");
}
#else
#define httpd_debug(fmt, ...) do { } while (0)
static inline void http_dbg_dump_text(const char *prefix, const char *data, int len){
    (void)prefix;
    (void)data;
    (void)len;
}
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
    char *hdr;

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

    hdr = os_malloc(192);
    if (hdr == NULL) {
        return;
    }

    snprintf(hdr, 192,
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
    os_free(hdr);
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

static const char *http_find_eol( const char *buf, size_t len ){
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

static void http_get_method( const char *header, size_t header_len,
                             char *method, size_t method_size ){
    const char *method_end;
    size_t method_len;

    method[0] = 0;

    if (!header || !method || method_size < 2) {
        return;
    }

    method_end = memchr(header, ' ', header_len);
    if (!method_end) {
        return;
    }

    method_len = method_end - header;
    if (method_len >= method_size) {
        method_len = method_size - 1;
    }

    memcpy(method, header, method_len);
    method[method_len] = 0;
}


static void http_get_uri( const char *header, size_t header_len,
                          char *uri, size_t uri_size ){
    const char *uri_start;
    const char *uri_end;
    size_t uri_len;

    uri[0] = 0;

    if (!header || !uri || uri_size < 2) {
        return;
    }

    uri_start = memchr(header, ' ', header_len);
    if (!uri_start) {
        return;
    }

    uri_start++;

    uri_end = memchr(uri_start, ' ', header + header_len - uri_start);
    if (!uri_end) {
        return;
    }

    uri_len = uri_end - uri_start;
    if (uri_len >= uri_size) {
        uri_len = uri_size - 1;
    }

    memcpy(uri, uri_start, uri_len);
    uri[uri_len] = 0;
}

static int32_t http_get_content_length( const char *header, size_t header_len ){
    const char *p;
    const char *end = header + header_len;
    int32_t n = 0;

    if (!header) {
        return 0;
    }

    p = lwip_strnstr(header, "Content-Length:", header_len);
    if (!p) {
        return 0;
    }

    p += 15;

    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }

    n = atoi(p);

    return n;
}

/* -------------------------------------------------------------------------- */
/* Static files                                                               */
/* -------------------------------------------------------------------------- */

static void http_serve_file( struct netconn *nc, const char *uri ){
    char path[32];
    lfs_file_t f;
    lfs_ssize_t r;
    int rc;

    if (nc == NULL || uri == NULL) {
        httpd_debug("serve_file: bad args nc=%p uri=%p", nc, uri);
        return;
    }

    httpd_debug("serve_file: uri='%s'", uri);

    if (!http_path_is_safe(uri)) {
        httpd_debug("serve_file: unsafe path '%s'", uri);
        http_send_text(nc, 400, "bad path\n");
        return;
    }

    if (strcmp(uri, "/") == 0) {
        snprintf(path, sizeof(path), "%s/index.html", WWW_DIR);
    } else {
        while (*uri == '/') { uri++; }
        snprintf(path, sizeof(path), "%s/%s", WWW_DIR, uri);
    }

    httpd_debug("serve_file: open path='%s'", path);

    rc = lfs_file_open(&g_lfs, &f, path, LFS_O_RDONLY);
    if (rc < 0) {
        httpd_debug("serve_file: open failed rc=%d", rc);
        http_send_text(nc, 404, "not found\n");
        return;
    }

    {
        char *hdr = os_malloc(128);
        if (hdr == NULL) {
            httpd_debug("serve_file: malloc failed");
            return;
        }

        snprintf(hdr, 128,
                "HTTP/1.1 200\r\n"
                "Content-Type: %s\r\n"
                "Cache-Control: no-cache\r\n"
                "Connection: close\r\n"
                "\r\n",
                http_content_type(path));

        httpd_debug("serve_file: send header type='%s'", http_content_type(path));

        (void)netconn_write(nc, hdr, strlen(hdr), NETCONN_COPY);

        os_free(hdr);
    }

    {
        uint8_t *chunk = os_malloc(HTTP_FILE_CHUNK);
        uint32_t total = 0;

        if (chunk == NULL) {
            httpd_debug("serve_file: malloc failed");
            return;
        }

        while (1) {
            r = lfs_file_read(&g_lfs, &f, chunk, HTTP_FILE_CHUNK);
            if (r <= 0) {
                httpd_debug("serve_file: read end r=%d total=%u", (int)r, total);
                break;
            }

            total += r;
            httpd_debug("serve_file: send chunk %d", (int)r);

            (void)netconn_write(nc, chunk, (size_t)r, NETCONN_COPY);
        }

        os_free(chunk);
    }

    (void)lfs_file_close(&g_lfs, &f);

    httpd_debug("serve_file: done '%s'", path);
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
        httpd_debug("bad request, %p %p %p", nc, method, uri);
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
		httpd_debug("BODY RAW len=%d: '%.*s'", body_len, body_len, body);

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

static void http_handle_one( struct netconn *nc ){
    char method[8];
    char uri[32];
    char *hdr_end;
    int32_t header_len;
    int32_t content_len;
    const char *body;
    int body_len;
    struct netbuf *nb = NULL;
    char *data = NULL;
    uint16_t data_len = 0;
    uint16_t total_need = 0;

    if (nc == NULL) {
        return;
    }

    memset(method, 0, sizeof(method));
    memset(uri, 0, sizeof(uri));

    if (netconn_recv(nc, &nb) != ERR_OK || nb == NULL) {
        goto end;
    }

    uint16_t first_len = 0;

    netbuf_first(nb);
    do {
        void *chunk;
        uint16_t chunk_len;

        netbuf_data(nb, &chunk, &chunk_len);
        first_len += chunk_len;
    } while (netbuf_next(nb) >= 0);

    if (first_len == 0 || first_len > HTTP_REQ_MAX_LEN) {
        goto end;
    }

    data = os_malloc(first_len);
    if (data == NULL) {
        goto end;
    }
    data[first_len-1] = '\0';

    netbuf_first(nb);
    do {
        void *chunk;
        uint16_t chunk_len;

        netbuf_data(nb, &chunk, &chunk_len);
        memcpy(data + data_len, chunk, chunk_len);
        data_len += chunk_len;
    } while (netbuf_next(nb) >= 0);

    hdr_end = lwip_strnstr(data, "\r\n\r\n", data_len);
    if (hdr_end == NULL) {
        httpd_debug("no header in first package");
        http_send_text(nc, 400, "bad request\n");
        goto end;
    }

    header_len = (hdr_end - data) + 4;

    http_get_uri(data, header_len, uri, sizeof(uri));
    http_get_method(data, header_len, method, sizeof(method));
    if (uri[0] == '\0' || method[0] == '\0') {
        httpd_debug("no uri or method");
        http_send_text(nc, 400, "bad request\n");
        goto end;
    }

    content_len = http_get_content_length(data, header_len);
    if (content_len < 0) {
        content_len = 0;
    }

    total_need = header_len + content_len;
    if (total_need == 0 || total_need > HTTP_REQ_MAX_LEN) {
        httpd_debug("request too large");
        http_send_text(nc, 400, "request too large\n");
        goto end;
    }

    if (total_need > data_len) {
        char *new_data = os_malloc(total_need);
        if (new_data == NULL) {
            goto end;
        }

        memcpy(new_data, data, data_len);
        os_free(data);
        data = new_data;

        while (data_len < total_need) {
            if (nb) {
                netbuf_delete(nb);
                nb = NULL;
            }

            if (netconn_recv(nc, &nb) != ERR_OK || nb == NULL) {
                httpd_debug("cant receive");
                http_send_text(nc, 400, "incomplete body\n");
                goto end;
            }

            netbuf_first(nb);
            do {
                void *chunk;
                uint16_t chunk_len;
                uint16_t remain;

                netbuf_data(nb, &chunk, &chunk_len);

                remain = total_need - data_len;
                if (chunk_len > remain) {
                    chunk_len = remain;
                }

                memcpy(data + data_len, chunk, chunk_len);
                data_len += chunk_len;

                if (data_len >= total_need) {
                    break;
                }
            } while (netbuf_next(nb) >= 0);
        }
    }

    //http_dbg_dump_text("BODY RAW", data, data_len);

    body = data + header_len;
    body_len = data_len - header_len;

    if (content_len > 0) {
        if (body_len > content_len) {
            body_len = content_len;
        }

        if (body_len < content_len) {
            http_send_text(nc, 400, "incomplete body\n");
            goto end;
        }
    } else {
        body = NULL;
        body_len = 0;
    }

    httpd_debug("REQ method='%.*s' uri='%.*s' body_len=%d",
            (int)sizeof(method), method,
            (int)sizeof(uri), uri,
            body_len
    );

    if (strncmp(uri, "/api/", 5) == 0) {
        http_handle_api(nc, method, uri, body, body_len);
        goto end;
    }

    http_serve_file(nc, uri);

end:
    if (data) {
        os_free(data);
    }
    if (nb) {
        netbuf_delete(nb);
    }
}

static void http_server_task( void *arg ){
    struct netconn *listen = NULL;
    err_t err;

    (void)arg;

    
    listen = netconn_new(NETCONN_TCP);
    netconn_bind(listen, IP_ADDR_ANY, HTTP_PORT);
    netconn_listen(listen);

    httpd_debug("listening on port %d", HTTP_PORT);

    while (1) {
        struct netconn *client = NULL;
        err = netconn_accept(listen, &client);
        httpd_debug("accept ret err=%d client=%p", (int)err, client);

        if (err != ERR_OK) {
            httpd_debug("accept failed err=%d client=%p", (int)err, client);
            if (client != NULL) {
                netconn_close(client);
                netconn_delete(client);
            }
            continue;
        }
        
        //ip4_addr_t client_ip = client->pcb.tcp->remote_ip;

        httpd_debug("client accepted nc=%p", client);

        netconn_set_recvtimeout(client, 3000);

        http_handle_one(client);
        netconn_close(client);
        netconn_delete(client);
    }
}

int32_t config_page_init( void ){
    int32_t ret;
    lfs_mkdir(&g_lfs, WWW_DIR);
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
