/*
 * ota_update.c - device-side firmware update checker for GitHub Releases.
 *
 * See inc/ota_update.h for the design notes (plain-HTTP constraint, accepted
 * document shapes, opt-in gating). This file speaks plain HTTP/1.1 over a
 * lwIP netconn, follows the configdb/web-api conventions of the other
 * modules (config keys under the "upd" prefix) and reuses the existing
 * firmware-OTA flash writer (ota.h) for the download + apply path.
 */
#include "sys_config.h"
#define LOG_LOCAL_LEVEL LOG_WARN

#include "ota_update.h"
#include "build_info_gen.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "lib/logc/log.h"
#include "configdb.h"
#include "utils.h"
#include "ota.h"
#include "device.h"
#include "cJSON.h"

#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/api.h"

/* ------------------------------------------------------------------ */
/* config keys (configdb)                                              */
/* ------------------------------------------------------------------ */

#define OTA_UPDATE_CFG_PREFIX               CONFIGDB_ADD_MODULE("upd")
#define OTA_UPDATE_CFG_ADD(name)            OTA_UPDATE_CFG_PREFIX "." name

#define OTA_UPDATE_CFG_EN_NAME              OTA_UPDATE_CFG_ADD("en")
#define OTA_UPDATE_CFG_PERIOD_NAME          OTA_UPDATE_CFG_ADD("period")
#define OTA_UPDATE_CFG_URL_NAME             OTA_UPDATE_CFG_ADD("url")

/* update-check period bounds (hours) */
#define OTA_UPDATE_PERIOD_MIN_H             (1u)
#define OTA_UPDATE_PERIOD_MAX_H             (24u * 30u)
#define OTA_UPDATE_PERIOD_DEF_H             (24u)

/* manifest body cap: api.github.com releases/latest is a few kB */
#define OTA_UPDATE_MANIFEST_MAX             (16u * 1024u)
/* sidecar "<asset>.crc32" is a short hex text file */
#define OTA_UPDATE_CRC_TEXT_MAX             (64u)

/* http limits */
#define OTA_UPDATE_HTTP_HDR_MAX             (2048u)
#define OTA_UPDATE_HTTP_RD_BUF              (1024u)
#define OTA_UPDATE_RECV_TIMEOUT_MS          (15000u)
#define OTA_UPDATE_REDIRECT_MAX             (3u)

#define OTA_UPDATE_FW_MIN_SIZE              (1024u)     /* sanity floor */

/* Release quarantine: a freshly published release may hide critical bugs for
 * a few days (after which it can be withdrawn). The automatic install path
 * refuses releases younger than this; manual install is exempt. There is no
 * wall clock in this firmware, so "now" is the Date: header of the GitHub
 * HTTP response and the release age is now_epoch - published_at. */
#define OTA_UPDATE_MIN_AGE_S                (3u * 24u * 3600u)

/* Everything below runs on the single "otaupd" worker task, so these
 * function-static scratch buffers are safe (and keep the 4 kB task stack
 * small: the header buffer alone would eat a quarter of it). */
static char s_manifest_buf[OTA_UPDATE_MANIFEST_MAX];
static char s_http_hdr[OTA_UPDATE_HTTP_HDR_MAX + 1];
static char s_crc_text[OTA_UPDATE_CRC_TEXT_MAX + 1];

static struct os_task s_task;
static volatile bool  s_req_check;      /* web API: check now          */
static volatile bool  s_req_install;    /* web API: install now        */
static bool           s_started;

/* runtime status, written by the worker, read by the web API */
static char    s_last_tag[OTA_UPDATE_TAG_MAX];
static char    s_last_err[OTA_UPDATE_ERR_MAX];
static int64_t s_last_check_ms;
static bool    s_avail;
static bool    s_busy;
static bool    s_hold;                  /* newer release, but quarantined */
static int32_t s_age_h;                 /* release age in hours, -1 = unknown */

/* ------------------------------------------------------------------ */
/* config                                                              */
/* ------------------------------------------------------------------ */

static void ota_update_config_sanitize( ota_update_config_t *cfg ){
    if (cfg == NULL) {
        return;
    }

    cfg->enabled = cfg->enabled ? true : false;

    if (cfg->period_h < OTA_UPDATE_PERIOD_MIN_H) {
        cfg->period_h = OTA_UPDATE_PERIOD_DEF_H;
    }
    if (cfg->period_h > OTA_UPDATE_PERIOD_MAX_H) {
        cfg->period_h = OTA_UPDATE_PERIOD_MAX_H;
    }

    cfg->url[sizeof(cfg->url) - 1] = '\0';
}

void ota_update_config_load( ota_update_config_t *cfg ){
    int32_t period = (int32_t)OTA_UPDATE_PERIOD_DEF_H;
    int8_t  en     = 0;

    if (cfg == NULL) {
        return;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->period_h = OTA_UPDATE_PERIOD_DEF_H;
    strncpy(cfg->url, OTA_UPDATE_URL_DEFAULT, sizeof(cfg->url) - 1);

    configdb_get_i8 (OTA_UPDATE_CFG_EN_NAME,     &en);
    configdb_get_i32(OTA_UPDATE_CFG_PERIOD_NAME, &period);
    configdb_get_blob(OTA_UPDATE_CFG_URL_NAME,   cfg->url, sizeof(cfg->url));

    cfg->enabled  = (en != 0);
    cfg->period_h = (uint32_t)period;

    ota_update_config_sanitize(cfg);
}

void ota_update_config_save( ota_update_config_t *cfg ){
    int8_t  en;
    int32_t period;

    if (cfg == NULL) {
        return;
    }

    ota_update_config_sanitize(cfg);

    en     = cfg->enabled ? 1 : 0;
    period = (int32_t)cfg->period_h;

    configdb_set_i8 (OTA_UPDATE_CFG_EN_NAME,     &en);
    configdb_set_i32(OTA_UPDATE_CFG_PERIOD_NAME, &period);
    configdb_set_blob(OTA_UPDATE_CFG_URL_NAME,   cfg->url, strlen(cfg->url) + 1);
}

static void status_set_err( const char *msg ){
    if (msg == NULL) {
        msg = "";
    }
    strncpy(s_last_err, msg, sizeof(s_last_err) - 1);
    s_last_err[sizeof(s_last_err) - 1] = '\0';
    if (s_last_err[0] != 0) {
        log_warn("upd: %s", s_last_err);
    }
}

void ota_update_status_json( cJSON *out ){
    ota_update_config_t cfg;

    if (out == NULL) {
        return;
    }

    ota_update_config_load(&cfg);

    cJSON_AddBoolToObject(out, "en",   cfg.enabled);
    cJSON_AddNumberToObject(out, "period_h", (double)cfg.period_h);
    cJSON_AddStringToObject(out, "url", cfg.url);

    cJSON_AddStringToObject(out, "cur", FW_VERSION);
    cJSON_AddStringToObject(out, "tag", s_last_tag);
    cJSON_AddStringToObject(out, "err", s_last_err);
    cJSON_AddBoolToObject(out, "avail", s_avail);
    cJSON_AddBoolToObject(out, "busy",  s_busy);
    cJSON_AddBoolToObject(out, "hold",  s_hold);
    cJSON_AddNumberToObject(out, "age_h", (double)s_age_h);
    cJSON_AddNumberToObject(out, "at", (double)s_last_check_ms);
}

/* ------------------------------------------------------------------ */
/* version compare (vX.Y.Z vs FW_VERSION, semver-ish)                  */
/* ------------------------------------------------------------------ */

static bool ver_triplet( const char *s, uint32_t out[3] ){
    const char *p = s;

    if (s == NULL) {
        return false;
    }

    while ((*p != 0) && ((*p < '0') || (*p > '9'))) {
        p++;                                /* skip leading 'v'/'V'/text */
    }

    return (sscanf(p, "%u.%u.%u", &out[0], &out[1], &out[2]) == 3)
           ? true : false;
}

/* true = tag is strictly newer than the running firmware */
static bool ver_is_newer( const char *tag ){
    uint32_t a[3] = {0, 0, 0};
    uint32_t b[3] = {0, 0, 0};
    uint8_t  i;

    if (!ver_triplet(tag, a) || !ver_triplet(FW_VERSION, b)) {
        return false;
    }

    for (i = 0; i < 3; i++) {
        if (a[i] != b[i]) {
            return (a[i] > b[i]);
        }
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* minimal HTTP/1.1 client (plain http:// only, no TLS in this build)  */
/* ------------------------------------------------------------------ */

typedef struct {
    char     host[96];
    uint16_t port;
    char     path[192];
} http_url_t;

static int http_parse_url( const char *url, http_url_t *out ){
    const char *p;
    const char *slash;
    size_t      n;
    char       *colon;
    char       *end;
    uint32_t    port;

    if (url == NULL || out == NULL) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    if (strncmp(url, "http://", 7) != 0) {
        /* https and everything else: this firmware has no TLS client */
        return -2;
    }

    p = url + 7;
    slash = strchr(p, '/');
    n = (slash != NULL) ? (size_t)(slash - p) : strlen(p);
    if (n == 0 || n >= sizeof(out->host)) {
        return -3;
    }
    memcpy(out->host, p, n);
    out->host[n] = 0;

    strncpy(out->path, (slash != NULL) ? slash : "/", sizeof(out->path) - 1);
    out->path[sizeof(out->path) - 1] = 0;

    out->port = 80;
    colon = strchr(out->host, ':');
    if (colon != NULL) {
        *colon = 0;
        port = (uint32_t)strtoul(colon + 1, &end, 10);
        if ((end == colon + 1) || (port == 0) || (port > 65535u)) {
            return -4;
        }
        out->port = (uint16_t)port;
    }

    if (out->host[0] == 0) {
        return -5;
    }
    return 0;
}

/* buffered reader over a netconn */
typedef struct {
    struct netconn *conn;
    uint8_t         buf[OTA_UPDATE_HTTP_RD_BUF];
    uint32_t        len;
    uint32_t        pos;
    bool            eof;
} http_rd_t;

static int http_rd_fill( http_rd_t *rd ){
    struct netbuf *nb = NULL;
    void  *data;
    u16_t  n;
    err_t  err;

    if (rd->pos < rd->len) {
        return 1;
    }
    if (rd->eof) {
        return 0;
    }

    err = netconn_recv(rd->conn, &nb);
    if (err != ERR_OK || nb == NULL) {
        rd->eof = true;
        return 0;
    }

    netbuf_data(nb, &data, &n);
    if (n > sizeof(rd->buf)) {
        n = sizeof(rd->buf);                /* never expected */
    }
    memcpy(rd->buf, data, n);
    netbuf_delete(nb);

    rd->len = n;
    rd->pos = 0;
    return (n > 0) ? 1 : 0;
}

static int http_rd_getc( http_rd_t *rd ){
    if (http_rd_fill(rd) <= 0) {
        return -1;
    }
    return rd->buf[rd->pos++];
}

/* body sink: return 0 to continue, != 0 to abort */
typedef int (*http_body_cb_t)( void *arg, const uint8_t *data, uint32_t len );

typedef struct {
    http_body_cb_t  body_cb;
    void           *body_arg;
    bool            want_len;               /* require a known body length */
    char            location[OTA_UPDATE_URL_MAX];  /* 3xx target, if any  */
    char            date[64];               /* Date: header (IMF-fixdate)  */
    long            status;
} http_req_t;

static bool hdr_prefix( const char *line, size_t len, const char *name ){
    size_t nl = strlen(name);

    if (len < nl || strncasecmp(line, name, nl) != 0) {
        return false;
    }
    return true;
}

/* days since 1970-01-01 from a proleptic-Gregorian y/m/d (Hinnant) */
static int64_t days_from_civil( int64_t y, uint32_t m, uint32_t d ){
    int64_t  era;
    uint32_t yoe, doy, doe;

    y -= (m <= 2u);
    era    = ((y >= 0) ? y : (y - 399)) / 400;
    yoe    = (uint32_t)(y - era * 400);
    doy    = (153u * (m + ((m > 2u) ? -3u : 9u)) + 2u) / 5u + d - 1u;
    doe    = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static int64_t hms_to_epoch( int64_t days, uint32_t hh, uint32_t mm, uint32_t ss ){
    return days * 86400 + (int64_t)hh * 3600 + (int64_t)mm * 60 + (int64_t)ss;
}

static uint32_t month_from_name( const char *s ){
    static const char *const mon[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    uint32_t i;

    if (s == NULL) {
        return 0;
    }
    for (i = 0; i < 12; i++) {
        if (strncasecmp(s, mon[i], 3) == 0) {
            return i + 1;
        }
    }
    return 0;
}

/* IMF-fixdate: "Tue, 15 Nov 2024 08:12:31 GMT" -> unix epoch (0 on error) */
static int64_t http_date_to_epoch( const char *s ){
    char     mon_name[4] = {0, 0, 0, 0};
    uint32_t day = 0, hh = 0, mm = 0, ss = 0;
    uint32_t mon;
    int      year = 0;

    if (s == NULL) {
        return 0;
    }

    if (sscanf(s, "%*3s, %u %3s %d %u:%u:%u",
               &day, mon_name, &year, &hh, &mm, &ss) != 6) {
        return 0;
    }

    mon = month_from_name(mon_name);
    if ((mon == 0) || (day == 0) || (day > 31u) || (year < 1970)) {
        return 0;
    }

    return hms_to_epoch(days_from_civil(year, mon, day), hh, mm, ss);
}

/* ISO-8601 UTC: "2024-11-15T08:12:31Z" -> unix epoch (0 on error) */
static int64_t iso8601_to_epoch( const char *s ){
    int     year = 0, mon = 0, day = 0;
    uint32_t hh = 0, mm = 0, ss = 0;

    if (s == NULL) {
        return 0;
    }
    if (sscanf(s, "%d-%d-%dT%u:%u:%u", &year, &mon, &day, &hh, &mm, &ss) != 6) {
        return 0;
    }
    if ((year < 1970) || (mon < 1) || (mon > 12) || (day < 1) || (day > 31)) {
        return 0;
    }

    return hms_to_epoch(days_from_civil(year, (uint32_t)mon, (uint32_t)day),
                        hh, mm, ss);
}

/* read + parse status line and headers, then stream the body.
 * returns the HTTP status (>= 100) or a negative error. */
static long http_exchange( struct netconn *conn, http_req_t *req ){
    http_rd_t rd;
    size_t    hn = 0;
    int       c;
    bool      chunked = false;
    uint32_t  content_len = 0;
    bool      have_len = false;
    long      sc;

    memset(&rd, 0, sizeof(rd));
    rd.conn = conn;

    /* --- status line --- */
    {
        char  line[64];
        size_t ln = 0;

        while ((c = http_rd_getc(&rd)) >= 0) {
            if (c == '\n') {
                break;
            }
            if (ln + 1 < sizeof(line)) {
                line[ln++] = (char)c;
            }
        }
        line[ln] = 0;

        if (strncmp(line, "HTTP/", 5) != 0) {
            return -10;
        }
        sc = atol(line + 9);                /* "HTTP/1.x NNN ..." */
        if (sc < 100 || sc > 599) {
            return -11;
        }
    }

    /* --- header block, ends at an empty line --- */
    while (hn < OTA_UPDATE_HTTP_HDR_MAX) {
        size_t ll = 0;

        while ((c = http_rd_getc(&rd)) >= 0) {
            if (c == '\n') {
                break;
            }
            if (c != '\r') {
                s_http_hdr[hn++] = (char)c;
                ll++;
            }
        }
        if (c < 0) {
            return -12;                     /* truncated */
        }
        if (ll == 0) {
            break;                          /* end of headers */
        }
        s_http_hdr[hn++] = '\n';
    }
    s_http_hdr[hn] = 0;

    /* header scan */
    {
        char *h = s_http_hdr;
        char *eol;

        while ((h != NULL) && (*h != 0)) {
            eol = strchr(h, '\n');
            {
                size_t ll = (eol != NULL) ? (size_t)(eol - h) : strlen(h);

                if (hdr_prefix(h, ll, "Content-Length:")) {
                    content_len = (uint32_t)strtoul(h + 15, NULL, 10);
                    have_len = true;
                } else if (hdr_prefix(h, ll, "Transfer-Encoding:")) {
                    if (strstr(h, "chunked") != NULL) {
                        chunked = true;
                    }
                } else if (hdr_prefix(h, ll, "Location:")) {
                    const char *v = h + 9;
                    size_t      vn;
                    size_t      cp;

                    while ((*v == ' ') || (*v == '\t')) {
                        v++;
                    }
                    vn = strcspn(v, "\r\n \t");
                    if (vn >= sizeof(req->location)) {
                        vn = sizeof(req->location) - 1;
                    }
                    for (cp = 0; cp < vn; cp++) {
                        req->location[cp] = v[cp];
                    }
                    req->location[vn] = 0;
                } else if (hdr_prefix(h, ll, "Date:")) {
                    /* IMF-fixdate, e.g. "Tue, 15 Nov 2024 08:12:31 GMT" */
                    const char *v = h + 5;
                    size_t      vn;
                    size_t      cp;

                    while ((*v == ' ') || (*v == '\t')) {
                        v++;
                    }
                    vn = strcspn(v, "\r\n");
                    if (vn >= sizeof(req->date)) {
                        vn = sizeof(req->date) - 1;
                    }
                    for (cp = 0; cp < vn; cp++) {
                        req->date[cp] = v[cp];
                    }
                    req->date[vn] = 0;
                }
            }

            h = (eol != NULL) ? (eol + 1) : NULL;
        }
    }

    req->status = sc;

    if ((sc >= 301) && (sc <= 308) && (sc != 304) && (req->location[0] != 0)) {
        return sc;                          /* caller follows redirect */
    }
    if (sc != 200) {
        return sc;                          /* caller logs the code */
    }
    if (req->body_cb == NULL) {
        return sc;
    }

    /* --- body --- */
    if (chunked) {
        for (;;) {
            char     szline[16];
            size_t   sn = 0;
            uint32_t csz;
            uint32_t got = 0;

            c = http_rd_getc(&rd);
            if (c < 0) {
                return -20;
            }
            szline[sn++] = (char)c;
            while ((sn < sizeof(szline) - 1) && (c = http_rd_getc(&rd)) >= 0) {
                if (c == '\n') {
                    break;
                }
                szline[sn++] = (char)c;
            }
            szline[sn] = 0;
            csz = (uint32_t)strtoul(szline, NULL, 16);
            if (csz == 0) {
                break;                      /* last chunk (trailers ignored) */
            }

            while (got < csz) {
                uint32_t want = csz - got;
                uint32_t have;
                uint32_t n;

                if (http_rd_fill(&rd) <= 0) {
                    return -21;
                }
                have = rd.len - rd.pos;
                n    = (want < have) ? want : have;
                if (req->body_cb(req->body_arg, rd.buf + rd.pos, n) != 0) {
                    return -22;
                }
                rd.pos += n;
                got    += n;
            }

            (void)http_rd_getc(&rd);        /* trailing CR */
            (void)http_rd_getc(&rd);        /* trailing LF */
        }
    } else if (have_len) {
        uint32_t left = content_len;

        while (left > 0) {
            uint32_t n;

            if (http_rd_fill(&rd) <= 0) {
                return -23;
            }
            n = rd.len - rd.pos;
            if (n > left) {
                n = left;
            }
            if (req->body_cb(req->body_arg, rd.buf + rd.pos, n) != 0) {
                return -24;
            }
            rd.pos += n;
            left   -= n;
        }
    } else {
        /* no length, no chunked: read until the peer closes */
        if (req->want_len) {
            return -25;
        }
        while (http_rd_fill(&rd) > 0) {
            if (req->body_cb(req->body_arg, rd.buf, rd.len - rd.pos) != 0) {
                return -26;
            }
            rd.pos = rd.len;
        }
    }

    return sc;
}

static long http_get( const char *url, http_body_cb_t cb, void *cb_arg,
                      bool want_len, char *date_out, size_t date_sz ){
    http_url_t u;
    ip_addr_t  ip;
    char       host[96];
    int        depth;
    long       sc = -1;

    if (date_out != NULL && date_sz > 0) {
        date_out[0] = 0;
    }

    if (http_parse_url(url, &u) != 0) {
        return -1;
    }

    for (depth = 0; depth <= OTA_UPDATE_REDIRECT_MAX; depth++) {
        struct netconn *conn;
        char            req[512];
        http_req_t      rq;
        err_t           err;

        strncpy(host, u.host, sizeof(host) - 1);
        host[sizeof(host) - 1] = 0;

        /* resolve (numeric or DNS). No route/DNS -> clean error. */
        if (!ipaddr_aton(host, &ip)) {
            if (netconn_gethostbyname(host, &ip, 1) != ERR_OK) {
                log_warn("upd: dns failed for '%s'", host);
                return -2;
            }
        }

        conn = netconn_new(NETCONN_TCP);
        if (conn == NULL) {
            return -3;
        }
        netconn_set_recvtimeout(conn, OTA_UPDATE_RECV_TIMEOUT_MS);

        err = netconn_connect(conn, &ip, u.port);
        if (err != ERR_OK) {
            log_warn("upd: connect %s:%u failed err=%d",
                     host, (unsigned)u.port, (int)err);
            netconn_delete(conn);
            return -4;
        }

        snprintf(req, sizeof(req),
                 "GET %s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: rnode-halow-ota/" FW_VERSION "\r\n"
                 "Accept: */*\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 u.path, host);

        err = netconn_write(conn, req, strlen(req), NETCONN_COPY);
        if (err != ERR_OK) {
            log_warn("upd: write failed err=%d", (int)err);
            netconn_close(conn);
            netconn_delete(conn);
            return -5;
        }

        memset(&rq, 0, sizeof(rq));
        rq.body_cb  = cb;
        rq.body_arg = cb_arg;
        rq.want_len = want_len;

        sc = http_exchange(conn, &rq);

        if ((date_out != NULL) && (date_sz > 0) && (rq.date[0] != 0)) {
            strncpy(date_out, rq.date, date_sz - 1);
            date_out[date_sz - 1] = 0;
        }

        netconn_close(conn);
        netconn_delete(conn);

        if ((sc >= 301) && (sc <= 308) && (sc != 304) && (rq.location[0] != 0)) {
            const char *loc = rq.location;

            log_info("upd: redirect(%ld) -> %s", sc, loc);

            if (strncmp(loc, "http://", 7) == 0) {
                if (http_parse_url(loc, &u) != 0) {
                    log_warn("upd: redirect target is not plain http");
                    return -6;
                }
            } else if (loc[0] == '/') {
                strncpy(u.path, loc, sizeof(u.path) - 1);   /* same host */
                u.path[sizeof(u.path) - 1] = 0;
            } else {
                log_warn("upd: unsupported relative redirect");
                return -7;
            }
            continue;
        }

        break;
    }

    return sc;
}

/* ------------------------------------------------------------------ */
/* release manifest parsing                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    char     tag[OTA_UPDATE_TAG_MAX];
    char     url[OTA_UPDATE_URL_MAX];       /* image download URL (http) */
    char     crc_url[OTA_UPDATE_URL_MAX];   /* optional "<asset>.crc32"  */
    uint32_t size;
    bool     have_size;
    uint32_t crc;
    bool     have_crc;
    int64_t  published;                     /* unix epoch of publication */
    bool     have_published;
    bool     prerelease;                    /* GitHub prerelease/draft   */
} release_info_t;

static bool ci_ends_with( const char *s, const char *suffix ){
    size_t ls = strlen(s);
    size_t lf = strlen(suffix);

    if (ls < lf) {
        return false;
    }
    return (strncasecmp(s + ls - lf, suffix, lf) == 0);
}

/* which release assets qualify as firmware images, best first */
static int asset_name_score( const char *name ){
    if (name[0] == 0) {
        return 0;
    }
    if (ci_ends_with(name, ".json")  ||
        ci_ends_with(name, ".sha256") ||
        ci_ends_with(name, ".crc32") ||
        ci_ends_with(name, ".sig")   ||
        ci_ends_with(name, ".tar")   ||
        ci_ends_with(name, ".tar.gz")) {
        return 0;
    }
    if (ci_ends_with(name, ".fw.bin")) {
        return 3;                           /* expected CI artifact */
    }
    if (strcmp(name, "fw.bin") == 0) {
        return 2;
    }
    if (ci_ends_with(name, ".bin")) {
        return 1;
    }
    return 0;
}

/* Accepts both the GitHub releases/latest JSON and the minimal mirror
 * manifest, see inc/ota_update.h. */
static int32_t release_parse( const char *body, release_info_t *ri ){
    cJSON *root;
    cJSON *j;

    root = cJSON_Parse(body);
    if (root == NULL) {
        return -1;
    }

    memset(ri, 0, sizeof(*ri));

    j = cJSON_GetObjectItemCaseSensitive(root, "tag_name");
    if (cJSON_IsString(j)) {
        /* --- GitHub Releases API shape --- */
        cJSON *assets = cJSON_GetObjectItemCaseSensitive(root, "assets");
        cJSON *j_pre  = cJSON_GetObjectItemCaseSensitive(root, "prerelease");
        cJSON *j_drft = cJSON_GetObjectItemCaseSensitive(root, "draft");
        cJSON *j_pub  = cJSON_GetObjectItemCaseSensitive(root, "published_at");
        cJSON *a;
        int    best = 0;
        char   best_name[96];

        /* Releases only: never auto-install a prerelease or draft.
         * (/releases/latest already excludes them, but the URL is
         * configurable, so check explicitly.) */
        if (cJSON_IsTrue(j_pre) || cJSON_IsTrue(j_drft)) {
            strncpy(ri->tag, j->valuestring, sizeof(ri->tag) - 1);
            ri->prerelease = true;
            cJSON_Delete(root);
            return -6;
        }

        if (cJSON_IsString(j_pub)) {
            ri->published      = iso8601_to_epoch(j_pub->valuestring);
            ri->have_published = (ri->published > 0);
        }

        strncpy(ri->tag, j->valuestring, sizeof(ri->tag) - 1);

        if (!cJSON_IsArray(assets)) {
            cJSON_Delete(root);
            return -2;
        }

        best_name[0] = 0;

        cJSON_ArrayForEach(a, assets) {
            cJSON *j_name = cJSON_GetObjectItemCaseSensitive(a, "name");
            cJSON *j_url  = cJSON_GetObjectItemCaseSensitive(a, "browser_download_url");
            cJSON *j_size = cJSON_GetObjectItemCaseSensitive(a, "size");
            const char *name;
            const char *burl;
            int         score;

            if (!cJSON_IsString(j_name) || !cJSON_IsString(j_url)) {
                continue;
            }
            name = j_name->valuestring;
            burl = j_url->valuestring;

            score = asset_name_score(name);
            if ((score == 0) || (score <= best)) {
                continue;
            }

            best = score;
            strncpy(best_name, name, sizeof(best_name) - 1);
            best_name[sizeof(best_name) - 1] = 0;
            strncpy(ri->url, burl, sizeof(ri->url) - 1);
            if (cJSON_IsNumber(j_size)) {
                ri->size      = (uint32_t)j_size->valuedouble;
                ri->have_size = true;
            }
        }

        if (best == 0) {
            cJSON_Delete(root);
            return -3;
        }

        /* crc sidecar "<chosen name>.crc32", if the release ships one */
        {
            size_t nl = strlen(best_name);

            cJSON_ArrayForEach(a, assets) {
                cJSON *j_bn   = cJSON_GetObjectItemCaseSensitive(a, "name");
                cJSON *j_burl = cJSON_GetObjectItemCaseSensitive(a, "browser_download_url");
                const char *bn;

                if (!cJSON_IsString(j_bn) || !cJSON_IsString(j_burl)) {
                    continue;
                }
                bn = j_bn->valuestring;
                if ((strlen(bn) == nl + 6) && (strncmp(bn, best_name, nl) == 0) &&
                    (strcmp(bn + nl, ".crc32") == 0)) {
                    strncpy(ri->crc_url, j_burl->valuestring,
                            sizeof(ri->crc_url) - 1);
                    break;
                }
            }
        }

        cJSON_Delete(root);
        return 0;
    }

    /* --- minimal mirror manifest shape --- */
    {
        cJSON *j_tag  = cJSON_GetObjectItemCaseSensitive(root, "tag");
        cJSON *j_ver  = cJSON_GetObjectItemCaseSensitive(root, "version");
        cJSON *j_url  = cJSON_GetObjectItemCaseSensitive(root, "url");
        cJSON *j_size = cJSON_GetObjectItemCaseSensitive(root, "size");
        cJSON *j_crc  = cJSON_GetObjectItemCaseSensitive(root, "crc32");
        cJSON *j_pub  = cJSON_GetObjectItemCaseSensitive(root, "published");
        cJSON *j_pub2 = cJSON_GetObjectItemCaseSensitive(root, "published_at");

        if (cJSON_IsString(j_tag)) {
            strncpy(ri->tag, j_tag->valuestring, sizeof(ri->tag) - 1);
        } else if (cJSON_IsString(j_ver)) {
            strncpy(ri->tag, j_ver->valuestring, sizeof(ri->tag) - 1);
        } else {
            cJSON_Delete(root);
            return -4;
        }

        if (!cJSON_IsString(j_url)) {
            cJSON_Delete(root);
            return -5;
        }
        strncpy(ri->url, j_url->valuestring, sizeof(ri->url) - 1);

        if (cJSON_IsNumber(j_size)) {
            ri->size      = (uint32_t)j_size->valuedouble;
            ri->have_size = true;
        }
        if (cJSON_IsNumber(j_crc)) {
            ri->crc      = (uint32_t)j_crc->valuedouble;
            ri->have_crc = true;
        } else if (cJSON_IsString(j_crc)) {
            ri->crc      = (uint32_t)strtoul(j_crc->valuestring, NULL, 0);
            ri->have_crc = true;
        }
        /* publication time for the quarantine: epoch number or ISO string */
        if (cJSON_IsNumber(j_pub)) {
            ri->published      = (int64_t)j_pub->valuedouble;
            ri->have_published = (ri->published > 0);
        } else if (cJSON_IsString(j_pub)) {
            ri->published      = iso8601_to_epoch(j_pub->valuestring);
            ri->have_published = (ri->published > 0);
        } else if (cJSON_IsString(j_pub2)) {
            ri->published      = iso8601_to_epoch(j_pub2->valuestring);
            ri->have_published = (ri->published > 0);
        }
    }

    cJSON_Delete(root);
    return 0;
}

typedef struct {
    char    *buf;
    uint32_t cap;
    uint32_t len;
    bool     too_big;
} accum_t;

static int accum_sink( void *arg, const uint8_t *data, uint32_t len ){
    accum_t *a = (accum_t *)arg;

    if (a->len + len > a->cap) {
        a->too_big = true;
        return -1;
    }
    memcpy(a->buf + a->len, data, len);
    a->len += len;
    return 0;
}

static uint32_t crc32_upd( uint32_t crc, const uint8_t *p, uint32_t n ){
    crc = crc ^ 0xFFFFFFFFu;
    while (n--) {
        uint32_t k;
        crc ^= (uint32_t)(*p++);
        for (k = 0; k < 8u; k++) {
            crc = (crc & 1u) ? (0xEDB88320u ^ (crc >> 1)) : (crc >> 1);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* fetch a small text sidecar "<asset>.crc32": bare hex or "0x..." */
static bool crc_sidecar_fetch( const char *url, uint32_t *out ){
    accum_t acc;
    long    sc;

    memset(&acc, 0, sizeof(acc));
    acc.buf = s_crc_text;
    acc.cap = OTA_UPDATE_CRC_TEXT_MAX;

    sc = http_get(url, accum_sink, &acc, false, NULL, 0);
    if (sc != 200 || acc.len == 0 || acc.too_big) {
        return false;
    }
    s_crc_text[acc.len] = 0;

    /* CI writes the sidecar as bare lowercase hex ("1a2b3c4d"); a "0x"
     * prefix is tolerated. Always hex: an all-digit CRC like "12345678"
     * must not be misread as decimal. */
    {
        const char *p = s_crc_text;

        while ((*p == ' ') || (*p == '\t') || (*p == '\r') || (*p == '\n')) {
            p++;
        }
        if ((p[0] == '0') && ((p[1] == 'x') || (p[1] == 'X'))) {
            p += 2;
        }
        *out = (uint32_t)strtoul(p, NULL, 16);
    }
    return (*out != 0);
}

/* fetch + parse the release manifest */
static int32_t release_fetch( const char *url, release_info_t *ri,
                              char *date_out, size_t date_sz ){
    accum_t acc;
    long    sc;

    memset(&acc, 0, sizeof(acc));
    acc.buf = s_manifest_buf;
    acc.cap = OTA_UPDATE_MANIFEST_MAX - 1;

    sc = http_get(url, accum_sink, &acc, false, date_out, date_sz);
    if (sc < 0) {
        log_warn("upd: manifest fetch failed (%ld)", sc);
        return -1;
    }
    if (sc != 200) {
        log_warn("upd: manifest http status %ld", sc);
        return -2;
    }
    if (acc.too_big) {
        log_warn("upd: manifest too big (cap %u)", (unsigned)acc.cap);
        return -3;
    }
    s_manifest_buf[acc.len] = 0;

    log_debug("upd: manifest len=%u", (unsigned)acc.len);

    return release_parse(s_manifest_buf, ri);
}

/* ------------------------------------------------------------------ */
/* check + install                                                     */
/* ------------------------------------------------------------------ */

/* check for a newer release; updates the shared status on success.
 * "now" for the quarantine is the Date: header of the manifest response
 * (there is no wall clock / SNTP in this firmware, get_time_ms() is
 * uptime-only). */
static int32_t update_check( release_info_t *ri ){
    ota_update_config_t cfg;
    char                date[64];
    int64_t             now_epoch;
    int32_t             rc;

    ota_update_config_load(&cfg);
    if (cfg.url[0] == 0) {
        strncpy(cfg.url, OTA_UPDATE_URL_DEFAULT, sizeof(cfg.url) - 1);
    }

    rc = release_fetch(cfg.url, ri, date, sizeof(date));
    if (rc == -6) {
        /* prerelease/draft: releases only, never offered for install */
        log_info("upd: '%s' is a prerelease/draft - skipped", ri->tag);
        status_set_err("");
        s_avail = false;
        s_hold  = false;
        s_age_h = -1;
        return 0;
    }
    if (rc != 0) {
        status_set_err("manifest fetch/parse failed");
        return rc;
    }

    s_last_check_ms = get_time_ms();
    strncpy(s_last_tag, ri->tag, sizeof(s_last_tag) - 1);
    s_last_tag[sizeof(s_last_tag) - 1] = 0;
    status_set_err("");
    s_avail = ver_is_newer(ri->tag);

    /* quarantine bookkeeping */
    now_epoch = http_date_to_epoch(date);
    if (s_avail && ri->have_published && (now_epoch > 0)) {
        int64_t age = now_epoch - ri->published;

        if (age < 0) {
            age = 0;                        /* clock skew between servers */
        }
        s_age_h = (int32_t)(age / 3600);
        s_hold  = (age < (int64_t)OTA_UPDATE_MIN_AGE_S);
    } else {
        /* age unknown: treat as quarantined, never auto-install blind */
        s_age_h = -1;
        s_hold  = true;
    }

    log_info("upd: release '%s', running '" FW_VERSION "', newer=%d hold=%d age_h=%ld",
             ri->tag, s_avail ? 1 : 0, s_hold ? 1 : 0, (long)s_age_h);

    return 0;
}

typedef struct {
    uint32_t off;
    uint32_t total;
    uint32_t crc;
    int32_t  write_err;
} fw_sink_t;

static int fw_sink( void *arg, const uint8_t *data, uint32_t len ){
    fw_sink_t *f = (fw_sink_t *)arg;
    int32_t    r;

    if (f->write_err != 0) {
        return -1;
    }
    if (f->off + len > f->total) {
        log_error("upd: body exceeds announced size");
        f->write_err = -100;
        return -1;
    }

    r = ota_fw_write_chunk(f->off, data, (uint16_t)len);
    if (r != 0) {
        log_error("upd: flash write failed off=%lu rc=%ld",
                  (unsigned long)f->off, (long)r);
        f->write_err = (int32_t)r;
        return -1;
    }

    f->crc  = crc32_upd(f->crc, data, len);
    f->off += len;
    return 0;
}

/* check + download + flash + reboot. Used by the periodic auto flow
 * (opt-in only, quarantine enforced) and by the explicit web "install
 * now" trigger (manual = human action, quarantine exempt). */
static void update_run_install( bool manual ){
    release_info_t ri;
    fw_sink_t      sink;
    uint32_t       expect_crc = 0;
    uint32_t       body_len   = 0;
    long           sc;
    int32_t        r;

    if (ota_fw_active() || ota_wota_active()) {
        status_set_err("another OTA session is active");
        return;
    }

    if (update_check(&ri) != 0) {
        return;
    }

    if (ri.prerelease) {
        log_info("upd: '%s' is a prerelease/draft - not installable", ri.tag);
        status_set_err("prerelease/draft releases are not installable");
        return;
    }

    if (!s_avail) {
        log_info("upd: already up to date (%s)", ri.tag);
        status_set_err("already up to date");
        return;
    }

    /* mandatory quarantine for the automatic path: a fresh release may
     * hide critical bugs and be withdrawn; manual install is exempt
     * (explicit human action). */
    if (!manual && s_hold) {
        if (s_age_h >= 0) {
            log_warn("upd: auto-install of '%s' skipped: quarantine (%ld h old, min %u h)",
                     ri.tag, (long)s_age_h,
                     (unsigned)(OTA_UPDATE_MIN_AGE_S / 3600u));
            snprintf(s_last_err, sizeof(s_last_err),
                     "auto-install held: %s is %ld h old (min %u h)",
                     ri.tag, (long)s_age_h,
                     (unsigned)(OTA_UPDATE_MIN_AGE_S / 3600u));
        } else {
            log_warn("upd: auto-install of '%s' skipped: publication time unknown",
                     ri.tag);
            snprintf(s_last_err, sizeof(s_last_err),
                     "auto-install held: %s publication time unknown",
                     ri.tag);
        }
        return;
    }
    if (manual && s_hold) {
        log_info("upd: manual install of '%s': quarantine not applied", ri.tag);
    }

    if (strncmp(ri.url, "http://", 7) != 0) {
        status_set_err("image URL is not plain http (no TLS in this firmware)");
        return;
    }

    body_len = ri.have_size ? ri.size : 0;
    if (body_len < OTA_UPDATE_FW_MIN_SIZE) {
        status_set_err("image size unknown or too small");
        return;
    }

    /* crc: manifest field, then "<asset>.crc32" sidecar, else transport-only */
    if (ri.have_crc) {
        expect_crc = ri.crc;
    } else if ((ri.crc_url[0] != 0) && crc_sidecar_fetch(ri.crc_url, &expect_crc)) {
        ri.have_crc = true;
        log_info("upd: crc sidecar 0x%08lx", (unsigned long)expect_crc);
    }
    if (!ri.have_crc) {
        log_warn("upd: no crc32 available - transport integrity only");
    }

    log_warn("upd: flashing '%s' (%lu bytes) from %s",
             ri.tag, (unsigned long)body_len, ri.url);

    memset(&sink, 0, sizeof(sink));
    sink.total = body_len;

    r = ota_fw_begin(body_len, expect_crc);
    if (r != 0) {
        status_set_err("ota_fw_begin failed");
        return;
    }

    sc = http_get(ri.url, fw_sink, &sink, true, NULL, 0);
    if (sc != 200) {
        log_error("upd: image download failed status=%ld", sc);
        (void)ota_fw_end_expect(sink.crc);  /* disarm the OTA session */
        status_set_err("image download failed");
        return;
    }
    if (sink.write_err != 0) {
        (void)ota_fw_end_expect(sink.crc);
        status_set_err("flash write failed");
        return;
    }
    if (sink.off != body_len) {
        log_error("upd: short body %lu/%lu",
                  (unsigned long)sink.off, (unsigned long)body_len);
        (void)ota_fw_end_expect(sink.crc);
        status_set_err("short image");
        return;
    }

    r = ota_fw_end_expect(expect_crc);
    if (r != 0) {
        log_error("upd: image crc mismatch rc=%ld", (long)r);
        status_set_err("image crc mismatch");
        return;
    }

    status_set_err("");
    log_warn("upd: firmware '%s' verified, rebooting now", ri.tag);

    os_sleep_ms(3000);                      /* let the log flush */
    device_reboot();
}

/* ------------------------------------------------------------------ */
/* worker task                                                         */
/* ------------------------------------------------------------------ */

static void ota_update_task( void *arg ){
    uint32_t elapsed_s = 0;

    (void)arg;

    log_debug("upd: task start");

    while (1) {
        ota_update_config_t cfg;

        os_sleep_ms(1000);

        if (s_req_install) {
            s_req_install = false;
            s_busy        = true;
            update_run_install(true);       /* manual: quarantine exempt */
            s_busy    = false;
            elapsed_s = 0;
            continue;
        }

        if (s_req_check) {
            release_info_t ri;

            s_req_check = false;
            s_busy      = true;
            (void)update_check(&ri);
            s_busy    = false;
            elapsed_s = 0;
            continue;
        }

        ota_update_config_load(&cfg);

        if (!cfg.enabled) {
            elapsed_s = 0;
            continue;
        }

        elapsed_s++;
        if (elapsed_s >= cfg.period_h * 3600u) {
            elapsed_s = 0;
            s_busy    = true;
            update_run_install(false);      /* auto: quarantine enforced */
            s_busy = false;
        }
    }
}

void ota_update_init( void ){
    ota_update_config_t cfg;

    if (s_started) {
        return;
    }

    /* touch the kvdb keys once so the defaults are visible via the web API */
    ota_update_config_load(&cfg);

    s_req_check   = false;
    s_req_install = false;
    s_last_check_ms = 0;
    s_avail       = false;
    s_busy        = false;
    s_hold        = false;
    s_age_h       = -1;
    s_last_tag[0] = 0;
    s_last_err[0] = 0;

    OS_TASK_INIT("otaupd", &s_task, ota_update_task, NULL,
                 OS_TASK_PRIORITY_BELOW_NORMAL, 4 * 1024);

    s_started = true;

    log_debug("upd: init en=%d period=%lu h url='%s'",
              cfg.enabled ? 1 : 0,
              (unsigned long)cfg.period_h,
              cfg.url);
}

void ota_update_check_now( void ){
    s_req_check = true;
}

void ota_update_install_now( void ){
    s_req_install = true;
}
