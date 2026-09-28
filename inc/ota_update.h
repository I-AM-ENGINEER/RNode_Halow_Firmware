#ifndef __OTA_UPDATE_H__
#define __OTA_UPDATE_H__

/*
 * Device-side firmware update checker against GitHub Releases.
 *
 * The firmware ships without any TLS client (mbedtls/openssl/libcurl and the
 * lwIP altcp_tls app are all excluded from this build), so GitHub's
 * https-only endpoints cannot be talked to directly.  The checker therefore
 * speaks plain HTTP/1.1 over a lwIP netconn and accepts two document shapes
 * at the configured URL:
 *
 *   1. GitHub Releases JSON (api.github.com .../releases/latest shape):
 *      { "tag_name": "v2.4.0", "assets": [ { "name": "...", "size": N,
 *        "browser_download_url": "http://..." }, ... ] }
 *   2. Minimal mirror manifest:
 *      { "tag": "v2.4.0", "url": "http://...", "size": N, "crc32": "0x..." }
 *
 * Because GitHub serves downloads over https, out of the box the check URL
 * must point at a plain-HTTP mirror (a tiny LAN reverse proxy that
 * terminates TLS, or any static file server).  Both the check and the image
 * URL must be http://; https URLs are refused with a clear log line.
 *
 * The image is streamed into the existing firmware-OTA partition writer
 * (ota_fw_begin / ota_fw_write_chunk / ota_fw_end_expect) and applied with
 * the usual reboot.  Automatic check+install only runs when the user opts in
 * via the web UI (cfg.upd.en, default off); a manual "install now" web
 * request always requires the explicit POST.
 */

#include "basic_include.h"
#include "cJSON.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define OTA_UPDATE_URL_MAX          (160)
#define OTA_UPDATE_TAG_MAX          (32)
#define OTA_UPDATE_ERR_MAX          (64)

/* Default release-check URL (GitHub API for this very repo). Needs a
 * plain-HTTP mirror/proxy in front of it, see file header. */
#define OTA_UPDATE_URL_DEFAULT \
    "http://api.github.com/repos/I-AM-ENGINEER/RNode_Halow_Firmware/releases/latest"

typedef struct {
    bool     enabled;                          /* cfg.upd.en   */
    uint32_t period_h;                         /* cfg.upd.period */
    char     url[OTA_UPDATE_URL_MAX];          /* cfg.upd.url  */

    /* runtime status (not persisted) */
    char     last_tag[OTA_UPDATE_TAG_MAX];     /* newest release tag seen */
    char     err[OTA_UPDATE_ERR_MAX];          /* last error string */
    int64_t  last_check_ms;                    /* 0 = never checked */
    bool     avail;                            /* newer release seen */
    bool     busy;                             /* check/install running */
} ota_update_config_t;

/* Start the background update task. Call once from main init. */
void ota_update_init( void );

void ota_update_config_load( ota_update_config_t *cfg );
void ota_update_config_save( ota_update_config_t *cfg );

/* Add the merged config + runtime status to a cJSON object
 * (en/period_h/url/cur/tag/err/avail/busy/at). */
void ota_update_status_json( cJSON *out );

/* Non-blocking triggers for the web API; the worker task picks them up. */
void ota_update_check_now( void );             /* check + record availability */
void ota_update_install_now( void );           /* check + download + flash + reboot */

#endif // __OTA_UPDATE_H__
