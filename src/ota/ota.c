// TODO
// Checksum cheking
#include "sys_config.h"
#include "build_info_gen.h"
//#define LOG_LOCAL_LEVEL     LOG_LEVEL_OTA
#include "lib/logc/log.h"

#include "ota.h"
#include "utils.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/ip4_addr.h"


#include "lib/ota/libota.h"
#include "lib/ota/fw.h"
#include "lib/fal/fal.h"
#include "lib/littlefs/lfs.h"
#include "littelfs_port.h"
#include "basic_include.h"
#include "device.h"
#include "utils.h"

typedef struct {
    bool     active;
    uint32_t total;
    uint32_t expect_crc32;
} ota_fw_ctx_t;

static const struct fal_partition *g_ota_part;
static bool g_ota_erased;
static uint32_t g_ota_total;
static ota_fw_ctx_t s_fw_ota;
static int64_t s_fw_ota_begin_ms;

#define OTA_FW_SESSION_TIMEOUT_MS (10u * 60u * 1000u)

bool ota_fw_active( void ){
    if( !s_fw_ota.active ){
        return false;
    }
    if( (get_time_ms() - s_fw_ota_begin_ms) > (int64_t)OTA_FW_SESSION_TIMEOUT_MS ){
        s_fw_ota.active = false;
        log_warn("ota: fw session timed out");
        return false;
    }
    return true;
}

static uint32_t crc32_fw( uint32_t crc, const uint8_t *p, uint32_t n ){
    uint32_t c = crc ^ 0xFFFFFFFFu;
    while (n--) {
        c ^= (uint32_t)(*p++);
        for (uint32_t k = 0; k < 8u; k++) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
    }
    return c ^ 0xFFFFFFFFu;
}

static const struct fal_partition *ota_fal_part_get( void ){
    if (g_ota_part != NULL) {
        return g_ota_part;
    }
    g_ota_part = fal_partition_find(FAL_PART_NAME_FIRMWARE);
    return g_ota_part;
}

static int32_t ota_fal_erase_if_needed( const struct fal_partition *p, uint32_t total, uint32_t off ){
    if (p == NULL) {
        return -10;
    }

    if (off == 0) {
        g_ota_erased = false;
        g_ota_total  = total;
    }

    if (g_ota_erased) {
        if (g_ota_total != total) {
            return -11;
        }
        return 0;
    }

    if (off != 0) {
        return -12; // no begin (we expect first chunk at off=0)
    }

    if (total == 0) {
        return -13;
    }
    if ((uint32_t)p->len < total) {
        return -14;
    }

    int32_t er = fal_partition_erase(p, 0, p->len);
    if (er < 0) {
        return -15;
    }

    g_ota_erased = true;
    return 0;
}

int32_t _libota_write_fw_ah( uint32_t tot_len, uint32_t off, const uint8_t *data, uint16_t len ){
    const struct fal_partition *p;

    if (data == NULL) {
        return -1;
    }
    if (len == 0) {
        return -2;
    }

    p = ota_fal_part_get();
    if (p == NULL) {
        return -3;
    }

    if (tot_len == 0) {
        return -4;
    }
    if (off > tot_len) {
        return -5;
    }
    if ((uint32_t)off + (uint32_t)len > tot_len) {
        return -6;
    }
    if ((uint32_t)off + (uint32_t)len > (uint32_t)p->len) {
        return -7;
    }

    int32_t er = ota_fal_erase_if_needed(p, tot_len, off);
    if (er != 0) {
        return er;
    }

    int32_t wr = fal_partition_write(p, off, data, len);
    if (wr < 0) {
        return -8;
    }

    if ((uint32_t)wr != (uint32_t)len) {
        return -9;
    }

    return 0;
}

int32_t ota_fw_begin( uint32_t total_size, uint32_t expect_crc32 ){
    const struct fal_partition *p;

    if (total_size == 0) { return -1; }

    p = ota_fal_part_get();
    if (p == NULL) { return -2; }

    if (total_size > (uint32_t)p->len) { return -3; }

    g_ota_erased = false;
    g_ota_total  = 0;

    s_fw_ota.active       = true;
    s_fw_ota.total        = total_size;
    s_fw_ota.expect_crc32 = expect_crc32;
    s_fw_ota_begin_ms     = get_time_ms();

    return 0;
}

int32_t ota_fw_write_chunk( uint32_t off, const uint8_t *data, uint16_t len ){
    if (!s_fw_ota.active) {
        return -1;
    }
    if (data == NULL || len == 0) {
        return -2;
    }

    int32_t r = _libota_write_fw_ah(s_fw_ota.total, off, data, len);
    if (r == 0) {
        s_fw_ota_begin_ms = get_time_ms();
    }
    return r;
}

int32_t ota_fw_end( void ){
    const struct fal_partition *p;
    static uint8_t buf[1024];
    uint32_t left;
    uint32_t offset;
    uint32_t crc;

    if (!s_fw_ota.active) { 
        return -1;
    }

    s_fw_ota.active = false;

    p = ota_fal_part_get();
    if (p == NULL) { 
        return -2;
    }

    left   = s_fw_ota.total;
    offset = 0;
    crc    = 0;

    while (left) {
        uint32_t n = (left > (uint32_t)sizeof(buf)) ? (uint32_t)sizeof(buf) : left;

        if (fal_partition_read(p, offset, buf, n) < 0) {
            return -3;
        }

        crc     = crc32_fw(crc, buf, n);
        offset += n;
        left   -= n;
    }

    if (crc != s_fw_ota.expect_crc32) {
        return -4;
    }

    return 0;
}

extern int32_t __real_lwip_netif_hook_inputdata(struct netif* nif, uint8_t* data, uint32_t len);

static int ota_cmd_firmware_data(struct netif* nif, uint8_t* data, uint32_t len){
    if (nif == NULL) {
        log_warn("FW_DATA: nif NULL");
        return -1;
    }
    if (data == NULL) {
        log_warn("FW_DATA: data NULL");
        return -1;
    }
    if (len < sizeof(struct eth_ota_fw_data)) {
        log_warn("FW_DATA: short len=%lu", (unsigned long)len);
        return -1;
    }

    struct eth_ota_fw_data *fw = (struct eth_ota_fw_data *)data;

    if (fw->hdr.proto != __be16(ETH_P_OTA)) {
        log_warn("FW_DATA: bad proto");
        return -1;
    }

    uint16 fw_len   = __be16(fw->len);
    uint32 fw_off   = __be32(fw->off);
    uint32 fw_total = __be32(fw->tot_len);

    log_trace("FW_DATA: off=%lu len=%u total=%lu",
            (unsigned long)fw_off, (unsigned int)fw_len, (unsigned long)fw_total);

    if (fw_len == 0 || fw_len > 1400) {
        log_trace("FW_DATA: bad fw_len=%u", (unsigned int)fw_len);
        return -1;
    }

    uint32 need = (uint32)sizeof(struct eth_ota_fw_data) + (uint32)fw_len;
    if (len < need) {
        log_trace("FW_DATA: truncated need=%lu got=%lu",
                (unsigned long)need, (unsigned long)len);
        return -1;
    }
    if (fw_off > fw_total) {
        log_trace("FW_DATA: off>total");
        return -1;
    }
    if ((fw_off + fw_len) > fw_total) {
        log_trace("FW_DATA: off+len>total");
        return -1;
    }

    int32 r = 0;
    /* Arm the same OTA guard the web path uses (s_fw_ota.active): the TX-wedge
     * watchdog's last-resort reboot and the ota_fw_active() checks must stay
     * suppressed during an eth flash session too -- a reboot mid-session (the
     * first chunk already erased the whole firmware partition) bricks the
     * node. Cleared on the final chunk or any write error. */
    if (fw_off == 0) {
        s_fw_ota.active = true;
        s_fw_ota.total  = fw_total;
    }
    r = _libota_write_fw_ah(fw_total, fw_off, fw->data, fw_len);
    log_trace("FW_DATA: write ret=%ld", (long)r);
    hgprintf("libota_write_fw_ah ret=%ld\r\n", (long)r);
    if (r != 0) {
        s_fw_ota.active = false;
        return -1;
    }
    if (fw_off + fw_len >= fw_total) {
        s_fw_ota.active = false;
    }

    struct eth_ota_fw_data answer;
    memset(&answer, 0, sizeof(answer));
    get_mac(answer.hdr.src);
    memcpy(answer.hdr.dest, fw->hdr.src, 6);
    answer.hdr.proto  = __be16(ETH_P_OTA);
    answer.hdr.stype  = ETH_P_OTA_FW_DATA_RESP;
    answer.hdr.status = 0;

    answer.version  = fw->version;
    answer.off      = fw->off;
    answer.tot_len  = fw->tot_len;
    answer.len      = fw->len;
    answer.checksum = fw->checksum;
    answer.chipid   = fw->chipid;

    uint16 frame_len = sizeof(struct eth_ota_fw_data);

    struct pbuf *p = pbuf_alloc(PBUF_RAW, frame_len, PBUF_RAM);
    if (!p) {
        log_warn("FW_DATA: pbuf_alloc failed");
        return -1;
    }

    memcpy(p->payload, &answer, frame_len);

    err_t e = ERR_IF;
    if (nif->linkoutput) {
        e = nif->linkoutput(nif, p);
    } else {
        log_warn("FW_DATA: linkoutput NULL");
    }

    pbuf_free(p);

    log_trace("FW_DATA: send=%d", (int)e);

    return (e == ERR_OK) ? 0 : -1;
}


static int ota_cmd_scan(struct netif* nif, uint8_t* data, uint32_t len){
    if(nif == NULL) {
        log_warn("SCAN: nif NULL");
        return -1;
    }
    if(data == NULL){
        log_warn("SCAN: data NULL");
        return -1;
    }
    if(len < sizeof(struct eth_ota_hdr)){
        log_warn("SCAN: short len=%lu", (unsigned long)len);
        return -1;
    }

    struct eth_ota_hdr* hdr = (struct eth_ota_hdr*)data;

    struct eth_ota_hdr answer_hdr;
    get_mac(answer_hdr.src);
    memcpy(answer_hdr.dest, hdr->src, 6);
    answer_hdr.proto = __be16(ETH_P_OTA);
    answer_hdr.stype = ETH_P_OTA_SCAN_REPORT;
    answer_hdr.status = 0;

    struct eth_ota_scan_report answer_report;
    memset(&answer_report, 0, sizeof(struct eth_ota_scan_report));
    answer_report.version = 0xff00ff00;

    uint16_t frame_len = (uint16_t)(sizeof(answer_hdr) + sizeof(answer_report));

    struct pbuf *p = pbuf_alloc(PBUF_RAW, frame_len, PBUF_RAM);
    if (!p) {
        log_warn("SCAN: pbuf_alloc failed");
        return -1;
    }

    uint8_t *w = (uint8_t *)p->payload;
    memcpy(w, &answer_hdr, sizeof(answer_hdr));
    memcpy(w + sizeof(answer_hdr), &answer_report, sizeof(answer_report));

    err_t e = ERR_IF;
    if (nif->linkoutput) {
        e = nif->linkoutput(nif, p);
    } else {
        log_warn("SCAN: linkoutput NULL");
    }

    pbuf_free(p);

    log_trace("SCAN: send=%d", (int)e);

    return (e == ERR_OK) ? 0 : -1;
}

static int ota_cmd_reboot(struct netif* nif, uint8_t* data, uint32_t len){
    device_reboot();
    return 0;
}

static int ota_cmd_get_ip( struct netif *nif, uint8_t *data, uint32_t len ){
    if (nif == NULL) {
        log_warn("GET_IP: nif NULL");
        return -1;
    }
    if (data == NULL) {
        log_warn("GET_IP: data NULL");
        return -1;
    }
    if (len < sizeof(struct eth_ota_hdr)) {
        log_warn("GET_IP: short len=%lu", (unsigned long)len);
        return -1;
    }

    struct eth_ota_hdr *hdr = (struct eth_ota_hdr *)data;

    uint32_t ip   = ip4_addr_get_u32(netif_ip4_addr(nif));
    uint32_t gw   = ip4_addr_get_u32(netif_ip4_gw(nif));
    uint32_t mask = ip4_addr_get_u32(netif_ip4_netmask(nif));

    struct eth_ota_get_ip_resp resp;
    memset(&resp, 0, sizeof(resp));

    get_mac(resp.hdr.src);
    memcpy(resp.hdr.dest, hdr->src, 6);
    resp.hdr.proto  = __be16(ETH_P_OTA);
    resp.hdr.stype  = ETH_P_OTA_FW_CUSTOM_GET_IP_RESP;
    resp.hdr.status = 0;

    /* ip4_addr_get_u32() already gives network byte order */
    resp.ip   = ip;
    resp.gw   = gw;
    resp.mask = mask;

    resp.version[0] = 0;
    strncpy(resp.version, FW_BUILD_VERSION, sizeof(resp.version) - 1);
    resp.version[sizeof(resp.version) - 1] = 0;

    struct pbuf *p = pbuf_alloc(PBUF_RAW, (uint16_t)sizeof(resp), PBUF_RAM);
    if (!p) {
        log_warn("GET_IP: pbuf_alloc failed");
        return -1;
    }

    memcpy(p->payload, &resp, sizeof(resp));

    err_t e = ERR_IF;
    if (nif->linkoutput) {
        e = nif->linkoutput(nif, p);
    } else {
        log_warn("GET_IP: linkoutput NULL");
    }

    pbuf_free(p);

    log_trace("GET_IP: send=%d ip=%08lx gw=%08lx mask=%08lx",
            (int)e,
            (unsigned long)__be32(ip),
            (unsigned long)__be32(gw),
            (unsigned long)__be32(mask));

    return (e == ERR_OK) ? 0 : -1;
}

static int ota_cmd_format_littlefs( struct netif *nif, uint8_t *data, uint32_t len ){
    int rc;
    struct eth_ota_hdr *hdr;
    struct eth_ota_hdr resp;
    struct pbuf *p;
    err_t e = ERR_IF;

    if (nif == NULL) {
        log_warn("FORMAT_LFS: nif NULL");
        return -1;
    }
    if (data == NULL) {
        log_warn("FORMAT_LFS: data NULL");
        return -1;
    }
    if (len < sizeof(struct eth_ota_hdr)) {
        log_warn("FORMAT_LFS: short len=%lu", (unsigned long)len);
        return -1;
    }

    hdr = (struct eth_ota_hdr *)data;

    rc = ota_format_littefs();

    memset(&resp, 0, sizeof(resp));
    get_mac(resp.src);
    memcpy(resp.dest, hdr->src, 6);
    resp.proto  = __be16(ETH_P_OTA);
    resp.stype  = ETH_P_OTA_FW_FORMAT_LITTLEFS_RESP;
    resp.status = (rc == 0) ? 0 : 1;

    p = pbuf_alloc(PBUF_RAW, (uint16_t)sizeof(resp), PBUF_RAM);
    if (p == NULL) {
        log_warn("FORMAT_LFS: pbuf_alloc failed");
        return -1;
    }

    memcpy(p->payload, &resp, sizeof(resp));

    if (nif->linkoutput) {
        e = nif->linkoutput(nif, p);
    } else {
        log_warn("FORMAT_LFS: linkoutput NULL");
    }

    pbuf_free(p);

    log_trace("FORMAT_LFS: format_rc=%d send=%d", rc, (int)e);

    if (rc != 0) {
        return -1;
    }

    return (e == ERR_OK) ? 0 : -1;
}

int ota_process_package(struct netif* nif, uint8_t* data, uint32_t len){
    if(len < sizeof(struct eth_ota_hdr)){
        return -1;
    }
    struct eth_ota_hdr* hdr = (struct eth_ota_hdr*)data;
    if(hdr->proto != __be16(ETH_P_OTA)){
        return -1;
    }

    log_trace("PROCESS: stype=%u len=%lu", (unsigned int)hdr->stype, (unsigned long)len);

    switch (hdr->stype){
        case ETH_P_OTA_SCAN:                log_trace("PROCESS: SCAN");       ota_cmd_scan(nif, data, len);           break;
        case ETH_P_OTA_FW_DATA:             log_trace("PROCESS: FW_DATA");    ota_cmd_firmware_data(nif, data, len);  break;
        case ETH_P_OTA_REBOOT:              log_trace("PROCESS: REBOOT");     ota_cmd_reboot(nif, data, len);         break;
        case ETH_P_OTA_FW_CUSTOM_GET_IP:    log_trace("PROCESS: GET_IP");     ota_cmd_get_ip(nif, data, len);         break;
        case ETH_P_OTA_FW_FORMAT_LITTLEFS:  log_trace("PROCESS: FORMAT_LFS"); ota_cmd_format_littlefs(nif, data, len);break;
        default:                            log_trace("PROCESS: unknown");                                            break;
    }
    return -1;
}

int32_t __wrap_lwip_netif_hook_inputdata(struct netif* nif, uint8_t* data, uint32_t len){
    if(ota_process_package(nif, data, len) == 0){
        return 0;
    }
    return __real_lwip_netif_hook_inputdata(nif, data, len);
}

int ota_reset_to_default( void ){
    const struct fal_partition *p;

    p = fal_partition_find(FAL_PART_NAME_KVDB);
    if (p == NULL) {
        return -1;
    }

    if (fal_partition_erase(p, 0, p->len) < 0) {
        return -2;
    }

    return 0;
}

int32_t ota_format_littefs( void ){
    return littlefs_reformat();
}
