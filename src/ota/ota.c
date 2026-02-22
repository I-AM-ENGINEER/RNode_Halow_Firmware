// TODO
// Checksum cheking

#include "ota.h"
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
#include "basic_include.h"
#include "sys_config.h"
#include "device.h"

extern lfs_t g_lfs;

//#define OTA_DEBUG

#ifdef OTA_DEBUG
#define ota_dbg(fmt, ...) os_printf("[OTA] " fmt "\r\n", ##__VA_ARGS__)
#else
#define ota_dbg(fmt, ...) do { } while (0)
#endif

static const struct fal_partition *g_ota_part;
static bool g_ota_erased;
static uint32_t g_ota_total;

static const struct fal_partition *ota_fal_part_get( void ){
    if (g_ota_part != NULL) {
        return g_ota_part;
    }
    g_ota_part = fal_partition_find(OTA_FAL_PART_NAME);
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

extern uint8 g_mac[6];
extern int32_t __real_lwip_netif_hook_inputdata(struct netif* nif, uint8_t* data, uint32_t len);

static int ota_cmd_firmware_data(struct netif* nif, uint8_t* data, uint32_t len){
    if (nif == NULL) {
        ota_dbg("FW_DATA: nif NULL");
        return -1;
    }
    if (data == NULL) {
        ota_dbg("FW_DATA: data NULL");
        return -1;
    }
    if (len < sizeof(struct eth_ota_fw_data)) {
        ota_dbg("FW_DATA: short len=%lu", (unsigned long)len);
        return -1;
    }

    struct eth_ota_fw_data *fw = (struct eth_ota_fw_data *)data;

    if (fw->hdr.proto != __be16(ETH_P_OTA)) {
        ota_dbg("FW_DATA: bad proto");
        return -1;
    }

    uint16 fw_len   = __be16(fw->len);
    uint32 fw_off   = __be32(fw->off);
    uint32 fw_total = __be32(fw->tot_len);

    ota_dbg("FW_DATA: off=%lu len=%u total=%lu",
            (unsigned long)fw_off, (unsigned int)fw_len, (unsigned long)fw_total);

    if (fw_len == 0 || fw_len > 1400) {
        ota_dbg("FW_DATA: bad fw_len=%u", (unsigned int)fw_len);
        return -1;
    }

    uint32 need = (uint32)sizeof(struct eth_ota_fw_data) + (uint32)fw_len;
    if (len < need) {
        ota_dbg("FW_DATA: truncated need=%lu got=%lu",
                (unsigned long)need, (unsigned long)len);
        return -1;
    }
    if (fw_off > fw_total) {
        ota_dbg("FW_DATA: off>total");
        return -1;
    }
    if ((fw_off + fw_len) > fw_total) {
        ota_dbg("FW_DATA: off+len>total");
        return -1;
    }

    int32 r = 0;
    r = _libota_write_fw_ah(fw_total, fw_off, fw->data, fw_len);
    ota_dbg("FW_DATA: write ret=%ld", (long)r);
    hgprintf("libota_write_fw_ah ret=%ld\r\n", (long)r);
    if (r != 0) {
        return -1;
    }

    struct eth_ota_fw_data answer;
    memset(&answer, 0, sizeof(answer));
    memcpy(answer.hdr.src,  g_mac, 6);
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
        ota_dbg("FW_DATA: pbuf_alloc failed");
        return -1;
    }

    memcpy(p->payload, &answer, frame_len);

    err_t e = ERR_IF;
    if (nif->linkoutput) {
        e = nif->linkoutput(nif, p);
    } else {
        ota_dbg("FW_DATA: linkoutput NULL");
    }

    pbuf_free(p);

    ota_dbg("FW_DATA: send=%d", (int)e);

    return (e == ERR_OK) ? 0 : -1;
}


static int ota_cmd_scan(struct netif* nif, uint8_t* data, uint32_t len){
    if(nif == NULL) {
        ota_dbg("SCAN: nif NULL");
        return -1;
    }
    if(data == NULL){
        ota_dbg("SCAN: data NULL");
        return -1;
    }
    if(len < sizeof(struct eth_ota_hdr)){
        ota_dbg("SCAN: short len=%lu", (unsigned long)len);
        return -1;
    }

    struct eth_ota_hdr* hdr = (struct eth_ota_hdr*)data;

    struct eth_ota_hdr answer_hdr;
    memcpy(answer_hdr.src, g_mac, 6);
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
        ota_dbg("SCAN: pbuf_alloc failed");
        return -1;
    }

    uint8_t *w = (uint8_t *)p->payload;
    memcpy(w, &answer_hdr, sizeof(answer_hdr));
    memcpy(w + sizeof(answer_hdr), &answer_report, sizeof(answer_report));

    err_t e = ERR_IF;
    if (nif->linkoutput) {
        e = nif->linkoutput(nif, p);
    } else {
        ota_dbg("SCAN: linkoutput NULL");
    }

    pbuf_free(p);

    ota_dbg("SCAN: send=%d", (int)e);

    return (e == ERR_OK) ? 0 : -1;
}

static int ota_cmd_reboot(struct netif* nif, uint8_t* data, uint32_t len){
    device_reboot();
    return 0;
}

static int ota_cmd_get_ip( struct netif *nif, uint8_t *data, uint32_t len ){
    if (nif == NULL) {
        ota_dbg("GET_IP: nif NULL");
        return -1;
    }
    if (data == NULL) {
        ota_dbg("GET_IP: data NULL");
        return -1;
    }
    if (len < sizeof(struct eth_ota_hdr)) {
        ota_dbg("GET_IP: short len=%lu", (unsigned long)len);
        return -1;
    }

    struct eth_ota_hdr *hdr = (struct eth_ota_hdr *)data;

    uint32_t ip   = ip4_addr_get_u32(netif_ip4_addr(nif));
    uint32_t gw   = ip4_addr_get_u32(netif_ip4_gw(nif));
    uint32_t mask = ip4_addr_get_u32(netif_ip4_netmask(nif));

    struct eth_ota_get_ip_resp resp;
    memset(&resp, 0, sizeof(resp));

    memcpy(resp.hdr.src,  g_mac,    6);
    memcpy(resp.hdr.dest, hdr->src, 6);
    resp.hdr.proto  = __be16(ETH_P_OTA);
    resp.hdr.stype  = ETH_P_OTA_FW_CUSTOM_GET_IP_RESP;
    resp.hdr.status = 0;

    /* ip4_addr_get_u32() already gives network byte order */
    resp.ip   = ip;
    resp.gw   = gw;
    resp.mask = mask;

    resp.version[0] = 0;
    strncpy(resp.version, FW_FULL_VERSION, sizeof(resp.version) - 1);
    resp.version[sizeof(resp.version) - 1] = 0;

    struct pbuf *p = pbuf_alloc(PBUF_RAW, (uint16_t)sizeof(resp), PBUF_RAM);
    if (!p) {
        ota_dbg("GET_IP: pbuf_alloc failed");
        return -1;
    }

    memcpy(p->payload, &resp, sizeof(resp));

    err_t e = ERR_IF;
    if (nif->linkoutput) {
        e = nif->linkoutput(nif, p);
    } else {
        ota_dbg("GET_IP: linkoutput NULL");
    }

    pbuf_free(p);

    ota_dbg("GET_IP: send=%d ip=%08lx gw=%08lx mask=%08lx",
            (int)e,
            (unsigned long)__be32(ip),
            (unsigned long)__be32(gw),
            (unsigned long)__be32(mask));

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

    ota_dbg("PROCESS: stype=%u len=%lu", (unsigned int)hdr->stype, (unsigned long)len);

    switch (hdr->stype){
        case ETH_P_OTA_SCAN:                ota_dbg("PROCESS: SCAN");       ota_cmd_scan(nif, data, len);           break;
        case ETH_P_OTA_FW_DATA:             ota_dbg("PROCESS: FW_DATA");    ota_cmd_firmware_data(nif, data, len);  break;
        case ETH_P_OTA_REBOOT:              ota_dbg("PROCESS: REBOOT");     ota_cmd_reboot(nif, data, len);         break;
        case ETH_P_OTA_FW_CUSTOM_GET_IP:    ota_dbg("PROCESS: GET_IP");     ota_cmd_get_ip(nif, data, len);         break;
        default:                            ota_dbg("PROCESS: unknown");                                            break;
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

    p = fal_partition_find("fdb_kvdb1");
    if (p == NULL) {
        return -1;
    }

    if (fal_partition_erase(p, 0, p->len) < 0) {
        return -2;
    }

    p = fal_partition_find("littlefs");
    if (p == NULL) {
        return -3;
    }

    if (fal_partition_erase(p, 0, p->len) < 0) {
        return -4;
    }

    return 0;
}
