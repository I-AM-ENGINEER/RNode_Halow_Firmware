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

#include "lib/ota/libota.h"
#include "lib/ota/fw.h"
#include "lib/fal/fal.h"
#include "basic_include.h"

extern uint8 g_mac[6];
extern int32_t __real_lwip_netif_hook_inputdata(struct netif* nif, uint8_t* data, uint32_t len);

static int ota_cmd_firmware_data(struct netif* nif, uint8_t* data, uint32_t len){
    if (nif == NULL) {
        return -1;
    }
    if (data == NULL) {
        return -1;
    }
    if (len < sizeof(struct eth_ota_fw_data)) {
        return -1;
    }

    struct eth_ota_fw_data *fw = (struct eth_ota_fw_data *)data;

    if (fw->hdr.proto != __be16(ETH_P_OTA)) {
        return -1;
    }

    uint16 fw_len   = __be16(fw->len);
    uint32 fw_off   = __be32(fw->off);
    uint32 fw_total = __be32(fw->tot_len);

    if (fw_len == 0 || fw_len > 1400) {
        return -1;
    }

    uint32 need = (uint32)sizeof(struct eth_ota_fw_data) + (uint32)fw_len;
    if (len < need) {
        return -1;
    }
    if (fw_off > fw_total) {
        return -1;
    }
    if ((fw_off + fw_len) > fw_total) {
        return -1;
    }

    //if (ota_checksum16(fw->data, fw_len) != fw->checksum) {
    //    return -1;
    //}

    int32 r = libota_write_fw_ah(fw_total, fw_off, fw->data, fw_len);
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
        return -1;
    }

    memcpy(p->payload, &answer, frame_len);

    
    err_t e = ERR_IF;
    if (nif->linkoutput) {
        e = nif->linkoutput(nif, p);
    }

    pbuf_free(p);
    return (e == ERR_OK) ? 0 : -1;
}


static int ota_cmd_scan(struct netif* nif, uint8_t* data, uint32_t len){
    if(nif == NULL) {
        return -1;
    }
    if(data == NULL){
        return -1;
    }
    if(len < sizeof(struct eth_ota_hdr)){
        return -1;
    }
    struct eth_ota_hdr* hdr = (struct eth_ota_hdr*)data;
    struct eth_ota_hdr answer_hdr;
    memcpy(answer_hdr.src, g_mac, 6); // MAC should be from another place
    memcpy(answer_hdr.dest, hdr->src, 6);
    answer_hdr.proto = __be16(ETH_P_OTA);
    answer_hdr.stype = ETH_P_OTA_SCAN_REPORT;
    answer_hdr.status = 0;
    struct eth_ota_scan_report answer_report;
    memset(&answer_report, 0, sizeof(struct eth_ota_scan_report));
    answer_report.version = 0xff00ff00; // Placeholder
    
    uint16_t frame_len = (uint16_t)(sizeof(answer_hdr) + sizeof(answer_report));

    struct pbuf *p = pbuf_alloc(PBUF_RAW, frame_len, PBUF_RAM);
    if (!p) {
        return -1;
    }

    uint8_t *w = (uint8_t *)p->payload;
    memcpy(w, &answer_hdr, sizeof(answer_hdr));
    memcpy(w + sizeof(answer_hdr), &answer_report, sizeof(answer_report));

    err_t e = ERR_IF;
    if (nif->linkoutput) {
        e = nif->linkoutput(nif, p);
    }

    pbuf_free(p);
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
    
    switch (hdr->stype){
        case ETH_P_OTA_SCAN:            ota_cmd_scan(nif, data, len);               break;
        case ETH_P_OTA_FW_DATA:         ota_cmd_firmware_data(nif, data, len);      break;
        default: break;
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

    return 0;
}
