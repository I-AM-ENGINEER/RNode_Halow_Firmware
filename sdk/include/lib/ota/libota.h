#ifndef _HGSDK_OTA_H_
#define _HGSDK_OTA_H_
#ifdef __cplusplus
extern "C" {
#endif

#define ETH_P_OTA (0x4847)

enum ETH_P_OTA_STYPE{
    ETH_P_OTA_REBOOT=1,
    ETH_P_OTA_SCAN,
    ETH_P_OTA_SCAN_REPORT,
    ETH_P_OTA_FW_DATA,
    ETH_P_OTA_FW_DATA_RESP,
    ETH_P_OTA_FW_GET_PARAM,
    ETH_P_OTA_FW_GET_PARAM_RESP,
    ETH_P_OTA_FW_SET_PARAM,
    ETH_P_OTA_FW_SET_PARAM_RESP,
    ETH_P_OTA_FW_CUSTOM_GET_IP = 0xF0,
    ETH_P_OTA_FW_CUSTOM_GET_IP_RESP = 0xF1,
};

enum HGIC_OTA_RESP_ERR_CODE{
    HGIC_OTA_RESP_ERR_OK=0,
    HGIC_OTA_RESP_ERR_CHECKSUM,
    HGIC_OTA_RESP_ERR_WRITE,
};

struct eth_ota_hdr{
    uint8  dest[6];
    uint8  src[6];
    uint16 proto;
    uint8  stype, status;
};

struct eth_ota_scan_report{
    struct eth_ota_hdr hdr;
    uint32 version;
    uint16 chipid;
    uint8  mode, rev;
    uint32 svn_version;
    uint32 app_version;
};

struct eth_ota_fw_data{
    struct eth_ota_hdr hdr;
    uint32 version;
    uint32 off, tot_len;
    uint16 len, checksum;
    uint16 chipid;
    uint8  data[0];
};

enum ETH_P_REBOOT_FLAGS{
    ETH_P_REBOOT_FLAGS_LOADDEF = BIT(0),
};

struct eth_ota_reboot{
    struct eth_ota_hdr hdr;
    uint32 flags;
};

struct hgic_ota_hdr{
    uint32 version;
    uint32 off;
    uint32 tot_len;
    uint16 len;
    uint16 checksum;
    uint16 chipid;
    uint16  err_code;
    uint8  data[0];
};

struct eth_ota_get_ip_resp{
    struct eth_ota_hdr hdr;
    uint32 ip;
    uint32 gw;
    uint32 mask;
    char version[32];
};

struct sk_buff *libota_proc(uint8 mode, struct sk_buff *skb);
uint16 libota_check_sum(uint8 *addr, int32 count);

#ifdef __cplusplus
}
#endif
#endif
