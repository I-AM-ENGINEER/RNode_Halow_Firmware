#include "config_page/config_api_calls.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "cJSON.h"
#include "lwip/netif.h"
#include "lwip/ip4_addr.h"
#include "lib/littlefs/lfs.h"
#include "ota.h"

#define OTA_TMP_BIN_MAX    2048

static uint32_t crc32_update_u8( uint32_t crc, const uint8_t *p, uint32_t n ){
    uint32_t c = crc ^ 0xFFFFFFFFu;

    while (n--) {
        c ^= (uint32_t)(*p++);
        for (uint32_t k = 0; k < 8; k++) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
    }

    return c ^ 0xFFFFFFFFu;
}

static int8_t b64_inv( char c ){
    if (c >= 'A' && c <= 'Z') { return (int8_t)(c - 'A'); }
    if (c >= 'a' && c <= 'z') { return (int8_t)(c - 'a' + 26); }
    if (c >= '0' && c <= '9') { return (int8_t)(c - '0' + 52); }
    if (c == '+') { return 62; }
    if (c == '/') { return 63; }
    if (c == '=') { return -2; }
    return -1;
}

static int32_t b64_decode( const char *in, uint8_t *out, uint32_t out_max, uint32_t *out_len ){
    uint32_t len = 0;

    if (in == NULL || out == NULL || out_len == NULL) { return -1; }

    while (*in) {
        int32_t v0, v1, v2, v3;

        if (in[0] == '\0' || in[1] == '\0' || in[2] == '\0' || in[3] == '\0') { return -1; }

        v0 = (int32_t)b64_inv(in[0]);
        v1 = (int32_t)b64_inv(in[1]);
        v2 = (int32_t)b64_inv(in[2]);
        v3 = (int32_t)b64_inv(in[3]);
        in += 4;

        if (v0 < 0 || v1 < 0) { return -1; }
        if (v2 == -1 || v3 == -1) { return -1; }
        if (v2 == -2 && v3 != -2) { return -1; }

        if (len + 1 > out_max) { return -1; }
        out[len++] = (uint8_t)(((uint32_t)v0 << 2) | ((uint32_t)v1 >> 4));

        if (v2 != -2) {
            if (len + 1 > out_max) { return -1; }
            out[len++] = (uint8_t)(((uint32_t)v1 << 4) | ((uint32_t)v2 >> 2));

            if (v3 != -2) {
                if (len + 1 > out_max) { return -1; }
                out[len++] = (uint8_t)(((uint32_t)v2 << 6) | (uint32_t)v3);
            }
        }
    }

    *out_len = len;
    return 0;
}

int32_t web_api_ota_begin_post( const cJSON *in, cJSON *out ){
    const cJSON *j_size;
    const cJSON *j_crc;
    uint32_t size;
    uint32_t crc;

    if (in == NULL) { 
        return -1; 
    }

    j_size = cJSON_GetObjectItemCaseSensitive((cJSON *)in, "size");
    j_crc  = cJSON_GetObjectItemCaseSensitive((cJSON *)in, "crc32");
    if (!cJSON_IsNumber(j_size) || !cJSON_IsNumber(j_crc)) { 
        return -1; 
    }

    size = (uint32_t)j_size->valuedouble;
    crc  = (uint32_t)j_crc->valuedouble;

    if (ota_lfs_begin(size, crc) != 0) {
        return -1; 
    }
    return 0;
}

int32_t web_api_ota_chunk_post( const cJSON *in, cJSON *out ){
    const cJSON *j_off;
    const cJSON *j_b64;
    uint32_t off;
    const char *b64;

    uint8_t *tmp;
    uint32_t n;
    size_t b64_len;
    size_t tmp_cap;

    (void)out;

    if (in == NULL) {
        return -1;
    }

    j_off = cJSON_GetObjectItemCaseSensitive((cJSON *)in, "off");
    j_b64 = cJSON_GetObjectItemCaseSensitive((cJSON *)in, "b64");
    if (!cJSON_IsNumber(j_off) || !cJSON_IsString(j_b64)) {
        return -2;
    }

    off = (uint32_t)j_off->valuedouble;
    b64 = j_b64->valuestring;

    b64_len = strlen(b64);
    tmp_cap = (b64_len / 4u) * 3u + 3u;  // worst-case decoded size
    if (tmp_cap == 0u || tmp_cap > (size_t)OTA_TMP_BIN_MAX) {
        return -3;
    }

    tmp = (uint8_t *)os_malloc((uint32_t)tmp_cap);
    if (tmp == NULL) {
        return -4;
    }

    if (b64_decode(b64, tmp, (uint32_t)tmp_cap, &n) != 0) {
        os_free(tmp);
        return -5;
    }

    if (ota_lfs_write(off, tmp, n) != 0) {
        os_free(tmp);
        return -6;
    }

    os_free(tmp);
    return 0;
}

int32_t web_api_ota_end_post( const cJSON *in, cJSON *out ){
    if (ota_lfs_end() != 0) { 
        return -1; 
    }
    return 0;
}

int32_t web_api_ota_write_post( const cJSON *in, cJSON *out ){
    if(ota_lfs_upgrade_from_tar() != 0){
        return -1;
    }

    if (ota_write_firmware_from_file() != 0) {
        return -2; 
    }
    return 0;
}
