#ifndef __OTA_H__
#define __OTA_H__

#include "basic_include.h"
#include <stdint.h>
#include <stdbool.h>

int32_t ota_reset_to_default(void);

/* Web OTA: write individual files directly to LittleFS */
int32_t ota_format_littefs( void );
int32_t ota_lfs_file_begin( const char *path, uint32_t total_size, uint32_t expect_crc32 );
int32_t ota_wota_file_write( const void *data, uint32_t len );
int32_t ota_wota_file_end( void );
bool   ota_wota_active( void );   /* true while a web-OTA file session is open */
void   ota_wota_session_abort( void );

/* Firmware OTA: direct flash write */
int32_t ota_fw_begin( uint32_t total_size, uint32_t expect_crc32 );
int32_t ota_fw_write_chunk( uint32_t off, const uint8_t *data, uint16_t len );
int32_t ota_fw_end( void );
bool    ota_fw_active( void );      /* true while a firmware-OTA session is open */

#endif // __OTA_H__
