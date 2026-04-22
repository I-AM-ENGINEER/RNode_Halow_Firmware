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

/* Firmware OTA: direct flash write */
int32_t ota_fw_begin( uint32_t total_size, uint32_t expect_crc32 );
int32_t ota_fw_write_chunk( uint32_t off, const uint8_t *data, uint16_t len );
int32_t ota_fw_end( void );

#endif // __OTA_H__
