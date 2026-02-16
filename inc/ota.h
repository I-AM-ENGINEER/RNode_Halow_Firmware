#ifndef __OTA_H__
#define __OTA_H__

#include "basic_include.h"
#include <stdint.h>
#include <stdbool.h>

#define OTA_TAR_FILE_PATH                   "/ota.tar"
#define OTA_FIWMWARE_FILE_PATH              "/fw.bin"

uint32_t ota_lfs_begin( uint32_t total_size, uint32_t expect_crc32 );
uint32_t ota_lfs_write( uint32_t off, const void *data, uint32_t len );
uint32_t ota_lfs_end( void );
int32_t ota_lfs_upgrade_from_tar( void );

int32_t ota_reset_to_default(void);
int32_t ota_write_firmware_from_file( void );

#endif // __OTA_H__
