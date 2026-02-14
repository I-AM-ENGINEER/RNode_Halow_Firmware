#ifndef __CONFIG_API_CALLS_H__
#define __CONFIG_API_CALLS_H__

#include <stdint.h>
#include "cJSON.h"

void web_api_notify_change( void );
uint32_t web_api_change_version( void );

int32_t web_api_heartbeat_get( const cJSON *in, cJSON *out );
int32_t web_api_ok_get( const cJSON *in, cJSON *out );

int32_t web_api_halow_cfg_get( const cJSON *in, cJSON *out );
int32_t web_api_halow_cfg_post( const cJSON *in, cJSON *out );

int32_t web_api_net_cfg_get( const cJSON *in, cJSON *out );
int32_t web_api_net_cfg_post( const cJSON *in, cJSON *out );

int32_t web_api_tcp_server_cfg_get( const cJSON *in, cJSON *out );
int32_t web_api_tcp_server_cfg_post( const cJSON *in, cJSON *out );

int32_t web_api_lbt_cfg_get( const cJSON *in, cJSON *out );
int32_t web_api_lbt_cfg_post( const cJSON *in, cJSON *out );

int32_t web_api_dev_stat_get( const cJSON *in, cJSON *out );
int32_t web_api_radio_stat_get( const cJSON *in, cJSON *out );

#endif // __CONFIG_API_CALLS_H__
