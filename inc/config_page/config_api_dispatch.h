#ifndef __CONFIG_API_DISPATCH_H__
#define __CONFIG_API_DISPATCH_H__

#include <stdint.h>

#include "cJSON.h"

#define WEB_API_RC_OK                 (0)
#define WEB_API_RC_BAD_REQUEST        (-400)
#define WEB_API_RC_NOT_FOUND          (-404)
#define WEB_API_RC_METHOD_NOT_ALLOWED (-405)
#define WEB_API_RC_INTERNAL           (-500)

int32_t web_api_dispatch( const char *method,
                          const char *uri,
                          const cJSON *in_json,
                          cJSON *out_json );

#endif /* __CONFIG_API_DISPATCH_H__ */
