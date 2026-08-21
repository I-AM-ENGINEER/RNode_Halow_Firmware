#ifndef TEST_STUB_TCP_SERVER_H
#define TEST_STUB_TCP_SERVER_H

#include <stdint.h>

int32_t tcp_server_send(const uint8_t *data, uint32_t len);
/* Takes ownership of an os_malloc'd buffer; freed on all exit paths. */
int32_t tcp_server_send_owned(uint8_t *os_buf, uint32_t len);

#endif
