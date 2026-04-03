#ifndef __RNS_LINK_PARSER_H__
#define __RNS_LINK_PARSER_H__

#include "rns/defines.h"

int rns_link_parser_parse( const uint8_t *packet, size_t packet_len, rns_link_packet_info_t *out );

#endif // __RNS_LINK_PARSER_H__
