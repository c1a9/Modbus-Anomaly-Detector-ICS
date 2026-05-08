#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include "modbus_def.h"

int parse_modbus_tcp_packet(const uint8_t *payload, int payload_len,
                            modbus_packet_t *pkt_out);

#endif
