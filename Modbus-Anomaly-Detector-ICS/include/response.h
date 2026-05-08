#ifndef RESPONSE_H
#define RESPONSE_H

#include "modbus_def.h"

void execute_response(detection_result_t *res, const modbus_packet_t *pkt);

#endif
