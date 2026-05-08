#ifndef DETECTOR_H
#define DETECTOR_H

#include "modbus_def.h"

void detect_anomaly(session_state_t *sess, const modbus_packet_t *pkt, 
                    feature_vector_t *feat, detection_result_t *result);

#endif
