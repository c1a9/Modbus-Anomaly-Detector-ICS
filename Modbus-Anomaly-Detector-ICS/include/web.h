#ifndef WEB_H
#define WEB_H

#include "modbus_def.h"

void init_web(void);
void web_update_status(const modbus_packet_t *pkt, feature_vector_t *feat, detection_result_t *res);
void start_web_server_thread(int port);
void stop_web_server(void);

#endif
