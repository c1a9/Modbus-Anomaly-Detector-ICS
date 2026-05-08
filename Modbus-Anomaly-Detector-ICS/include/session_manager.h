#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include "modbus_def.h"

int session_manager_init(void);
session_state_t* session_get_or_create(uint32_t src_ip, uint32_t dst_ip);
void session_update_stats(session_state_t *sess, const modbus_packet_t *pkt);
void session_extract_features(session_state_t *sess, const modbus_packet_t *pkt, feature_vector_t *feat);
void session_manager_cleanup(void);

#endif
