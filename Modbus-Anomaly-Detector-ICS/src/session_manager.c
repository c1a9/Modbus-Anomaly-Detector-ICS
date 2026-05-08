#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "modbus_def.h"
#include "session_manager.h"

#define HASH_TABLE_SIZE 65536

static session_state_t **hash_table = NULL;
static pthread_rwlock_t table_lock = PTHREAD_RWLOCK_INITIALIZER;

static uint32_t session_hash(uint32_t src_ip, uint32_t dst_ip) {
    return (src_ip ^ dst_ip) % HASH_TABLE_SIZE;
}

int session_manager_init(void) {
    hash_table = calloc(HASH_TABLE_SIZE, sizeof(session_state_t *));
    if (!hash_table) return -1;
    return 0;
}

session_state_t* session_get_or_create(uint32_t src_ip, uint32_t dst_ip) {
    uint32_t idx = session_hash(src_ip, dst_ip);
    
    pthread_rwlock_rdlock(&table_lock);
    session_state_t *s = hash_table[idx];
    while (s) {
        if (s->src_ip == src_ip && s->dst_ip == dst_ip) {
            pthread_rwlock_unlock(&table_lock);
            return s;
        }
        s = s->next;
    }
    pthread_rwlock_unlock(&table_lock);
    
    s = calloc(1, sizeof(session_state_t));
    if (!s) return NULL;
    s->src_ip = src_ip;
    s->dst_ip = dst_ip;
    s->last_timestamp_ms = 0;
    
    pthread_rwlock_wrlock(&table_lock);
    s->next = hash_table[idx];
    hash_table[idx] = s;
    pthread_rwlock_unlock(&table_lock);
    
    return s;
}

void session_update_stats(session_state_t *sess, const modbus_packet_t *pkt) {
    if (!sess || !pkt) return;
    
    switch (pkt->func_code) {
        case MODBUS_FC_READ_COILS:
        case MODBUS_FC_READ_DISCRETE_INPUTS:
        case MODBUS_FC_READ_HOLDING_REGISTERS:
        case MODBUS_FC_READ_INPUT_REGISTERS:
            sess->read_count++;
            break;
        case MODBUS_FC_WRITE_SINGLE_COIL:
        case MODBUS_FC_WRITE_SINGLE_REGISTER:
        case MODBUS_FC_WRITE_MULTIPLE_COILS:
        case MODBUS_FC_WRITE_MULTIPLE_REGISTERS:
            sess->write_count++;
            break;
        default:
            break;
    }
    sess->pkt_count++;
    
    int32_t interval = 0;
    if (sess->last_timestamp_ms > 0) {
        interval = pkt->timestamp_ms - sess->last_timestamp_ms;
        if (interval < 0) interval = 0;
    }
    
    if (interval > 0) {
        sess->intervals[sess->interval_idx] = interval;
        sess->interval_idx = (sess->interval_idx + 1) % INTERVAL_WINDOW_SIZE;
        if (sess->interval_count < INTERVAL_WINDOW_SIZE)
            sess->interval_count++;
        
        if (sess->interval_count >= 2) {
            double sum = 0.0;
            for (int i = 0; i < sess->interval_count; i++)
                sum += sess->intervals[i];
            float mean = sum / sess->interval_count;
            
            double var = 0.0;
            for (int i = 0; i < sess->interval_count; i++) {
                double diff = sess->intervals[i] - mean;
                var += diff * diff;
            }
            float std = sqrt(var / sess->interval_count);
            
            if (sess->interval_count >= 20 && !sess->baseline_ready) {
                sess->baseline_interval_mean = mean;
                sess->baseline_interval_std = std;
                sess->baseline_ready = 1;
                sess->baseline_established_time = time(NULL);
            } else if (sess->baseline_ready) {
                sess->baseline_interval_mean = 0.95f * sess->baseline_interval_mean + 0.05f * mean;
                sess->baseline_interval_std = 0.95f * sess->baseline_interval_std + 0.05f * std;
            }
        }
    }
    
    sess->last_timestamp_ms = pkt->timestamp_ms;
    sess->last_func_code = pkt->func_code;
    sess->last_reg_addr = pkt->reg_addr;
    sess->last_reg_value = pkt->reg_value;
}

void session_extract_features(session_state_t *sess, const modbus_packet_t *pkt, 
                              feature_vector_t *feat) {
    memset(feat, 0, sizeof(feature_vector_t));
    if (!sess) return;
    
    if (sess->last_timestamp_ms > 0 && pkt->timestamp_ms > sess->last_timestamp_ms)
        feat->interval_ms = pkt->timestamp_ms - sess->last_timestamp_ms;
    
    feat->func_code = pkt->func_code;
    feat->value_change = abs((int)pkt->reg_value - (int)sess->last_reg_value);
    
    if (sess->write_count > 0)
        feat->read_write_ratio = (float)sess->read_count / sess->write_count;
    else
        feat->read_write_ratio = (float)sess->read_count;
    
    if (feat->interval_ms > 0)
        feat->pkt_freq_hz = 1000.0f / feat->interval_ms;
}

void session_manager_cleanup(void) {
    if (!hash_table) return;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        session_state_t *s = hash_table[i];
        while (s) {
            session_state_t *next = s->next;
            free(s);
            s = next;
        }
    }
    free(hash_table);
    hash_table = NULL;
}
