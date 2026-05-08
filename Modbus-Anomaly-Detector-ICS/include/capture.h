#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include <pthread.h>
#include "modbus_def.h"

// 包队列节点
typedef struct packet_node {
    modbus_packet_t pkt;
    struct packet_node *next;
} packet_node_t;

// 包队列（线程安全）
typedef struct {
    packet_node_t *head;
    packet_node_t *tail;
    int count;
    int max_size;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} packet_queue_t;

// 队列操作
int packet_queue_init(packet_queue_t *q, int max_size);
void packet_queue_destroy(packet_queue_t *q);
int packet_queue_push(packet_queue_t *q, const modbus_packet_t *pkt);
int packet_queue_pop(packet_queue_t *q, modbus_packet_t *pkt, int timeout_ms);

// 抓包线程参数
typedef struct {
    const char *interface;
    packet_queue_t *queue;
    int promisc;
    int snaplen;
} capture_args_t;

// 抓包线程主函数
void* capture_thread(void *arg);

// IP地址转换（32位整数到字符串）
static inline const char* ip_to_str(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

#endif
