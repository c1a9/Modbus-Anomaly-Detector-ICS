#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include "modbus_def.h"
#include "capture.h"
#include "logger.h"
#include "protocol.h"   // 添加这一行

// 包队列实现
int packet_queue_init(packet_queue_t *q, int max_size) {
    memset(q, 0, sizeof(packet_queue_t));
    q->max_size = max_size;
    if (pthread_mutex_init(&q->lock, NULL) != 0) return -1;
    if (pthread_cond_init(&q->cond, NULL) != 0) {
        pthread_mutex_destroy(&q->lock);
        return -1;
    }
    return 0;
}

void packet_queue_destroy(packet_queue_t *q) {
    pthread_mutex_lock(&q->lock);
    packet_node_t *node = q->head;
    while (node) {
        packet_node_t *next = node->next;
        free(node);
        node = next;
    }
    pthread_mutex_unlock(&q->lock);
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->cond);
}

int packet_queue_push(packet_queue_t *q, const modbus_packet_t *pkt) {
    pthread_mutex_lock(&q->lock);
    if (q->count >= q->max_size) {
        packet_node_t *old = q->head;
        if (old) {
            q->head = old->next;
            if (q->tail == old) q->tail = NULL;
            free(old);
            q->count--;
        }
    }
    packet_node_t *node = malloc(sizeof(packet_node_t));
    if (!node) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    node->pkt = *pkt;
    node->next = NULL;
    if (q->tail) {
        q->tail->next = node;
        q->tail = node;
    } else {
        q->head = q->tail = node;
    }
    q->count++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

int packet_queue_pop(packet_queue_t *q, modbus_packet_t *pkt, int timeout_ms) {
    pthread_mutex_lock(&q->lock);
    while (q->count == 0) {
        if (timeout_ms == 0) {
            pthread_mutex_unlock(&q->lock);
            return -1;
        }
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
        if (pthread_cond_timedwait(&q->cond, &q->lock, &ts) != 0) {
            pthread_mutex_unlock(&q->lock);
            return -1;
        }
    }
    packet_node_t *node = q->head;
    *pkt = node->pkt;
    q->head = node->next;
    if (q->tail == node) q->tail = NULL;
    free(node);
    q->count--;
    pthread_mutex_unlock(&q->lock);
    return 0;
}

// 删除原有的 parse_modbus_tcp 函数，直接使用 protocol.c 中的实现

// pcap回调
static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    packet_queue_t *q = (packet_queue_t *)user;
    struct ip *iph = (struct ip *)(bytes + 14);
    int ip_hlen = iph->ip_hl * 4;
    if (iph->ip_p != IPPROTO_TCP) return;
    struct tcphdr *tcph = (struct tcphdr *)((u_char *)iph + ip_hlen);
    int tcp_hlen = tcph->th_off * 4;
    if (ntohs(tcph->th_sport) != MODBUS_PORT && ntohs(tcph->th_dport) != MODBUS_PORT)
        return;
    const u_char *payload = (u_char *)tcph + tcp_hlen;
    int payload_len = h->caplen - (14 + ip_hlen + tcp_hlen);
    if (payload_len <= 7) return;

    // 调试输出
    printf("[DEBUG] Packet captured: %s:%d -> %s:%d\n",
           inet_ntoa(iph->ip_src), ntohs(tcph->th_sport),
           inet_ntoa(iph->ip_dst), ntohs(tcph->th_dport));

    modbus_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_ip = iph->ip_src.s_addr;
    pkt.dst_ip = iph->ip_dst.s_addr;
    pkt.src_port = ntohs(tcph->th_sport);
    pkt.dst_port = ntohs(tcph->th_dport);
    pkt.timestamp_ms = (int64_t)h->ts.tv_sec * 1000 + h->ts.tv_usec / 1000;

    // 调用完整的协议解析函数
    parse_modbus_tcp_packet(payload, payload_len, &pkt);

    printf("[DEBUG] func=0x%02x, reg_addr=%d, reg_value=%d\n",
           pkt.func_code, pkt.reg_addr, pkt.reg_value);

    packet_queue_push(q, &pkt);
}

void* capture_thread(void *arg) {
    capture_args_t *args = (capture_args_t *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(args->interface, args->snaplen, args->promisc, 1000, errbuf);
    if (!handle) {
        log_write(LOG_ERR, "pcap_open_live failed: %s", errbuf);
        return NULL;
    }
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp port 502", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        log_write(LOG_ERR, "pcap_compile failed: %s", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);
    log_write(LOG_INFO, "Capture started on %s", args->interface);
    pcap_loop(handle, -1, pcap_callback, (u_char *)args->queue);
    pcap_close(handle);
    return NULL;
}
