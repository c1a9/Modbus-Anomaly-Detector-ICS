#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include "modbus_def.h"
#include "logger.h"
#include "capture.h"          // 提供 ip_to_str

static uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, int tcph_len) {
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t tcp_length;
    } ph;
    ph.src_addr = iph->saddr;
    ph.dst_addr = iph->daddr;
    ph.zero = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_length = htons(tcph_len);
    int len = sizeof(ph) + tcph_len;
    uint8_t *buf = malloc(len);
    if (!buf) return 0;
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcph, tcph_len);
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)buf;
    for (int i = 0; i < len / 2; i++) sum += ptr[i];
    if (len % 2) sum += ((uint8_t *)buf)[len - 1];
    free(buf);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

int send_tcp_reset(uint32_t src_ip, uint16_t src_port,
                   uint32_t dst_ip, uint16_t dst_port,
                   uint32_t seq, uint32_t ack) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return -1;
    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        close(sock);
        return -1;
    }
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(packet));
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = src_ip;
    iph->daddr = dst_ip;
    iph->check = 0;
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack);
    tcph->doff = 5;
    tcph->rst = 1;
    tcph->ack = 1;
    tcph->window = htons(8192);
    tcph->check = tcp_checksum(iph, tcph, sizeof(struct tcphdr));
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dst_ip;
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(sock);
        return -1;
    }
    close(sock);
    return 0;
}

void execute_response(detection_result_t *res, const modbus_packet_t *pkt) {
    if (!res->is_anomaly) return;
    log_write(LOG_ALERT, "Modbus Anomaly: %s -> %s score=%.2f reason=%s",
              ip_to_str(pkt->src_ip), ip_to_str(pkt->dst_ip),
              res->confidence, res->reason);
    if (res->severity >= 3) {
        send_tcp_reset(pkt->dst_ip, pkt->dst_port, pkt->src_ip, pkt->src_port, rand(), rand());
        send_tcp_reset(pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port, rand(), rand());
        log_write(LOG_NOTICE, "Sent TCP RST to %s <-> %s",
                  ip_to_str(pkt->src_ip), ip_to_str(pkt->dst_ip));
    }
}
