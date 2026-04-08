#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include <unistd.h>
#include "../include/modbus_def.h"

static pcap_t *handle = NULL;
static char errbuf[PCAP_ERRBUF_SIZE];

static int parse_modbus_pdu(const u_char *payload, int len, ModbusPacket *pkt) {
    if (len < 2) return -1;
    pkt->func_code = payload[0];
    if (pkt->func_code == MODBUS_FUNC_READ) {
        if (len >= 5) {
            pkt->reg_addr = (payload[1] << 8) | payload[2];
            pkt->reg_value = 0;
        }
    } else if (pkt->func_code == MODBUS_FUNC_WRITE) {
        if (len >= 5) {
            pkt->reg_addr = (payload[1] << 8) | payload[2];
            pkt->reg_value = (payload[3] << 8) | payload[4];
        }
    } else {
        pkt->reg_addr = 0;
        pkt->reg_value = 0;
    }
    return 0;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    ModbusPacket *pkt = (ModbusPacket *)user;
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    int ip_header_len, tcp_header_len;
    const u_char *tcp_payload;
    int payload_len;

    ip_hdr = (struct ip *)(packet + 14);
    ip_header_len = ip_hdr->ip_hl * 4;
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_header_len);
    tcp_header_len = tcp_hdr->th_off * 4;

    if (ntohs(tcp_hdr->th_sport) != MODBUS_PORT && ntohs(tcp_hdr->th_dport) != MODBUS_PORT)
        return;

    inet_ntop(AF_INET, &(ip_hdr->ip_src), (char *)pkt->src_ip, IP_STR_LEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), (char *)pkt->dst_ip, IP_STR_LEN);

    tcp_payload = (u_char *)tcp_hdr + tcp_header_len;
    payload_len = header->caplen - (14 + ip_header_len + tcp_header_len);
    if (payload_len <= 7) return;

    parse_modbus_pdu(tcp_payload + 7, payload_len - 7, pkt);

    struct timeval tv = header->ts;
    pkt->timestamp = (i32)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

// 初始化 pcap 句柄
static int init_pcap(void) {
    const char *dev = "any";
    handle = pcap_open_live(dev, 65536, 1, 0, errbuf);  // 超时设为 0，非阻塞
    if (handle == NULL) {
        fprintf(stderr, "Cannot open device: %s\n", errbuf);
        return -1;
    }
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp port 502", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Failed to compile filter\n");
        pcap_close(handle);
        handle = NULL;
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to set filter\n");
        pcap_freecode(&fp);
        pcap_close(handle);
        handle = NULL;
        return -1;
    }
    pcap_freecode(&fp);
    // 设置为非阻塞模式
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "Failed to set nonblock: %s\n", errbuf);
        // 非阻塞失败也可以继续，但会阻塞
    }
    printf("[INFO] Listening on %s for Modbus/TCP port 502\n", dev);
    return 0;
}

void capture_packet(ModbusPacket *pkt) {
    static int initialized = 0;
    if (!initialized) {
        if (init_pcap() != 0) {
            memset(pkt, 0, sizeof(ModbusPacket));
            return;
        }
        initialized = 1;
    }

    // 使用 select 等待数据包，超时 100ms
    int fd = pcap_get_selectable_fd(handle);
    if (fd < 0) {
        // 降级：直接调用 pcap_dispatch 一次
        int ret = pcap_dispatch(handle, 1, packet_handler, (u_char *)pkt);
        if (ret <= 0) memset(pkt, 0, sizeof(ModbusPacket));
        return;
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  // 100ms
    int sel = select(fd + 1, &fds, NULL, NULL, &tv);
    if (sel > 0 && FD_ISSET(fd, &fds)) {
        // 有数据可读
        int ret = pcap_dispatch(handle, 1, packet_handler, (u_char *)pkt);
        if (ret <= 0) memset(pkt, 0, sizeof(ModbusPacket));
    } else {
        // 超时或无数据
        memset(pkt, 0, sizeof(ModbusPacket));
    }
}
