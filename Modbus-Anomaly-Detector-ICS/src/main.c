#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <getopt.h>
#include "modbus_def.h"
#include "capture.h"
#include "session_manager.h"
#include "detector.h"
#include "response.h"
#include "logger.h"
#include "config.h"
#include "web.h"

static volatile int running = 1;

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) running = 0;
}

static void* analyzer_thread(void *arg) {
    packet_queue_t *queue = (packet_queue_t *)arg;
    modbus_packet_t pkt;
    while (running) {
        if (packet_queue_pop(queue, &pkt, 100) == 0) {
			if (pkt.dst_port != MODBUS_PORT) {
				 continue;
			}
			session_state_t *sess = session_get_or_create(pkt.src_ip, pkt.dst_ip);
            feature_vector_t feat;
            session_extract_features(sess, &pkt, &feat);
			session_update_stats(sess, &pkt);
            detection_result_t res;
            detect_anomaly(sess, &pkt, &feat, &res);
            // 应用配置中的阈值覆盖
            if (res.confidence >= g_config.anomaly_threshold_high) {
                res.is_anomaly = 1;
                res.severity = 3;
            } else if (res.confidence >= g_config.anomaly_threshold_medium) {
                res.is_anomaly = 1;
                res.severity = 2;
            }
            execute_response(&res, &pkt);
            web_update_status(&pkt, &feat, &res);
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int opt;
    char *config_file = "/etc/modbus_ids/modbus_ids.conf";
    char *interface = NULL;
    int daemon_flag = 0;
    while ((opt = getopt(argc, argv, "c:i:dh")) != -1) {
        switch (opt) {
            case 'c': config_file = optarg; break;
            case 'i': interface = optarg; break;
            case 'd': daemon_flag = 1; break;
            case 'h':
                printf("Usage: %s [-c config] [-i interface] [-d]\n", argv[0]);
                return 0;
        }
    }
    if (load_config(config_file) != 0) {
        fprintf(stderr, "Config file not found, using defaults\n");
    }
    if (interface) strncpy(g_config.interface, interface, sizeof(g_config.interface)-1);
    if (daemon_flag) g_config.daemonize = 1;

    if (g_config.daemonize && daemon(0, 0) < 0) {
        perror("daemon");
        return 1;
    }
    log_init("modbus-ids", LOG_DAEMON);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (session_manager_init() != 0) {
        log_write(LOG_ERR, "Session manager init failed");
        return 1;
    }
    packet_queue_t pkt_queue;
    packet_queue_init(&pkt_queue, 10000);

    capture_args_t cap_args = { .interface = g_config.interface, .queue = &pkt_queue, .promisc = 1, .snaplen = 65536 };
    pthread_t capture_tid;
    pthread_create(&capture_tid, NULL, capture_thread, &cap_args);

    #define ANALYZER_THREADS 2
    pthread_t analyzers[ANALYZER_THREADS];
    for (int i = 0; i < ANALYZER_THREADS; i++)
        pthread_create(&analyzers[i], NULL, analyzer_thread, &pkt_queue);

    start_web_server_thread(g_config.web_port);
    log_write(LOG_INFO, "Modbus IDS started on %s", g_config.interface);

    while (running) sleep(1);

    log_write(LOG_INFO, "Shutting down...");
    running = 0;
    pthread_cancel(capture_tid);
    pthread_join(capture_tid, NULL);
    for (int i = 0; i < ANALYZER_THREADS; i++)
        pthread_join(analyzers[i], NULL);
    packet_queue_destroy(&pkt_queue);
    session_manager_cleanup();
    stop_web_server();
    log_close();
    return 0;
}
