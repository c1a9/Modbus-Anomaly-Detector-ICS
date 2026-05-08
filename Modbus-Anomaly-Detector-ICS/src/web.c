#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "modbus_def.h"
#include "web.h"
#include "logger.h"

static pthread_t web_thread;
static volatile int web_running = 0;
static int web_port = 8080;

// 共享的最新状态
static modbus_packet_t last_pkt;
static feature_vector_t last_feat;
static detection_result_t last_res;
static pthread_mutex_t status_mutex = PTHREAD_MUTEX_INITIALIZER;

void init_web(void) {
    (void)system("mkdir -p web");
    // 生成index.html (同原版)
    FILE *fp = fopen("web/index.html", "w");
    if (fp) {
        fprintf(fp, "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">"
            "<title>Modbus IDS</title>"
            "<style>body{font-family:monospace;background:#1e1e2e;color:#cdd6f4;padding:20px;}"
            "table{border-collapse:collapse;width:100%%;}"
            "th,td{border:1px solid #45475a;padding:8px;}th{background:#313244;}"
            ".anomaly{background:#f38ba8;color:#1e1e2e;}</style>"
            "<script>setInterval(function(){fetch('status.json').then(r=>r.json()).then(d=>{"
            "document.getElementById('src_ip').innerText=d.src_ip;"
            "document.getElementById('func').innerText=d.func_code;"
            "document.getElementById('status').innerText=d.is_anomaly?'ANOMALY':'Normal';"
            "document.getElementById('score').innerText=d.confidence;"
            "document.getElementById('reason').innerText=d.reason;"
            "document.getElementById('interval').innerText=d.interval_ms;"
            "document.getElementById('rw').innerText=d.read_write_ratio;"
            "document.getElementById('change').innerText=d.value_change;"
            "let row=document.getElementById('row');row.className=d.is_anomaly?'anomaly':'';"
            "}).catch(e=>{});},500);</script></head><body>"
            "<h2>Modbus IDS Dashboard</h2><table>"
            "<tr><th>Source IP</th><th>Func</th><th>Status</th><th>Score</th><th>Reason</th></tr>"
            "<tr id='row'><td id='src_ip'>-</td><td id='func'>-</td><td id='status'>-</td>"
            "<td id='score'>-</td><td id='reason'>-</td></tr>"
            "<tr><th>Interval(ms)</th><th>R/W Ratio</th><th>Value Change</th></tr>"
            "<tr><td id='interval'>-</td><td id='rw'>-</td><td id='change'>-</td></tr>"
            "</table></body></html>");
        fclose(fp);
    }
    // 初始status.json
    fp = fopen("web/status.json", "w");
    if (fp) {
        fprintf(fp, "{\"src_ip\":\"-\",\"func_code\":0,\"is_anomaly\":0,\"confidence\":0.0,"
                "\"reason\":\"waiting\",\"interval_ms\":0,\"read_write_ratio\":0,\"value_change\":0}");
        fclose(fp);
    }
}

void web_update_status(const modbus_packet_t *pkt, feature_vector_t *feat, detection_result_t *res) {
    pthread_mutex_lock(&status_mutex);
    if (pkt) last_pkt = *pkt;
    if (feat) last_feat = *feat;
    if (res) last_res = *res;
    pthread_mutex_unlock(&status_mutex);
    // 写JSON文件
    FILE *fp = fopen("web/status.json", "w");
    if (fp) {
        char src_ip[16];
        struct in_addr addr;
        addr.s_addr = last_pkt.src_ip;
        strcpy(src_ip, inet_ntoa(addr));
        fprintf(fp, "{\"src_ip\":\"%s\",\"func_code\":%d,\"is_anomaly\":%d,"
                "\"confidence\":%.2f,\"reason\":\"%s\",\"interval_ms\":%d,"
                "\"read_write_ratio\":%.2f,\"value_change\":%d}",
                src_ip, last_pkt.func_code, last_res.is_anomaly,
                last_res.confidence, last_res.reason, last_feat.interval_ms,
                last_feat.read_write_ratio, last_feat.value_change);
        fclose(fp);
    }
}

static void* http_server_thread(void *arg) {
    int port = *(int*)arg;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log_write(LOG_ERR, "web socket failed");
        return NULL;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_write(LOG_ERR, "web bind failed");
        close(server_fd);
        return NULL;
    }
    listen(server_fd, 5);
    log_write(LOG_INFO, "Web server started on port %d", port);
    web_running = 1;
    while (web_running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        struct timeval tv = {1, 0};
        if (select(server_fd+1, &fds, NULL, NULL, &tv) > 0) {
            int client = accept(server_fd, NULL, NULL);
            if (client < 0) continue;
            char buf[4096];
            int n = read(client, buf, sizeof(buf)-1);
            if (n > 0) {
                buf[n] = '\0';
                char path[256] = "/";
                sscanf(buf, "%*s %s", path);
                if (strcmp(path, "/") == 0) strcpy(path, "/index.html");
                if (strstr(path, "..")) {
                    const char *resp = "HTTP/1.1 403\r\n\r\n";
                    write(client, resp, strlen(resp));
                } else {
                    char full[512];
                    snprintf(full, sizeof(full), "web%s", path);
                    FILE *fp = fopen(full, "rb");
                    if (!fp) {
                        const char *resp = "HTTP/1.1 404\r\n\r\n";
                        write(client, resp, strlen(resp));
                    } else {
                        const char *content = "text/plain";
                        if (strstr(path, ".html")) content = "text/html";
                        else if (strstr(path, ".json")) content = "application/json";
                        dprintf(client, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n", content);
                        char fbuf[8192];
                        size_t r;
                        while ((r = fread(fbuf, 1, sizeof(fbuf), fp)) > 0)
                            write(client, fbuf, r);
                        fclose(fp);
                    }
                }
            }
            close(client);
        }
    }
    close(server_fd);
    return NULL;
}

void start_web_server_thread(int port) {
    web_port = port;
    init_web();
    pthread_create(&web_thread, NULL, http_server_thread, &web_port);
}

void stop_web_server(void) {
    web_running = 0;
    pthread_join(web_thread, NULL);
}
