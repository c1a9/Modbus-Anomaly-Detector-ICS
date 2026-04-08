#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include "../include/modbus_def.h"

static pid_t http_pid = 0;

static void generate_html(void) {
    FILE *fp = fopen("web/index.html", "w");
    if (!fp) return;
    fprintf(fp,
        "<!DOCTYPE html>\n"
        "<html><head><meta charset=\"UTF-8\"><title>Modbus ICS Anomaly Detection</title>\n"
        "<style>body{font-family:monospace;background:#1e1e2e;color:#cdd6f4;padding:20px;}"
        "table{border-collapse:collapse;width:100%%;}"
        "th,td{border:1px solid #45475a;padding:8px;text-align:left;}"
        "th{background:#313244;}.anomaly{background:#f38ba8;color:#1e1e2e;}</style>\n"
        "<script>setInterval(function(){fetch('status.json').then(r=>r.json()).then(data=>{\n"
        "document.getElementById('src_ip').innerText=data.src_ip;\n"
        "document.getElementById('func').innerText=data.func_code;\n"
        "document.getElementById('anomaly').innerText=data.is_anomaly?'Anomaly':'Normal';\n"
        "document.getElementById('score').innerText=data.score;\n"
        "document.getElementById('reason').innerText=data.reason;\n"
        "document.getElementById('interval').innerText=data.interval_ms;\n"
        "document.getElementById('rw_ratio').innerText=data.read_write_ratio;\n"
        "document.getElementById('value_change').innerText=data.value_change;\n"
        "let row=document.getElementById('last_row');row.className=data.is_anomaly?'anomaly':'';\n"
        "}).catch(e=>console.error);},500);</script>\n"
        "</head><body><h2>Modbus ICS Anomaly Detection Dashboard</h2>\n"
        "<table><tr><th>Source IP</th><th>Func Code</th><th>Status</th><th>Score</th><th>Reason</th></tr>\n"
        "<tr id='last_row'><td id='src_ip'>-</td><td id='func'>-</td><td id='anomaly'>-</td>"
        "<td id='score'>-</td><td id='reason'>-</td></tr>\n"
        "<tr><th>Interval(ms)</th><th>R/W Ratio</th><th>Value Change</th><td colspan='2'></td></tr>\n"
        "<tr><td id='interval'>-</td><td id='rw_ratio'>-</td><td id='value_change'>-</td><td colspan='2'></td></tr>\n"
        "</table><p>Auto-refresh 0.5s | iptables -L INPUT to see blocking rules</p></body></html>\n");
    fclose(fp);
}

static void generate_initial_status(void) {
    FILE *fp = fopen("web/status.json", "w");
    if (!fp) return;
    fprintf(fp,
        "{\n"
        "  \"src_ip\":\"0.0.0.0\",\n"
        "  \"dst_ip\":\"0.0.0.0\",\n"
        "  \"func_code\":0,\n"
        "  \"reg_addr\":0,\n"
        "  \"reg_value\":0,\n"
        "  \"timestamp\":0,\n"
        "  \"interval_ms\":0,\n"
        "  \"read_write_ratio\":0.0,\n"
        "  \"value_change\":0,\n"
        "  \"anomaly_score\":0.0,\n"
        "  \"is_anomaly\":0,\n"
        "  \"score\":0.0,\n"
        "  \"reason\":\"waiting for data\"\n"
        "}\n");
    fclose(fp);
}

void init_web(void) {
    system("mkdir -p web");
    generate_html();
    generate_initial_status();
}

void web_update_status(ModbusPacket *pkt, Feature *feat, AIResult *res) {
    FILE *fp = fopen("web/status.json", "w");
    if (!fp) return;
    fprintf(fp,
        "{\n"
        "  \"src_ip\":\"%s\",\n"
        "  \"dst_ip\":\"%s\",\n"
        "  \"func_code\":%d,\n"
        "  \"reg_addr\":%d,\n"
        "  \"reg_value\":%d,\n"
        "  \"timestamp\":%d,\n"
        "  \"interval_ms\":%d,\n"
        "  \"read_write_ratio\":%.2f,\n"
        "  \"value_change\":%d,\n"
        "  \"anomaly_score\":%.2f,\n"
        "  \"is_anomaly\":%d,\n"
        "  \"score\":%.2f,\n"
        "  \"reason\":\"%s\"\n"
        "}\n",
        pkt->src_ip, pkt->dst_ip, pkt->func_code,
        pkt->reg_addr, pkt->reg_value, pkt->timestamp,
        feat->interval_ms, feat->read_write_ratio, feat->value_change,
        feat->anomaly_score, res->is_anomaly, res->score, res->reason);
    fclose(fp);
}

static void handle_client(int client_fd) {
    char buffer[4096];
    int n = read(client_fd, buffer, sizeof(buffer) - 1);
    if (n <= 0) { close(client_fd); return; }
    buffer[n] = '\0';
    char method[16], path[256], version[16];
    sscanf(buffer, "%s %s %s", method, path, version);
    if (strcmp(path, "/") == 0) strcpy(path, "/index.html");
    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "web%s", path);
    if (strstr(path, "..") != NULL) {
        const char *resp = "HTTP/1.1 403 Forbidden\r\n\r\n";
        write(client_fd, resp, strlen(resp));
        close(client_fd);
        return;
    }
    FILE *fp = fopen(fullpath, "rb");
    if (!fp) {
        const char *resp = "HTTP/1.1 404 Not Found\r\n\r\n";
        write(client_fd, resp, strlen(resp));
        close(client_fd);
        return;
    }
    const char *ext = strrchr(path, '.');
    const char *content_type = "text/plain";
    if (ext) {
        if (strcmp(ext, ".html") == 0) content_type = "text/html";
        else if (strcmp(ext, ".json") == 0) content_type = "application/json";
        else if (strcmp(ext, ".css") == 0) content_type = "text/css";
        else if (strcmp(ext, ".js") == 0) content_type = "application/javascript";
    }
    dprintf(client_fd, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nConnection: close\r\n\r\n", content_type);
    char filebuf[8192];
    size_t bytes;
    while ((bytes = fread(filebuf, 1, sizeof(filebuf), fp)) > 0)
        write(client_fd, filebuf, bytes);
    fclose(fp);
    close(client_fd);
}

static void run_http_server(void) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8000);
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); close(server_fd); exit(1); }
    if (listen(server_fd, 5) < 0) { perror("listen"); close(server_fd); exit(1); }
    printf("[HTTP] Server started on port 8000\n");
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;
        handle_client(client_fd);
    }
    close(server_fd);
}

void start_http_server(void) {
    pid_t pid = fork();
    if (pid == 0) { run_http_server(); exit(0); }
    else if (pid > 0) {
        http_pid = pid;
        printf("[INFO] HTTP server (pure C) running on port 8000\n");
        printf("[INFO] Open browser at http://127.0.0.1:8000\n");
        sleep(1);
    } else { perror("fork"); }
}

void stop_http_server(void) {
    if (http_pid > 0) {
        kill(http_pid, SIGTERM);
        waitpid(http_pid, NULL, 0);
        http_pid = 0;
        printf("[INFO] HTTP server stopped.\n");
    }
}
