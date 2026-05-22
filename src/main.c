#include "filter.h"
#include "log_queue.h"
#include "packet_parser.h"
#include "tun_iface.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PACKET_BUF 65536

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-c rules.conf] [-l logfile] [-i tun_name]\n"
            "  TUN-демон: чтение IP-пакетов, фильтрация, отложенный лог.\n"
            "  VPN-детект в ядре: загрузите tun_vpn_detect.ko (make load-kmod)\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *config = "config/rules.conf";
    const char *logpath = "/tmp/tund.log";
    const char *tun_name = TUN_NAME_DEFAULT;

    int opt;
    while ((opt = getopt(argc, argv, "c:l:i:h")) != -1) {
        switch (opt) {
        case 'c': config = optarg; break;
        case 'l': logpath = optarg; break;
        case 'i': tun_name = optarg; break;
        default: usage(argv[0]); return 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Нужны права root (sudo)\n");
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    filter_engine_t *fe = filter_create();
    if (!fe) {
        perror("filter_create");
        return 1;
    }
    if (filter_load_file(fe, config) != 0)
        fprintf(stderr, "Предупреждение: не загружен %s, фильтр пуст\n", config);

    if (log_queue_init(logpath) != 0) {
        perror("log_queue_init");
        filter_destroy(fe);
        return 1;
    }

    tun_device_t tun;
    int rc = tun_create(&tun, tun_name);
    if (rc != 0) {
        fprintf(stderr, "tun_create: %s\n", strerror(-rc));
        log_queue_shutdown();
        filter_destroy(fe);
        return 1;
    }

    fprintf(stderr,
            "tund: интерфейс %s (fd=%d). Настройте IP: scripts/setup_tun.sh\n"
            "      Лог: %s. Ядро: sudo dmesg -w\n",
            tun.name, tun.fd, logpath);

    uint8_t buf[PACKET_BUF];
    unsigned long accepted = 0, dropped = 0;

    while (g_running) {
        ssize_t n = tun_read_packet(&tun, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("tun_read");
            break;
        }
        if (n == 0)
            continue;

        parsed_packet_t pkt;
        if (packet_parse(buf, (size_t)n, &pkt) != 0)
            continue;

        char rule_name[48] = "";
        filter_action_t action = filter_apply(fe, &pkt, rule_name, sizeof(rule_name));

        if (action == FILTER_DROP) {
            dropped++;
            log_queue_push(LOG_EVT_DROP, &pkt, rule_name);
            continue;
        }

        if (tun_write_packet(&tun, buf, (size_t)n) < 0)
            perror("tun_write");
        else
            accepted++;

        log_queue_push(LOG_EVT_ACCEPT, &pkt, "");
    }

    fprintf(stderr, "Статистика: accept=%lu drop=%lu\n", accepted, dropped);

    tun_close(&tun);
    log_queue_shutdown();
    filter_destroy(fe);
    return 0;
}
