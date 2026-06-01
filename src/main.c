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
            "Usage: %s [-c rules.conf] [-l logfile] [-i tun_name] [-q]\n"
            "  TUN-демон: перехват IP через tun0, фильтрация, отложенный лог.\n"
            "  VPN в ядре: tun_vpn_detect.ko (scripts/start.sh)\n"
            "  -q  логировать только BLOCK\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *config = "config/rules.conf";
    const char *logpath = "/tmp/tund.log";
    const char *tun_name = TUN_NAME_DEFAULT;
    int quiet = 0;

    int opt;
    while ((opt = getopt(argc, argv, "c:l:i:qh")) != -1) {
        switch (opt) {
        case 'c': config = optarg; break;
        case 'l': logpath = optarg; break;
        case 'i': tun_name = optarg; break;
        case 'q': quiet = 1; break;
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
    log_queue_set_quiet(quiet);

    tun_device_t tun;
    int rc = tun_create(&tun, tun_name);
    if (rc != 0) {
        fprintf(stderr, "tun_create: %s\n", strerror(-rc));
        log_queue_shutdown();
        filter_destroy(fe);
        return 1;
    }

    fprintf(stderr,
            "tund: интерфейс %s (fd=%d). Lab: scripts/setup_lab.sh\n"
            "      Лог: %s. Ядро: dmesg | grep tun_vpn_detect\n",
            tun.name, tun.fd, logpath);

    uint8_t buf[PACKET_BUF];
    unsigned long accepted = 0, dropped = 0, bytes_in = 0, parse_skip = 0;

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

        bytes_in += (unsigned long)n;

        parsed_packet_t pkt;
        if (packet_parse(buf, (size_t)n, &pkt) != 0) {
            parse_skip++;
            continue;
        }

        char rule_name[48] = "";
        filter_action_t action = filter_apply(fe, &pkt, rule_name,
                                              sizeof(rule_name), NULL);

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

    fprintf(stderr,
            "Статистика: accept=%lu drop=%lu bytes_in=%lu parse_skip=%lu "
            "log_dropped=%lu\n",
            accepted, dropped, bytes_in, parse_skip, log_queue_dropped());

    for (int i = 0; i < filter_rule_count(fe); i++) {
        char rname[48];
        if (filter_rule_name(fe, i, rname, sizeof(rname)) == 0 &&
            filter_rule_hits(fe, i) > 0)
            fprintf(stderr, "  rule[%d] %s hits=%lu\n",
                    i, rname, filter_rule_hits(fe, i));
    }

    tun_close(&tun);
    log_queue_shutdown();
    filter_destroy(fe);
    return 0;
}
