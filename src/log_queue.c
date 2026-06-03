#include "log_queue.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_QUEUE_CAP 256

typedef struct {
    log_event_kind_t kind;
    parsed_packet_t pkt;
    char rule_name[80];
} log_item_t;

static struct {
    log_item_t items[LOG_QUEUE_CAP];
    int head, tail, count;
    pthread_mutex_t mu;
    pthread_cond_t not_empty;
    pthread_t thread;
    int running;
    int quiet;
    unsigned long dropped;
    FILE *fp;
} g_log;

/**
 * Возвращает строковое имя IP-протокола для лога.
 *
 * @param p  Номер протокола (6, 17, 1).
 * @return "TCP", "UDP", "ICMP" или "OTHER".
 */
static const char *proto_name(uint8_t p)
{
    switch (p) {
    case 6: return "TCP";
    case 17: return "UDP";
    case 1: return "ICMP";
    default: return "OTHER";
    }
}

/**
 * Фоновый поток: извлекает события из очереди и пишет в файл и stderr.
 *
 * @param arg  Не используется.
 * @return NULL.
 */
static void *log_worker(void *arg)
{
    (void)arg;
    while (g_log.running) {
        pthread_mutex_lock(&g_log.mu);
        while (g_log.count == 0 && g_log.running)
            pthread_cond_wait(&g_log.not_empty, &g_log.mu);

        if (!g_log.running && g_log.count == 0) {
            pthread_mutex_unlock(&g_log.mu);
            break;
        }

        log_item_t item = g_log.items[g_log.head];
        g_log.head = (g_log.head + 1) % LOG_QUEUE_CAP;
        g_log.count--;
        pthread_mutex_unlock(&g_log.mu);

        if (item.kind == LOG_EVT_ACCEPT && g_log.quiet)
            continue;

        const char *action = item.kind == LOG_EVT_DROP ? "BLOCK" : "ACCEPT";
        const char *rule = item.rule_name[0] ? item.rule_name : "-";

        if (g_log.fp) {
            fprintf(g_log.fp,
                    "[%s] %s %s %s:%u -> %s:%u (%zu bytes) rule=%s\n",
                    item.pkt.timestamp, action, proto_name(item.pkt.protocol),
                    item.pkt.src_ip_str, item.pkt.src_port,
                    item.pkt.dst_ip_str, item.pkt.dst_port,
                    item.pkt.total_len, rule);
            fflush(g_log.fp);
        }

        fprintf(stderr,
                "[%s] %s %s %s:%u -> %s:%u rule=%s\n",
                item.pkt.timestamp, action, proto_name(item.pkt.protocol),
                item.pkt.src_ip_str, item.pkt.src_port,
                item.pkt.dst_ip_str, item.pkt.dst_port, rule);
    }
    return NULL;
}

/* См. объявление в log_queue.h */
int log_queue_init(const char *log_path)
{
    memset(&g_log, 0, sizeof(g_log));
    g_log.fp = log_path ? fopen(log_path, "a") : NULL;
    pthread_mutex_init(&g_log.mu, NULL);
    pthread_cond_init(&g_log.not_empty, NULL);
    g_log.running = 1;
    if (pthread_create(&g_log.thread, NULL, log_worker, NULL) != 0)
        return -1;
    return 0;
}

/* См. объявление в log_queue.h */
void log_queue_shutdown(void)
{
    pthread_mutex_lock(&g_log.mu);
    g_log.running = 0;
    pthread_cond_broadcast(&g_log.not_empty);
    pthread_mutex_unlock(&g_log.mu);
    pthread_join(g_log.thread, NULL);
    if (g_log.fp)
        fclose(g_log.fp);
    pthread_mutex_destroy(&g_log.mu);
    pthread_cond_destroy(&g_log.not_empty);
}

/* См. объявление в log_queue.h */
void log_queue_push(log_event_kind_t kind, const parsed_packet_t *pkt,
                    const char *rule_name)
{
    pthread_mutex_lock(&g_log.mu);
    if (g_log.count >= LOG_QUEUE_CAP) {
        g_log.dropped++;
        pthread_mutex_unlock(&g_log.mu);
        return;
    }

    log_item_t *slot = &g_log.items[g_log.tail];
    slot->kind = kind;
    slot->pkt = *pkt;
    snprintf(slot->rule_name, sizeof(slot->rule_name), "%s",
             rule_name ? rule_name : "");

    g_log.tail = (g_log.tail + 1) % LOG_QUEUE_CAP;
    g_log.count++;
    pthread_cond_signal(&g_log.not_empty);
    pthread_mutex_unlock(&g_log.mu);
}

unsigned long log_queue_dropped(void)
{
    unsigned long n;
    pthread_mutex_lock(&g_log.mu);
    n = g_log.dropped;
    pthread_mutex_unlock(&g_log.mu);
    return n;
}

void log_queue_set_quiet(int quiet)
{
    pthread_mutex_lock(&g_log.mu);
    g_log.quiet = quiet ? 1 : 0;
    pthread_mutex_unlock(&g_log.mu);
}
