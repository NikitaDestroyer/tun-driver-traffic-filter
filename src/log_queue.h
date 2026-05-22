#ifndef LOG_QUEUE_H
#define LOG_QUEUE_H

#include "packet_parser.h"
#include <stddef.h>

typedef enum {
    LOG_EVT_ACCEPT = 0,
    LOG_EVT_DROP
} log_event_kind_t;

int log_queue_init(const char *log_path);
void log_queue_shutdown(void);

/* Постановка в очередь — без printf в hot path фильтрации */
void log_queue_push(log_event_kind_t kind, const parsed_packet_t *pkt,
                    const char *rule_name);

#endif
