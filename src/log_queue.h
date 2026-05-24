#ifndef LOG_QUEUE_H
#define LOG_QUEUE_H

#include "packet_parser.h"
#include <stddef.h>

typedef enum {
    LOG_EVT_ACCEPT = 0,
    LOG_EVT_DROP
} log_event_kind_t;

/**
 * Инициализирует очередь логов и запускает фоновый поток записи.
 *
 * @param log_path  Путь к файлу лога (append); NULL — только stderr.
 * @return 0 при успехе, -1 если не удалось создать поток.
 */
int log_queue_init(const char *log_path);

/**
 * Останавливает поток, сливает очередь и закрывает файл лога.
 */
void log_queue_shutdown(void);

/**
 * Ставит событие в очередь без блокирующего I/O в вызывающем потоке.
 *
 * При переполнении очереди (256 элементов) событие отбрасывается.
 *
 * @param kind       LOG_EVT_ACCEPT или LOG_EVT_DROP.
 * @param pkt        Разобранный пакет (копируется в очередь).
 * @param rule_name  Имя правила для DROP; для ACCEPT может быть пустым.
 */
void log_queue_push(log_event_kind_t kind, const parsed_packet_t *pkt,
                    const char *rule_name);

#endif
