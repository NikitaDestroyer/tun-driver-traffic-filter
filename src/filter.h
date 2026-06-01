#ifndef FILTER_H
#define FILTER_H

#include "packet_parser.h"

/** Действие фильтра над пакетом. */
typedef enum {
    FILTER_ACCEPT = 0,
    FILTER_DROP   = 1
} filter_action_t;

/** Непрозрачный движок правил (до MAX_RULES записей). */
typedef struct filter_engine filter_engine_t;

/**
 * Создаёт пустой движок фильтрации (calloc).
 *
 * @return Указатель на engine или NULL при ошибке памяти.
 */
filter_engine_t *filter_create(void);

/**
 * Освобождает движок фильтрации.
 *
 * @param fe  Движок; допускается NULL.
 */
void filter_destroy(filter_engine_t *fe);

/**
 * Загружает правила из текстового файла (BLOCK_PROTO, BLOCK_DST_PORT, BLOCK_SRC_IP).
 *
 * @param fe    Движок для заполнения.
 * @param path  Путь к конфигу.
 * @return 0 при успешном открытии файла, -1 если файл не найден.
 */
int filter_load_file(filter_engine_t *fe, const char *path);

/**
 * Применяет правила к разобранному пакету (первое совпадение).
 *
 * @param fe             Движок с загруженными правилами.
 * @param pkt            Разобранный пакет; невалидные пакеты пропускаются.
 * @param rule_name      Буфер для имени сработавшего правила (может быть NULL).
 * @param rule_name_len  Размер буфера rule_name.
 * @param rule_index     Индекс правила при DROP (может быть NULL).
 * @return FILTER_DROP при совпадении, иначе FILTER_ACCEPT.
 */
filter_action_t filter_apply(filter_engine_t *fe, const parsed_packet_t *pkt,
                            char *rule_name, size_t rule_name_len,
                            int *rule_index);

/**
 * Возвращает число срабатываний правила по индексу (0 .. count-1).
 *
 * @param fe     Движок фильтрации.
 * @param index  Индекс правила.
 * @return Количество DROP по этому правилу.
 */
unsigned long filter_rule_hits(filter_engine_t *fe, int index);

/**
 * Возвращает количество загруженных правил.
 */
int filter_rule_count(filter_engine_t *fe);

/**
 * Копирует имя правила по индексу в buf.
 *
 * @return 0 при успехе, -1 если index вне диапазона.
 */
int filter_rule_name(filter_engine_t *fe, int index, char *buf, size_t len);

#endif
