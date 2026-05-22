#ifndef FILTER_H
#define FILTER_H

#include "packet_parser.h"

typedef enum {
    FILTER_ACCEPT = 0,
    FILTER_DROP   = 1
} filter_action_t;

typedef struct filter_engine filter_engine_t;

filter_engine_t *filter_create(void);
void filter_destroy(filter_engine_t *fe);
int filter_load_file(filter_engine_t *fe, const char *path);
filter_action_t filter_apply(filter_engine_t *fe, const parsed_packet_t *pkt,
                            char *rule_name, size_t rule_name_len);

#endif
