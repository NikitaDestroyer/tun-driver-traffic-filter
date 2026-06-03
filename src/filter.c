#include "filter.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RULES 32
#define RULE_NAME_LEN 80

typedef enum {
    RULE_BLOCK_PROTO,
    RULE_BLOCK_DST_PORT,
    RULE_BLOCK_SRC_IP
} rule_type_t;

typedef struct {
    rule_type_t type;
    char name[RULE_NAME_LEN];
    uint8_t proto;
    uint16_t port;
    uint32_t ip;
    unsigned long hits;
} rule_t;

struct filter_engine {
    rule_t rules[MAX_RULES];
    int count;
};

/* См. объявление в filter.h */
filter_engine_t *filter_create(void)
{
    return calloc(1, sizeof(filter_engine_t));
}

/* См. объявление в filter.h */
void filter_destroy(filter_engine_t *fe)
{
    free(fe);
}

/**
 * Удаляет ведущие и завершающие пробельные символы in-place.
 *
 * @param s  Строка для обрезки.
 */
static void trim(char *s)
{
    while (*s && isspace((unsigned char)*s))
        memmove(s, s + 1, strlen(s));
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
}

/**
 * Преобразует имя протокола (TCP/UDP/ICMP) в номер IP-протокола.
 *
 * @param s    Строка протокола (без учёта регистра).
 * @param out  Выход: 6, 17 или 1.
 * @return 0 при успехе, -1 для неизвестного имени.
 */
static int parse_proto(const char *s, uint8_t *out)
{
    if (!strcasecmp(s, "TCP")) { *out = 6; return 0; }
    if (!strcasecmp(s, "UDP")) { *out = 17; return 0; }
    if (!strcasecmp(s, "ICMP")) { *out = 1; return 0; }
    return -1;
}

/* См. объявление в filter.h */
int filter_load_file(filter_engine_t *fe, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (!line[0] || line[0] == '#')
            continue;
        if (fe->count >= MAX_RULES)
            break;

        rule_t *r = &fe->rules[fe->count];
        char cmd[32], arg[64];
        if (sscanf(line, "%31s %63s", cmd, arg) < 2)
            continue;

        if (!strcasecmp(cmd, "BLOCK_PROTO")) {
            if (parse_proto(arg, &r->proto) != 0)
                continue;
            r->type = RULE_BLOCK_PROTO;
            snprintf(r->name, sizeof(r->name), "BLOCK_PROTO %s", arg);
        } else if (!strcasecmp(cmd, "BLOCK_DST_PORT")) {
            r->type = RULE_BLOCK_DST_PORT;
            r->port = (uint16_t)atoi(arg);
            snprintf(r->name, sizeof(r->name), "BLOCK_DST_PORT %s", arg);
        } else if (!strcasecmp(cmd, "BLOCK_SRC_IP")) {
            struct in_addr a;
            if (inet_pton(AF_INET, arg, &a) != 1)
                continue;
            r->type = RULE_BLOCK_SRC_IP;
            r->ip = a.s_addr;
            snprintf(r->name, sizeof(r->name), "BLOCK_SRC_IP %s", arg);
        } else {
            continue;
        }
        fe->count++;
    }

    fclose(f);
    return 0;
}

/* См. объявление в filter.h */
filter_action_t filter_apply(filter_engine_t *fe, const parsed_packet_t *pkt,
                            char *rule_name, size_t rule_name_len,
                            int *rule_index)
{
    if (!pkt || !pkt->valid)
        return FILTER_ACCEPT;

    if (rule_index)
        *rule_index = -1;

    for (int i = 0; i < fe->count; i++) {
        const rule_t *r = &fe->rules[i];
        int match = 0;

        switch (r->type) {
        case RULE_BLOCK_PROTO:
            match = (pkt->protocol == r->proto);
            break;
        case RULE_BLOCK_DST_PORT:
            match = (pkt->dst_port == r->port);
            break;
        case RULE_BLOCK_SRC_IP:
            match = (pkt->src_ip == r->ip);
            break;
        }

        if (match) {
            fe->rules[i].hits++;
            if (rule_name && rule_name_len)
                snprintf(rule_name, rule_name_len, "%s", r->name);
            if (rule_index)
                *rule_index = i;
            return FILTER_DROP;
        }
    }
    return FILTER_ACCEPT;
}

unsigned long filter_rule_hits(filter_engine_t *fe, int index)
{
    if (!fe || index < 0 || index >= fe->count)
        return 0;
    return fe->rules[index].hits;
}

int filter_rule_count(filter_engine_t *fe)
{
    return fe ? fe->count : 0;
}

int filter_rule_name(filter_engine_t *fe, int index, char *buf, size_t len)
{
    if (!fe || index < 0 || index >= fe->count || !buf || len == 0)
        return -1;
    snprintf(buf, len, "%s", fe->rules[index].name);
    return 0;
}
