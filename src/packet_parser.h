#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define PARSED_IP_STR_LEN 16
#define PARSED_TS_LEN     24

/** Результат разбора IPv4-пакета (TCP/UDP/ICMP). */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  protocol; /* 6 TCP, 17 UDP, 1 ICMP */
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  tcp_flags;
    size_t   total_len;
    char     src_ip_str[PARSED_IP_STR_LEN];
    char     dst_ip_str[PARSED_IP_STR_LEN];
    char     timestamp[PARSED_TS_LEN];
    int      valid;
    int      frag;   /* 1 если IPv4 fragment (не анализируем L4) */
} parsed_packet_t;

/**
 * Разбирает raw IPv4-буфер и заполняет parsed_packet_t.
 *
 * Поддерживаются TCP, UDP и ICMP. IPv6 и неизвестные протоколы отклоняются.
 *
 * @param buf  Указатель на начало IP-пакета.
 * @param len  Длина буфера в байтах.
 * @param out  Выходная структура; при успехе out->valid = 1.
 * @return 0 при успешном разборе, -1 если пакет слишком короткий или не IPv4/L4.
 */
int packet_parse(const uint8_t *buf, size_t len, parsed_packet_t *out);

#endif
