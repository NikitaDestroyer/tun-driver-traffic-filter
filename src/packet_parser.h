#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define PARSED_IP_STR_LEN 16
#define PARSED_TS_LEN     24

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
} parsed_packet_t;

int packet_parse(const uint8_t *buf, size_t len, parsed_packet_t *out);

#endif
