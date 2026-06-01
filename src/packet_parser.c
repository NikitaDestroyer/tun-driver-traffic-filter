#include "packet_parser.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/**
 * Формирует строку текущего локального времени (YYYY-MM-DD HH:MM:SS).
 *
 * @param buf     Буфер для записи.
 * @param buflen  Размер буфера.
 */
static void format_ts(char *buf, size_t buflen)
{
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", &tm);
}

/* См. объявление в packet_parser.h */
int packet_parse(const uint8_t *buf, size_t len, parsed_packet_t *out)
{
    memset(out, 0, sizeof(*out));
    format_ts(out->timestamp, sizeof(out->timestamp));

    if (len < sizeof(struct iphdr))
        return -1;

    const struct iphdr *ip = (const struct iphdr *)buf;
    if (ip->version != 4)
        return -1;

    size_t ip_hdr_len = (size_t)ip->ihl * 4;
    if (len < ip_hdr_len)
        return -1;

    out->src_ip = ip->saddr;
    out->dst_ip = ip->daddr;
    out->protocol = ip->protocol;
    out->total_len = ntohs(ip->tot_len);

    if (out->total_len > len)
        return -1;

    if (ntohs(ip->frag_off) & (IP_MF | IP_OFFMASK))
        out->frag = 1;

    inet_ntop(AF_INET, &ip->saddr, out->src_ip_str, sizeof(out->src_ip_str));
    inet_ntop(AF_INET, &ip->daddr, out->dst_ip_str, sizeof(out->dst_ip_str));

    if (out->frag)
        return -1;

    const uint8_t *l4 = buf + ip_hdr_len;
    size_t l4_len = len - ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
        const struct tcphdr *tcp = (const struct tcphdr *)l4;
        size_t tcp_hdr_len = (size_t)tcp->doff * 4;

        if (tcp->doff < 5 || tcp_hdr_len > l4_len)
            return -1;

        out->src_port = ntohs(tcp->source);
        out->dst_port = ntohs(tcp->dest);
        out->tcp_flags = tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) |
                         (tcp->psh << 3) | (tcp->ack << 4);
    } else if (ip->protocol == IPPROTO_UDP && l4_len >= sizeof(struct udphdr)) {
        const struct udphdr *udp = (const struct udphdr *)l4;
        out->src_port = ntohs(udp->source);
        out->dst_port = ntohs(udp->dest);
    } else if (ip->protocol == IPPROTO_ICMP && l4_len >= 8) {
        out->src_port = 0;
        out->dst_port = 0;
    } else {
        return -1;
    }

    out->valid = 1;
    return 0;
}
