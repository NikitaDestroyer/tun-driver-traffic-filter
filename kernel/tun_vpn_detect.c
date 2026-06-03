// SPDX-License-Identifier: GPL-2.0
/*
 * tun_vpn_detect.c — VPN-детект для единого TUN-комплекса.
 *
 * - Hook только на трафик, связанный с tun0 (и inbound с lab veth).
 * - Фильтрация правил — только в userspace (tund); здесь NF_ACCEPT.
 * - printk только в log_work_handler (workqueue), не в hook.
 * - Очередь событий (kfifo), дедупликация flows с TTL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/kfifo.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/inet.h>

#include "vpn_signatures.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Course Project");
MODULE_DESCRIPTION("TUN-bound VPN detect with deferred kernel log");

#define CONN_MAX        256
#define CONN_TTL_SEC    300
#define LOG_QUEUE_SIZE  64
#define PAYLOAD_MAX     128

/** Запись таблицы активных flows (5-tuple). */
struct conn_entry {
	__be32 saddr, daddr;
	__be16 sport, dport;
	u8 protocol;
	unsigned long last_seen;
};

/** Событие для отложенного printk. */
struct log_event {
	enum vpn_sig vpn;
	char src[16];
	char dst[16];
	u16 sport;
	u16 dport;
	char proto[8];
};

static struct conn_entry conn_table[CONN_MAX];
static DEFINE_SPINLOCK(conn_lock);
static DEFINE_SPINLOCK(fifo_lock);

static DECLARE_KFIFO(log_fifo, struct log_event, LOG_QUEUE_SIZE);
static struct work_struct log_work;
static atomic_t log_scheduled;

static unsigned long dropped_events;

static char *iface = "tun0";
module_param(iface, charp, 0644);
MODULE_PARM_DESC(iface, "TUN interface name (only this traffic is analyzed)");

static char *lab_if = "veth-h";
module_param(lab_if, charp, 0644);
MODULE_PARM_DESC(lab_if, "Lab veth on host for inbound to tun IP");

static char *tun_ip = "10.0.0.1";
module_param(tun_ip, charp, 0644);
MODULE_PARM_DESC(tun_ip, "TUN IPv4 address for inbound lab traffic");

module_param(dropped_events, ulong, 0444);
MODULE_PARM_DESC(dropped_events, "Log events dropped due to full queue");

static __be32 tun_ip_be;

static const char *vpn_name(enum vpn_sig v)
{
	switch (v) {
	case VPN_WIREGUARD: return "WireGuard";
	case VPN_OPENVPN:   return "OpenVPN";
	case VPN_IKE_IPSEC: return "IKE/IPsec";
	default:            return "unknown";
	}
}

static const char *proto_str(u8 p)
{
	if (p == IPPROTO_TCP)  return "TCP";
	if (p == IPPROTO_UDP)  return "UDP";
	if (p == IPPROTO_ICMP) return "ICMP";
	return "OTHER";
}

/**
 * Проверяет, относится ли пакет к TUN-пайплайну.
 */
static bool match_tun_traffic(const struct nf_hook_state *state, __be32 daddr)
{
	if (state->in && strncmp(state->in->name, iface, IFNAMSIZ) == 0)
		return true;
	if (state->out && strncmp(state->out->name, iface, IFNAMSIZ) == 0)
		return true;
	if (lab_if && lab_if[0] && state->in &&
	    strncmp(state->in->name, lab_if, IFNAMSIZ) == 0 &&
	    daddr == tun_ip_be)
		return true;
	return false;
}

/**
 * Безопасно читает payload из skb через skb_copy_bits().
 */
static int skb_read_payload(struct sk_buff *skb, int offset, u8 *buf, int len)
{
	int ret;

	if (len > PAYLOAD_MAX)
		len = PAYLOAD_MAX;
	ret = skb_copy_bits(skb, offset, buf, len);
	return ret == 0 ? len : 0;
}

/**
 * Workqueue: единственное место printk для VPN-событий.
 */
static void log_work_handler(struct work_struct *work)
{
	struct log_event evt;

	(void)work;

	for (;;) {
		unsigned long flags;
		int got;

		spin_lock_irqsave(&fifo_lock, flags);
		got = kfifo_get(&log_fifo, &evt);
		spin_unlock_irqrestore(&fifo_lock, flags);
		if (!got)
			break;

		printk(KERN_INFO
		       "tun_vpn_detect: NEW VPN [%s] %s:%u -> %s:%u proto=%s\n",
		       vpn_name(evt.vpn), evt.src, evt.sport,
		       evt.dst, evt.dport, evt.proto);
	}

	atomic_set(&log_scheduled, 0);

	if (!kfifo_is_empty(&log_fifo) &&
	    atomic_cmpxchg(&log_scheduled, 0, 1) == 0)
		schedule_work(&log_work);
}

/**
 * Ставит VPN-событие в kfifo (без printk в hook).
 */
static void enqueue_vpn_log(enum vpn_sig vpn, __be32 saddr, __be32 daddr,
			    u16 sport, u16 dport, const char *proto)
{
	struct log_event evt;
	unsigned long flags;

	memset(&evt, 0, sizeof(evt));
	evt.vpn = vpn;
	snprintf(evt.src, sizeof(evt.src), "%pI4", &saddr);
	snprintf(evt.dst, sizeof(evt.dst), "%pI4", &daddr);
	evt.sport = sport;
	evt.dport = dport;
	snprintf(evt.proto, sizeof(evt.proto), "%s", proto);

	spin_lock_irqsave(&fifo_lock, flags);
	if (kfifo_in(&log_fifo, &evt, 1) != 1)
		dropped_events++;
	spin_unlock_irqrestore(&fifo_lock, flags);

	if (atomic_cmpxchg(&log_scheduled, 0, 1) == 0)
		schedule_work(&log_work);
}

static void conn_purge_expired(void)
{
	unsigned long now = jiffies;
	unsigned long ttl = CONN_TTL_SEC * HZ;
	int i;

	for (i = 0; i < CONN_MAX; i++) {
		if (conn_table[i].last_seen &&
		    time_after(now, conn_table[i].last_seen + ttl))
			memset(&conn_table[i], 0, sizeof(conn_table[i]));
	}
}

static int conn_find_or_add(__be32 saddr, __be32 daddr, __be16 sport,
			    __be16 dport, u8 protocol, int *is_new)
{
	int i, free_i = -1;
	unsigned long flags;

	*is_new = 0;
	spin_lock_irqsave(&conn_lock, flags);
	conn_purge_expired();

	for (i = 0; i < CONN_MAX; i++) {
		struct conn_entry *e = &conn_table[i];

		if (!e->last_seen) {
			if (free_i < 0)
				free_i = i;
			continue;
		}
		if (e->saddr == saddr && e->daddr == daddr &&
		    e->sport == sport && e->dport == dport &&
		    e->protocol == protocol) {
			e->last_seen = jiffies;
			spin_unlock_irqrestore(&conn_lock, flags);
			return 0;
		}
	}

	if (free_i < 0)
		free_i = 0;

	conn_table[free_i].saddr = saddr;
	conn_table[free_i].daddr = daddr;
	conn_table[free_i].sport = sport;
	conn_table[free_i].dport = dport;
	conn_table[free_i].protocol = protocol;
	conn_table[free_i].last_seen = jiffies;
	*is_new = 1;
	spin_unlock_irqrestore(&conn_lock, flags);
	return 0;
}

/**
 * Netfilter hook: VPN-детект на TUN-трафике, без фильтрации и без printk.
 */
static unsigned int tun_vpn_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct iphdr _iph, *iph;
	struct udphdr _udph, *udph;
	struct tcphdr _tcph, *tcph;
	u16 sport = 0, dport = 0;
	u8 payload[PAYLOAD_MAX];
	int payload_len = 0;
	int payload_off = 0;
	int is_new = 0;
	enum vpn_sig vpn;
	bool is_syn = false;

	(void)priv;

	if (!skb || skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (!iph || iph->version != 4)
		return NF_ACCEPT;

	if (!match_tun_traffic(state, iph->daddr))
		return NF_ACCEPT;

	if (iph->protocol == IPPROTO_UDP) {
		udph = skb_header_pointer(skb, iph->ihl * 4, sizeof(_udph),
					  &_udph);
		if (!udph)
			return NF_ACCEPT;
		sport = ntohs(udph->source);
		dport = ntohs(udph->dest);
		payload_off = iph->ihl * 4 + sizeof(struct udphdr);
		payload_len = skb_read_payload(skb, payload_off,
					       payload, PAYLOAD_MAX);
	} else if (iph->protocol == IPPROTO_TCP) {
		tcph = skb_header_pointer(skb, iph->ihl * 4, sizeof(_tcph),
					  &_tcph);
		if (!tcph)
			return NF_ACCEPT;
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);
		is_syn = (tcph->syn && !tcph->ack);
	} else {
		return NF_ACCEPT;
	}

	conn_find_or_add(iph->saddr, iph->daddr, htons(sport), htons(dport),
			 iph->protocol, &is_new);

	if (!is_new)
		return NF_ACCEPT;

	if (iph->protocol == IPPROTO_TCP && !is_syn)
		return NF_ACCEPT;

	vpn = vpn_detect(iph->protocol, sport, dport, payload, payload_len);
	if (vpn != VPN_NONE)
		enqueue_vpn_log(vpn, iph->saddr, iph->daddr, sport, dport,
				proto_str(iph->protocol));

	return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops[] = {
	{
		.hook     = tun_vpn_hook,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook     = tun_vpn_hook,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FIRST,
	},
};

static int __init tun_vpn_init(void)
{
	int ret;

	if (!in4_pton(tun_ip, -1, (u8 *)&tun_ip_be, -1, NULL)) {
		pr_err("tun_vpn_detect: invalid tun_ip %s\n", tun_ip);
		return -EINVAL;
	}

	INIT_KFIFO(log_fifo);
	atomic_set(&log_scheduled, 0);
	INIT_WORK(&log_work, log_work_handler);

	ret = nf_register_net_hooks(&init_net, nf_ops, ARRAY_SIZE(nf_ops));
	if (ret < 0) {
		pr_err("tun_vpn_detect: nf_register_net_hooks failed %d\n", ret);
		return ret;
	}

	pr_info("tun_vpn_detect: loaded iface=%s lab_if=%s tun_ip=%s\n",
		iface, lab_if ? lab_if : "-", tun_ip);
	return 0;
}

static void __exit tun_vpn_exit(void)
{
	cancel_work_sync(&log_work);
	nf_unregister_net_hooks(&init_net, nf_ops, ARRAY_SIZE(nf_ops));
	pr_info("tun_vpn_detect: unloaded (dropped_events=%lu)\n",
		dropped_events);
}

module_init(tun_vpn_init);
module_exit(tun_vpn_exit);
