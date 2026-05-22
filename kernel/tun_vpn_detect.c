// SPDX-License-Identifier: GPL-2.0
/*
 * Минимальный модуль: netfilter + детект 3 VPN + отложенный printk (workqueue).
 * printk НЕ вызывается из hook-функции фильтрации.
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
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/inet.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Course Project");
MODULE_DESCRIPTION("VPN signature detect with deferred kernel log");

#define CONN_MAX 64

enum vpn_sig {
	VPN_NONE = 0,
	VPN_WIREGUARD,
	VPN_OPENVPN,
	VPN_IKE_IPSEC,
};

struct conn_entry {
	__be32 saddr, daddr;
	__be16 sport, dport;
	u8 protocol;
	u8 seen;
};

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

static struct log_event pending_evt;
static struct work_struct log_work;
static DEFINE_SPINLOCK(evt_lock);
static atomic_t log_pending;

/* 1 = отбрасывать ICMP в hook (без printk) */
static bool block_icmp = true;
module_param(block_icmp, bool, 0644);
MODULE_PARM_DESC(block_icmp, "Drop ICMP in netfilter hook (no printk)");

static const char *vpn_name(enum vpn_sig v)
{
	switch (v) {
	case VPN_WIREGUARD:   return "WireGuard";
	case VPN_OPENVPN:     return "OpenVPN";
	case VPN_IKE_IPSEC:   return "IKE/IPsec";
	default:              return "unknown";
	}
}

static void log_work_handler(struct work_struct *work)
{
	struct log_event evt;
	enum vpn_sig vpn;

	(void)work;

	if (!atomic_cmpxchg(&log_pending, 1, 0))
		return;

	spin_lock(&evt_lock);
	evt = pending_evt;
	vpn = pending_evt.vpn;
	spin_unlock(&evt_lock);

	printk(KERN_INFO
	       "tun_vpn_detect: NEW VPN [%s] %s:%u -> %s:%u proto=%s\n",
	       vpn_name(vpn), evt.src, evt.sport, evt.dst, evt.dport, evt.proto);
}

static void schedule_vpn_log(enum vpn_sig vpn, __be32 saddr, __be32 daddr,
			     u16 sport, u16 dport, const char *proto)
{
	spin_lock(&evt_lock);
	pending_evt.vpn = vpn;
	snprintf(pending_evt.src, sizeof(pending_evt.src), "%pI4", &saddr);
	snprintf(pending_evt.dst, sizeof(pending_evt.dst), "%pI4", &daddr);
	pending_evt.sport = sport;
	pending_evt.dport = dport;
	snprintf(pending_evt.proto, sizeof(pending_evt.proto), "%s", proto);
	spin_unlock(&evt_lock);

	if (atomic_cmpxchg(&log_pending, 0, 1) == 0)
		schedule_work(&log_work);
}

static int conn_find_or_add(__be32 saddr, __be32 daddr, __be16 sport,
			    __be16 dport, u8 protocol, int *is_new)
{
	int i, free_i = -1;
	unsigned long flags;

	spin_lock_irqsave(&conn_lock, flags);
	for (i = 0; i < CONN_MAX; i++) {
		struct conn_entry *e = &conn_table[i];
		if (!e->seen) {
			if (free_i < 0)
				free_i = i;
			continue;
		}
		if (e->saddr == saddr && e->daddr == daddr &&
		    e->sport == sport && e->dport == dport &&
		    e->protocol == protocol) {
			*is_new = 0;
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
	conn_table[free_i].seen = 1;
	*is_new = 1;
	spin_unlock_irqrestore(&conn_lock, flags);
	return 0;
}

static enum vpn_sig detect_vpn(u8 protocol, u16 sport, u16 dport,
			       const u8 *payload, int payload_len)
{
	/* WireGuard: типичный UDP 51820 */
	if (protocol == IPPROTO_UDP &&
	    (sport == 51820 || dport == 51820))
		return VPN_WIREGUARD;

	/* OpenVPN: 1194 TCP/UDP или opcode в payload */
	if ((protocol == IPPROTO_UDP || protocol == IPPROTO_TCP) &&
	    (sport == 1194 || dport == 1194))
		return VPN_OPENVPN;

	if (protocol == IPPROTO_UDP && payload_len >= 1) {
		u8 op = payload[0];
		if (op >= 1 && op <= 8)
			return VPN_OPENVPN;
	}

	/* IKE/IPsec: UDP 500 / 4500 */
	if (protocol == IPPROTO_UDP &&
	    (sport == 500 || dport == 500 || sport == 4500 || dport == 4500))
		return VPN_IKE_IPSEC;

	return VPN_NONE;
}

static const char *proto_str(u8 p)
{
	if (p == IPPROTO_TCP)
		return "TCP";
	if (p == IPPROTO_UDP)
		return "UDP";
	if (p == IPPROTO_ICMP)
		return "ICMP";
	return "OTHER";
}

static unsigned int tun_vpn_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	u16 sport = 0, dport = 0;
	const u8 *payload = NULL;
	int payload_len = 0;
	int is_new = 0;
	enum vpn_sig vpn;

	(void)priv;
	(void)state;

	if (!skb)
		return NF_ACCEPT;

	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->version != 4)
		return NF_ACCEPT;

	/* Фильтрация: без printk */
	if (block_icmp && iph->protocol == IPPROTO_ICMP)
		return NF_DROP;

	if (iph->protocol == IPPROTO_UDP) {
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
			return NF_ACCEPT;
		udph = udp_hdr(skb);
		sport = ntohs(udph->source);
		dport = ntohs(udph->dest);
		{
			int hdr_len = iph->ihl * 4 + sizeof(struct udphdr);
			if (!pskb_may_pull(skb, hdr_len + 1))
				return NF_ACCEPT;
			udph = udp_hdr(skb);
			payload = (u8 *)udph + sizeof(struct udphdr);
			payload_len = ntohs(udph->len) - sizeof(struct udphdr);
			if (payload_len < 0)
				payload_len = 0;
		}
	} else if (iph->protocol == IPPROTO_TCP) {
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
			return NF_ACCEPT;
		tcph = tcp_hdr(skb);
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);
		payload = NULL;
		payload_len = 0;
	} else {
		return NF_ACCEPT;
	}

	conn_find_or_add(iph->saddr, iph->daddr, htons(sport), htons(dport),
			 iph->protocol, &is_new);

	if (!is_new)
		return NF_ACCEPT;

	vpn = detect_vpn(iph->protocol, sport, dport, payload, payload_len);
	if (vpn != VPN_NONE)
		schedule_vpn_log(vpn, iph->saddr, iph->daddr, sport, dport,
				 proto_str(iph->protocol));

	return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops[] = {
	{
		.hook     = tun_vpn_hook,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook     = tun_vpn_hook,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	},
};

static int __init tun_vpn_init(void)
{
	int ret;

	atomic_set(&log_pending, 0);
	INIT_WORK(&log_work, log_work_handler);

	ret = nf_register_net_hooks(&init_net, nf_ops, ARRAY_SIZE(nf_ops));
	if (ret < 0) {
		pr_err("tun_vpn_detect: nf_register_net_hooks failed %d\n", ret);
		return ret;
	}

	pr_info("tun_vpn_detect: loaded (WireGuard/OpenVPN/IKE detect, deferred log)\n");
	return 0;
}

static void __exit tun_vpn_exit(void)
{
	cancel_work_sync(&log_work);
	nf_unregister_net_hooks(&init_net, nf_ops, ARRAY_SIZE(nf_ops));
	pr_info("tun_vpn_detect: unloaded\n");
}

module_init(tun_vpn_init);
module_exit(tun_vpn_exit);
