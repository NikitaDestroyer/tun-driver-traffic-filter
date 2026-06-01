/* SPDX-License-Identifier: GPL-2.0 */
/*
 * vpn_signatures.h — эвристики VPN по полям пакета (не только по порту).
 *
 * Используется из tun_vpn_detect.c; payload читается через skb_copy_bits().
 */

#ifndef VPN_SIGNATURES_H
#define VPN_SIGNATURES_H

#include <linux/types.h>
#include <linux/in.h>
#include <linux/ip.h>

/** Идентификаторы VPN-сигнатур. */
enum vpn_sig {
	VPN_NONE = 0,
	VPN_WIREGUARD,
	VPN_OPENVPN,
	VPN_IKE_IPSEC,
};

/**
 * WireGuard: UDP 51820 + тип сообщения 1–4 и типичная длина handshake.
 *
 * @param payload      Первые байты UDP payload (минимум 4).
 * @param payload_len  Длина payload.
 * @return 1 если похоже на WireGuard.
 */
static inline int vpn_match_wireguard(const u8 *payload, int payload_len)
{
	u8 msg_type;

	if (payload_len < 4)
		return 0;

	msg_type = payload[0];
	/* WireGuard message types: 1–4 (handshake/data) */
	if (msg_type < 1 || msg_type > 4)
		return 0;

	/* Initiation/Response handshake — типичные размеры */
	if (msg_type <= 2 && payload_len >= 92)
		return 1;
	if (msg_type >= 3 && payload_len >= 32)
		return 1;

	return 0;
}

/**
 * OpenVPN: порт 1194 или P_CONTROL opcode в первых битах заголовка.
 *
 * OpenVPN packet: (opcode << 3) | key_id; opcode 1–8 для control.
 *
 * @param payload      UDP payload.
 * @param payload_len  Длина.
 * @return 1 если похоже на OpenVPN control/data.
 */
static inline int vpn_match_openvpn_payload(const u8 *payload, int payload_len)
{
	u8 op;

	if (payload_len < 1)
		return 0;

	op = payload[0] >> 3;
	return op >= 1 && op <= 8;
}

/**
 * IKEv2: минимум 28 байт заголовка, major version = 2.
 *
 * @param payload      UDP payload (IKE message).
 * @param payload_len  Длина.
 * @return 1 если похоже на IKEv2.
 */
static inline int vpn_match_ikev2(const u8 *payload, int payload_len)
{
	u8 major;

	if (payload_len < 28)
		return 0;

	/* Byte 17: MjVer (high nibble) = 2 for IKEv2 */
	major = (payload[17] >> 4) & 0x0f;
	return major == 2;
}

/**
 * Определяет VPN по протоколу, портам и содержимому payload.
 *
 * @param protocol     IPPROTO_TCP или IPPROTO_UDP.
 * @param sport        Порт источника (host order).
 * @param dport        Порт назначения (host order).
 * @param payload      Буфер payload (может быть NULL).
 * @param payload_len  Длина payload.
 * @return VPN_WIREGUARD, VPN_OPENVPN, VPN_IKE_IPSEC или VPN_NONE.
 */
static inline enum vpn_sig vpn_detect(u8 protocol, u16 sport, u16 dport,
				      const u8 *payload, int payload_len)
{
	/* WireGuard: UDP 51820 + структурная проверка */
	if (protocol == IPPROTO_UDP &&
	    (sport == 51820 || dport == 51820)) {
		if (payload && vpn_match_wireguard(payload, payload_len))
			return VPN_WIREGUARD;
		/* Порт + минимальный размер без полного handshake */
		if (payload_len >= 32)
			return VPN_WIREGUARD;
	}

	/* OpenVPN: порт 1194 */
	if ((protocol == IPPROTO_UDP || protocol == IPPROTO_TCP) &&
	    (sport == 1194 || dport == 1194))
		return VPN_OPENVPN;

	if (protocol == IPPROTO_UDP && payload &&
	    vpn_match_openvpn_payload(payload, payload_len))
		return VPN_OPENVPN;

	/* IKE/IPsec: UDP 500/4500 + IKEv2 header */
	if (protocol == IPPROTO_UDP &&
	    (sport == 500 || dport == 500 || sport == 4500 || dport == 4500)) {
		if (payload && vpn_match_ikev2(payload, payload_len))
			return VPN_IKE_IPSEC;
		if (payload_len >= 28)
			return VPN_IKE_IPSEC;
	}

	return VPN_NONE;
}

#endif /* VPN_SIGNATURES_H */
