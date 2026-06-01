#!/bin/bash
# test_vpn_detect.sh — VPN-детект через lab (client -> tun0), не localhost.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENT_NS="${CLIENT_NS:-tun_lab_client}"
TUN_IP="${TUN_IP:-10.0.0.1}"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "Запустите от root" >&2
	exit 1
fi

if ! lsmod | grep -q '^tun_vpn_detect '; then
	echo "Модуль не загружен. Запустите: sudo $ROOT/scripts/start.sh" >&2
	exit 1
fi

echo "=== VPN detect через lab (client -> $TUN_IP) ==="
dmesg -C 2>/dev/null || true

# WireGuard-like: 32+ байт payload, первый байт тип 1
printf '\x01' | ip netns exec "$CLIENT_NS" nc -u -w1 "$TUN_IP" 51820 2>/dev/null || true
sleep 1

# OpenVPN port
echo test | ip netns exec "$CLIENT_NS" nc -u -w1 "$TUN_IP" 1194 2>/dev/null || true
sleep 1

# IKE port
printf '\x00%.0s' {1..28} | ip netns exec "$CLIENT_NS" nc -u -w1 "$TUN_IP" 500 2>/dev/null || true
sleep 2

echo "--- dmesg tun_vpn_detect ---"
dmesg | grep tun_vpn_detect | grep "NEW VPN" | tail -10 || true

count="$(dmesg | grep -c "NEW VPN" || true)"
if [[ "$count" -ge 1 ]]; then
	echo "OK: VPN events in dmesg ($count)"
else
	echo "WARN: нет NEW VPN в dmesg (проверьте lab и iface=tun0)"
	exit 1
fi
