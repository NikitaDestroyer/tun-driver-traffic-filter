#!/bin/bash
# Настройка tun0 для теста (запускать от root)

set -e

IFACE="${1:-tun0}"
IP="${2:-10.0.0.1}"
MASK="${3:-255.255.255.0}"

ip link set dev "$IFACE" up 2>/dev/null || true
ip addr flush dev "$IFACE" 2>/dev/null || true
ip addr add "${IP}/24" dev "$IFACE"
ip route add 10.0.0.0/24 dev "$IFACE" 2>/dev/null || true

echo "OK: $IFACE -> $IP/24"
ip addr show dev "$IFACE"
