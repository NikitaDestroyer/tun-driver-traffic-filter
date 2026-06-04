#!/bin/bash
# teardown_lab.sh — удаление lab netns и veth.

set -euo pipefail

CLIENT_NS="${CLIENT_NS:-tun_lab_client}"
VETH_H="${VETH_H:-veth-h}"
IFACE="${TUN_IFACE:-tun0}"
CLIENT_IP="${CLIENT_IP:-10.0.0.2}"

ip route del "${CLIENT_IP}/32" dev "$IFACE" 2>/dev/null || true
ip link del "$VETH_H" 2>/dev/null || true
ip netns del "$CLIENT_NS" 2>/dev/null || true

echo "OK: lab teardown"
