#!/bin/bash
IFACE="${1:-tun0}"
ip link set dev "$IFACE" down 2>/dev/null || true
ip addr flush dev "$IFACE" 2>/dev/null || true
echo "OK: $IFACE down"
