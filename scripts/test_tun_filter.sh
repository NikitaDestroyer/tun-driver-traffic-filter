#!/bin/bash
# test_tun_filter.sh — проверка фильтрации через tun0 (lab + tund).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENT_NS="${CLIENT_NS:-tun_lab_client}"
TUN_IP="${TUN_IP:-10.0.0.1}"
LOGFILE="${TUND_LOG:-/tmp/tund.log}"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "Запустите от root" >&2
	exit 1
fi

if ! ip netns list | grep -q "$CLIENT_NS"; then
	echo "Lab не поднят. Запустите: sudo $ROOT/scripts/start.sh" >&2
	exit 1
fi

echo "=== test_tun_filter: ping (ICMP) ==="
: > "$LOGFILE"
sleep 0.5
ip netns exec "$CLIENT_NS" ping -c 2 -W 1 "$TUN_IP" >/dev/null 2>&1 || true
sleep 1

if grep -q "BLOCK ICMP" "$LOGFILE" 2>/dev/null; then
	echo "OK: ICMP blocked (rules.conf)"
elif grep -q "ACCEPT ICMP" "$LOGFILE" 2>/dev/null; then
	echo "OK: ICMP accepted (проверьте rules.conf)"
else
	echo "WARN: нет ICMP записей в $LOGFILE"
fi

grep -E "BLOCK|ACCEPT" "$LOGFILE" | tail -5 || true
