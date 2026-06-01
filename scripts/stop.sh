#!/bin/bash
# stop.sh — остановка tund, выгрузка модуля, teardown lab.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PIDFILE="/tmp/tund.pid"
IFACE="${TUN_IFACE:-tun0}"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "Запустите от root: sudo $0" >&2
	exit 1
fi

if [[ -f "$PIDFILE" ]]; then
	pid="$(cat "$PIDFILE")"
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -f "$PIDFILE"
fi

rmmod tun_vpn_detect 2>/dev/null || true
"$ROOT/scripts/teardown_lab.sh" 2>/dev/null || true
"$ROOT/scripts/teardown_tun.sh" "$IFACE" 2>/dev/null || true

echo "OK: система остановлена"
