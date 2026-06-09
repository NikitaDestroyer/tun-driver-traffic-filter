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

stop_tund() {
	local pid
	for pid in $(pgrep -x tund 2>/dev/null || true); do
		kill "$pid" 2>/dev/null || true
	done
	rm -f "$PIDFILE"
	sleep 0.5
	for pid in $(pgrep -x tund 2>/dev/null || true); do
		kill -9 "$pid" 2>/dev/null || true
	done
}
stop_tund

rmmod tun_vpn_detect 2>/dev/null || true
"$ROOT/scripts/teardown_lab.sh" 2>/dev/null || true
"$ROOT/scripts/teardown_tun.sh" "$IFACE" 2>/dev/null || true

echo "OK: система остановлена"
