#!/bin/bash
# start.sh — единый запуск: сборка, tund (tun0), lab, kernel-модуль.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
PIDFILE="/tmp/tund.pid"
LOGFILE="${TUND_LOG:-/tmp/tund.log}"
RULES="${TUND_RULES:-$ROOT/config/rules.conf}"
IFACE="${TUN_IFACE:-tun0}"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "Запустите от root: sudo $0" >&2
	exit 1
fi

cd "$ROOT"
make -s

echo "=== tund (создаёт $IFACE) ==="
if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
	echo "tund уже запущен (pid $(cat "$PIDFILE"))"
else
	: > "$LOGFILE"
	nohup "$BUILD/tund" -c "$RULES" -l "$LOGFILE" -i "$IFACE" -q \
		>> /tmp/tund.stderr 2>&1 &
	echo $! > "$PIDFILE"
	sleep 1
	if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
		echo "Ошибка запуска tund, см. /tmp/tund.stderr" >&2
		cat /tmp/tund.stderr 2>/dev/null || true
		exit 1
	fi
	echo "tund pid=$(cat "$PIDFILE"), log=$LOGFILE"
fi

echo "=== Lab (veth + маршруты) ==="
"$ROOT/scripts/setup_lab.sh"

echo "=== Kernel module ==="
if lsmod | grep -q '^tun_vpn_detect '; then
	rmmod tun_vpn_detect 2>/dev/null || true
fi
insmod "$BUILD/tun_vpn_detect.ko" iface="$IFACE" lab_if=veth-h tun_ip=10.0.0.1

echo ""
echo "Система запущена. Тест: sudo $ROOT/scripts/test_all.sh"
echo "dmesg: sudo dmesg -w | grep tun_vpn_detect"
