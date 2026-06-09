#!/bin/bash
# demo_traffic.sh — демонстрация перехвата разного трафика через tun0.
#
# Показывает BLOCK/ACCEPT в /tmp/tund.log (ICMP, UDP, TCP) и VPN в dmesg.
# Запуск: sudo ./scripts/demo_traffic.sh
# Опции:
#   --no-restore   не возвращать tund к config/rules.conf и -q после демо
#   --skip-setup   не перезапускать tund/lab (система уже поднята start.sh)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
PIDFILE="/tmp/tund.pid"
LOGFILE="${TUND_LOG:-/tmp/tund.log}"
DEMO_RULES="$ROOT/config/rules.demo.conf"
PROD_RULES="${TUND_RULES:-$ROOT/config/rules.conf}"
IFACE="${TUN_IFACE:-tun0}"
CLIENT_NS="${CLIENT_NS:-tun_lab_client}"
TUN_IP="${TUN_IP:-10.0.0.1}"
HOST_VETH_IP="${HOST_VETH_IP:-10.0.0.254}"

RESTORE=1
SKIP_SETUP=0

for arg in "$@"; do
	case "$arg" in
	--no-restore) RESTORE=0 ;;
	--skip-setup) SKIP_SETUP=1 ;;
	-h|--help)
		echo "Usage: sudo $0 [--no-restore] [--skip-setup]"
		exit 0
		;;
	*)
		echo "Неизвестный аргумент: $arg" >&2
		exit 1
		;;
	esac
done

if [[ "$(id -u)" -ne 0 ]]; then
	echo "Запустите от root: sudo $0" >&2
	exit 1
fi

section() {
	echo ""
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  $*"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

show_log() {
	local pattern="${1:-.}"
	echo "--- /tmp/tund.log (последние совпадения) ---"
	grep -E "$pattern" "$LOGFILE" 2>/dev/null | tail -8 || echo "(нет записей)"
}

show_vpn_dmesg() {
	echo "--- dmesg (NEW VPN) ---"
	dmesg | grep 'tun_vpn_detect: NEW VPN' | tail -10 || echo "(нет событий VPN)"
}

vpn_types_found() {
	dmesg | grep 'tun_vpn_detect: NEW VPN' | sed -n 's/.*NEW VPN \[\([^]]*\)\].*/\1/p' | sort -u
}

# Остановить только tund (lab и модуль не трогаем)
stop_tund_only() {
	local pid
	for pid in $(pgrep -x tund 2>/dev/null || true); do
		kill "$pid" 2>/dev/null || true
	done
	if [[ -f "$PIDFILE" ]]; then
		rm -f "$PIDFILE"
	fi
	sleep 0.5
	for pid in $(pgrep -x tund 2>/dev/null || true); do
		kill -9 "$pid" 2>/dev/null || true
	done
	sleep 0.3
}

# $1=rules.conf  $2=quiet (1 = флаг -q)
start_tund() {
	local rules="$1"
	local quiet="${2:-0}"
	local -a qarg=()

	[[ "$quiet" == "1" ]] && qarg=(-q)

	stop_tund_only
	if ip link show "$IFACE" &>/dev/null; then
		ip link delete dev "$IFACE" 2>/dev/null || true
	fi

	: > "$LOGFILE"
	: > /tmp/tund.stderr
	nohup "$BUILD/tund" -c "$rules" -l "$LOGFILE" -i "$IFACE" "${qarg[@]}" \
		>/tmp/tund.stderr 2>&1 &
	echo $! > "$PIDFILE"
	sleep 1
	if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
		echo "Ошибка запуска tund:" >&2
		cat /tmp/tund.stderr >&2 || true
		exit 1
	fi
}

ensure_lab_and_kmod() {
	if ! ip netns list | grep -q "$CLIENT_NS"; then
		"$ROOT/scripts/setup_lab.sh"
	fi
	if ! lsmod | grep -q '^tun_vpn_detect '; then
		insmod "$BUILD/tun_vpn_detect.ko" iface="$IFACE" lab_if=veth-h tun_ip="$TUN_IP"
	fi
	"$ROOT/scripts/setup_lab.sh" >/dev/null
}

cd "$ROOT"
[[ -x "$BUILD/tund" ]] || make -s

section "Подготовка: tund + lab + tun_vpn_detect (демо-правила, лог ACCEPT+BLOCK)"
if [[ "$SKIP_SETUP" -eq 0 ]]; then
	start_tund "$DEMO_RULES" 0
	ensure_lab_and_kmod
	echo "tund pid=$(cat "$PIDFILE"), rules=$DEMO_RULES"
	echo "lab: ip netns exec $CLIENT_NS ..."
	ip -br addr show "$IFACE" 2>/dev/null || true
else
	if ! pgrep -x tund >/dev/null; then
		echo "tund не запущен. Уберите --skip-setup или: sudo $ROOT/scripts/start.sh" >&2
		exit 1
	fi
	: > "$LOGFILE"
fi

# ─── 1. ICMP ───────────────────────────────────────────────────────────
section "1/4  ICMP — ping (ожидается BLOCK)"
ip netns exec "$CLIENT_NS" ping -c 2 -W 1 "$TUN_IP" >/dev/null 2>&1 || true
sleep 1
show_log 'BLOCK ICMP'
if ! grep -q 'BLOCK ICMP' "$LOGFILE"; then
	echo "WARN: нет BLOCK ICMP" >&2
fi

# ─── 2. UDP ────────────────────────────────────────────────────────────
section "2/4  UDP — хост → клиент через tun0 (53 BLOCK, 9999 ACCEPT)"
echo "  (tund видит пакеты, маршрутизируемые через tun0; см. ip route get 10.0.0.2)"
echo test | nc -u -w1 10.0.0.2 53 2>/dev/null || true
echo test | nc -u -w1 10.0.0.2 9999 2>/dev/null || true
sleep 1
show_log 'UDP'
if ! grep -q 'BLOCK UDP' "$LOGFILE"; then
	echo "WARN: нет BLOCK UDP :53" >&2
fi
if ! grep -q 'ACCEPT UDP' "$LOGFILE"; then
	echo "WARN: нет ACCEPT UDP :9999" >&2
fi

# ─── 3. TCP ────────────────────────────────────────────────────────────
section "3/4  TCP — хост → клиент через tun0 (22 BLOCK, 80 ACCEPT)"
nc -z -w1 10.0.0.2 22 2>/dev/null || true
nc -z -w1 10.0.0.2 80 2>/dev/null || true
sleep 1
show_log 'TCP'
if ! grep -q 'BLOCK TCP' "$LOGFILE"; then
	echo "WARN: нет BLOCK TCP :22" >&2
fi
if ! grep -q 'ACCEPT TCP' "$LOGFILE"; then
	echo "WARN: нет ACCEPT TCP :80" >&2
fi

# ─── 4. VPN (ядро) ─────────────────────────────────────────────────────
section "4/4  VPN — client → tun0 (WireGuard / OpenVPN / IKE → dmesg)"
dmesg -C 2>/dev/null || true
printf '\x01' | ip netns exec "$CLIENT_NS" nc -u -w1 "$TUN_IP" 51820 2>/dev/null || true
sleep 0.5
echo test | ip netns exec "$CLIENT_NS" nc -u -w1 "$TUN_IP" 1194 2>/dev/null || true
sleep 0.5
printf '\x00%.0s' {1..28} | ip netns exec "$CLIENT_NS" nc -u -w1 "$TUN_IP" 500 2>/dev/null || true
sleep 2
show_vpn_dmesg
vpn_count="$(dmesg | grep -c 'NEW VPN' || true)"
if [[ "$vpn_count" -lt 1 ]]; then
	echo "WARN: нет NEW VPN в dmesg (проверьте lab и tun_vpn_detect)" >&2
else
	echo "OK: VPN-событий: $vpn_count (типы: $(vpn_types_found | tr '\n' ' '))"
fi

# ─── Итог ──────────────────────────────────────────────────────────────
section "Сводка"
echo "Фильтр (userspace, разные протоколы):"
grep -E 'BLOCK|ACCEPT' "$LOGFILE" | sort -u || true
echo ""
echo "VPN (ядро, типы: WireGuard / OpenVPN / IKE):"
dmesg | grep 'tun_vpn_detect: NEW VPN' | sort -u || true
types="$(vpn_types_found | tr '\n' ' ')"
[[ -n "$types" ]] && echo "  распознано: $types"
echo ""
echo "Маршрут клиента → tun0:"
ip netns exec "$CLIENT_NS" ip route get "$TUN_IP" 2>/dev/null || true

if [[ "$RESTORE" -eq 1 && "$SKIP_SETUP" -eq 0 ]]; then
	section "Восстановление: tund с $PROD_RULES и -q"
	start_tund "$PROD_RULES" 1
	"$ROOT/scripts/setup_lab.sh" >/dev/null
	echo "Готово. Режим как после start.sh"
else
	echo ""
	echo "tund оставлен в демо-режиме. Восстановление: sudo $ROOT/scripts/start.sh"
fi

echo ""
echo "Полный лог: $LOGFILE"
echo "Следить в реальном времени: sudo tail -f $LOGFILE"
