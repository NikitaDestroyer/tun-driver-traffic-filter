#!/bin/bash
# test_all.sh — полный прогон: start уже должен быть или поднимаем lab+tund+kmod.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "Запустите от root: sudo $0" >&2
	exit 1
fi

# Если система не запущена — стартуем
if ! pgrep -x tund >/dev/null 2>&1; then
	echo "=== start.sh ==="
	"$ROOT/scripts/start.sh"
fi

echo ""
"$ROOT/scripts/test_tun_filter.sh"

echo ""
"$ROOT/scripts/test_vpn_detect.sh"

echo ""
echo "=== test_all: OK ==="
