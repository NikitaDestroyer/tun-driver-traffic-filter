#!/bin/bash
# Быстрый тест kernel-модуля (нужен root и загруженный модуль)

set -e

echo "=== Проверка dmesg после имитации VPN-портов ==="
dmesg -C 2>/dev/null || true

# UDP «WireGuard»
timeout 1 bash -c 'echo test | nc -u -w1 127.0.0.1 51820' 2>/dev/null || true
sleep 1

# UDP «OpenVPN»
timeout 1 bash -c 'echo test | nc -u -w1 127.0.0.1 1194' 2>/dev/null || true
sleep 1

# UDP «IKE»
timeout 1 bash -c 'echo test | nc -u -w1 127.0.0.1 500' 2>/dev/null || true
sleep 1

echo "--- Последние сообщения модуля ---"
dmesg | grep tun_vpn_detect | tail -10
