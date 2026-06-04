#!/bin/bash
# setup_lab.sh — lab-стенд: netns client + veth, маршруты на tun0.
#
# Требует root. tun0 должен быть создан tund (start.sh запускает tund после setup_tun).
#
# Топология:
#   client (10.0.0.2) --veth-c/veth-h-- host (10.0.0.254) --> tun0 (10.0.0.1)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IFACE="${TUN_IFACE:-tun0}"
TUN_IP="${TUN_IP:-10.0.0.1}"
CLIENT_NS="${CLIENT_NS:-tun_lab_client}"
VETH_H="${VETH_H:-veth-h}"
VETH_C="${VETH_C:-veth-c}"
HOST_VETH_IP="${HOST_VETH_IP:-10.0.0.254}"
CLIENT_IP="${CLIENT_IP:-10.0.0.2}"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "Запустите от root: sudo $0" >&2
	exit 1
fi

# Удалить старый lab при повторном запуске
"$ROOT/scripts/teardown_lab.sh" 2>/dev/null || true

echo "=== Создание veth и netns $CLIENT_NS ==="
ip netns add "$CLIENT_NS"
ip link add "$VETH_H" type veth peer name "$VETH_C"
ip link set "$VETH_C" netns "$CLIENT_NS"

ip addr add "${HOST_VETH_IP}/24" dev "$VETH_H"
ip link set "$VETH_H" up

ip netns exec "$CLIENT_NS" ip addr add "${CLIENT_IP}/24" dev "$VETH_C"
ip netns exec "$CLIENT_NS" ip link set "$VETH_C" up
ip netns exec "$CLIENT_NS" ip link set lo up

# Маршрут клиента: вся lab-сеть через veth-h (шлюз 10.0.0.254)
if ! ip netns exec "$CLIENT_NS" ip route add "${TUN_IP}/32" via "$HOST_VETH_IP" 2>/dev/null; then
	ip netns exec "$CLIENT_NS" ip route replace "${TUN_IP}/32" via "$HOST_VETH_IP"
fi

# На хосте: трафик к клиенту через tun0 (после того как tund поднимет интерфейс)
ip route replace "${CLIENT_IP}/32" dev "$IFACE" 2>/dev/null || true

# Поднять tun0 если уже существует
"$ROOT/scripts/setup_tun.sh" "$IFACE" "$TUN_IP" || true
ip route replace "${CLIENT_IP}/32" dev "$IFACE" 2>/dev/null || true

echo "=== Lab готов ==="
echo "  client ns:  $CLIENT_NS ($CLIENT_IP)"
echo "  host veth:  $VETH_H ($HOST_VETH_IP)"
echo "  tun:        $IFACE ($TUN_IP)"
echo ""
echo "Пример: ip netns exec $CLIENT_NS ping -c1 $TUN_IP"
