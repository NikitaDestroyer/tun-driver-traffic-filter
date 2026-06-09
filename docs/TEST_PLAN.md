# План тестирования

Единый комплекс: весь трафик lab идёт через `tun0`. Требуется **Linux**, **root**, `make`, `ip`, `nc`.

## Подготовка

```bash
make
sudo ./scripts/start.sh
```

## 1. Фильтрация (userspace)

```bash
sudo ./scripts/test_tun_filter.sh
```

**Ожидание** в `/tmp/tund.log`:

```text
[...] BLOCK ICMP 10.0.0.2:0 -> 10.0.0.1:0 rule=BLOCK_PROTO ICMP
```

(При `BLOCK_PROTO ICMP` в `config/rules.conf`.)

**Ручная проверка:**

```bash
ip netns exec tun_lab_client ping -c1 10.0.0.1
grep BLOCK /tmp/tund.log | tail -3
```

## 2. VPN-детект (ядро, через tun0)

```bash
sudo ./scripts/test_vpn_detect.sh
```

**Ожидание** в `dmesg`:

```text
tun_vpn_detect: NEW VPN [WireGuard] 10.0.0.2:... -> 10.0.0.1:51820 proto=UDP
```

**Важно:** трафик с `tun_lab_client`, не `127.0.0.1` без lab.

## 3. Демонстрация разного трафика

```bash
sudo ./scripts/demo_traffic.sh
```

Показывает BLOCK/ACCEPT для ICMP, UDP (53/9999), TCP (22/80) в `/tmp/tund.log` и три типа VPN в `dmesg`. Правила: `config/rules.demo.conf`. После прогона восстанавливает `rules.conf` и `-q`.

## 4. Полный прогон

```bash
sudo ./scripts/test_all.sh
```

## 5. Остановка

```bash
sudo ./scripts/stop.sh
```

## 6. Параметры модуля

```bash
cat /sys/module/tun_vpn_detect/parameters/iface
cat /sys/module/tun_vpn_detect/parameters/dropped_events
```

## Соответствие заданию

| Требование | Проверка |
|------------|----------|
| TUN-интерфейс | `ip addr show tun0` после start |
| Перехват IP | записи в `/tmp/tund.log` |
| Фильтрация | BLOCK по rules.conf |
| 3 VPN | 3 типа в dmesg после test_vpn_detect |
| dmesg без hot path | printk только в workqueue (см. ARCHITECTURE.md) |
| Стороны + порты | формат `src:port -> dst:port` |
