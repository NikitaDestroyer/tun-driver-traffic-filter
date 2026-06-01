# Отчёт о реализации

## Архитектура

Единый комплекс вокруг `tun0`: lab направляет трафик клиента (`10.0.0.2`) на TUN; `tund` фильтрует; `tun_vpn_detect.ko` детектирует VPN на том же интерфейсе.

Подробнее: [ARCHITECTURE.md](ARCHITECTURE.md).

## Изменения (unified)

1. **Один data plane** — `scripts/setup_lab.sh`, маршруты, netns `tun_lab_client`.
2. **Фильтрация только userspace** — удалён `block_icmp` из kernel-модуля.
3. **VPN только на tun0** — параметры `iface`, `lab_if`, `tun_ip`.
4. **Очередь событий kfifo** — без потери одного pending-события.
5. **Сигнатуры** — `vpn_signatures.h`, `skb_copy_bits`.
6. **Метрики tund** — bytes, parse_skip, log_dropped, rule hits.

## Ограничения

- IPv4 only.
- Lab обязателен для демонстрации VPN через TUN.
- Эвристики VPN упрощённые (курсовой уровень).

## Тесты

См. [TEST_PLAN.md](TEST_PLAN.md).

```bash
sudo ./scripts/test_all.sh
```

## Результаты

После `test_all.sh`:

- `/tmp/tund.log` — BLOCK/ACCEPT с `10.0.0.2` → `10.0.0.1`.
- `dmesg` — `NEW VPN [...]` для WireGuard/OpenVPN/IKE.
