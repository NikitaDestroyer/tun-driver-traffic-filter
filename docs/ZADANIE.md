# Задание (минимальная реализация)

## Что сделано в проекте

| Требование | Реализация |
|------------|------------|
| TUN-интерфейс | `src/tun_iface.c` — `/dev/net/tun`, интерфейс `tun0` |
| Перехват IP-трафика | `src/main.c` — read/write пакетов |
| Парсинг TCP/UDP/ICMP | `src/packet_parser.c` |
| Фильтрация | `src/filter.c` + `config/rules.conf` |
| Лог без вывода в hot path | `src/log_queue.c` — очередь + поток |
| 3 VPN-сигнатуры | `kernel/tun_vpn_detect.c` — WireGuard, OpenVPN, IKE |
| Вывод в консоль ядра | `printk` только в `log_work_handler` (workqueue) |
| Не printk при фильтрации | hook возвращает `NF_DROP` без логов |

## VPN-сигнатуры (упрощённые)

1. **WireGuard** — UDP, порт 51820 (src или dst)
2. **OpenVPN** — TCP/UDP 1194 или opcode 1–8 в UDP payload
3. **IKE/IPsec** — UDP 500 или 4500

## Как сдать отчёт

Скриншоты: `ip addr`, работа `tund`, `dmesg` с `NEW VPN`, файл `/tmp/tund.log`.
