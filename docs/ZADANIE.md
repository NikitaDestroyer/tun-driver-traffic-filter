# Задание

Тема: «Разработка виртуального сетевого интерфейса с функциями мониторинга и фильтрации трафика на основе TUN-драйвера Linux».

## Требования

1. TUN — виртуальный интерфейс, перехват IP в реальном времени.
2. Анализ и фильтрация трафика.
3. Сигнатуры ≥ 3 VPN → сообщения о **новых** подключениях в **консоль ядра** (IP, порты).
4. **Не** выводить в консоль ядра во время фильтрации (hot path).

## Реализация (единый комплекс)

| Требование | Компонент | Как проверить |
|------------|-----------|---------------|
| TUN-интерфейс | `src/tun_iface.c`, `tund` | `ip addr show tun0` после `start.sh` |
| Перехват IP | `src/main.c` | записи в `/tmp/tund.log` |
| Парсинг TCP/UDP/ICMP | `src/packet_parser.c` | формат лога с портами |
| Фильтрация | `src/filter.c`, `config/rules.conf` | `test_tun_filter.sh` |
| Лог без hot path | `src/log_queue.c` | очередь + поток |
| 3 VPN-сигнатуры | `kernel/vpn_signatures.h` | `docs/VPN_SIGNATURES.md` |
| dmesg о NEW VPN | `kernel/tun_vpn_detect.c` | `test_vpn_detect.sh` |
| printk не в hook | workqueue `log_work_handler` | `docs/ARCHITECTURE.md` |
| Единый пайплайн tun0 | `scripts/setup_lab.sh`, параметры `iface` | `test_all.sh` |

## VPN-сигнатуры

См. [VPN_SIGNATURES.md](VPN_SIGNATURES.md).

## Запуск

```bash
sudo ./scripts/start.sh
sudo ./scripts/test_all.sh
sudo ./scripts/stop.sh
```
