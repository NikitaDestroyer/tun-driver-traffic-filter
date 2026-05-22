# TUN-драйвер: мониторинг и фильтрация трафика

Минимальный учебный проект: userspace-демон на TUN + kernel-модуль для
обнаружения VPN-сигнатур и вывода в `dmesg` (без `printk` в hot path фильтрации).

## Требования

- Linux (Ubuntu 22.04 / Debian 12 / WSL2 с ядром Linux)
- `gcc`, `make`, заголовки ядра: `sudo apt install build-essential linux-headers-$(uname -r)`

## Сборка

```bash
make
```

## Запуск (два терминала)

**Терминал 1 — kernel-модуль:**

```bash
sudo make load-kmod
sudo dmesg -w
```

**Терминал 2 — TUN-демон:**

```bash
sudo ./scripts/setup_tun.sh
sudo ./build/tund -c config/rules.conf
```

## Тест VPN-детекта в ядре

Трафик с типичными портами VPN увидит модуль (см. `dmesg`):

- WireGuard: UDP 51820
- OpenVPN: UDP/TCP 1194
- IKE/IPsec: UDP 500 / 4500

Пример (с другой машины или `nc`):

```bash
# имитация «нового» UDP на 51820
nc -u 127.0.0.1 51820
```

## Остановка

```bash
sudo ./build/tund -s          # если запущен
sudo make unload-kmod
sudo ./scripts/teardown_tun.sh
```

## Структура

```
├── kernel/tun_vpn_detect.c   # netfilter, VPN-сигнатуры, workqueue → printk
├── src/                      # userspace TUN-демон
├── config/rules.conf
├── scripts/
└── Makefile
```
