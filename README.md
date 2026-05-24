# TUN-драйвер: мониторинг и фильтрация трафика

Программный комплекс на базе TUN-драйвера Linux: userspace-демон перехватывает IP-пакеты через виртуальный интерфейс, а kernel-модуль обнаруживает VPN-сигнатуры в сетевом стеке. Логирование вынесено из «горячего пути» фильтрации — в userspace через очередь и поток, в ядре через workqueue.

Подробное техническое описание модулей: [docs/REPORT_ON_MODULES.md](docs/REPORT_ON_MODULES.md).

## Возможности

### Userspace-демон (`tund`)

- Создание и работа с виртуальным TUN-интерфейсом (`/dev/net/tun`, режим `IFF_TUN | IFF_NO_PI`).
- Перехват IPv4-пакетов в реальном времени: чтение из TUN, фильтрация, запись обратно или отбрасывание.
- Парсинг заголовков TCP, UDP и ICMP (адреса, порты, флаги TCP, длина пакета).
- Фильтрация по правилам из конфигурационного файла:
  - `BLOCK_PROTO` — блокировка по протоколу (TCP / UDP / ICMP);
  - `BLOCK_DST_PORT` — блокировка по порту назначения;
  - `BLOCK_SRC_IP` — блокировка по IP источника.
- Асинхронное логирование: события ACCEPT/BLOCK ставятся в очередь и выводятся отдельным потоком (в stderr и файл), без `printf` в цикле обработки пакетов.
- Статистика принятых и отброшенных пакетов при завершении.

### Kernel-модуль (`tun_vpn_detect.ko`)

- Перехват IPv4-трафика через Netfilter (`NF_INET_LOCAL_OUT`, `NF_INET_PRE_ROUTING`).
- Обнаружение сигнатур трёх VPN-решений:
  - **WireGuard** — UDP 51820/UDP;
  - **OpenVPN** — 1194/TCP или UDP, либо opcode 1–8 в UDP payload;
  - **IKE/IPsec** — 500/UDP или 4500/UDP.
- Дедупликация: сообщение о «новом подключении» выводится один раз на пару (src, dst, sport, dport, proto).
- Отложенный вывод в `dmesg`: `printk` только в обработчике workqueue, не в hook-функции Netfilter.
- Опциональная фильтрация ICMP без логирования (параметр модуля `block_icmp`, по умолчанию включён).

## Требования

- Linux (Ubuntu 22.04 / Debian 12 / WSL2 с ядром Linux)
- `gcc`, `make`, заголовки ядра: `sudo apt install build-essential linux-headers-$(uname -r)`
- Утilities: `ip`, `nc` (для тестов)

## Сборка

```bash
make
```

Собираются:

- `build/tund` — userspace-демон;
- `build/tun_vpn_detect.ko` — kernel-модуль.

## Использование

### Быстрый старт (два терминала)

**Терминал 1 — kernel-модуль и мониторинг ядра:**

```bash
sudo make load-kmod
sudo dmesg -w
```

**Терминал 2 — TUN-демон:**

```bash
sudo ./scripts/setup_tun.sh
sudo ./build/tund -c config/rules.conf
```

Демон требует права root. После запуска пакеты, проходящие через `tun0`, анализируются и фильтруются; лог пишется в `/tmp/tund.log` и stderr.

### Параметры демона

```bash
sudo ./build/tund [-c rules.conf] [-l logfile] [-i tun_name]
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `-c` | Путь к файлу правил фильтрации | `config/rules.conf` |
| `-l` | Путь к файлу лога | `/tmp/tund.log` |
| `-i` | Имя TUN-интерфейса | `tun0` |

### Настройка TUN-интерфейса

Скрипт поднимает интерфейс и назначает адрес:

```bash
sudo ./scripts/setup_tun.sh [iface] [ip] [mask]
# по умолчанию: tun0, 10.0.0.1, 255.255.255.0
```

### Правила фильтрации

Файл `config/rules.conf` — по одному правилу на строку. Применяется **первое совпадение**:

```
# BLOCK_PROTO ICMP | TCP | UDP
# BLOCK_DST_PORT 22
# BLOCK_SRC_IP 192.168.1.100

BLOCK_PROTO ICMP
```

Строки с `#` и пустые игнорируются.

### Тест VPN-детекта в ядре

Автоматический тест (модуль должен быть загружен):

```bash
sudo ./scripts/test_vpn_detect.sh
```

Или вручную — трафик на типичные VPN-порты (см. `dmesg`):

```bash
nc -u 127.0.0.1 51820   # WireGuard
nc -u 127.0.0.1 1194    # OpenVPN
nc -u 127.0.0.1 500     # IKE/IPsec
```

### Параметры kernel-модуля

```bash
# Отключить блокировку ICMP в hook
echo 0 | sudo tee /sys/module/tun_vpn_detect/parameters/block_icmp
```

### Остановка

```bash
# Ctrl+C в терминале с tund

sudo make unload-kmod
sudo ./scripts/teardown_tun.sh
```

## Структура проекта

```
├── kernel/tun_vpn_detect.c   # Netfilter hook, VPN-сигнатуры, workqueue → printk
├── src/                      # userspace TUN-демон
│   ├── main.c                # точка входа, главный цикл
│   ├── tun_iface.c           # работа с /dev/net/tun
│   ├── packet_parser.c       # разбор IPv4/TCP/UDP/ICMP
│   ├── filter.c              # движок правил
│   └── log_queue.c           # очередь логов + поток
├── config/rules.conf         # правила фильтрации
├── scripts/                  # setup/teardown/test
├── docs/
│   ├── ZADANIE.md            # постановка задачи
│   └── REPORT_ON_MODULES.md  # техническое описание модулей
└── Makefile
```

## Пример вывода

**Userspace (stderr / `/tmp/tund.log`):**

```
[2026-05-25 12:00:01] BLOCK ICMP 10.0.0.2:0 -> 10.0.0.1:0 rule=BLOCK_PROTO ICMP
[2026-05-25 12:00:02] ACCEPT TCP 10.0.0.2:54321 -> 10.0.0.1:80 rule=-
```

**Kernel (`dmesg`):**

```
tun_vpn_detect: NEW VPN [WireGuard] 127.0.0.1:54321 -> 127.0.0.1:51820 proto=UDP
```
