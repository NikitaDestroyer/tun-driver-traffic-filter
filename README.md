# TUN Traffic Filter — единый комплекс

Программный комплекс на базе **TUN-драйвера Linux**: виртуальный интерфейс `tun0`, перехват и фильтрация IP-трафика в userspace, обнаружение VPN на том же интерфейсе с выводом в `dmesg`.

Архитектура: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)  
Тесты: [docs/TEST_PLAN.md](docs/TEST_PLAN.md)

## Быстрый старт

```bash
make
sudo ./scripts/start.sh          # lab + tund + kernel module
sudo ./scripts/test_all.sh       # автопроверка
sudo ./scripts/demo_traffic.sh   # демо: ICMP/UDP/TCP + 3 VPN
sudo dmesg | grep tun_vpn_detect # VPN-события
sudo ./scripts/stop.sh
```

## Компоненты

| Компонент | Назначение |
|-----------|------------|
| **tund** | TUN read/write, парсинг, `rules.conf`, лог ACCEPT/BLOCK |
| **tun_vpn_detect.ko** | VPN на `tun0`, NEW flow → workqueue → dmesg |
| **scripts/** | lab (netns), start/stop, тесты |

Фильтрация — **только** в userspace. Ядро **не** дублирует правила.

## Сборка

```bash
make
# build/tund, build/tun_vpn_detect.ko
```

Требования: Linux, `gcc`, `make`, `linux-headers-$(uname -r)`, `ip`, `nc`.

## tund

```bash
sudo ./build/tund [-c rules.conf] [-l logfile] [-i tun0] [-q]
```

| Флаг | Описание |
|------|----------|
| `-c` | Файл правил |
| `-l` | Лог (default `/tmp/tund.log`) |
| `-i` | Имя TUN |
| `-q` | Логировать только BLOCK |

## Правила (`config/rules.conf`)

```
BLOCK_PROTO ICMP
# BLOCK_DST_PORT 22
# BLOCK_SRC_IP 10.0.0.99
```

## Kernel module

Параметры:

| Параметр | Default | Описание |
|----------|---------|----------|
| `iface` | tun0 | TUN-интерфейс |
| `lab_if` | veth-h | Lab veth (inbound к tun IP) |
| `tun_ip` | 10.0.0.1 | IP tun для inbound-детекта |
| `dropped_events` | ro | Потерянные события очереди |

## Структура

```
├── kernel/
│   ├── tun_vpn_detect.c
│   └── vpn_signatures.h
├── src/                 # tund
├── scripts/             # start, stop, lab, test_*
├── config/rules.conf
└── docs/
    ├── ARCHITECTURE.md
    ├── TEST_PLAN.md
    ├── VPN_SIGNATURES.md
    └── ZADANIE.md
```

## Пример вывода

**/tmp/tund.log:**

```
[2026-05-28 12:00:01] BLOCK ICMP 10.0.0.2:0 -> 10.0.0.1:0 rule=BLOCK_PROTO ICMP
```

**dmesg:**

```
tun_vpn_detect: NEW VPN [WireGuard] 10.0.0.2:54321 -> 10.0.0.1:51820 proto=UDP
```

**IPv4 only.**
