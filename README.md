# beeping

> **English TL;DR:** classic `ping` you can also *hear* — a high «пик» beep on
> every packet sent, a low «пук» on every reply. The gap between them is your
> RTT, a lost packet is a «пик» without its «пук». CLI-compatible with the
> classic `ping`. Run: `uv run beeping.py ya.ru` (or `pipx install beeping`).

Классический `ping`, который ещё и **слышно**: каждый отправленный пакет —
«пик», каждый ответ — «пук». Пауза между ними = RTT, потеря пакета — «пик»
без «пука». Задержку и её изменения видно на слух.

## Запуск

```bash
uv run beeping.py [параметры] host        # deps подтягиваются из PEP-723 шапки
uv run beeping.py ya.ru -i 0.5
```

Зависимости: `numpy`, `sounddevice`. Python ≥ 3.10. Права root не нужны
(dgram-ICMP): macOS 10.14+ из коробки; на Linux —
`sysctl -w net.ipv4.ping_group_range="0 2147483647"` либо `sudo`.

## Совместимость с классическим ping

CLI совместим с BSD ping на macOS и iputils ping на Linux: getopt-стиль
(кластеризация `-qc5`, присоединённые значения `-i0.5`), long-опции GNU,
пер-платформенная семантика `-t`/`-W`/`-A` — как у «родного» ping каждой ОС.
Вывод в stdout — в формате ping своей платформы (BSD-стиль на macOS,
iputils-стиль на Linux); служебные сообщения beeping идут в stderr.

| Флаг | Значение | Поддержка |
|---|---|---|
| `-c N` | стоп после N пакетов (0 = вечно) | ✅ |
| `-i SEC` | интервал, дробные | ✅ |
| `-s BYTES` | data bytes, default 56 (как у ping) | ✅ |
| `-l N` | предзагрузка N пакетов | ✅ |
| `-f` | flood: до 100/с, точки как у ping | ✅ |
| `-p HEX` | payload-паттерн (повторяется) | ✅ |
| `-t` | macOS: общий timeout (BSD) / Linux: TTL (iputils) | ✅ |
| `--ttl N` | TTL на любой платформе | ✅ |
| `-w SEC` | deadline | ✅ |
| `-W` | ожидание ответа: ms на macOS / сек на Linux | ✅ |
| `-a`, `-A` | BEL в выводе на ответ (macOS `-A` = audible, Linux `-A` = adaptive) | ✅ |
| `-D` | метки времени | ✅ |
| `-n`, `-q`, `-v`, `-o` | numeric / тихо / подроб / выход по 1-му ответу | ✅ |
| `-I iface\|addr`, `-S addr` | привязка к интерфейсу / адресу | ✅ |
| `-Q tos`, `-r`, `-b`, `--ttl` | TOS / bypass routing / broadcast | ✅ |
| `-4`, `-6` | IPv4 / IPv6 (ICMPv6) | ✅ |
| `-h`, `--help` | справка | ✅ |
| `-R`, `-m`, `-T`, `-L`, `-d`, `-U` | record route, mark, … | ⚠️ берутся, но игнорируются с warning в stderr |

Коды выхода, как у iputils ping: `0` — был хоть один ответ, `1` — ответов
нет, `2` — ошибка запуска (нераспознанный флаг, резолв, сокет). Работает и
`SIGINFO` (Ctrl+T на macOS): промежуточная статистика в stderr.

Кластеризация и long-опции: `ping -qc5 ya.ru` == `beeping -qc5 ya.ru` ==
`beeping --quiet --count 5 ya.ru`.

## Что не отключается

Звук. Это суть beeping: «пи́к»/«пук» всегда, любыми флагами. `-q` глушит только
текстовую выдачу; звук не пишется в stdout, поэтому парсеры вывода ping
работают как обычно.

## Примеры

```bash
uv run beeping.py ya.ru                 # по умолчанию: -i 1, -s 56
uv run beeping.py 1.1.1.1 -i 0.3        # джиттер слышнее
uv run beeping.py -f -c 50 ya.ru        # шторм пи́ков на потерях
uv run beeping.py -6 ::1                # IPv6
uv run beeping.py ya.ru -v              # подробности в stderr
```
