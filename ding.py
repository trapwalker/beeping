#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy>=1.24", "sounddevice>=0.4.6"]
# ///
"""ding — классический ping, который ещё и слышно.

CLI-флаги совместимы с классическим ping: getopt-стиль (кластеризация -qc5,
присоединённые значения -c5), семантика BSD ping на macOS (iputils на Linux),
GNU long-опции. Вывод — в формате ping своей платформы. Коды выхода:
0 — был хотя бы один ответ, 1 — ответов нет, 2 — ошибка запуска.

Туда — «пик», обратно — «пук»; пауза = RTT, потеря = «пик» без «пука».
Звук в ding есть всегда — флагами он не отключается (звук не пишется
в stdout и не мешает парсингу вывода).
"""

from __future__ import annotations

import random
import select
import signal
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace

try:
    import numpy as np
    import sounddevice as sd
except ImportError as e:  # запущено без uv
    sys.exit(f"не хватает зависимостей ({e}) — запускай через uv: uv run {sys.argv[0]}")

SR = 44100
IS_MAC = sys.platform == "darwin"

# --- звук ---------------------------------------------------------------


def tone(f0: float, f1: float, dur: float, vol: float) -> np.ndarray:
    """Синус с глиссандо f0→f1 и короткими фейдами, моно float32."""
    n = int(dur * SR)
    phase = 2.0 * np.pi * np.cumsum(np.linspace(f0, f1, n)) / SR
    env = np.ones(n)
    k = max(1, int(0.006 * SR))
    env[:k] = np.linspace(0.0, 1.0, k)
    env[-k:] = np.linspace(1.0, 0.0, k)
    return (np.sin(phase) * env * vol).astype(np.float32)


# «пик» — короткий высокий тон; «пук» — низкий, съезжающий вниз («бульк»)
PICK = tone(1568, 1568, 0.050, 0.40)
PUK = tone(700, 320, 0.110, 0.55)


class Mixer:
    """Одновременное воспроизведение налагающихся тонов без обрезания."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pos = 0                  # сколько сэмплов уже отдано в колонки
        self._events: list[list] = []  # [start, samples]
        try:
            self.stream = sd.OutputStream(
                samplerate=SR, channels=1, dtype="float32",
                blocksize=0, latency="low", callback=self._cb,
            )
        except OSError as e:
            sys.exit(f"ding: не удалось открыть аудиовыход: {e}")
        self.stream.start()

    def play(self, samples: np.ndarray) -> None:
        with self._lock:
            if len(self._events) > 64:  # защита от лавины тонов при -f
                del self._events[: len(self._events) - 64]
            self._events.append([self._pos + int(0.015 * SR), samples])

    def _cb(self, out, frames, t, status) -> None:
        try:
            out[:] = 0.0
            with self._lock:
                base = self._pos
                self._pos += frames
                for start, arr in self._events:
                    i0 = max(base - start, 0)
                    i1 = min(len(arr), base + frames - start)
                    if i1 > i0:
                        j0 = start + i0 - base
                        j1 = j0 + (i1 - i0)
                        out[j0:j1, 0] += arr[i0:i1]
                self._events = [ev for ev in self._events
                                if ev[0] + len(ev[1]) > self._pos]
            np.clip(out, -1.0, 1.0, out=out)
        except Exception:
            pass  # звук не должен ронять пинг


# --- ICMP / ICMPv6 ------------------------------------------------------


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_echo(fam: str, ident: int, seq: int, payload: bytes) -> bytes:
    """v6: чексумму считает ядро (IPV6_CHECKSUM, offset 2)."""
    if fam == "6":
        return struct.pack("!BBHHH", 128, 0, 0, ident, seq) + payload
    pkt = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    return struct.pack("!BBHHH", 8, 0, checksum(pkt), ident, seq) + payload


def open_icmp(v6: bool):
    """SOCK_DGRAM ICMP не требует root (macOS; Linux при ping_group_range).
    Возвращает (sock, is_raw): raw — это фоллбэк, там нужен sudo."""
    proto = socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP
    fam = socket.AF_INET6 if v6 else socket.AF_INET
    for t in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try:
            return socket.socket(fam, t, proto), t == socket.SOCK_RAW
        except OSError:
            continue
    sys.exit(
        "ding: не удалось открыть ICMP-сокет. Попробуй sudo, а на Linux:\n"
        '  sysctl -w net.ipv4.ping_group_range="0   2147483647"'
    )


def parse_reply(data: bytes):
    """→ (type, code, ident, seq) или None. SOCK_RAW несёт IP-заголовок спереди."""
    if data and data[0] >> 4 == 4:
        data = data[(data[0] & 0x0F) * 4:]
    if len(data) < 8:
        return None
    return data[0], data[1], *struct.unpack("!HH", data[4:8])


def parse_error_ref(data: bytes):
    """id/seq нашего пакета, вложенного в ICMP-ошибку."""
    body = data[8:]
    if len(body) >= 48 and body[0] >> 4 == 6:      # внутри исходный IPv6-пакет
        body = body[40:]
    elif body and body[0] >> 4 == 4:               # внутри исходный IPv4-пакет
        body = body[(body[0] & 0x0F) * 4:]
    if len(body) >= 8:
        return struct.unpack("!HH", body[4:8])
    return None


ERR_NAMES = {
    "4": {3: "Destination Net Unreachable", 11: "Time to live exceeded"},
    "6": {1: "Destination Unreachable", 2: "Packet Too Big",
          3: "Time Exceeded", 4: "Parameter Problem"},
}
ECHO_REQ = {"4": 8, "6": 128}
ECHO_REP = {"4": 0, "6": 129}

# --- CLI ----------------------------------------------------------------


def usage(code: int) -> None:
    t_desc = "timeout, s (BSD-style)" if IS_MAC else "ttl (iputils-style)"
    w_desc = "waittime, ms (BSD-style)" if IS_MAC else "timeout, s (iputils-style)"
    print(f"""Usage: ding [options] host

Options:
  -c count        send count packets, then exit (0 = forever)
  -i interval     seconds between sends (fractional ok)
  -s packetsize   data bytes, default 56 (like ping)
  -l preload      preloaded burst, then normal mode
  -f              flood: packets as fast as replies come or 100/s
  -p pattern      payload pattern, hex (up to 16 bytes, repeats)
  -t timeout      {t_desc}
  -w deadline     hard deadline, seconds, then exit
  -W waittime     per-reply wait: {w_desc}
  -a (and -A)     audible: BEL (\\a) in the output per reply
  -A (Linux)      adaptive: interval follows RTT
  -D              timestamps on every output line
  -n              numeric output, no names
  -o              exit after first reply
  -q              quiet: startup line + summary only (sound keeps going)
  -v              verbose
  -I iface|addr   bind to interface (macOS: IP_BOUND_IF) or source address
  -S srcaddr      source address
  -Q tos          set TOS/DSCP (int or 0x..)
  -r              bypass routing tables
  -b              allow pinging broadcast
  --ttl n         IP TTL (any platform)
  -4 / -6         force IPv4 / IPv6
  -h --help       this text

Sound (the whole point of ding): every send = «пик», every reply = «пук».
The gap between them is the RTT, losses are «пик» with no «пук».""")
    sys.exit(code)


def parse_args(argv: list[str]) -> SimpleNamespace:
    cfg = SimpleNamespace(
        host=None, count=0, interval=1.0, size=56, preload=0,
        deadline=None, wait=None, flood=False, numeric=False, quiet=False,
        verbose=False, bel=False, adaptive=False, timestamps=False,
        onefire=False, broadcast=False, dontroute=False, report_out=False,
        pattern_bytes=None, source=None, iface_name=None,
        tos=None, ttl=None, family=socket.AF_UNSPEC,
    )
    warns: list[str] = []

    def die(msg: str, code: int = 2) -> None:
        print(f"ding: {msg}", file=sys.stderr)
        sys.exit(code)

    def _int(v: str, flag: str) -> int:
        try:
            return int(v, 0)
        except ValueError:
            die(f"invalid value for {flag}: {v!r}")

    def _float(v: str, flag: str) -> float:
        try:
            return float(v)
        except ValueError:
            die(f"invalid value for {flag}: {v!r}")

    def apply_value(ch: str, v: str) -> None:
        if ch == "c":
            cfg.count = _int(v, "-c")
            if cfg.count < 0:
                die("count must be >= 0")
        elif ch == "i":
            cfg.interval = _float(v, "-i")
        elif ch == "s":
            cfg.size = _int(v, "-s")
        elif ch == "l":
            cfg.preload = _int(v, "-l")
        elif ch == "t":
            if IS_MAC:
                cfg.deadline = _float(v, "-t")
            else:
                cfg.ttl = _int(v, "-t")
        elif ch == "w":
            cfg.deadline = _float(v, "-w")
        elif ch == "W":
            cfg.wait = _float(v, "-W") / 1000.0 if IS_MAC else _float(v, "-W")
        elif ch == "I":
            cfg.iface_raw = v
        elif ch == "S":
            cfg.source = v
        elif ch == "p":
            if len(v) % 2 or any(c not in "0123456789abcdefABCDEF" for c in v):
                die("patterns must be specified as even-length hex digits")
            cfg.pattern_bytes = bytes.fromhex(v) or b"\x00"
        elif ch == "Q":
            cfg.tos = _int(v, "-Q")
        else:  # T, m, M — известные, но не поддержанные
            warns.append(f"flag -{ch} is not supported, ignored")

    def apply_bool(ch: str) -> None:
        if ch == "a":
            cfg.bel = True
        elif ch == "A":
            if IS_MAC:
                cfg.bel = True  # BSD-style: -A audible
            else:
                cfg.adaptive = True  # iputils-style: -A adaptive
        elif ch == "D":
            cfg.timestamps = True
        elif ch == "f":
            cfg.flood = True
        elif ch == "n":
            cfg.numeric = True
        elif ch == "q":
            cfg.quiet = True
        elif ch == "v":
            cfg.verbose = True
        elif ch == "r":
            cfg.dontroute = True
        elif ch == "b":
            cfg.broadcast = True
        elif ch == "o":
            cfg.onefire = True
        elif ch == "O":
            cfg.report_out = True
        elif ch == "4":
            cfg.family = socket.AF_INET
        elif ch == "6":
            cfg.family = socket.AF_INET6
        else:  # R, L, d, U — известные, но не поддержанные
            warns.append(f"flag -{ch} is not supported, ignored")

    LONG_VALUE = {"count": "c", "interval": "i", "size": "s", "packetsize": "s",
                  "preload": "l", "deadline": "w", "timeout": "t", "wait": "W",
                  "waittime": "W", "interface": "I", "source": "S",
                  "pattern": "p", "tos": "Q"}
    LONG_BOOL = {"flood": "f", "numeric": "n", "quiet": "q", "verbose": "v",
                 "audible": "a", "timestamps": "D", "broadcast": "b",
                 "dontroute": "r", "one-reply": "o", "outstanding": "O",
                 "adaptive": "A", "ipv4": "4", "ipv6": "6"}

    hosts: list[str] = []
    VALUE_SHORT = "cisltwWIpSQTmM"
    BOOL_SHORT = "aAbDfnqrvbo46OLRdU"
    i = 0
    args = list(argv)
    while i < len(args):
        a = args[i]
        if a == "--":
            hosts.extend(args[i + 1:])
            break
        if a.startswith("--"):
            key, _, val = a[2:].partition("=")
            if key == "help":
                usage(0)
            if key == "ttl":
                if not val:
                    i += 1
                    if i >= len(args):
                        die("--ttl requires an argument")
                    val = args[i]
                cfg.ttl = _int(val, "--ttl")
            elif key in LONG_VALUE:
                if not val:
                    i += 1
                    if i >= len(args):
                        die(f"--{key} requires an argument")
                    val = args[i]
                apply_value(LONG_VALUE[key], val)
            elif key in LONG_BOOL:
                apply_bool(LONG_BOOL[key])
            else:
                die(f"unrecognized option --{key} (try -h)")
            i += 1
            continue
        if len(a) > 1 and a[0] == "-":
            body = a[1:]
            j = 0
            while j < len(body):
                ch = body[j]
                if ch == "h":
                    usage(0)
                if ch in VALUE_SHORT:
                    v = body[j + 1:]
                    if not v:
                        i += 1
                        if i >= len(args):
                            die(f"option -{ch} requires an argument")
                        v = args[i]
                    apply_value(ch, v)
                    j = len(body)
                elif ch in BOOL_SHORT:
                    apply_bool(ch)
                    j += 1
                else:
                    die(f"invalid option -- '{ch}' (try -h)")
            i += 1
            continue
        hosts.append(a)
        i += 1

    if len(hosts) == 0:
        usage(2)
    if len(hosts) > 1:
        die("only one destination allowed")
    cfg.host = hosts[0]

    if cfg.family == socket.AF_UNSPEC:
        cfg.family = socket.AF_INET6 if ":" in cfg.host else socket.AF_INET

    if cfg.size < 0 or cfg.size > 65527:
        die(f"invalid packetsize {cfg.size}")
    if cfg.preload < 0:
        die("preload must be >= 0")
    if cfg.wait is not None and cfg.wait <= 0:
        die("waittime must be positive")
    if cfg.deadline is not None and cfg.deadline <= 0:
        die("deadline must be positive")
    if not cfg.flood and cfg.interval < 0.01:
        die("interval below 10 ms needs -f")
    if cfg.count and cfg.preload > cfg.count:
        cfg.preload = cfg.count
    cfg.iface_raw = getattr(cfg, "iface_raw", None)
    if cfg.iface_raw:
        if ":" in cfg.iface_raw:
            cfg.source = cfg.iface_raw  # IPv6-литерал
        else:
            try:
                socket.inet_aton(cfg.iface_raw)
                cfg.source = cfg.iface_raw  # IPv4-литерал
            except OSError:
                cfg.iface_name = cfg.iface_raw
    for w in warns:
        print(f"ding: {w}", file=sys.stderr)
    return cfg


# --- розетка ------------------------------------------------------------


def build_socket(cfg: SimpleNamespace, v6: bool):
    warns: list[str] = []
    sock, is_raw = open_icmp(v6)

    def so(level, opt, val, what):
        if opt is None:
            warns.append(f"{what}: not supported on this platform")
            return
        try:
            sock.setsockopt(level, opt, val)
        except OSError as e:
            warns.append(f"{what}: {e}")

    if cfg.iface_name:
        if v6:
            so(socket.IPPROTO_IPV6, getattr(socket, "IPV6_BOUND_IF", 125),
               socket.if_nametoindex(cfg.iface_name), f"-I {cfg.iface_name}")
        else:
            so(socket.IPPROTO_IP, getattr(socket, "IP_BOUND_IF", 25),
               socket.if_nametoindex(cfg.iface_name), f"-I {cfg.iface_name}")
    if cfg.source:
        try:
            sock.bind((cfg.source, 0))
        except OSError as e:
            warns.append(f"bind {cfg.source}: {e}")
    if cfg.broadcast:
        so(socket.SOL_SOCKET, socket.SO_BROADCAST, 1, "-b")
    if cfg.dontroute:
        so(socket.SOL_SOCKET, socket.SO_DONTROUTE, 1, "-r")
    if v6:
        if is_raw:  # на dgram-сокетах чексумму считает ядро (darwin: EPERM)
            so(socket.IPPROTO_ICMPV6, getattr(socket, "IPV6_CHECKSUM", 26), 2, "checksum")
        if cfg.tos is not None:
            so(socket.IPPROTO_IPV6, getattr(socket, "IPV6_TCLASS", None), cfg.tos, "-Q")
        if cfg.ttl is not None:
            so(socket.IPPROTO_IPV6, getattr(socket, "IPV6_UNICAST_HOPS", None),
               cfg.ttl, "ttl")
        hop_opts = [getattr(socket, "IPV6_RECVHOPLIMIT", None)]
        if IS_MAC:
            hop_opts += [37, 20]  # darwin: RFC3542 и RFC2292 версии
        set_hlim = False
        for opt in hop_opts:
            if opt is None:
                continue
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, opt, 1)
                set_hlim = True
                break
            except OSError:
                continue
        if not set_hlim:
            warns.append("hlim recv: not supported on this platform")
    else:
        if cfg.tos is not None:
            so(socket.IPPROTO_IP, socket.IP_TOS, cfg.tos, "-Q")
        if cfg.ttl is not None:
            so(socket.IPPROTO_IP, socket.IP_TTL, cfg.ttl, "ttl")
        so(socket.IPPROTO_IP, getattr(socket, "IP_RECVTTL", 24 if IS_MAC else None),
           1, "ttl recv")
    sock.setblocking(False)
    return sock, warns


def anc_ttl(anc: list) -> int | None:
    """TTL/hlim из ancillary: на linux — 4-байтовый int, на darwin — один
    байт. Уровень IP/IPv6 + короткий буфер однозначно указывают на TTL,
    т.к. других cmsg мы не просим."""
    for level, _typ, val in anc:
        if level not in (socket.IPPROTO_IP, socket.IPPROTO_IPV6):
            continue
        if len(val) == 4:
            try:
                return struct.unpack("i", val)[0]
            except struct.error:
                pass
        if len(val) == 1:
            return val[0]
    return None


# --- main ---------------------------------------------------------------


def main() -> None:
    cfg = parse_args(sys.argv[1:])
    v6 = cfg.family == socket.AF_INET6
    fam = "6" if v6 else "4"
    try:
        sockaddr = socket.getaddrinfo(cfg.host, None, cfg.family)[0][4]
    except OSError as e:
        print(f"ding: cannot resolve {cfg.host!r}: {e}", file=sys.stderr)
        sys.exit(2)
    ip = sockaddr[0].split("%")[0]

    sock, warns = build_socket(cfg, v6)
    for w in warns:
        print(f"ding: {w}", file=sys.stderr)

    ident = random.randrange(1, 0x10000)
    mixer = Mixer()

    sent = received = 0
    rtts: list[float] = []
    pending: dict[int, list] = {}   # seq → [t0(perf_counter), timer(monotonic)|None]
    expired: dict[int, float] = {}  # seq → t0 (снятые по -W; поздние ответы считаем)
    seq_next = 0
    preload_left = cfg.preload
    t_start = time.monotonic()
    deadline_at = t_start + cfg.deadline if cfg.deadline is not None else None
    next_send = t_start
    done_sending = False
    done_at = None
    stop = False

    if IS_MAC:  # классический BSD-заголовок
        print(f"PING {cfg.host} ({ip}): {cfg.size} data bytes", flush=True)
    else:       # iputils-заголовок
        print(f"PING {cfg.host} ({ip}) {cfg.size}({cfg.size + 28}) bytes of data.",
              flush=True)
    print("ding: «пик» туда, «пук» обратно; пауза = задержка. Ctrl+C — итоги.",
          file=sys.stderr, flush=True)

    if hasattr(signal, "SIGINFO"):  # Ctrl+T на macOS: промежуточная статистика
        def _info(_sig, _frm):
            print(f"ding: {sent} sent, {received} received, "
                  f"{len(pending)} in flight", file=sys.stderr, flush=True)
        try:
            signal.signal(signal.SIGINFO, _info)
        except Exception:
            pass

    def make_payload() -> bytes:
        pat = cfg.pattern_bytes or b"\x00"
        if cfg.size >= 8:  # как iputils: первые 8 байт — время отправки
            n = cfg.size - 8
            return struct.pack("!Q", time.perf_counter_ns()) + (pat * (n // len(pat) + 1))[:n]
        return (pat * (cfg.size // len(pat) + 1))[:cfg.size]

    def send_probe() -> None:
        nonlocal sent, seq_next
        try:
            sock.sendto(build_echo(fam, ident, seq_next, make_payload()), sockaddr)
        except OSError as e:
            print(f"ding: sendto: {e}", file=sys.stderr, flush=True)
            return
        sent += 1
        now2 = time.monotonic()
        if cfg.wait is not None:
            timer = now2 + cfg.wait
        elif cfg.report_out:
            timer = now2 + max(0.05, cfg.interval)
        else:
            timer = None
        pending[seq_next] = [time.perf_counter(), timer]
        if cfg.flood and not cfg.quiet:
            print(".", end="", flush=True)
        seq_next = (seq_next + 1) & 0xFFFF

    def handle(data: bytes, anc: list, src) -> None:
        nonlocal received, stop
        msg = parse_reply(data)
        if msg is None:
            return
        mtype, mcode, mid, mseq = msg
        src_ip = src[0].split("%")[0]
        if mid != ident or src_ip != ip:
            if cfg.verbose:
                print(f"ding: foreign ICMP type={mtype} code={mcode} from {src_ip}",
                      file=sys.stderr, flush=True)
            return
        if mtype == ECHO_REP[fam]:  # эхо-ответ
            e = pending.pop(mseq, None)
            t0 = e[0] if e is not None else expired.get(mseq)
            if t0 is None:
                if cfg.verbose:
                    print(f"ding: unexpected reply seq={mseq}", file=sys.stderr, flush=True)
                return
            rtt_ms = (time.perf_counter() - t0) * 1000.0
            received += 1
            rtts.append(rtt_ms)
            mixer.play(PUK)
            if cfg.wait is None or rtt_ms <= cfg.wait * 1000.0:
                ttl = anc_ttl(anc)
                if cfg.flood:
                    if not cfg.quiet:
                        print("\b" + ("\a" if cfg.bel else ""), end="", flush=True)
                else:
                    line = f"{cfg.size} bytes from {ip}: icmp_seq={mseq}"
                    if ttl is not None:
                        label = "hlim" if v6 else "ttl"
                        line += f" {label}={ttl}"
                    line += f" time={rtt_ms:.3f} ms" if IS_MAC else f" time={rtt_ms:.1f} ms"
                    if cfg.timestamps:
                        line = f"[{time.time():.3f}] " + line
                    if cfg.bel:
                        line += "\a"
                    if not cfg.quiet:
                        print(line, flush=True)
            elif cfg.verbose:
                print(f"ding: late reply seq={mseq} (counted, not printed)",
                      file=sys.stderr, flush=True)
            if cfg.onefire:
                stop = True
        elif mtype in ERR_NAMES[fam]:
            ref = parse_error_ref(data)
            if ref and ref[0] == ident and ref[1] in pending:
                pending.pop(ref[1])
                if not cfg.quiet:
                    print(f"From {ip}: icmp_seq={ref[1]} "
                          f"{ERR_NAMES[fam][mtype]}", flush=True)
        elif cfg.verbose:
            print(f"ding: ICMP type={mtype} code={mcode} from {ip}",
                  file=sys.stderr, flush=True)

    def drain() -> None:
        while True:
            try:
                data, anc, _flags, src = sock.recvmsg(2048, 512)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            handle(data, anc, src)

    def reap(now2: float) -> None:
        if cfg.wait is not None:
            for sq in [s for s, e in pending.items()
                       if e[1] is not None and now2 >= e[1]]:
                # BSD-семантика: молча уходит в потери, поздний ответ учтётся
                expired[sq] = pending.pop(sq)[0]
        elif cfg.report_out:
            for sq, e in list(pending.items()):
                if e[1] is not None and now2 >= e[1]:
                    print(f"no answer yet for icmp_seq={sq}", flush=True)
                    e[1] = now2 + max(0.05, cfg.interval)

    try:
        while True:
            now = time.monotonic()
            if done_sending:
                timeout = 0.05
            elif cfg.flood:
                timeout = max(0.0, min(next_send - now, 0.01))
            else:
                timeout = max(0.0, next_send - now)
            if pending and (cfg.wait is not None or cfg.report_out):
                nd = min(e[1] for e in pending.values())
                timeout = min(timeout, max(0.0, nd - now))
            ready, _, _ = select.select([sock], [], [], timeout)
            if ready:
                drain()
                if stop:
                    break
            now = time.monotonic()
            reap(now)
            if deadline_at is not None and now >= deadline_at:
                break  # как ping -t: выходим сразу, недождённые — потери
            if not done_sending:
                if cfg.flood:
                    want = (preload_left > 0 or not pending
                            or now >= next_send) and len(pending) < 100
                else:
                    want = preload_left > 0 or now >= next_send
                if want and (cfg.count == 0 or sent < cfg.count):
                    send_probe()
                    if preload_left > 0:
                        preload_left -= 1
                        if preload_left == 0:
                            next_send = now + cfg.interval
                    elif cfg.flood:
                        next_send = now + 0.01
                    else:
                        next_send = max(next_send + cfg.interval, now + 0.02)
                if cfg.count and sent >= cfg.count:
                    done_sending = True
                    done_at = now + max(1.0, cfg.interval)
            elif not pending or now >= done_at:
                break
    except KeyboardInterrupt:
        pass
    finally:
        try:
            mixer.stream.stop(); mixer.stream.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        if cfg.flood and not cfg.quiet:
            print(flush=True)
        elapsed = (time.monotonic() - t_start) * 1000
        lost = sent - received
        if IS_MAC:
            print(f"\n--- {cfg.host} ping statistics ---")
            print(f"{sent} packets transmitted, {received} packets received, "
                  f"{lost / sent * 100:.1f}% packet loss" if sent else
                  f"0 packets transmitted, 0 packets received, 100.0% packet loss")
            if rtts:
                mn, av, mx = min(rtts), sum(rtts) / len(rtts), max(rtts)
                var = sum((r - av) ** 2 for r in rtts) / len(rtts)
                print(f"round-trip min/avg/max/stddev = "
                      f"{mn:.3f}/{av:.3f}/{mx:.3f}/{var ** 0.5:.3f} ms")
        else:
            print(f"\n--- {cfg.host} ping statistics ---")
            print(f"{sent} packets transmitted, {received} received, "
                  f"{lost / sent * 100:g}% packet loss, time {elapsed:.0f}ms"
                  if sent else "0 packets transmitted, 0 received, 100% packet loss")
            if rtts:
                mn, av, mx = min(rtts), sum(rtts) / len(rtts), max(rtts)
                mdev = sum(abs(r - av) for r in rtts) / len(rtts)
                print(f"rtt min/avg/max/mdev = "
                      f"{mn:.3f}/{av:.3f}/{mx:.3f}/{mdev:.3f} ms")
        sys.exit(0 if received else 1)


if __name__ == "__main__":
    main()
