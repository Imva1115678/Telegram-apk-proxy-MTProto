"""Живая проверка MTProto-прокси.

Проверка честная: через прокси делается настоящее начало авторизации
в Telegram (запрос req_pq_multi). Если Telegram ответил resPQ с нашим nonce —
прокси точно рабочий. Это надёжнее, чем просто «порт открыт».

Виды ключей (secret):
  * обычный — 32 hex-символа
  * dd...  — со случайным дополнением
  * ee...  — Fake TLS: соединение выглядит как HTTPS к обычному сайту
"""

import hashlib
import hmac
import os
import random
import socket
import struct
import threading
import time

from . import x25519
from .aes import AesCtr

DC_ID = 2
REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463
TAG_INTERMEDIATE = 0xEEEEEEEE
TAG_PADDED = 0xDDDDDDDD

# Тесты включают это, чтобы проверить именно тот AES, что работает на телефоне.
PURE_AES = False

_BAD_STARTS = (b"HEAD", b"POST", b"GET ", b"OPTI", b"PVrG",
               b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd", b"\x16\x03\x01\x02")


class CheckError(Exception):
    pass


class Result(object):
    __slots__ = ("ok", "ping_ms", "error")

    def __init__(self, ok, ping_ms=None, error=""):
        self.ok = ok
        self.ping_ms = ping_ms
        self.error = error

    def __repr__(self):
        return "Result(ok=%r, ping_ms=%r, error=%r)" % (self.ok, self.ping_ms, self.error)


def split_secret(secret_hex):
    """-> (ключ 16 байт, режим, домен для Fake TLS)"""
    raw = bytes.fromhex(secret_hex)
    if len(raw) == 16:
        return raw, "classic", None
    if len(raw) == 17 and raw[0] == 0xDD:
        return raw[1:17], "secure", None
    if len(raw) > 17 and raw[0] == 0xEE:
        return raw[1:17], "tls", raw[17:]
    raise CheckError("непонятный ключ")


def _ctr(key, iv):
    return AesCtr(key, iv, pure=PURE_AES)


# --------------------------------------------------------------------------
#  Fake TLS: ClientHello как у обычного браузера + подпись секретом
# --------------------------------------------------------------------------

def _grease_values(n):
    vals = []
    while len(vals) < n:
        b = (random.randrange(16) << 4) | 0x0A
        v = bytes([b, b])
        if v not in vals:
            vals.append(v)
    return vals


def _ext(ext_type, data):
    return ext_type + len(data).to_bytes(2, "big") + data


def build_client_hello(key16, domain, now=None):
    """-> (запись TLS ровно 517 байт, client_random как отправлен)"""
    g = _grease_values(5)
    sni = b"\x00" + len(domain).to_bytes(2, "big") + domain
    groups = g[2] + b"\x00\x1d\x00\x17\x00\x18"
    alpn = b"\x02h2\x08http/1.1"
    sigs = bytes.fromhex("0403 0804 0401 0503 0805 0501 0806 0601")
    shares = g[2] + b"\x00\x01\x00" + b"\x00\x1d\x00\x20" + x25519.public_key()
    versions = g[3] + b"\x03\x04\x03\x03"
    ext = b"".join([
        _ext(g[1], b""),
        _ext(b"\x00\x00", len(sni).to_bytes(2, "big") + sni),
        _ext(b"\x00\x17", b""),
        _ext(b"\xff\x01", b"\x00"),
        _ext(b"\x00\x0a", len(groups).to_bytes(2, "big") + groups),
        _ext(b"\x00\x0b", b"\x01\x00"),
        _ext(b"\x00\x23", b""),
        _ext(b"\x00\x10", len(alpn).to_bytes(2, "big") + alpn),
        _ext(b"\x00\x05", b"\x01\x00\x00\x00\x00"),
        _ext(b"\x00\x0d", len(sigs).to_bytes(2, "big") + sigs),
        _ext(b"\x00\x12", b""),
        _ext(b"\x00\x33", len(shares).to_bytes(2, "big") + shares),
        _ext(b"\x00\x2d", b"\x01\x01"),
        _ext(b"\x00\x2b", bytes([len(versions)]) + versions),
        _ext(b"\x00\x1b", b"\x02\x00\x02"),
        _ext(g[4], b"\x00"),
    ])
    ciphers = g[0] + bytes.fromhex(
        "1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035")
    head = (b"\x03\x03" + b"\x00" * 32 + b"\x20" + os.urandom(32)
            + len(ciphers).to_bytes(2, "big") + ciphers + b"\x01\x00")
    # добиваем расширением padding до 512 байт (как Telegram)
    used = 4 + len(head) + 2 + len(ext)
    pad = 512 - used - 4
    if pad >= 0:
        ext += _ext(b"\x00\x15", b"\x00" * pad)
    body = head + len(ext).to_bytes(2, "big") + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    digest = hmac.new(key16, record, hashlib.sha256).digest()
    ts = int(now if now is not None else time.time()).to_bytes(4, "little")
    digest = digest[:28] + bytes(a ^ b for a, b in zip(digest[28:], ts))
    record = record[:11] + digest + record[43:]
    return record, digest


# --------------------------------------------------------------------------
#  Соединения
# --------------------------------------------------------------------------

class _Conn(object):
    def __init__(self, sock, deadline):
        self.sock = sock
        self.deadline = deadline

    def _arm(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout("deadline")
        self.sock.settimeout(left)

    def send(self, data):
        self._arm()
        self.sock.sendall(data)

    def recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            self._arm()
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise CheckError("прокси оборвал соединение")
            buf += chunk
        return bytes(buf)


class _TlsConn(_Conn):
    """Поток внутри поддельного TLS (секреты ee...)."""

    def __init__(self, sock, deadline, key16, domain):
        _Conn.__init__(self, sock, deadline)
        self._buf = b""
        self._first = True
        hello, client_digest = build_client_hello(key16, domain)
        _Conn.send(self, hello)
        records = []
        while True:
            rec = self._record()
            kind = rec[0]
            if kind == 0x15:
                raise CheckError("ключ не подошёл")
            if not records and kind != 0x16:
                raise CheckError("странный ответ сервера")
            if kind not in (0x14, 0x16, 0x17) or len(records) > 6:
                raise CheckError("странный ответ сервера")
            records.append(rec)
            if kind == 0x17:
                break
        whole = b"".join(records)
        if len(whole) < 43:
            raise CheckError("странный ответ сервера")
        zeroed = whole[:11] + b"\x00" * 32 + whole[43:]
        expected = hmac.new(key16, client_digest + zeroed, hashlib.sha256).digest()
        if not hmac.compare_digest(whole[11:43], expected):
            # так отвечает настоящий сайт: ключ устарел или это не прокси
            raise CheckError("ключ не подошёл")

    def _record(self):
        hdr = _Conn.recv_exact(self, 5)
        length = int.from_bytes(hdr[3:5], "big")
        if length > 18432:
            raise CheckError("странный ответ сервера")
        return hdr + _Conn.recv_exact(self, length)

    def send(self, data):
        out = []
        if self._first:
            out.append(b"\x14\x03\x03\x00\x01\x01")
            self._first = False
        for i in range(0, len(data), 16384):
            chunk = data[i:i + 16384]
            out.append(b"\x17\x03\x03" + len(chunk).to_bytes(2, "big") + chunk)
        _Conn.send(self, b"".join(out))

    def recv_exact(self, n):
        while len(self._buf) < n:
            rec = self._record()
            if rec[0] == 0x17:
                self._buf += rec[5:]
            elif rec[0] != 0x14:
                raise CheckError("прокси оборвал соединение")
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


# --------------------------------------------------------------------------
#  Obfuscated2 + запрос к Telegram
# --------------------------------------------------------------------------

def obfuscated_init(key16, tag, dc=DC_ID):
    """-> (64 байта для отправки, шифратор, дешифратор)"""
    while True:
        init = bytearray(os.urandom(64))
        if init[0] == 0xEF or bytes(init[0:4]) in _BAD_STARTS or init[4:8] == b"\x00\x00\x00\x00":
            continue
        break
    init[56:60] = struct.pack("<I", tag)
    init[60:62] = struct.pack("<h", dc)
    init = bytes(init)
    rev = init[8:56][::-1]
    enc = _ctr(hashlib.sha256(init[8:40] + key16).digest(), init[40:56])
    dec = _ctr(hashlib.sha256(rev[0:32] + key16).digest(), rev[32:48])
    encrypted = enc.update(init)
    return init[:56] + encrypted[56:64], enc, dec


def _msg_id():
    t = time.time()
    return (int(t) << 32) | (int((t - int(t)) * 4294967296.0) & 0xFFFFFFFC)


def req_pq_multi(nonce):
    data = struct.pack("<I", REQ_PQ_MULTI) + nonce
    return b"\x00" * 8 + struct.pack("<q", _msg_id()) + struct.pack("<i", len(data)) + data


def frame(payload, padded):
    if padded:
        payload += os.urandom(random.randrange(4))
    return struct.pack("<I", len(payload)) + payload


def check(proxy, timeout=7.0):
    """Проверяет один прокси. Никогда не бросает исключений -> Result."""
    try:
        key16, mode, domain = split_secret(proxy.secret)
    except (CheckError, ValueError):
        return Result(False, error="непонятный ключ")
    deadline = time.monotonic() + timeout
    sock = None
    try:
        try:
            sock = socket.create_connection((proxy.server, proxy.port), timeout=min(timeout, 5.0))
        except socket.gaierror:
            return Result(False, error="адрес не найден")
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if mode == "tls":
            conn = _TlsConn(sock, deadline, key16, domain)
        else:
            conn = _Conn(sock, deadline)
        tag = TAG_INTERMEDIATE if mode == "classic" else TAG_PADDED
        init, enc, dec = obfuscated_init(key16, tag)
        nonce = os.urandom(16)
        packet = frame(req_pq_multi(nonce), padded=(tag == TAG_PADDED))
        started = time.monotonic()
        conn.send(init + enc.update(packet))
        length = struct.unpack("<I", dec.update(conn.recv_exact(4)))[0]
        if length == 4:
            code = struct.unpack("<i", dec.update(conn.recv_exact(4)))[0]
            return Result(False, error="Telegram ответил ошибкой %d" % code)
        if length < 40 or length > 8192:
            return Result(False, error="Telegram не ответил")
        body = dec.update(conn.recv_exact(length))
        rtt = time.monotonic() - started
        if (body[0:8] != b"\x00" * 8 or struct.unpack("<I", body[20:24])[0] != RES_PQ
                or body[24:40] != nonce):
            return Result(False, error="Telegram не ответил")
        return Result(True, ping_ms=max(1, int(round(rtt * 1000))))
    except CheckError as e:
        return Result(False, error=str(e))
    except socket.timeout:
        return Result(False, error="не отвечает")
    except ConnectionRefusedError:
        return Result(False, error="соединение отклонено")
    except OSError:
        return Result(False, error="нет соединения")
    except Exception:  # на всякий случай: проверка не должна ронять приложение
        return Result(False, error="ошибка проверки")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def check_many(proxies, on_result, workers=24, timeout=7.0, stop_event=None, retry_ok=True):
    """Проверяет список в несколько потоков, в порядке списка.

    on_result(proxy, result) вызывается из рабочих потоков.
    Если раньше работавший прокси не ответил, пробуем ещё раз —
    чтобы одна потерянная проверка не выкидывала его из списка.
    """
    items = list(proxies)
    if not items:
        return
    lock = threading.Lock()
    pos = [0]

    def worker():
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            with lock:
                if pos[0] >= len(items):
                    return
                p = items[pos[0]]
                pos[0] += 1
            res = check(p, timeout)
            if not res.ok and retry_ok and p.status == "ok":
                res = check(p, timeout)
            try:
                on_result(p, res)
            except Exception:
                pass

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(workers, len(items)))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
