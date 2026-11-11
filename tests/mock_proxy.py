"""Поддельный MTProto-прокси + «Telegram» для тестов (работает на 127.0.0.1).

Серверная сторона написана независимо от клиента и берёт AES из библиотеки
cryptography, поэтому тест по-настоящему проверяет клиентскую часть.

Режимы: ok | silent (молчит) | close (сразу закрывает) | real_site (как обычный сайт)
"""

import hashlib
import hmac
import os
import socket
import struct
import threading
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463


def ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError("client closed")
        buf += chunk
    return buf


class TlsReader(object):
    def __init__(self, conn):
        self.conn = conn
        self.buf = b""

    def read(self, n):
        while len(self.buf) < n:
            hdr = recv_exact(self.conn, 5)
            body = recv_exact(self.conn, int.from_bytes(hdr[3:5], "big"))
            if hdr[0] == 0x14:
                continue
            assert hdr[0] == 0x17, hdr
            self.buf += body
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


class RawReader(object):
    def __init__(self, conn):
        self.conn = conn

    def read(self, n):
        return recv_exact(self.conn, n)


class MockProxy(object):
    def __init__(self, secret_hex, mode="ok"):
        self.secret = bytes.fromhex(secret_hex)
        self.mode = mode
        self.errors = []
        self.seen = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(10)
            self._serve(conn)
        except Exception as e:  # записываем, тест посмотрит
            self.errors.append(repr(e))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _serve(self, conn):
        s = self.secret
        tls = len(s) > 17 and s[0] == 0xEE
        key = s[1:17] if len(s) >= 17 else s
        if self.mode == "close":
            return
        if self.mode == "silent":
            time.sleep(8)
            return
        if tls:
            hdr = recv_exact(conn, 5)
            assert hdr[:3] == b"\x16\x03\x01", hdr
            body = recv_exact(conn, int.from_bytes(hdr[3:5], "big"))
            hello = hdr + body
            self.seen.append(("hello_len", len(hello)))
            digest = hello[11:43]
            zeroed = hello[:11] + b"\x00" * 32 + hello[43:]
            expected = hmac.new(key, zeroed, hashlib.sha256).digest()
            x = bytes(a ^ b for a, b in zip(digest, expected))
            session_id = hello[44:76]
            if self.mode == "real_site" or x[:28] != b"\x00" * 28:
                # как настоящий сайт: «чужой» ServerHello без нашей подписи
                self._send_server_hello(conn, digest, session_id, fake=True)
                time.sleep(0.5)
                return
            ts = int.from_bytes(x[28:32], "little")
            assert abs(ts - time.time()) < 120, "clock skew"
            assert hello[43] == 0x20
            domain = s[17:]
            assert domain in hello, "SNI missing"
            self.seen.append(("sni", domain.decode()))
            self._send_server_hello(conn, digest, session_id)
            reader = TlsReader(conn)

            def send(data):
                conn.sendall(b"\x17\x03\x03" + len(data).to_bytes(2, "big") + data)
        else:
            reader = RawReader(conn)
            send = conn.sendall
        init = reader.read(64)
        dec = ctr(hashlib.sha256(init[8:40] + key).digest(), init[40:56])
        plain = dec.update(init)
        tag = plain[56:60]
        dc = struct.unpack("<h", plain[60:62])[0]
        self.seen.append(("tag", tag.hex()))
        self.seen.append(("dc", dc))
        if tag not in (b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd", b"\xef\xef\xef\xef"):
            return  # неверный ключ -> мусор -> закрываем, как настоящий прокси
        rev = init[8:56][::-1]
        enc = ctr(hashlib.sha256(rev[:32] + key).digest(), rev[32:48])
        ln = struct.unpack("<I", dec.update(reader.read(4)))[0]
        pkt = dec.update(reader.read(ln))
        assert pkt[0:8] == b"\x00" * 8
        assert struct.unpack("<i", pkt[16:20])[0] == 20
        assert struct.unpack("<I", pkt[20:24])[0] == REQ_PQ_MULTI
        self.seen.append(("padding", ln - 40))
        nonce = pkt[24:40]
        body = (struct.pack("<I", RES_PQ) + nonce + os.urandom(16)
                + b"\x08" + os.urandom(8) + b"\x00\x00\x00"
                + struct.pack("<I", 0x1CB5C415) + struct.pack("<i", 1)
                + struct.pack("<q", 0x0BC35F3509F7B7A5))
        msg = (b"\x00" * 8 + struct.pack("<q", (int(time.time()) << 32) | 1)
               + struct.pack("<i", len(body)) + body)
        send(enc.update(struct.pack("<I", len(msg)) + msg))
        time.sleep(0.2)

    def _send_server_hello(self, conn, client_digest, session_id, fake=False):
        sh_body = (b"\x03\x03" + b"\x00" * 32 + b"\x20" + session_id + b"\x13\x01\x00"
                   + b"\x00\x2e" + b"\x00\x33\x00\x24\x00\x1d\x00\x20" + os.urandom(32)
                   + b"\x00\x2b\x00\x02\x03\x04")
        hs = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
        rec = b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs
        noise = os.urandom(1500)
        resp = (rec + b"\x14\x03\x03\x00\x01\x01"
                + b"\x17\x03\x03" + len(noise).to_bytes(2, "big") + noise)
        if fake:
            digest = os.urandom(32)
        else:
            digest = hmac.new(self.secret[1:17], client_digest + resp, hashlib.sha256).digest()
        conn.sendall(resp[:11] + digest + resp[43:])
