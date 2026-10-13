#!/usr/bin/env python3
"""Host-side client for the in-loader RPC server.

Protocol (little-endian, see ps5-kstuff-ldr/src/rpc_server.c):
  Request:  u32 cmd, u32 arg_len, bytes[arg_len]
  Response: i64 status, u32 resp_len, bytes[resp_len]

Example:
    from kstuff_rpc import Client, KEKCALL_SCAN_CDEVSW
    c = Client("192.168.2.2", 9030)
    c.ping()
    kbase = c.kbase()
    first_qword = c.read(kbase, 8)
    c.write64(kbase + 0x100, 0xdeadbeef)
    rc = c.kekcall(KEKCALL_SCAN_CDEVSW, 0, 0, 0)
"""
from __future__ import annotations

import socket
import struct
import sys

CMD_PING    = 0x01
CMD_READ    = 0x02
CMD_WRITE   = 0x03
CMD_WRITE64 = 0x04
CMD_KEKCALL = 0x05
CMD_KBASE   = 0x06
CMD_EXIT    = 0x07
CMD_IOCTL_PATH = 0x08
CMD_GET_PID    = 0x09
CMD_IOCTL_FD   = 0x0a

# Kekcall numbers (keep in sync with ps5-kstuff-ldr/src/kekcall.h)
KEKCALL_A53_DUMP        = 8
KEKCALL_DUMP_MEM        = 19
KEKCALL_GET_KBASE       = 24
KEKCALL_SAFE_PEEK       = 25
KEKCALL_SCAN_CDEVSW     = 26
KEKCALL_WRITE64         = 27
KEKCALL_INJECT_CDEVPRIV = 38


class RpcError(RuntimeError):
    pass


class Client:
    def __init__(self, host: str, port: int = 9030, timeout: float = 10.0):
        self._s = socket.create_connection((host, port), timeout=timeout)
        self._s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # ---- low-level ------------------------------------------------------
    def _send(self, cmd: int, args: bytes = b"") -> tuple[int, bytes]:
        hdr = struct.pack("<II", cmd, len(args))
        self._s.sendall(hdr + args)
        resp_hdr = self._recv_exact(12)
        status, rlen = struct.unpack("<qI", resp_hdr)
        payload = self._recv_exact(rlen) if rlen else b""
        return status, payload

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._s.recv(n - len(buf))
            if not chunk:
                raise RpcError("connection closed mid-response")
            buf.extend(chunk)
        return bytes(buf)

    def _call(self, cmd: int, args: bytes = b"") -> bytes:
        status, payload = self._send(cmd, args)
        if status != 0:
            raise RpcError(f"cmd 0x{cmd:02x} failed: status={status}")
        return payload

    # ---- commands -------------------------------------------------------
    def ping(self) -> bytes:
        p = self._call(CMD_PING)
        if p != b"PONG":
            raise RpcError(f"bad PONG: {p!r}")
        return p

    def kbase(self) -> int:
        return struct.unpack("<Q", self._call(CMD_KBASE))[0]

    def read(self, kaddr: int, length: int) -> bytes:
        # Server (KEKCALL_DUMP_MEM) aligns down to 8 bytes. Compensate: read
        # a window covering [kaddr, kaddr+length) at an 8-byte-aligned base
        # and slice. Length also effectively rounds up on server side.
        base = kaddr & ~7
        head = kaddr - base
        total = head + length
        if total & 7:
            total = (total + 7) & ~7
        raw = self._call(CMD_READ, struct.pack("<QI", base, total))
        return raw[head:head+length]

    def read_u64(self, kaddr: int) -> int:
        return struct.unpack("<Q", self.read(kaddr, 8))[0]

    def write(self, kaddr: int, data: bytes) -> None:
        if len(data) % 8:
            raise ValueError("write length must be multiple of 8")
        self._call(CMD_WRITE, struct.pack("<Q", kaddr) + data)

    def write64(self, kaddr: int, value: int) -> None:
        self._call(CMD_WRITE64, struct.pack("<QQ", kaddr, value & ((1 << 64) - 1)))

    def write_bytes(self, kaddr: int, data: bytes) -> None:
        """Byte-granular patch via 8-byte RMW windows."""
        cur = kaddr
        end = kaddr + len(data)
        while cur < end:
            base = cur & ~7
            window = bytearray(self.read(base, 8))
            off = cur - base
            n = min(8 - off, end - cur)
            window[off:off+n] = data[cur-kaddr:cur-kaddr+n]
            self.write64(base, struct.unpack("<Q", bytes(window))[0])
            cur += n

    def kekcall(self, nr: int, a1: int = 0, a2: int = 0, a3: int = 0) -> int:
        args = struct.pack("<IQQQ", nr, a1 & ((1 << 64) - 1),
                           a2 & ((1 << 64) - 1), a3 & ((1 << 64) - 1))
        return struct.unpack("<q", self._call(CMD_KEKCALL, args))[0]

    def ioctl_path(self, path: str, flags: int, cmd: int,
                   in_data: bytes = b"", out_len: int = 0) -> tuple[int, int, bytes]:
        """open(path, flags) → ioctl(fd, cmd, buf) → close. Returns (ret, errno, out)."""
        pb = path.encode()
        hdr = struct.pack("<IIIII", len(pb), flags, cmd & 0xffffffff,
                          len(in_data), out_len)
        payload = self._call(CMD_IOCTL_PATH, hdr + pb + in_data)
        ret, err = struct.unpack("<ii", payload[:8])
        return ret, err, payload[8:8+out_len]

    def get_pid(self) -> int:
        return struct.unpack("<I", self._call(CMD_GET_PID))[0]

    def ioctl_fd(self, fd: int, cmd: int,
                 in_data: bytes = b"", out_len: int = 0) -> tuple[int, int, bytes]:
        hdr = struct.pack("<IIII", fd & 0xffffffff, cmd & 0xffffffff,
                          len(in_data), out_len)
        payload = self._call(CMD_IOCTL_FD, hdr + in_data)
        ret, err = struct.unpack("<ii", payload[:8])
        return ret, err, payload[8:8+out_len]

    def exit_server(self) -> None:
        try:
            self._call(CMD_EXIT)
        except RpcError:
            pass

    def close(self) -> None:
        try:
            self._s.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


# ---- CLI smoke-test -----------------------------------------------------
def _main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"usage: {argv[0]} <host> [port]", file=sys.stderr)
        return 2
    host = argv[1]
    port = int(argv[2]) if len(argv) > 2 else 9030
    with Client(host, port) as c:
        c.ping()
        print("PING ok")
        kb = c.kbase()
        print(f"kbase = 0x{kb:016x}")
        if kb and kb > 0xffffffff00000000:
            first = c.read_u64(kb)
            print(f"[{kb:#x}] = 0x{first:016x}")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
