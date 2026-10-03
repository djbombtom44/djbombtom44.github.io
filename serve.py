#!/usr/bin/env python3
"""
Serve app.html with the headers Firefox-WASM needs (cross-origin isolation)
AND provide a small built-in Wisp proxy at  ws://localhost:<port>/wisp/  so networking works
out of the box. Pure standard library, Python 3.8+.

    python3 serve.py [--port 8000] [--allow-private]

Then open http://localhost:8000/

Safety defaults (the relay is an open TCP proxy, so it is locked down):
  * listens on 127.0.0.1 only
  * only accepts WebSocket connections whose Host is localhost/127.0.0.1 and whose Origin
    is this same server (blocks other websites and DNS-rebinding), plus any site you explicitly
    list with --allow-origin (e.g. your GitHub Pages site, so it can use this fast local relay)
  * refuses to connect to private / loopback / link-local addresses (so a page can't reach
    your LAN). Pass --allow-private if you want to browse local/LAN sites through it.
"""
import argparse, asyncio, base64, contextlib, hashlib, ipaddress, os, socket, struct, sys
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
FILE = next((p for p in (os.path.join(HERE, n) for n in ("app.html", "firefox-wasm-bundle.html")) if os.path.exists(p)), os.path.join(HERE, "app.html"))
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
MAX_WS_MSG = 32 * 1024 * 1024

# Wisp v1 close reasons
R_VOLUNTARY, R_NETERR, R_INVALID, R_UNREACH, R_TIMEOUT, R_REFUSED, R_BLOCKED = 0x02, 0x03, 0x41, 0x42, 0x43, 0x44, 0x48


def hostname(h):
    h = h.strip()
    return h[1:h.index("]")] if h.startswith("[") else h.split(":")[0]


def unmask(data, mask):
    n = len(data)
    if not n:
        return data
    m = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(m, "big")).to_bytes(n, "big")


def ws_frame(op, payload=b""):
    n = len(payload)
    if n < 126:
        hdr = bytes([0x80 | op, n])
    elif n < 65536:
        hdr = bytes([0x80 | op, 126]) + struct.pack(">H", n)
    else:
        hdr = bytes([0x80 | op, 127]) + struct.pack(">Q", n)
    return hdr + payload


async def ws_read(reader):
    """Return (opcode, payload) for the next complete message / control frame."""
    buf, mop = bytearray(), None
    while True:
        b1, b2 = await reader.readexactly(2)
        fin, op, ln = b1 & 0x80, b1 & 0x0F, b2 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", await reader.readexactly(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", await reader.readexactly(8))[0]
        if ln > MAX_WS_MSG:
            raise ConnectionError("frame too large")
        mask = await reader.readexactly(4) if b2 & 0x80 else None
        data = await reader.readexactly(ln) if ln else b""
        if mask:
            data = unmask(data, mask)
        if op >= 0x8:
            return op, data
        if op != 0:
            mop = op
        buf += data
        if len(buf) > MAX_WS_MSG:
            raise ConnectionError("message too large")
        if fin:
            return mop, bytes(buf)


class Stream:
    def __init__(self):
        self.q = asyncio.Queue()
        self.task = None


class WispSession:
    def __init__(self, reader, writer, allow_private):
        self.r, self.w, self.allow_private = reader, writer, allow_private
        self.streams, self.lock = {}, asyncio.Lock()

    async def send(self, op, payload=b""):
        async with self.lock:
            self.w.write(ws_frame(op, payload))
            await self.w.drain()

    async def wisp(self, typ, sid, payload=b""):
        await self.send(0x2, bytes([typ]) + struct.pack("<I", sid) + payload)

    async def run(self):
        try:
            await self.wisp(3, 0, struct.pack("<I", 128))  # initial CONTINUE (standard Wisp v1 greeting)
            while True:
                op, data = await ws_read(self.r)
                if op == 0x8:
                    with contextlib.suppress(Exception):
                        await self.send(0x8, data[:2])
                    break
                if op == 0x9:
                    await self.send(0xA, data)
                elif op in (0x1, 0x2):
                    self.handle(data)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            for st in list(self.streams.values()):
                st.q.put_nowait(None)
                if st.task:
                    st.task.cancel()
            self.streams.clear()

    def handle(self, data):
        if len(data) < 5:
            return
        typ, sid, payload = data[0], struct.unpack_from("<I", data, 1)[0], data[5:]
        if typ == 1:  # CONNECT
            if len(payload) < 3 or sid in self.streams:
                return
            stype, port, host = payload[0], struct.unpack_from("<H", payload, 1)[0], payload[3:].decode("utf-8", "replace")
            if stype != 1:  # TCP only
                asyncio.ensure_future(self.wisp(4, sid, bytes([R_INVALID])))
                return
            st = Stream()
            self.streams[sid] = st
            st.task = asyncio.ensure_future(self.stream_main(sid, host, port, st))
        elif typ == 2:  # DATA
            st = self.streams.get(sid)
            if st:
                st.q.put_nowait(payload)
        elif typ == 4:  # CLOSE (from client)
            st = self.streams.pop(sid, None)
            if st:
                st.q.put_nowait(None)

    async def open(self, host, port):
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        infos.sort(key=lambda i: i[0] != socket.AF_INET)  # IPv4 first
        err = None
        for fam, _, _, _, addr in infos:
            ip = ipaddress.ip_address(addr[0])
            if ip.version == 6 and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            if not self.allow_private and (not ip.is_global or ip.is_multicast):
                err = PermissionError("blocked address")
                continue
            try:
                return await asyncio.open_connection(addr[0], port, family=fam)
            except OSError as e:
                err = e
        raise err or OSError("no usable address")

    async def pump_remote(self, sid, st, rd):
        try:
            while True:
                chunk = await rd.read(65536)
                if not chunk:
                    break
                await self.wisp(2, sid, chunk)
        except (ConnectionError, OSError):
            pass
        finally:
            st.q.put_nowait(None)

    async def stream_main(self, sid, host, port, st):
        reason, wr, pump = R_VOLUNTARY, None, None
        try:
            try:
                rd, wr = await asyncio.wait_for(self.open(host, port), 15)
            except PermissionError:
                reason = R_BLOCKED; return
            except asyncio.TimeoutError:
                reason = R_TIMEOUT; return
            except ConnectionRefusedError:
                reason = R_REFUSED; return
            except OSError:
                reason = R_UNREACH; return
            sock = wr.get_extra_info("socket")
            if sock:
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            pump = asyncio.ensure_future(self.pump_remote(sid, st, rd))
            try:
                while True:
                    data = await st.q.get()
                    if data is None:
                        break
                    wr.write(data)
                    await wr.drain()
            except (ConnectionError, OSError):
                reason = R_NETERR
        finally:
            if pump:
                pump.cancel()
            if wr:
                with contextlib.suppress(Exception):
                    wr.close()
            if self.streams.pop(sid, None) is not None:  # not already closed by the client
                with contextlib.suppress(Exception):
                    await self.wisp(4, sid, bytes([reason]))


async def handle_conn(reader, writer, args):
    async def respond(code, text, body=b"", extra=""):
        writer.write(f"HTTP/1.1 {code} {text}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n{extra}\r\n".encode() + body)
        with contextlib.suppress(Exception):
            await writer.drain()
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        lines = head.decode("latin1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        hdrs = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
        route = path.split("?")[0]

        if hdrs.get("upgrade", "").lower() == "websocket" and route.startswith("/wisp"):
            host = hdrs.get("host", "")
            origin = hdrs.get("origin")
            if hostname(host) not in LOCAL_HOSTS or (origin and urlparse(origin).netloc != host
                                                     and origin.rstrip("/") not in args.allow_origin):
                return await respond(403, "Forbidden", b"wisp: same-origin localhost only\n")
            key = hdrs.get("sec-websocket-key", "")
            accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
            writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
            await writer.drain()
            sock = writer.get_extra_info("socket")
            if sock:
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            await WispSession(reader, writer, args.allow_private).run()
            return

        if method not in ("GET", "HEAD"):
            return await respond(405, "Method Not Allowed")
        if route in ("/", "/index.html", "/app.html", "/firefox-wasm-bundle.html"):
            size = os.path.getsize(FILE)
            writer.write(("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                          f"Content-Length: {size}\r\nCross-Origin-Opener-Policy: same-origin\r\n"
                          "Cross-Origin-Embedder-Policy: require-corp\r\nConnection: close\r\n\r\n").encode())
            if method == "GET":
                with open(FILE, "rb") as f:
                    while chunk := f.read(1 << 20):
                        writer.write(chunk)
                        await writer.drain()
            return
        await respond(404, "Not Found", b"not found\n")
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, ValueError, OSError):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("port_pos", nargs="?", type=int, help=argparse.SUPPRESS)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--allow-origin", action="append", default=[], metavar="ORIGIN",
                    help="also accept the Wisp relay from this site, e.g. https://you.github.io (repeatable)")
    ap.add_argument("--allow-private", action="store_true", help="let the Wisp relay reach localhost/LAN addresses")
    args = ap.parse_args()
    args.allow_origin = [o.rstrip("/") for o in args.allow_origin]
    port = args.port or args.port_pos or 8000
    server = await asyncio.start_server(lambda r, w: handle_conn(r, w, args), "127.0.0.1", port, limit=1 << 20)
    print(f"Page:  http://localhost:{port}/")
    print(f"Wisp:  ws://localhost:{port}/wisp/   (private/LAN targets {'ALLOWED' if args.allow_private else 'blocked'})")
    for o in args.allow_origin:
        print(f"Also accepting Wisp connections from {o}")
    print("Ctrl+C to stop")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
