"""
vici.py - Lightweight, Pure-Python client for strongSwan VICI Protocol
Zero external dependencies. Compatible with strongSwan 5.x / 6.x.
"""

import collections
import os
import socket
import struct


class PacketType:
    CMD_REQUEST = 0
    CMD_RESPONSE = 1
    CMD_UNKNOWN = 2
    EVENT_REGISTER = 3
    EVENT_UNREGISTER = 4
    EVENT_CONFIRM = 5
    EVENT_UNKNOWN = 6
    EVENT = 7


class ElementType:
    SECTION_START = 1
    SECTION_END = 2
    KEY_VALUE = 3
    LIST_START = 4
    LIST_ITEM = 5
    LIST_END = 6


class ViciException(Exception):
    """Base exception for VICI errors."""
    pass


class CommandException(ViciException):
    """Raised when a VICI command returns an error or failure."""
    pass


class Message:
    """Parser and serializer for VICI structured messages."""

    @staticmethod
    def parse(data: bytes) -> dict:
        """Parse raw VICI message bytes into nested dict/list structures."""
        idx = 0
        total_len = len(data)
        root = collections.OrderedDict()
        stack = [root]

        while idx < total_len:
            elem_type = data[idx]
            idx += 1

            if elem_type == ElementType.SECTION_START:
                nlen = data[idx]
                idx += 1
                name = data[idx : idx + nlen].decode("utf-8", errors="replace")
                idx += nlen
                new_sec = collections.OrderedDict()
                top = stack[-1]
                if isinstance(top, dict):
                    top[name] = new_sec
                elif isinstance(top, list):
                    top.append({name: new_sec})
                stack.append(new_sec)

            elif elem_type == ElementType.SECTION_END:
                if len(stack) > 1:
                    stack.pop()

            elif elem_type == ElementType.KEY_VALUE:
                nlen = data[idx]
                idx += 1
                name = data[idx : idx + nlen].decode("utf-8", errors="replace")
                idx += nlen
                vlen = struct.unpack("!H", data[idx : idx + 2])[0]
                idx += 2
                val = data[idx : idx + vlen].decode("utf-8", errors="replace")
                idx += vlen
                top = stack[-1]
                if isinstance(top, dict):
                    top[name] = val

            elif elem_type == ElementType.LIST_START:
                nlen = data[idx]
                idx += 1
                name = data[idx : idx + nlen].decode("utf-8", errors="replace")
                idx += nlen
                new_list = []
                top = stack[-1]
                if isinstance(top, dict):
                    top[name] = new_list
                stack.append(new_list)

            elif elem_type == ElementType.LIST_ITEM:
                vlen = struct.unpack("!H", data[idx : idx + 2])[0]
                idx += 2
                val = data[idx : idx + vlen].decode("utf-8", errors="replace")
                idx += vlen
                top = stack[-1]
                if isinstance(top, list):
                    top.append(val)

            elif elem_type == ElementType.LIST_END:
                if len(stack) > 1 and isinstance(stack[-1], list):
                    stack.pop()

            else:
                raise ViciException(f"Unknown VICI element type: {elem_type} at offset {idx-1}")

        return root

    @staticmethod
    def serialize(data: dict) -> bytes:
        """Serialize a dict into VICI message bytes."""
        out = bytearray()

        def _encode(key, val):
            if isinstance(val, dict):
                kbytes = str(key).encode("utf-8")
                out.append(ElementType.SECTION_START)
                out.append(len(kbytes))
                out.extend(kbytes)
                for subk, subv in val.items():
                    _encode(subk, subv)
                out.append(ElementType.SECTION_END)
            elif isinstance(val, list):
                kbytes = str(key).encode("utf-8")
                out.append(ElementType.LIST_START)
                out.append(len(kbytes))
                out.extend(kbytes)
                for item in val:
                    ibytes = str(item).encode("utf-8")
                    out.append(ElementType.LIST_ITEM)
                    out.extend(struct.pack("!H", len(ibytes)))
                    out.extend(ibytes)
                out.append(ElementType.LIST_END)
            else:
                kbytes = str(key).encode("utf-8")
                vbytes = str(val).encode("utf-8")
                out.append(ElementType.KEY_VALUE)
                out.append(len(kbytes))
                out.extend(kbytes)
                out.extend(struct.pack("!H", len(vbytes)))
                out.extend(vbytes)

        if isinstance(data, dict):
            for k, v in data.items():
                _encode(k, v)
        return bytes(out)


class Transport:
    """Manages low-level socket communication for VICI packets."""

    def __init__(self, sock: socket.socket):
        self._sock = sock

    def _recvall(self, length: int) -> bytes:
        buf = bytearray()
        while len(buf) < length:
            chunk = self._sock.recv(length - len(buf))
            if not chunk:
                raise ConnectionResetError("VICI socket connection closed prematurely")
            buf.extend(chunk)
        return bytes(buf)

    def send_packet(self, ptype: int, payload: bytes = b""):
        pkt_len = 1 + len(payload)
        header = struct.pack("!IB", pkt_len, ptype)
        self._sock.sendall(header + payload)

    def receive_packet(self) -> tuple[int, bytes]:
        raw_header = self._recvall(5)
        pkt_len, ptype = struct.unpack("!IB", raw_header)
        payload_len = pkt_len - 1
        payload = self._recvall(payload_len) if payload_len > 0 else b""
        return ptype, payload


class Session:
    """High-level client session to strongSwan over VICI UNIX domain socket."""

    def __init__(self, socket_path: str = None, sock: socket.socket = None):
        self._owned_sock = False
        if isinstance(socket_path, socket.socket):
            sock = socket_path
            socket_path = None
        if sock is not None:
            self._sock = sock
        else:
            if not socket_path:
                socket_path = "/run/strongswan/charon.vici"
            # Strip unix:// prefix if present
            if socket_path.startswith("unix://"):
                socket_path = socket_path[7:]
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.connect(socket_path)
            self._owned_sock = True

        self._transport = Transport(self._sock)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def request(self, command: str, message: dict = None) -> dict:
        """Execute a non-streaming command and return response dict."""
        cmd_bytes = command.encode("ascii")
        msg_bytes = Message.serialize(message) if message else b""
        payload = bytes([len(cmd_bytes)]) + cmd_bytes + msg_bytes

        self._transport.send_packet(PacketType.CMD_REQUEST, payload)
        ptype, res_payload = self._transport.receive_packet()

        if ptype == PacketType.CMD_UNKNOWN:
            raise CommandException(f"Unknown VICI command '{command}'")
        if ptype != PacketType.CMD_RESPONSE:
            raise ViciException(f"Unexpected packet type {ptype} in response to '{command}'")

        res = Message.parse(res_payload)
        if res.get("success") == "no":
            raise CommandException(f"Command '{command}' failed: {res.get('errmsg', 'Unknown error')}")
        return res

    def stream(self, command: str, event: str, message: dict = None):
        """Execute a streaming command and yield response events."""
        ev_bytes = event.encode("ascii")
        self._transport.send_packet(PacketType.EVENT_REGISTER, bytes([len(ev_bytes)]) + ev_bytes)
        ptype, _ = self._transport.receive_packet()
        if ptype != PacketType.EVENT_CONFIRM:
            raise ViciException(f"Failed to register for event '{event}' (ptype {ptype})")

        cmd_bytes = command.encode("ascii")
        msg_bytes = Message.serialize(message) if message else b""
        payload = bytes([len(cmd_bytes)]) + cmd_bytes + msg_bytes

        self._transport.send_packet(PacketType.CMD_REQUEST, payload)

        try:
            while True:
                ptype, res_payload = self._transport.receive_packet()
                if ptype == PacketType.EVENT:
                    elen = res_payload[0]
                    ev_data = res_payload[1 + elen :]
                    yield Message.parse(ev_data)
                elif ptype == PacketType.CMD_RESPONSE:
                    break
                elif ptype == PacketType.CMD_UNKNOWN:
                    raise CommandException(f"Unknown streaming command '{command}'")
                else:
                    raise ViciException(f"Unexpected packet type {ptype} during stream '{command}'")
        finally:
            try:
                self._transport.send_packet(PacketType.EVENT_UNREGISTER, bytes([len(ev_bytes)]) + ev_bytes)
                self._transport.receive_packet()
            except Exception:
                pass

    def list_sas(self, req: dict = None):
        """Query currently active IKE and CHILD SAs."""
        yield from self.stream("list-sas", "list-sa", req)

    def list_certs(self, req: dict = None):
        """Query loaded X.509 and other public certificates."""
        yield from self.stream("list-certs", "list-cert", req)

    def list_conns(self, req: dict = None):
        """Query configured connections."""
        yield from self.stream("list-conns", "list-conn", req)

    def version(self) -> dict:
        """Query strongSwan daemon version info."""
        return self.request("version")

    def stats(self) -> dict:
        """Query strongSwan daemon stats."""
        return self.request("stats")


def connect(socket_path: str = None) -> Session:
    """Convenience factory function."""
    return Session(socket_path=socket_path)
