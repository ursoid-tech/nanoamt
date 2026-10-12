#!/usr/bin/env python3
"""Stateful AMTQ relay seeds. Each stream starts with inner-family flags."""
import pathlib
import struct
import sys

sys.dont_write_bytecode = True
from seeds import checksum

destination = pathlib.Path(sys.argv[1])


def operation(kind, payload=b""):
    return bytes([kind]) + struct.pack("!H", len(payload)) + payload


def varint(value):
    length = 1 if value < 64 else 2 if value < 16384 else 4 if value < 1073741824 else 8
    encoded = bytearray(value.to_bytes(length, "big"))
    encoded[0] |= {1: 0, 2: 64, 4: 128, 8: 192}[length]
    return bytes(encoded)


def record(kind, payload):
    return varint(kind) + varint(len(payload)) + payload


for family in (0, 1):
    flags = bytes([family])
    wrapped = (destination / ("data6" if family else "data")).read_bytes()
    packet = bytearray(wrapped[2:])
    if not family:
        packet[8] = 32
        packet[10:12] = b"\0\0"
        packet[10:12] = checksum(bytes(packet[:20]))
    (destination / f"relay-data{family}").write_bytes(flags + operation(2, bytes(packet)))
    for context_id in (1, 2, 63, 64, 16384):
        payload = operation(4, bytes([context_id])) if context_id < 256 else operation(0, record(4, varint(context_id)))
        payload += operation(2, bytes(packet)) + operation(5) + operation(2, bytes(packet))
        (destination / f"contexts{family}-{context_id}").write_bytes(flags + payload)
    for kind in (0, 1, 2, 3, 4, 63, 64, 1073741824):
        (destination / f"control{family}-{kind}").write_bytes(flags + operation(0, record(kind, b"\0\1")))
    (destination / f"policy{family}").write_bytes(flags + operation(7) + operation(3, b"\x0b") + operation(7) + operation(2, bytes(packet)))
    (destination / f"timeout{family}").write_bytes(flags + operation(6, bytes(1001)))
