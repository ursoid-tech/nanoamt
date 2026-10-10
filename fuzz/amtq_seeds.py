"""Write structured AMTQ fuzzer seeds into the supplied corpus directory."""
import pathlib
import struct
import sys


def command(op, data):
    return bytes([op]) + struct.pack("!H", len(data)) + data


def checksum(data):
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    value = sum(words)
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return struct.pack("!H", value ^ 65535)


root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
ip = bytearray.fromhex("45000021000000002a110000c000020ae8010203")
ip[10:12] = checksum(ip)
message = b"\x06\x00" + ip + bytes.fromhex("04d21388000d0000") + b"hello"
seeds = {
    "complete": b"\x01" + command(1, b"\x00\x00" + message),
    "fragments": b"\x01"
    + command(1, bytes([1, 0, 1, len(message), 20]) + message[20:])
    + command(1, bytes([1, 0, 1, len(message), 0]) + message[:24]),
    "context": b"\x01" + command(0, bytes([3, 1, 0, 2, 2, 1, 0])) + command(4, b""),
    "settings": b"\x00" + command(4, b"") + command(0, bytes([0, 2, 0, 1])) + command(4, b""),
    "membership": b"\x01" + command(2, b"") + command(4, b"") + command(1, b"\x00\x00" + message),
    "ipv6": b"\x03" + command(0, bytes([2, 2, 1, 0])) + command(4, b""),
}
for name, data in seeds.items():
    (root / name).write_bytes(data)
