"""Write structured AMTQ fuzzer seeds into the supplied corpus directory."""
import pathlib
import struct
import sys


def command(op, data):
    return bytes([op]) + struct.pack("!H", len(data)) + data


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    value = sum(words)
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return struct.pack("!H", value ^ 65535)


def varint(value):
    for width, tag in ((1, 0), (2, 1), (4, 2), (8, 3)):
        if value < 1 << (width * 8 - 2):
            return (value | tag << (width * 8 - 2)).to_bytes(width, "big")
    raise ValueError("value exceeds QUIC varint range")


def control(kind, value):
    return command(0, varint(kind) + varint(len(value)) + value)


def stream(index, data=b"", event=0):
    # fuzz/amtq.c maps operation 5/6/7 to DATA/FIN/RESET and the upper
    # bits to server unidirectional stream ID 3 + 4 * index.
    return command(5 + event + 8 * index, data)


def block_header(block=1, context=0):
    return b"\0" + varint(context) + varint(block)


def close_context(final, context=0):
    return control(3, varint(context) + varint(final))


root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
ip = bytearray.fromhex("45000021000000002a110000c000020ae8010203")
ip[10:12] = checksum(ip)
message = b"\x06\x00" + ip + bytes.fromhex("04d21388000d0000") + b"hello"
record = varint(len(message)) + message
header = block_header()
# Match fixture_dual_config's IPv6 source/group and build a valid UDP checksum.
source6 = bytes.fromhex("20010db800000000000000000000000a")
group6 = bytes.fromhex("ff3e0000000000000000000000001234")
udp6 = bytearray.fromhex("04d21388000d0000") + b"hello"
udp6[6:8] = checksum(source6 + group6 + struct.pack("!II", len(udp6), 17) + udp6)
message6 = b"\x06\x00" + struct.pack("!IHBB", 0x60000000, len(udp6), 17, 42) + source6 + group6 + udp6
record6 = varint(len(message6)) + message6
seeds = {
    "complete": b"\x01" + command(1, b"\x00\x00" + message),
    "fragments": b"\x01"
    + command(1, bytes([1, 0, 1, len(message), 20]) + message[20:])
    + command(1, bytes([1, 0, 1, len(message), 0]) + message[:24]),
    "context": b"\x01" + command(0, bytes([3, 1, 0, 2, 2, 1, 0])) + command(4, b""),
    "settings": b"\x00" + command(4, b"") + command(0, bytes([0, 2, 0, 1])) + command(4, b""),
    "membership": b"\x01" + command(2, b"") + command(4, b"") + command(1, b"\x00\x00" + message),
    "ipv6": b"\x03" + command(0, bytes([2, 2, 1, 0])) + command(4, b""),
    # Flag 0x04 enables both modes and reliable preference; 0x01 completes the
    # initial exchange including Context 0 ACK before interpreting commands.
    "reliable-stream": b"\x05" + stream(0, header + record) + stream(0, event=1),
    "reliable-fin": b"\x05" + stream(0, header + record, event=1),
    "reliable-ipv6": b"\x07" + stream(0, header + record6, event=1),
    "reliable-multiple-records": b"\x05" + stream(0, header + record + record, event=1),
    "reliable-split": b"\x05"
    + b"".join(stream(0, bytes([byte])) for byte in b"\x40\x00\x40\x00\x40\x01\x40" + bytes([len(message)]) + message)
    + stream(0, event=1),
    "reliable-context": b"\x05"
    + control(2, varint(64) + b"\x01") + command(4, b"")
    + stream(0, block_header(context=64) + record, event=1) + close_context(1, context=64),
    "reliable-close": b"\x05" + close_context(2)
    + stream(1, block_header(2) + record, event=1) + stream(0, header + record, event=1),
    "reliable-close-timeout": b"\x05" + close_context(1) + command(3, bytes(10000)) + command(4, b""),
    "reliable-above-final": b"\x05" + close_context(1) + stream(0, block_header(2) + record, event=1),
    "reliable-withdraw": b"\x05" + stream(0, header + record[:10])
    + command(2, b"") + stream(0, record[10:], event=1),
    "reliable-reset": b"\x05" + stream(0, header + record[:10]) + stream(0, event=2),
    "reliable-reset-early": b"\x05" + stream(0, event=2),
    "reliable-truncated-fin": b"\x05" + stream(0, header + record[:-1], event=1),
    "reliable-empty-fin": b"\x05" + stream(0, header, event=1),
    "reliable-duplicate": b"\x05" + stream(0, header + record, event=1)
    + stream(1, header + record, event=1),
    "reliable-zero-block": b"\x05" + stream(0, block_header(0) + record, event=1),
    "reliable-zero-length": b"\x05" + stream(0, header + b"\0", event=1),
    "reliable-large-length": b"\x05" + stream(0, header + varint(65578)),
    "reliable-stream-limit": b"\x05" + b"".join(stream(i, block_header(i + 1)) for i in range(5)),
    "reliable-unknown": b"\x05" + stream(0, b"\x01unknown", event=1),
    "reliable-unknown-reset": b"\x05" + stream(0, b"\x01unknown") + stream(0, event=2),
    "reliable-wrong-context": b"\x05" + stream(0, block_header(context=1) + record, event=1),
    "reliable-wrong-mode": b"\x01" + stream(0, header + record, event=1),
    "reliable-settings": b"\x04" + command(4, b"") + control(0, b"\x00\x03") + command(4, b""),
}
for name, data in seeds.items():
    (root / name).write_bytes(data)
