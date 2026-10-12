#!/usr/bin/env python3
"""Generate raw AMT seeds plus signed-report sequences for fuzz-relay."""
import ipaddress
import pathlib
import struct
import sys

sys.dont_write_bytecode = True
# The gateway seed module also emits its raw packets into argv[1].
from seeds import checksum

destination = pathlib.Path(sys.argv[1])
destination.mkdir(parents=True, exist_ok=True)


def operation(kind, payload):
    return bytes([kind]) + struct.pack("!H", len(payload)) + payload


def report(version, kind, addresses):
    group = ipaddress.ip_address("232.1.2.3" if version == 4 else "ff3e::1234").packed
    sources = b"".join(ipaddress.ip_address(address).packed for address in addresses)
    record = struct.pack("!BBH", kind, 0, len(addresses)) + group + sources
    body = bytearray(struct.pack("!BBHHH", 0x22 if version == 4 else 143, 0, 0, 0, 1) + record)
    if version == 4:
        header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x46, 0xc0, 24 + len(body), 0, 0, 1, 2, 0,
                                       bytes(4), bytes([224, 0, 0, 22])) + bytes([0x94, 4, 0, 0]))
        body[2:4] = checksum(bytes(body))
        header[10:12] = checksum(bytes(header))
        return bytes(header + body)
    source, target = bytes(16), ipaddress.IPv6Address("ff02::16").packed
    pseudo = source + target + struct.pack("!I3xB", len(body), 58)
    body[2:4] = checksum(pseudo + bytes(body))
    header = struct.pack("!IHBB", 0x60000000, 8 + len(body), 0, 1) + source + target
    return header + bytes([58, 0, 5, 2, 0, 0, 1, 0]) + bytes(body)


for version in (4, 6):
    primary = "192.0.2.10" if version == 4 else "2001:db8::a"
    other = "192.0.2.11" if version == 4 else "2001:db8::b"
    for kind in range(1, 7):
        for addresses in ([], [primary], [other], [primary, other]):
            packet = report(version, kind, addresses)
            name = f"report{version}-{kind}-{len(addresses)}-{addresses == [other]}"
            (destination / name).write_bytes(packet)
            # Operation 1 attaches a valid per-run AMT cookie before parsing.
            sequence = operation(1, packet) + operation(4, b"") + operation(3, bytes(21))
            sequence += operation(4, b"")
            (destination / (name + "-sequence")).write_bytes(sequence)
    sequence = operation(1, report(version, 2, []))
    sequence += operation(1, report(version, 6, [primary]))
    sequence += operation(3, bytes(21)) + operation(4, b"")
    sequence += operation(1, report(version, 3, [])) + operation(3, bytes(21))
    (destination / f"exclude-block-leave{version}").write_bytes(sequence)
