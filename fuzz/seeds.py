#!/usr/bin/env python3
import pathlib
import struct
import sys

def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return struct.pack("!H", total ^ 65535)

def ip(payload, protocol, source, destination):
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 1, protocol, 0,
                                   bytes(source), bytes(destination)))
    header[10:12] = checksum(header)
    return header + payload

destination = pathlib.Path(sys.argv[1])
destination.mkdir(parents=True, exist_ok=True)
(destination / "advertisement").write_bytes(bytes([2, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1]))
query = bytearray([0x11, 100, 0, 0, 0, 0, 0, 0, 2, 125, 0, 0])
query[2:4] = checksum(query)
(destination / "query").write_bytes(bytes([4]) + bytes(11) + ip(query, 2, [192, 0, 2, 1], [224, 0, 0, 1]))
udp = struct.pack("!HHHH", 1234, 5000, 13, 0) + b"\x40\x00\x80\xff\x01"
(destination / "data").write_bytes(bytes([6, 0]) + ip(udp, 17, [192, 0, 2, 10], [232, 1, 2, 3]))

import ipaddress
src6 = ipaddress.IPv6Address('2001:db8::a').packed
dst6 = ipaddress.IPv6Address('ff3e::1234').packed

def ip6(payload, protocol):
    return struct.pack('!IHBB', 0x60000000, len(payload), protocol, 32) + src6 + dst6 + payload

(destination / 'data6').write_bytes(bytes([6, 0]) + ip6(udp, 17))
for v6 in (False, True):
    fragments = []
    for offset, payload, more in ((8, udp[8:], 0), (0, udp[:8], 1)):
        if v6:
            frag = struct.pack('!BBHI', 17, 0, offset | more, 42)
            packet = ip6(frag + payload, 44)
        else:
            packet = bytearray(ip(payload, 17, [192, 0, 2, 10], [232, 1, 2, 3]))
            packet[4:8] = struct.pack('!HH', 42, offset // 8 | (more << 13))
            packet[10:12] = b'\0\0'
            packet[10:12] = checksum(packet[:20])
        fragments.append(bytes([6, 0]) + packet)
    stream = b'\xf0' + b''.join(struct.pack('!H', len(p)) + p for p in fragments)
    (destination / ('fragments6' if v6 else 'fragments4')).write_bytes(stream)
