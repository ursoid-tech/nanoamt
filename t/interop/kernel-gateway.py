# Kernel gateway multicast integrity fixture, run inside isolated namespaces.
import hashlib, pathlib, socket, struct, sys, time
role, version, interface, work = sys.argv[1:]
version = int(version)
work = pathlib.Path(work)
family = socket.AF_INET if version == 4 else socket.AF_INET6
source = '192.0.2.10' if version == 4 else '2001:db8::a'
group = '232.42.42.71' if version == 4 else 'ff3e::8000:71'
local = '192.0.2.200' if version == 4 else '2001:db8::c8'
index = socket.if_nametoindex(interface)
payloads = [struct.pack('!I', n) + bytes((n * 19 + i * 13) & 255 for i in range(996)) for n in range(64)]
sock = socket.socket(family, socket.SOCK_DGRAM)
if role == 'receive':
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
    sock.bind(('' if version == 4 else '::', 5000))
    if version == 4:
        sock.setsockopt(socket.IPPROTO_IP, 39, socket.inet_aton(group) + socket.inet_aton(local) + socket.inet_aton(source))
    else:
        def address(ip):
            return struct.pack('=HHI', socket.AF_INET6, 0, 0) + socket.inet_pton(socket.AF_INET6, ip) + struct.pack('=I', 0) + bytes(100)
        sock.setsockopt(socket.IPPROTO_IPV6, 46, struct.pack('=I', index) + bytes(4) + address(group) + address(source))
    (work / 'receiver-ready').touch()
    deadline = time.monotonic() + 45
    packets = {}
    sock.settimeout(1)
    while len(packets) < 64 and time.monotonic() < deadline:
        try:
            packet, peer = sock.recvfrom(2000)
        except TimeoutError:
            continue
        assert peer[0] == source, peer
        sequence = struct.unpack('!I', packet[:4])[0]
        assert sequence < 64 and packet == payloads[sequence], sequence
        packets[sequence] = packet
    assert len(packets) == 64, len(packets)
    data = b''.join(packets[n] for n in range(64))
    (work / 'received.bin').write_bytes(data)
else:
    sock.bind((source, 0))
    if version == 4:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source))
    else:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
    data = b''.join(payloads)
    (work / 'sent.bin').write_bytes(data)
    for packet in payloads:
        sock.sendto(packet, (group, 5000))
        time.sleep(.002)
print(f'{role}: IPv{version} packets=64 bytes={len(data)} SHA256={hashlib.sha256(data).hexdigest()}')
