#!/bin/sh
set -eu
ip link set lo up
ip link add uplink type veth peer name peer
ip address add 10.0.0.1/24 dev uplink
ip link set uplink up
ip link set peer up
ip link add amtr type amt mode relay local 10.0.0.1 dev uplink relay_port 2268
ip address add 192.0.2.10/24 dev amtr
ip -6 address add 2001:db8::a/64 dev amtr nodad
ip link set amtr up
ip -6 route add ff00::/8 dev amtr
"$1" "$2" "$3"
