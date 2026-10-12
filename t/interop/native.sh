#!/bin/sh
set -eu
ip link set lo up
ip link add native0 type veth peer name peer0
ip address add 192.0.2.10/24 dev native0
ip address add 192.0.2.20/24 dev native0
ip -6 address add 2001:db8::a/64 dev native0 nodad
ip -6 address add 2001:db8::b/64 dev native0 nodad
ip address add 192.0.2.30/24 dev peer0
ip -6 address add 2001:db8::c/64 dev peer0 nodad
ip link set native0 up
ip link set peer0 up
ip route add 232.0.0.0/8 dev native0
ip -6 route add ff00::/8 dev native0
if [ "$3" = lo ]; then
    ip address del 192.0.2.10/24 dev native0
    ip address del 192.0.2.20/24 dev native0
    ip address add 192.0.2.10/24 dev lo
    ip address add 192.0.2.20/24 dev lo
    ip route replace 232.0.0.0/8 dev lo
fi
"$1" network "$2" "$3"
