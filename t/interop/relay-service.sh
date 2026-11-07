#!/bin/sh
set -eu
ip link set lo up
ip link add native0 type veth peer name peer0
ip link set native0 mtu 9000
ip link set peer0 mtu 9000
ip address add 192.0.2.10/24 dev native0
ip -6 address add 2001:db8::a/64 dev native0 nodad
ip link set native0 up
ip link set peer0 up
ip route add 232.0.0.0/8 dev native0
ip -6 route add ff00::/8 dev native0
relay_log=$(mktemp)
relay_pid=
cleanup() {
    if [ -n "$relay_pid" ]; then
        kill -TERM "$relay_pid" 2>/dev/null || :
        wait "$relay_pid" 2>/dev/null || :
    fi
    rm -f "$relay_log"
}
trap cleanup EXIT
bind=0.0.0.0
if [ "$3" = 1 ]; then bind=::; fi
"$1" --interface native0 --bind "$bind" > /dev/null 2> "$relay_log" &
relay_pid=$!
if ! "$2" "$3" "$4"; then cat "$relay_log" >&2; exit 1; fi
kill -TERM "$relay_pid"
if ! wait "$relay_pid"; then cat "$relay_log" >&2; exit 1; fi
relay_pid=
if ip maddr show dev native0 | rg -q 'inet 232\.|inet6 ff3e:'; then
    cat "$relay_log" >&2
    echo 'relay left native subscriptions installed' >&2
    exit 1
fi
