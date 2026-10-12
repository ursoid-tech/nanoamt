#!/bin/sh
# Isolated nanoamt relay -> Linux AMT gateway interoperability.
set -eu
relay=$1
inner=$2
case "$inner" in 4|6) ;; *) exit 2 ;; esac
work=$(mktemp -d /tmp/nanoamt-kernel-gateway.XXXXXX)
namespace=
relay_pid=
receiver_pid=
cleanup() {
 status=$?
 trap - EXIT
 for pid in $receiver_pid $relay_pid $namespace; do kill -TERM "$pid" 2>/dev/null || :; done
 for pid in $receiver_pid $relay_pid $namespace; do wait "$pid" 2>/dev/null || :; done
 if [ "$status" = 0 ]; then rm -rf "$work"; else
  echo "kernel-gateway: retained diagnostics: $work" >&2
  cat "$work/relay.log" >&2 || :
  cat "$work/receiver.log" >&2 || :
 fi
 exit "$status"
}
trap cleanup EXIT
unshare --net sh -c 'touch "$1"; exec sleep 90' sh "$work/namespace-ready" &
namespace=$!
while [ ! -f "$work/namespace-ready" ]; do kill -0 "$namespace"; sleep .01; done
rcv() { nsenter -t "$namespace" -n -- "$@"; }
ip link set lo up
ip link add uplink type veth peer name receiver0
ip link set receiver0 netns "$namespace"
ip address add 198.51.100.1/24 dev uplink
ip link set uplink up
rcv ip link set lo up
rcv ip address add 198.51.100.2/24 dev receiver0
rcv ip link set receiver0 up
ip link add native0 type veth peer name nativepeer
ip address add 192.0.2.10/24 dev native0
ip -6 address add 2001:db8::a/64 dev native0 nodad
ip link set native0 up
ip link set nativepeer up
ip route add 232.0.0.0/8 dev native0
ip -6 route add ff00::/8 dev native0
"$relay" --linux-gateway-family "$inner" --query-source6 fe80::1 --interface native0 --bind 198.51.100.1 >"$work/relay.log" 2>&1 &
relay_pid=$!
rcv ip link add amtg type amt mode gateway local 198.51.100.2 discovery 198.51.100.1 dev receiver0 relay_port 2268 gateway_port 2268
rcv ip address add 192.0.2.200/24 dev amtg
rcv ip -6 address add 2001:db8::c8/64 dev amtg nodad
rcv ip link set amtg up
rcv ip route add 232.0.0.0/8 dev amtg
rcv ip -6 route add ff00::/8 dev amtg
rcv python3 "$(dirname "$0")/kernel-gateway.py" receive "$inner" amtg "$work" >"$work/receiver.log" 2>&1 &
receiver_pid=$!
group=232.42.42.71
if [ "$inner" = 6 ]; then group=ff3e::8000:71; fi
attempt=0
until ip maddr show dev native0 | grep -F "$group" >/dev/null; do
 kill -0 "$relay_pid"
 kill -0 "$receiver_pid"
 attempt=$((attempt+1))
 if [ "$attempt" -gt 2000 ]; then echo 'kernel gateway membership not installed' >&2; exit 1; fi
 sleep .01
done
python3 "$(dirname "$0")/kernel-gateway.py" send "$inner" native0 "$work" >"$work/sender.log" 2>&1
wait "$receiver_pid"
receiver_pid=
cmp "$work/sent.bin" "$work/received.bin"
echo "kernel-gateway: IPv$inner native multicast hash passed"
