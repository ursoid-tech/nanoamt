# nanoamt

Lightweight C implementation of Automatic Multicast Tunneling (AMT, [RFC 7450](https://www.rfc-editor.org/rfc/rfc7450)).

## Build

```sh
make
make check
```

The classic AMT and experimental AMTQ Datagram relay cores are available
through `nanoamt/relay.h` and `nanoamt/amtq_relay.h`. They share the bounded
IGMP/MLD reception-state API in `nanoamt/membership.h`.
See [relay integration and implementation milestones](docs/relay.md) for
the API contract, optional OpenSSL provider, and AMTQ/qlinq runtime work.

On Linux, `make NANOAMT_BUILD_NATIVE=1 NANOAMT_BUILD_OPENSSL=1` also builds
`build/nanoamt-relay`, a classic AMT service with native multicast capture,
indexed fanout scaling, dynamic PMTU discovery, and transactional source/group
subscriptions. Run `build/nanoamt-relay --help` for listener, upstream interface,
MTU, Linux kernel gateway compatibility, and resource options. Native capture
requires `CAP_NET_RAW`.
