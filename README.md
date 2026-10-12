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
