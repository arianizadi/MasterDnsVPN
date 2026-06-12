# MasterDnsVPN Mobile Bridge

This package is intentionally inside the `MasterDnsVPN` module so it can import
`internal/client` and `internal/config`.

Build the iOS framework from `MasterDnsVPN`:

```sh
gomobile bind -target ios -o ../iOS/Vendor/EngineBridge.xcframework ./mobilebridge
```

The Swift packet tunnel extension expects this API:

- `StartEngine(profileJSON, socksListenAddress, logCallback) -> error`
- `StartPacketEngine(profileJSON, packetCallback, logCallback) -> error`
- `WritePacket(packet []byte) -> error`
- `StopEngine() -> error`
- `EngineStatus() -> JSON string`
- `ValidateProfile(profileJSON) -> error`

VayDNS profiles run a local SOCKS5 listener through `vaydns/client`.
MasterDnsVPN profiles support two iOS runtime modes:

- `hevSocks`: the stable path. `StartEngine` runs the built-in SOCKS5 mode,
  forces the requested listen address, and requires `PROTOCOL_TYPE` `SOCKS5`
  with `LOCAL_DNS_ENABLED` disabled. The embedded iOS path also clamps packet
  and setup duplication to `1x` to avoid upload-side pressure from doubled DNS
  traffic.
- `nativePacket`: the experimental packet path. `StartPacketEngine` runs the
  MasterDnsVPN runtime without local TCP/DNS listener sockets and attaches a
  gVisor netstack adapter. iOS sends `NEPacketTunnelFlow` IP packets through
  `WritePacket`; the adapter handles TCP flows and DNS UDP/53 packets through
  the existing MasterDnsVPN stream and DNS-cache paths. Generic non-DNS UDP is
  counted and dropped.

MasterDnsVPN mobile profiles can use desktop client keys under
`masterdns.clientConfig`:

```json
{
  "masterdns": {
    "runtimeMode": "hevSocks",
    "clientConfig": {
      "PROTOCOL_TYPE": "SOCKS5",
      "DOMAINS": ["t.example.com"],
      "LOCAL_DNS_ENABLED": false,
      "DATA_ENCRYPTION_METHOD": 5,
      "ENCRYPTION_KEY": "shared-secret",
      "FEC_LEVEL": "balanced"
    }
  }
}
```

Legacy aliases still import: `encryptionKey`, `encryptionLevel`,
`encryptionMethod`, `baseEncodeData`, and the lower-camel FEC fields fill
missing canonical `clientConfig` keys. Canonical desktop keys win when both are
present.

`DATA_ENCRYPTION_METHOD` follows desktop bounds `0` through `5`.
`encryptionLevel` maps to AES-GCM methods: `standard` -> `3`, `strong` -> `4`,
and `maximum` -> `5`. `FEC_LEVEL` can be `none`, `conservative`, `balanced`, or
`aggressive`; the server can still clamp or disable FEC during negotiation.

MasterDnsVPN resolver entries must be UDP IP endpoints or bounded CIDR ranges.
Hostnames, DoH/DoT entries, and oversized CIDR expansions are rejected for the
iOS bridge.

The bridge vendors a generated-source gVisor revision under
`third_party/gvisor` and pins it with a local `replace` directive. Newer gVisor
module snapshots currently require Bazel-generated files that are not present
when consumed directly by `go test`/`gomobile bind`.
