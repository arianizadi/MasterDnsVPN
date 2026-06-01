# MasterDnsVPN Mobile Bridge

This package is intentionally inside the `MasterDnsVPN` module so it can import
`internal/client` and `internal/config`.

Build the iOS framework from `MasterDnsVPN`:

```sh
gomobile bind -target ios -o ../iOS/Vendor/EngineBridge.xcframework ./mobilebridge
```

The Swift packet tunnel extension expects this API:

- `StartEngine(profileJSON, socksListenAddress, logCallback) -> error`
- `StopEngine() -> error`
- `EngineStatus() -> JSON string`
- `ValidateProfile(profileJSON) -> error`

VayDNS profiles run a local SOCKS5 listener through `vaydns/client`.
MasterDnsVPN profiles run the built-in SOCKS5 mode with local DNS disabled.

MasterDnsVPN mobile profiles can use preset fields:

```json
{
  "masterdns": {
    "encryptionKey": "shared-secret",
    "encryptionLevel": "maximum",
    "fecLevel": "balanced"
  }
}
```

`encryptionLevel` maps to AES-GCM methods: `standard` -> `3`, `strong` ->
`4`, and `maximum` -> `5`. The server must use the matching encryption method.
`fecLevel` can be `none`, `conservative`, `balanced`, or `aggressive`; the
server can still clamp or disable FEC during negotiation.
