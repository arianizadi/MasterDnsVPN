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
