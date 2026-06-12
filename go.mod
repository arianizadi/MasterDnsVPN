// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

module masterdnsvpn-go

go 1.25.0

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c
	github.com/klauspost/compress v1.18.5
	github.com/net2share/vaydns v0.0.0
	github.com/pierrec/lz4/v4 v4.1.26
	github.com/sirupsen/logrus v1.9.4
	github.com/xssnick/raptorq v0.0.0
	golang.org/x/crypto v0.51.0
	golang.org/x/sys v0.44.0
	gvisor.dev/gvisor v0.0.0-20231020174304-b8a429915ff1
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/xtaci/kcp-go/v5 v5.6.61 // indirect
	github.com/xtaci/smux v1.5.50 // indirect
	golang.org/x/mobile v0.0.0-20260602190626-68735029466e // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
)

replace github.com/net2share/vaydns => ../vaydns

replace github.com/xssnick/raptorq => ../raptorq

replace gvisor.dev/gvisor => ./third_party/gvisor

tool golang.org/x/mobile/cmd/gobind
