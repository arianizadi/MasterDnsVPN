package mobilebridge

import (
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	masterclient "masterdnsvpn-go/internal/client"
)

const validVayDNSKey = "0000000000000000000000000000000000000000000000000000000000000000"

func TestValidateProfileAcceptsVayDNS(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad VayDNS",
		"protocol": "vaydns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1"}],
		"vaydns": {"publicKey": "` + validVayDNSKey + `", "recordType": "txt"}
	}`

	if err := ValidateProfile(raw); err != nil {
		t.Fatalf("ValidateProfile returned error: %v", err)
	}
}

func TestValidateProfileAcceptsLegacyMasterDNSEncryption(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad MasterDns",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1:53"}],
		"masterdns": {"encryptionKey": "secret", "encryptionMethod": 1}
	}`

	if err := ValidateProfile(raw); err != nil {
		t.Fatalf("ValidateProfile should accept desktop-bounded legacy encryption methods: %v", err)
	}
}

func TestValidateProfileRejectsOutOfRangeMasterDNSEncryption(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad MasterDns",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1:53"}],
		"masterdns": {"encryptionKey": "secret", "encryptionMethod": 6}
	}`

	if err := ValidateProfile(raw); err == nil {
		t.Fatal("ValidateProfile should reject encryption methods outside desktop bounds")
	}
}

func TestValidateProfileDefaultsMasterDNSToAES256GCM(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad MasterDns",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1"}],
		"masterdns": {"encryptionKey": "secret"}
	}`

	profile, _, err := parseAndValidateProfile(raw)
	if err != nil {
		t.Fatalf("parseAndValidateProfile returned error: %v", err)
	}
	if profile.MasterDNS.EncryptionMethod != 5 {
		t.Fatalf("unexpected encryption method: got=%d want=5", profile.MasterDNS.EncryptionMethod)
	}
}

func TestValidateProfileAppliesMasterDNSLevels(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad MasterDns",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1"}],
		"masterdns": {
			"encryptionKey": "secret",
			"encryptionLevel": "AES-192-GCM",
			"fecLevel": "aggressive"
		}
	}`

	profile, _, err := parseAndValidateProfile(raw)
	if err != nil {
		t.Fatalf("parseAndValidateProfile returned error: %v", err)
	}
	if profile.MasterDNS.EncryptionLevel != "strong" || profile.MasterDNS.EncryptionMethod != 4 {
		t.Fatalf("unexpected encryption level mapping: level=%q method=%d", profile.MasterDNS.EncryptionLevel, profile.MasterDNS.EncryptionMethod)
	}
	if profile.MasterDNS.FECLevel != "aggressive" ||
		!profile.MasterDNS.FECEnabled ||
		profile.MasterDNS.FECGroupSize != 16 ||
		profile.MasterDNS.FECOverheadPercent != 40 ||
		profile.MasterDNS.FECFlushTimeoutMS != 15 {
		t.Fatalf("unexpected FEC level mapping: %+v", profile.MasterDNS)
	}
}

func TestValidateProfileRejectsConflictingMasterDNSEncryptionLevel(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad MasterDns",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1"}],
		"masterdns": {"encryptionKey": "secret", "encryptionLevel": "maximum", "encryptionMethod": 3}
	}`

	if err := ValidateProfile(raw); err == nil {
		t.Fatal("ValidateProfile should reject conflicting encryption level and method")
	}
}

func TestValidateProfileRejectsInvalidMasterDNSFECLevel(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad MasterDns",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1"}],
		"masterdns": {"encryptionKey": "secret", "fecLevel": "extreme"}
	}`

	if err := ValidateProfile(raw); err == nil {
		t.Fatal("ValidateProfile should reject invalid FEC level")
	}
}

func TestValidateProfileRejectsMasterDNSDoHResolver(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad MasterDns",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "doh", "address": "https://cloudflare-dns.com/dns-query"}],
		"masterdns": {"encryptionKey": "secret", "encryptionMethod": 5}
	}`

	if err := ValidateProfile(raw); err == nil {
		t.Fatal("ValidateProfile should reject non-UDP MasterDnsVPN resolvers")
	}
}

func TestValidateProfileAcceptsMasterDNSClientConfigNativeTCP(t *testing.T) {
	raw := `{
		"version": 2,
		"name": "Dad MasterDns Native",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"domains": ["t.example.com", "backup.example.com"],
		"resolvers": [{"type": "udp", "address": "[2001:db8::1]:5353"}],
		"masterdns": {
			"runtimeMode": "nativePacket",
			"clientConfig": {
				"PROTOCOL_TYPE": "TCP",
				"DOMAINS": ["t.example.com", "backup.example.com"],
				"LOCAL_DNS_ENABLED": true,
				"DATA_ENCRYPTION_METHOD": 5,
				"ENCRYPTION_KEY": "secret",
				"MIN_UPLOAD_MTU": 40,
				"MAX_UPLOAD_MTU": 150,
				"UPLOAD_COMPRESSION_TYPE": 0,
				"DOWNLOAD_COMPRESSION_TYPE": 0,
				"RESOLVER_BALANCING_STRATEGY": 2
			}
		}
	}`

	profile, _, err := parseAndValidateProfile(raw)
	if err != nil {
		t.Fatalf("parseAndValidateProfile returned error: %v", err)
	}
	if profile.MasterDNS.runtimeMode() != runtimeModeNativePacket {
		t.Fatalf("unexpected runtimeMode: %q", profile.MasterDNS.runtimeMode())
	}
	if profile.MasterDNS.EncryptionKey != "secret" {
		t.Fatal("expected ENCRYPTION_KEY from clientConfig to populate legacy bridge field")
	}
}

func TestValidateProfileRejectsHevSocksIncompatibleClientConfig(t *testing.T) {
	raw := `{
		"version": 2,
		"name": "Dad MasterDns TCP",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1"}],
		"masterdns": {
			"runtimeMode": "hevSocks",
			"clientConfig": {
				"PROTOCOL_TYPE": "TCP",
				"DOMAINS": ["t.example.com"],
				"DATA_ENCRYPTION_METHOD": 5,
				"ENCRYPTION_KEY": "secret"
			}
		}
	}`

	if err := ValidateProfile(raw); err == nil {
		t.Fatal("ValidateProfile should reject TCP clientConfig in hevSocks mode")
	}
}

func TestBuildMasterDNSConfigClampsHevSocksDuplication(t *testing.T) {
	raw := `{
		"version": 2,
		"name": "Dad MasterDns Hev",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1"}],
		"masterdns": {
			"runtimeMode": "hevSocks",
			"clientConfig": {
				"PROTOCOL_TYPE": "SOCKS5",
				"DOMAINS": ["t.example.com"],
				"DATA_ENCRYPTION_METHOD": 5,
				"ENCRYPTION_KEY": "secret",
				"PACKET_DUPLICATION_COUNT": 4,
				"SETUP_PACKET_DUPLICATION_COUNT": 4
			}
		}
	}`

	profile, _, err := parseAndValidateProfile(raw)
	if err != nil {
		t.Fatalf("parseAndValidateProfile returned error: %v", err)
	}
	cfg, cleanup, err := buildMasterDNSConfig(profile, "127.0.0.1:18080", true)
	defer cleanup()
	if err != nil {
		t.Fatalf("buildMasterDNSConfig returned error: %v", err)
	}
	if cfg.PacketDuplicationCount != 1 || cfg.SetupPacketDuplicationCount != 1 {
		t.Fatalf(
			"expected iOS Hev duplication clamp to 1x, got packet=%d setup=%d",
			cfg.PacketDuplicationCount,
			cfg.SetupPacketDuplicationCount,
		)
	}
}

func TestValidateProfileAcceptsBoundedCIDRResolver(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad MasterDns CIDR",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "192.0.2.0/30:53"}],
		"masterdns": {"encryptionKey": "secret", "encryptionMethod": 5}
	}`

	if err := ValidateProfile(raw); err != nil {
		t.Fatalf("ValidateProfile should accept bounded CIDR resolvers: %v", err)
	}
}

func TestValidateProfileRejectsOversizedCIDRResolver(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad MasterDns CIDR",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "192.0.2.0/20:53"}],
		"masterdns": {"encryptionKey": "secret", "encryptionMethod": 5}
	}`

	if err := ValidateProfile(raw); err == nil {
		t.Fatal("ValidateProfile should reject oversized CIDR resolver expansion")
	}
}

func TestStartPacketEngineRequiresPacketCallback(t *testing.T) {
	raw := `{
		"version": 2,
		"name": "Dad MasterDns Native",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1"}],
		"masterdns": {
			"runtimeMode": "nativePacket",
			"clientConfig": {
				"PROTOCOL_TYPE": "TCP",
				"DOMAINS": ["t.example.com"],
				"DATA_ENCRYPTION_METHOD": 5,
				"ENCRYPTION_KEY": "secret"
			}
		}
	}`

	err := StartPacketEngine(raw, nil, nil)
	if err == nil {
		t.Fatal("StartPacketEngine should require a packet callback")
	}
	if !strings.Contains(err.Error(), "packet callback") {
		t.Fatalf("unexpected StartPacketEngine error: %v", err)
	}
}

func TestWritePacketRequiresActiveNativeRuntime(t *testing.T) {
	StopEngine()

	err := WritePacket([]byte{0x45})
	if err == nil {
		t.Fatal("WritePacket should fail when no native packet runtime is active")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Fatalf("unexpected WritePacket error: %v", err)
	}
}

func TestNativeTargetFromID(t *testing.T) {
	target, port, atyp, ok := nativeTargetFromID(stack.TransportEndpointID{
		LocalAddress: tcpip.AddrFrom4([4]byte{203, 0, 113, 7}),
		LocalPort:    443,
	})
	if !ok {
		t.Fatal("expected IPv4 target to parse")
	}
	if target != "203.0.113.7" || port != 443 || atyp != masterclient.SOCKS5_ATYP_IPV4 {
		t.Fatalf("unexpected IPv4 target: target=%q port=%d atyp=%d", target, port, atyp)
	}

	target, port, atyp, ok = nativeTargetFromID(stack.TransportEndpointID{
		LocalAddress: tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		LocalPort:    853,
	})
	if !ok {
		t.Fatal("expected IPv6 target to parse")
	}
	if target != "2001:db8::1" || port != 853 || atyp != masterclient.SOCKS5_ATYP_IPV6 {
		t.Fatalf("unexpected IPv6 target: target=%q port=%d atyp=%d", target, port, atyp)
	}
}

func TestBuildMasterDNSConfigClampsARQWindowForMobile(t *testing.T) {
	makeProfile := func(clientConfigJSON string) profile {
		raw := `{
			"version": 2,
			"name": "Window Clamp",
			"protocol": "masterdns",
			"domain": "t.example.com",
			"resolvers": [{"type": "udp", "address": "1.1.1.1"}],
			"masterdns": {
				"runtimeMode": "nativePacket",
				"clientConfig": ` + clientConfigJSON + `
			}
		}`
		parsed, _, err := parseAndValidateProfile(raw)
		if err != nil {
			t.Fatalf("parseAndValidateProfile returned error: %v", err)
		}
		return parsed
	}

	cases := []struct {
		name         string
		clientConfig string
		wantWindow   int
	}{
		{
			name:         "default window is clamped",
			clientConfig: `{"PROTOCOL_TYPE": "TCP", "LOCAL_DNS_ENABLED": true, "ENCRYPTION_KEY": "secret"}`,
			wantWindow:   maxMobileARQWindowSize,
		},
		{
			name:         "oversized window is clamped",
			clientConfig: `{"PROTOCOL_TYPE": "TCP", "LOCAL_DNS_ENABLED": true, "ENCRYPTION_KEY": "secret", "ARQ_WINDOW_SIZE": 2000}`,
			wantWindow:   maxMobileARQWindowSize,
		},
		{
			name:         "smaller window is preserved",
			clientConfig: `{"PROTOCOL_TYPE": "TCP", "LOCAL_DNS_ENABLED": true, "ENCRYPTION_KEY": "secret", "ARQ_WINDOW_SIZE": 128}`,
			wantWindow:   128,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, cleanup, err := buildMasterDNSConfig(makeProfile(tc.clientConfig), defaultSocksListenAddress, false)
			if cleanup != nil {
				defer cleanup()
			}
			if err != nil {
				t.Fatalf("buildMasterDNSConfig returned error: %v", err)
			}
			if cfg.ARQWindowSize != tc.wantWindow {
				t.Fatalf("ARQWindowSize = %d, want %d", cfg.ARQWindowSize, tc.wantWindow)
			}
		})
	}
}
