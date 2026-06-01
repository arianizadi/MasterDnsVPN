package mobilebridge

import "testing"

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

func TestValidateProfileRejectsWeakMasterDNSEncryption(t *testing.T) {
	raw := `{
		"version": 1,
		"name": "Dad MasterDns",
		"protocol": "masterdns",
		"domain": "t.example.com",
		"resolvers": [{"type": "udp", "address": "1.1.1.1:53"}],
		"masterdns": {"encryptionKey": "secret", "encryptionMethod": 1}
	}`

	if err := ValidateProfile(raw); err == nil {
		t.Fatal("ValidateProfile should reject non-AES-GCM MasterDnsVPN profiles")
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
