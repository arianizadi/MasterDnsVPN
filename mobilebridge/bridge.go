// Package mobilebridge exposes the DNS tunnel engines through a gomobile-safe
// API for the iOS packet tunnel extension.
package mobilebridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"masterdnsvpn-go/internal/arq"
	masterclient "masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/fec"
	masterlog "masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"

	vaydnsclient "github.com/net2share/vaydns/client"
	log "github.com/sirupsen/logrus"
)

const (
	defaultSocksListenAddress = "127.0.0.1:18080"
	startupGrace              = 500 * time.Millisecond
	stopGrace                 = 5 * time.Second
	runtimeModeHevSocks       = "hevSocks"
	runtimeModeNativePacket   = "nativePacket"
	maxMobileResolverHosts    = 1024
	maxMobileARQWindowSize    = 256
)

// LogCallback is implemented by Swift and receives engine log lines.
type LogCallback interface {
	Log(line string)
}

// PacketCallback is implemented by Swift native packet runtimes.
type PacketCallback interface {
	WritePacket(packet []byte)
}

type resolverProfile struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

type vaydnsProfile struct {
	PublicKey   string `json:"publicKey"`
	RecordType  string `json:"recordType"`
	MaxQnameLen int    `json:"maxQnameLen"`
}

type masterDNSProfile struct {
	RuntimeMode        string                     `json:"runtimeMode"`
	ClientConfig       map[string]json.RawMessage `json:"clientConfig"`
	EncryptionKey      string                     `json:"encryptionKey"`
	EncryptionLevel    string                     `json:"encryptionLevel"`
	EncryptionMethod   int                        `json:"encryptionMethod"`
	BaseEncodeData     bool                       `json:"baseEncodeData"`
	FECLevel           string                     `json:"fecLevel"`
	FECEnabled         bool                       `json:"fecEnabled"`
	FECDirection       string                     `json:"fecDirection"`
	FECGroupSize       int                        `json:"fecGroupSize"`
	FECOverheadPercent int                        `json:"fecOverheadPercent"`
	FECSymbolSize      int                        `json:"fecSymbolSize"`
	FECFlushTimeoutMS  int                        `json:"fecFlushTimeoutMs"`
}

type profile struct {
	Version   int               `json:"version"`
	Name      string            `json:"name"`
	Protocol  string            `json:"protocol"`
	Domain    string            `json:"domain"`
	Domains   []string          `json:"domains,omitempty"`
	Resolvers []resolverProfile `json:"resolvers"`
	VayDNS    *vaydnsProfile    `json:"vaydns,omitempty"`
	MasterDNS *masterDNSProfile `json:"masterdns,omitempty"`
}

type engineRunner struct {
	ctx                context.Context
	cancel             context.CancelFunc
	done               chan struct{}
	profile            profile
	profileJSON        string
	socksListenAddress string
	logCallback        LogCallback
	packetCallback     PacketCallback
	masterApp          *masterclient.Client
	masterCleanup      func()
	nativePacket       *nativePacketEngine
}

type engineState struct {
	mu                 sync.Mutex
	active             *engineRunner
	profileName        string
	protocol           string
	runtimeMode        string
	socksListenAddress string
	startedAt          time.Time
	lastError          string
}

var state engineState

// StartEngine starts exactly one selected engine and exposes its local SOCKS5
// endpoint on socksListenAddress. socksListenAddress defaults to 127.0.0.1:18080.
func StartEngine(profileJSON string, socksListenAddress string, logCallback LogCallback) error {
	parsed, normalizedJSON, err := parseAndValidateProfile(profileJSON)
	if err != nil {
		return err
	}

	listenAddress := strings.TrimSpace(socksListenAddress)
	if listenAddress == "" {
		listenAddress = defaultSocksListenAddress
	}
	if _, _, err := splitHostPortDefault(listenAddress, 0); err != nil {
		return fmt.Errorf("invalid SOCKS listen address: %w", err)
	}
	arq.ResetGlobalStats()
	fec.ResetGlobalStats()

	ctx, cancel := context.WithCancel(context.Background())
	runner := &engineRunner{
		ctx:                ctx,
		cancel:             cancel,
		done:               make(chan struct{}),
		profile:            parsed,
		profileJSON:        normalizedJSON,
		socksListenAddress: listenAddress,
		logCallback:        logCallback,
	}

	state.mu.Lock()
	if state.active != nil {
		state.mu.Unlock()
		cancel()
		return errors.New("engine already running")
	}
	state.active = runner
	state.profileName = parsed.Name
	state.protocol = parsed.Protocol
	state.runtimeMode = ""
	if parsed.MasterDNS != nil {
		state.runtimeMode = parsed.MasterDNS.runtimeMode()
	}
	state.socksListenAddress = listenAddress
	state.startedAt = time.Now().UTC()
	state.lastError = ""
	state.mu.Unlock()

	startMemoryReleaseLoop(ctx)
	errCh := make(chan error, 1)
	go func() {
		defer close(runner.done)
		err := runner.run()
		if err != nil && runner.ctx.Err() == nil {
			runner.logf("engine exited: %v", err)
			setLastError(err)
		}
		clearActiveRunner(runner)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
		return nil
	case <-time.After(startupGrace):
		runner.logf("engine started: protocol=%s socks=%s", parsed.Protocol, listenAddress)
		return nil
	}
}

// StopEngine stops the active engine, if any.
func StopEngine() error {
	state.mu.Lock()
	runner := state.active
	state.mu.Unlock()
	if runner == nil {
		return nil
	}

	runner.cancel()
	select {
	case <-runner.done:
		return nil
	case <-time.After(stopGrace):
		return errors.New("engine stop timed out")
	}
}

// EngineStatus returns a JSON status object for the active engine.
func EngineStatus() string {
	state.mu.Lock()
	defer state.mu.Unlock()

	status := map[string]any{
		"running":            state.active != nil,
		"profileName":        state.profileName,
		"protocol":           state.protocol,
		"runtimeMode":        state.runtimeMode,
		"socksListenAddress": state.socksListenAddress,
		"lastError":          state.lastError,
		"arq":                arq.GlobalStatsSnapshot(),
		"fec":                fec.GlobalStatsSnapshot(),
	}
	if state.active != nil && state.active.nativePacket != nil {
		status["nativePacket"] = state.active.nativePacket.snapshot()
	}
	if !state.startedAt.IsZero() {
		status["startedAt"] = state.startedAt.Format(time.RFC3339)
	}

	raw, err := json.Marshal(status)
	if err != nil {
		return `{"running":false,"lastError":"status encoding failed"}`
	}
	return string(raw)
}

// ValidateProfile validates a profile JSON payload without starting an engine.
func ValidateProfile(profileJSON string) error {
	_, _, err := parseAndValidateProfile(profileJSON)
	return err
}

// StartPacketEngine starts the native-packet MasterDnsVPN engine.
func StartPacketEngine(profileJSON string, packetCallback PacketCallback, logCallback LogCallback) error {
	parsed, normalizedJSON, err := parseAndValidateProfile(profileJSON)
	if err != nil {
		return err
	}
	if parsed.Protocol != "masterdns" {
		return errors.New("native packet engine is only available for MasterDnsVPN profiles")
	}
	if parsed.MasterDNS.runtimeMode() != runtimeModeNativePacket {
		return errors.New("StartPacketEngine requires masterdns.runtimeMode nativePacket")
	}
	if packetCallback == nil {
		return errors.New("StartPacketEngine requires a packet callback")
	}

	cfg, cleanup, err := buildMasterDNSConfig(parsed, defaultSocksListenAddress, false)
	if err != nil {
		return err
	}

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		cleanup()
		return fmt.Errorf("client codec setup failed: %w", err)
	}

	logger := masterlog.NewWithWriter("MasterDnsVPN Mobile", cfg.LogLevel, callbackWriter{callback: logCallback})
	app := masterclient.New(cfg, logger, codec)
	if err := app.BuildConnectionMap(); err != nil {
		cleanup()
		return err
	}

	native, err := newNativePacketEngine(app, packetCallback, logCallback)
	if err != nil {
		cleanup()
		return err
	}

	arq.ResetGlobalStats()
	fec.ResetGlobalStats()

	ctx, cancel := context.WithCancel(context.Background())
	runner := &engineRunner{
		ctx:                ctx,
		cancel:             cancel,
		done:               make(chan struct{}),
		profile:            parsed,
		profileJSON:        normalizedJSON,
		socksListenAddress: defaultSocksListenAddress,
		logCallback:        logCallback,
		packetCallback:     packetCallback,
		masterApp:          app,
		masterCleanup:      cleanup,
		nativePacket:       native,
	}

	state.mu.Lock()
	if state.active != nil {
		state.mu.Unlock()
		native.close()
		cancel()
		cleanup()
		return errors.New("engine already running")
	}
	state.active = runner
	state.profileName = parsed.Name
	state.protocol = parsed.Protocol
	state.runtimeMode = runtimeModeNativePacket
	state.socksListenAddress = ""
	state.startedAt = time.Now().UTC()
	state.lastError = ""
	state.mu.Unlock()

	startMemoryReleaseLoop(ctx)
	errCh := make(chan error, 1)
	go func() {
		defer close(runner.done)
		err := runner.runMasterDNSNativePacket()
		if err != nil && runner.ctx.Err() == nil {
			runner.logf("native packet engine exited: %v", err)
			setLastError(err)
		}
		clearActiveRunner(runner)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
		return nil
	case <-time.After(startupGrace):
		runner.logf("native packet engine starting: protocol=%s", parsed.Protocol)
		return nil
	}
}

// WritePacket injects an IP packet into the native packet runtime.
func WritePacket(packet []byte) error {
	state.mu.Lock()
	runner := state.active
	state.mu.Unlock()
	if runner == nil || runner.nativePacket == nil {
		return errors.New("MasterDnsVPN native packet runtime is not running")
	}
	return runner.nativePacket.writePacket(packet)
}

func (r *engineRunner) run() error {
	switch r.profile.Protocol {
	case "vaydns":
		return r.runVayDNS()
	case "masterdns":
		return r.runMasterDNS()
	default:
		return fmt.Errorf("unsupported protocol: %s", r.profile.Protocol)
	}
}

func (r *engineRunner) runVayDNS() error {
	log.SetOutput(callbackWriter{callback: r.logCallback})

	resolverSpec := r.profile.Resolvers[0]
	resolverType := vaydnsclient.ResolverType(strings.ToLower(strings.TrimSpace(resolverSpec.Type)))
	resolverAddr, err := normalizeResolverAddress(resolverSpec, 53)
	if err != nil {
		return err
	}

	resolver, err := vaydnsclient.NewResolver(resolverType, resolverAddr)
	if err != nil {
		return err
	}

	server, err := vaydnsclient.NewTunnelServer(r.profile.Domain, r.profile.VayDNS.PublicKey)
	if err != nil {
		return err
	}
	server.RecordType = defaultString(strings.ToLower(strings.TrimSpace(r.profile.VayDNS.RecordType)), "txt")
	server.MaxQnameLen = r.profile.VayDNS.MaxQnameLen

	tunnel, err := vaydnsclient.NewTunnel(resolver, server)
	if err != nil {
		return err
	}
	r.logf("starting VayDNS listener on %s through %s resolver %s", r.socksListenAddress, resolverSpec.Type, resolverAddr)
	if contextTunnel, ok := any(tunnel).(interface {
		ListenAndServeContext(context.Context, string) error
	}); ok {
		return contextTunnel.ListenAndServeContext(r.ctx, r.socksListenAddress)
	}

	contextDone := make(chan struct{})
	go func() {
		select {
		case <-r.ctx.Done():
			_ = tunnel.Close()
		case <-contextDone:
		}
	}()
	defer close(contextDone)

	return tunnel.ListenAndServe(r.socksListenAddress)
}

func (r *engineRunner) runMasterDNS() error {
	if r.profile.MasterDNS.runtimeMode() != runtimeModeHevSocks {
		return errors.New("StartEngine supports MasterDnsVPN only in hevSocks runtimeMode; use StartPacketEngine for nativePacket")
	}

	cfg, cleanup, err := buildMasterDNSConfig(r.profile, r.socksListenAddress, true)
	if err != nil {
		return err
	}
	defer cleanup()

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("client codec setup failed: %w", err)
	}

	logger := masterlog.NewWithWriter("MasterDnsVPN Mobile", cfg.LogLevel, callbackWriter{callback: r.logCallback})
	app := masterclient.New(cfg, logger, codec)
	if err := app.BuildConnectionMap(); err != nil {
		return err
	}

	r.logf("starting MasterDnsVPN SOCKS5 listener on %s with %d resolver(s)", r.socksListenAddress, len(cfg.Resolvers))
	return app.Run(r.ctx)
}

func (r *engineRunner) runMasterDNSNativePacket() error {
	if r.masterCleanup != nil {
		defer r.masterCleanup()
	}
	if r.nativePacket != nil {
		r.nativePacket.start(r.ctx)
		defer r.nativePacket.close()
	}
	if r.masterApp == nil {
		return errors.New("native packet engine missing MasterDnsVPN client")
	}

	r.logf("starting MasterDnsVPN native packet runtime with TCP and DNS packet adapter")
	return r.masterApp.RunExternalPacketRuntime(r.ctx)
}

func parseAndValidateProfile(raw string) (profile, string, error) {
	var p profile
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, "", fmt.Errorf("invalid profile JSON: %w", err)
	}

	p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	p.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p.Domain)), ".")
	p.Domains = normalizeProfileDomains(append([]string{p.Domain}, p.Domains...))
	if len(p.Domains) > 0 {
		p.Domain = p.Domains[0]
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Version != 1 && p.Version != 2 {
		return p, "", fmt.Errorf("unsupported profile version: %d", p.Version)
	}
	if p.Name == "" {
		return p, "", errors.New("profile name is required")
	}
	if p.Domain == "" || strings.ContainsAny(p.Domain, "/:") {
		return p, "", errors.New("profile domain is invalid")
	}
	if len(p.Resolvers) == 0 {
		return p, "", errors.New("at least one resolver is required")
	}

	switch p.Protocol {
	case "vaydns":
		if p.VayDNS == nil {
			return p, "", errors.New("vaydns settings are required")
		}
		if strings.TrimSpace(p.VayDNS.PublicKey) == "" {
			return p, "", errors.New("vaydns.publicKey is required")
		}
		if p.VayDNS.MaxQnameLen == 0 {
			p.VayDNS.MaxQnameLen = 101
		}
		if p.VayDNS.RecordType == "" {
			p.VayDNS.RecordType = "txt"
		}
		for _, resolver := range p.Resolvers {
			if _, err := vaydnsclient.NewResolver(vaydnsclient.ResolverType(strings.ToLower(strings.TrimSpace(resolver.Type))), resolver.Address); err != nil {
				return p, "", fmt.Errorf("invalid VayDNS resolver: %w", err)
			}
			if _, err := normalizeResolverAddress(resolver, 53); err != nil {
				return p, "", err
			}
		}
		if _, err := vaydnsclient.NewTunnelServer(p.Domain, p.VayDNS.PublicKey); err != nil {
			return p, "", err
		}
	case "masterdns":
		if p.MasterDNS == nil {
			return p, "", errors.New("masterdns settings are required")
		}
		if err := normalizeMasterDNSProfile(p.MasterDNS, p.Domains); err != nil {
			return p, "", err
		}
		if p.MasterDNS.EncryptionKey == "" {
			return p, "", errors.New("masterdns.encryptionKey is required")
		}
		if p.MasterDNS.EncryptionMethod < 0 || p.MasterDNS.EncryptionMethod > 5 {
			return p, "", errors.New("masterdns encryption method must be between 0 and 5")
		}
		if _, err := masterDNSResolverLines(p.Resolvers); err != nil {
			return p, "", err
		}
		cfg, cleanup, err := buildMasterDNSConfig(p, defaultSocksListenAddress, p.MasterDNS.runtimeMode() == runtimeModeHevSocks)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			return p, "", err
		}
		if p.MasterDNS.runtimeMode() == runtimeModeHevSocks && cfg.LocalDNSEnabled {
			return p, "", errors.New("hevSocks runtimeMode cannot use LOCAL_DNS_ENABLED")
		}
	default:
		return p, "", fmt.Errorf("unsupported protocol: %q", p.Protocol)
	}

	normalized, err := json.Marshal(p)
	if err != nil {
		return p, "", err
	}
	return p, string(normalized), nil
}

func normalizeResolverAddress(resolver resolverProfile, defaultPort int) (string, error) {
	resolverType := strings.ToLower(strings.TrimSpace(resolver.Type))
	address := strings.TrimSpace(resolver.Address)
	if address == "" {
		return "", errors.New("resolver address is required")
	}

	switch resolverType {
	case "doh":
		u, err := url.Parse(address)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", fmt.Errorf("invalid DoH resolver address: %s", address)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return "", fmt.Errorf("invalid DoH resolver scheme: %s", u.Scheme)
		}
		return address, nil
	case "dot":
		host, port, err := splitHostPortDefault(address, 853)
		if err != nil {
			return "", fmt.Errorf("invalid DoT resolver address: %w", err)
		}
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	case "udp":
		host, port, err := splitHostPortDefault(address, defaultPort)
		if err != nil {
			return "", fmt.Errorf("invalid UDP resolver address: %w", err)
		}
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	default:
		return "", fmt.Errorf("unsupported resolver type: %s", resolver.Type)
	}
}

func buildMasterDNSConfig(p profile, socksListenAddress string, enforceHevSocks bool) (config.ClientConfig, func(), error) {
	cleanup := func() {}

	resolverLines, err := masterDNSResolverLines(p.Resolvers)
	if err != nil {
		return config.ClientConfig{}, cleanup, err
	}

	tempDir, err := os.MkdirTemp("", "masterdnsvpn-mobilebridge-*")
	if err != nil {
		return config.ClientConfig{}, cleanup, fmt.Errorf("create mobilebridge config dir: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tempDir) }

	resolversPath := tempDir + string(os.PathSeparator) + "client_resolvers.txt"
	if err := os.WriteFile(resolversPath, []byte(strings.Join(resolverLines, "\n")+"\n"), 0o600); err != nil {
		cleanup()
		return config.ClientConfig{}, func() {}, fmt.Errorf("write mobilebridge resolvers: %w", err)
	}

	rawConfig, err := json.Marshal(p.MasterDNS.ClientConfig)
	if err != nil {
		cleanup()
		return config.ClientConfig{}, func() {}, fmt.Errorf("encode masterdns.clientConfig: %w", err)
	}
	encodedConfig := base64.StdEncoding.EncodeToString(rawConfig)
	overrides := config.ClientConfigOverrides{
		ResolversFilePath: &resolversPath,
		Values:            map[string]any{},
	}
	// Each TCP flow gets its own ARQ window, so per-stream buffers multiply by
	// the number of concurrent flows. Desktop-sized windows blow through the
	// iOS extension's ~50 MB jetsam budget during parallel transfers.
	if window, ok := clientConfigInt(p.MasterDNS.ClientConfig, "ARQ_WINDOW_SIZE"); !ok || window > maxMobileARQWindowSize {
		overrides.Values["ARQWindowSize"] = maxMobileARQWindowSize
	}
	if enforceHevSocks {
		listenIP, listenPort, err := splitHostPortDefault(socksListenAddress, 18080)
		if err != nil {
			cleanup()
			return config.ClientConfig{}, func() {}, err
		}
		overrides.Values["ProtocolType"] = "SOCKS5"
		overrides.Values["ListenIP"] = listenIP
		overrides.Values["ListenPort"] = listenPort
		overrides.Values["SOCKS5Auth"] = false
		overrides.Values["LocalDNSEnabled"] = false
		overrides.Values["PacketDuplicationCount"] = 1
		overrides.Values["SetupPacketDuplicationCount"] = 1
	}

	cfg, err := config.LoadClientConfigFromJSONBase64WithOverrides(encodedConfig, overrides)
	if err != nil {
		cleanup()
		return config.ClientConfig{}, func() {}, fmt.Errorf("invalid masterdns.clientConfig: %w", err)
	}
	cfg.ConfigPath = "<mobilebridge>"
	cfg.ConfigDir = tempDir
	return cfg, cleanup, nil
}

func masterDNSResolverLines(resolvers []resolverProfile) ([]string, error) {
	result := make([]string, 0, len(resolvers))
	seen := make(map[string]struct{}, len(resolvers))
	for _, resolver := range resolvers {
		if strings.ToLower(strings.TrimSpace(resolver.Type)) != "udp" {
			return nil, errors.New("MasterDnsVPN supports only udp resolver entries")
		}
		line, err := normalizeMasterDNSResolverLine(resolver.Address)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		result = append(result, line)
	}
	if len(result) == 0 {
		return nil, errors.New("at least one MasterDnsVPN resolver is required")
	}
	return result, nil
}

func normalizeMasterDNSResolverLine(address string) (string, error) {
	host, port, err := splitResolverTargetPort(address, 53)
	if err != nil {
		return "", fmt.Errorf("invalid MasterDnsVPN resolver: %w", err)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if port == 53 {
			return addr.String(), nil
		}
		return net.JoinHostPort(addr.String(), strconv.Itoa(port)), nil
	}
	prefix, err := netip.ParsePrefix(host)
	if err != nil {
		return "", fmt.Errorf("MasterDnsVPN resolver must be an IP address or CIDR: %s", host)
	}
	count, ok := mobileResolverHostCount(prefix)
	if !ok || count > maxMobileResolverHosts {
		return "", fmt.Errorf("MasterDnsVPN resolver CIDR expands to too many hosts: %s", host)
	}
	text := prefix.Masked().String()
	if port == 53 {
		return text, nil
	}
	if prefix.Addr().Is6() {
		return "[" + text + "]:" + strconv.Itoa(port), nil
	}
	return text + ":" + strconv.Itoa(port), nil
}

func splitResolverTargetPort(raw string, defaultPort int) (string, int, error) {
	text := strings.TrimSpace(raw)
	if strings.Contains(text, "/") && strings.Count(text, ":") == 1 && !strings.HasPrefix(text, "[") {
		separator := strings.LastIndexByte(text, ':')
		host := strings.TrimSpace(text[:separator])
		portText := strings.TrimSpace(text[separator+1:])
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port: %s", portText)
		}
		return host, port, nil
	}
	return splitHostPortDefault(text, defaultPort)
}

func mobileResolverHostCount(prefix netip.Prefix) (int, bool) {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		hostBits := 32 - prefix.Bits()
		if hostBits >= 31 {
			return 2, hostBits == 31
		}
		return max((1<<hostBits)-2, 1), true
	}

	hostBits := 128 - prefix.Bits()
	if hostBits > 10 {
		return 0, false
	}
	total := 1 << hostBits
	if prefix.Bits() < 127 {
		return max(total-1, 1), true
	}
	return total, true
}

func masterDNSResolvers(resolvers []resolverProfile) ([]config.ResolverAddress, error) {
	result := make([]config.ResolverAddress, 0, len(resolvers))
	seen := make(map[string]struct{}, len(resolvers))
	for _, resolver := range resolvers {
		if strings.ToLower(strings.TrimSpace(resolver.Type)) != "udp" {
			return nil, errors.New("MasterDnsVPN supports only udp resolver entries")
		}
		host, port, err := splitHostPortDefault(resolver.Address, 53)
		if err != nil {
			return nil, fmt.Errorf("invalid MasterDnsVPN resolver: %w", err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("MasterDnsVPN resolver must be an IP address: %s", host)
		}
		key := net.JoinHostPort(addr.String(), strconv.Itoa(port))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, config.ResolverAddress{IP: addr.String(), Port: port})
	}
	if len(result) == 0 {
		return nil, errors.New("at least one MasterDnsVPN resolver is required")
	}
	return result, nil
}

func resolverMap(resolvers []config.ResolverAddress) map[string]int {
	result := make(map[string]int, len(resolvers))
	for _, resolver := range resolvers {
		if _, ok := result[resolver.IP]; !ok {
			result[resolver.IP] = resolver.Port
		}
	}
	return result
}

func splitHostPortDefault(raw string, defaultPort int) (string, int, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "", 0, errors.New("address is empty")
	}

	host, portText, err := net.SplitHostPort(text)
	if err != nil {
		if defaultPort == 0 {
			return "", 0, err
		}
		if strings.Count(text, ":") > 1 && !strings.HasPrefix(text, "[") {
			if _, parseErr := netip.ParseAddr(text); parseErr == nil {
				return text, defaultPort, nil
			}
			if _, parseErr := netip.ParsePrefix(text); parseErr == nil {
				return text, defaultPort, nil
			}
			return "", 0, err
		}
		host = text
		portText = strconv.Itoa(defaultPort)
	}

	host = strings.Trim(host, "[]")
	if host == "" {
		return "", 0, errors.New("host is empty")
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port: %s", portText)
	}
	return host, port, nil
}

func clearActiveRunner(runner *engineRunner) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.active == runner {
		state.active = nil
	}
}

func setLastError(err error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if err != nil {
		state.lastError = err.Error()
	}
}

func (r *engineRunner) logf(format string, args ...any) {
	safeLog(r.logCallback, fmt.Sprintf(format, args...))
}

func safeLog(callback LogCallback, line string) {
	if callback == nil {
		return
	}
	callback.Log(strings.TrimSpace(line))
}

type callbackWriter struct {
	callback LogCallback
}

func (w callbackWriter) Write(p []byte) (int, error) {
	safeLog(w.callback, string(p))
	return len(p), nil
}

func defaultString(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func normalizeMasterDNSProfile(settings *masterDNSProfile, domains []string) error {
	if settings == nil {
		return nil
	}

	settings.RuntimeMode = strings.TrimSpace(settings.RuntimeMode)
	if settings.RuntimeMode == "" {
		settings.RuntimeMode = runtimeModeHevSocks
	}
	switch settings.RuntimeMode {
	case runtimeModeHevSocks, runtimeModeNativePacket:
	default:
		return fmt.Errorf("invalid masterdns.runtimeMode: %q", settings.RuntimeMode)
	}
	settings.ClientConfig = normalizeClientConfigMap(settings.ClientConfig)
	if _, ok := settings.ClientConfig["DOMAINS"]; !ok {
		setClientConfigJSON(settings.ClientConfig, "DOMAINS", domains)
	}
	if _, ok := settings.ClientConfig["PROTOCOL_TYPE"]; !ok {
		setClientConfigJSON(settings.ClientConfig, "PROTOCOL_TYPE", "SOCKS5")
	}
	if _, ok := settings.ClientConfig["LOCAL_DNS_ENABLED"]; !ok {
		setClientConfigJSON(settings.ClientConfig, "LOCAL_DNS_ENABLED", false)
	}
	protocolType, _ := clientConfigString(settings.ClientConfig, "PROTOCOL_TYPE")
	protocolType = strings.ToUpper(strings.TrimSpace(protocolType))
	localDNSEnabled, _ := clientConfigBool(settings.ClientConfig, "LOCAL_DNS_ENABLED")
	if settings.runtimeMode() == runtimeModeHevSocks {
		if protocolType != "" && protocolType != "SOCKS5" {
			return errors.New("hevSocks runtimeMode requires PROTOCOL_TYPE SOCKS5")
		}
		if localDNSEnabled {
			return errors.New("hevSocks runtimeMode cannot use LOCAL_DNS_ENABLED")
		}
	}

	settings.EncryptionKey = strings.TrimSpace(settings.EncryptionKey)
	if key, ok := clientConfigString(settings.ClientConfig, "ENCRYPTION_KEY"); ok && settings.EncryptionKey == "" {
		settings.EncryptionKey = strings.TrimSpace(key)
	}
	settings.EncryptionLevel = normalizeEncryptionLevel(settings.EncryptionLevel)
	if settings.EncryptionLevel != "" {
		method, err := encryptionMethodForLevel(settings.EncryptionLevel)
		if err != nil {
			return fmt.Errorf("invalid masterdns.encryptionLevel: %q", settings.EncryptionLevel)
		}
		if settings.EncryptionMethod != 0 && settings.EncryptionMethod != method {
			return fmt.Errorf("masterdns.encryptionLevel %q conflicts with encryptionMethod %d", settings.EncryptionLevel, settings.EncryptionMethod)
		}
		settings.EncryptionMethod = method
	}
	if method, ok := clientConfigInt(settings.ClientConfig, "DATA_ENCRYPTION_METHOD"); ok {
		settings.EncryptionMethod = method
	}
	if settings.EncryptionMethod == 0 {
		settings.EncryptionMethod = 5
	}
	if _, ok := settings.ClientConfig["DATA_ENCRYPTION_METHOD"]; !ok {
		setClientConfigJSON(settings.ClientConfig, "DATA_ENCRYPTION_METHOD", settings.EncryptionMethod)
	}
	if _, ok := settings.ClientConfig["ENCRYPTION_KEY"]; !ok && settings.EncryptionKey != "" {
		setClientConfigJSON(settings.ClientConfig, "ENCRYPTION_KEY", settings.EncryptionKey)
	}
	if baseEncode, ok := clientConfigBool(settings.ClientConfig, "BASE_ENCODE_DATA"); ok {
		settings.BaseEncodeData = baseEncode
	} else {
		setClientConfigJSON(settings.ClientConfig, "BASE_ENCODE_DATA", settings.BaseEncodeData)
	}

	if level, ok := clientConfigString(settings.ClientConfig, "FEC_LEVEL"); ok {
		settings.FECLevel = level
	}
	if enabled, ok := clientConfigBool(settings.ClientConfig, "FEC_ENABLED"); ok {
		settings.FECEnabled = enabled
	}
	if direction, ok := clientConfigString(settings.ClientConfig, "FEC_DIRECTION"); ok {
		settings.FECDirection = direction
	}
	if value, ok := clientConfigInt(settings.ClientConfig, "FEC_GROUP_SIZE"); ok {
		settings.FECGroupSize = value
	}
	if value, ok := clientConfigInt(settings.ClientConfig, "FEC_OVERHEAD_PERCENT"); ok {
		settings.FECOverheadPercent = value
	}
	if value, ok := clientConfigInt(settings.ClientConfig, "FEC_SYMBOL_SIZE"); ok {
		settings.FECSymbolSize = value
	}
	if value, ok := clientConfigInt(settings.ClientConfig, "FEC_FLUSH_TIMEOUT_MS"); ok {
		settings.FECFlushTimeoutMS = value
	}
	settings.FECLevel = fec.NormalizeLevel(settings.FECLevel)
	if settings.FECLevel != "" {
		params, err := fec.ParamsForLevel(settings.FECLevel)
		if err != nil {
			return fmt.Errorf("invalid masterdns.fecLevel: %q", settings.FECLevel)
		}
		applyFECParams(settings, params)
		setClientConfigJSON(settings.ClientConfig, "FEC_LEVEL", settings.FECLevel)
		setFECClientConfig(settings)
		return nil
	}

	applyFECParams(settings, fec.NormalizeParams(fec.Params{
		Enabled:         settings.FECEnabled,
		Direction:       settings.FECDirection,
		GroupSize:       settings.FECGroupSize,
		OverheadPercent: settings.FECOverheadPercent,
		SymbolSize:      settings.FECSymbolSize,
		FlushTimeoutMS:  settings.FECFlushTimeoutMS,
	}))
	setFECClientConfig(settings)
	return nil
}

func applyFECParams(settings *masterDNSProfile, params fec.Params) {
	settings.FECEnabled = params.Enabled
	settings.FECDirection = params.Direction
	settings.FECGroupSize = params.GroupSize
	settings.FECOverheadPercent = params.OverheadPercent
	settings.FECSymbolSize = params.SymbolSize
	settings.FECFlushTimeoutMS = params.FlushTimeoutMS
}

func setFECClientConfig(settings *masterDNSProfile) {
	setClientConfigJSON(settings.ClientConfig, "FEC_ENABLED", settings.FECEnabled)
	setClientConfigJSON(settings.ClientConfig, "FEC_DIRECTION", settings.FECDirection)
	setClientConfigJSON(settings.ClientConfig, "FEC_GROUP_SIZE", settings.FECGroupSize)
	setClientConfigJSON(settings.ClientConfig, "FEC_OVERHEAD_PERCENT", settings.FECOverheadPercent)
	setClientConfigJSON(settings.ClientConfig, "FEC_SYMBOL_SIZE", settings.FECSymbolSize)
	setClientConfigJSON(settings.ClientConfig, "FEC_FLUSH_TIMEOUT_MS", settings.FECFlushTimeoutMS)
}

func (settings *masterDNSProfile) runtimeMode() string {
	if settings == nil || strings.TrimSpace(settings.RuntimeMode) == "" {
		return runtimeModeHevSocks
	}
	return strings.TrimSpace(settings.RuntimeMode)
}

func normalizeProfileDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	result := make([]string, 0, len(domains))
	for _, raw := range domains {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	return result
}

func normalizeClientConfigMap(input map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(input)+8)
	for key, value := range input {
		normalized := strings.ToUpper(strings.TrimSpace(key))
		if normalized == "" {
			continue
		}
		result[normalized] = append(json.RawMessage(nil), value...)
	}
	return result
}

func setClientConfigJSON(config map[string]json.RawMessage, key string, value any) {
	if config == nil {
		return
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	config[key] = raw
}

func clientConfigString(config map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := config[key]
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, true
	}
	return "", false
}

func clientConfigBool(config map[string]json.RawMessage, key string) (bool, bool) {
	raw, ok := config[key]
	if !ok {
		return false, false
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, true
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		switch strings.ToLower(strings.TrimSpace(text)) {
		case "true", "1", "yes", "on":
			return true, true
		case "false", "0", "no", "off":
			return false, true
		}
	}
	return false, false
}

func clientConfigInt(config map[string]json.RawMessage, key string) (int, bool) {
	raw, ok := config[key]
	if !ok {
		return 0, false
	}
	var value int
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, true
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		parsed, err := strconv.Atoi(strings.TrimSpace(text))
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func normalizeEncryptionLevel(level string) string {
	normalized := strings.ToLower(strings.TrimSpace(level))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	normalized = strings.ReplaceAll(normalized, " ", "-")
	switch normalized {
	case "":
		return ""
	case "standard", "aes-128", "aes-128-gcm", "aes128", "aes128-gcm", "128":
		return "standard"
	case "strong", "aes-192", "aes-192-gcm", "aes192", "aes192-gcm", "192":
		return "strong"
	case "maximum", "max", "strongest", "aes-256", "aes-256-gcm", "aes256", "aes256-gcm", "256":
		return "maximum"
	default:
		return normalized
	}
}

func encryptionMethodForLevel(level string) (int, error) {
	switch normalizeEncryptionLevel(level) {
	case "standard":
		return 3, nil
	case "strong":
		return 4, nil
	case "maximum":
		return 5, nil
	default:
		return 0, fmt.Errorf("unsupported encryption level")
	}
}

func init() {
	log.SetOutput(callbackWriter{})
	log.SetLevel(log.InfoLevel)
}

var _ io.Writer = callbackWriter{}
