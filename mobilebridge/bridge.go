// Package mobilebridge exposes the DNS tunnel engines through a gomobile-safe
// API for the iOS packet tunnel extension.
package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
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
)

// LogCallback is implemented by Swift and receives engine log lines.
type LogCallback interface {
	Log(line string)
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
	EncryptionKey      string `json:"encryptionKey"`
	EncryptionLevel    string `json:"encryptionLevel"`
	EncryptionMethod   int    `json:"encryptionMethod"`
	BaseEncodeData     bool   `json:"baseEncodeData"`
	FECLevel           string `json:"fecLevel"`
	FECEnabled         bool   `json:"fecEnabled"`
	FECDirection       string `json:"fecDirection"`
	FECGroupSize       int    `json:"fecGroupSize"`
	FECOverheadPercent int    `json:"fecOverheadPercent"`
	FECSymbolSize      int    `json:"fecSymbolSize"`
	FECFlushTimeoutMS  int    `json:"fecFlushTimeoutMs"`
}

type profile struct {
	Version   int               `json:"version"`
	Name      string            `json:"name"`
	Protocol  string            `json:"protocol"`
	Domain    string            `json:"domain"`
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
}

type engineState struct {
	mu                 sync.Mutex
	active             *engineRunner
	profileName        string
	protocol           string
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
	state.socksListenAddress = listenAddress
	state.startedAt = time.Now().UTC()
	state.lastError = ""
	state.mu.Unlock()

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
		"socksListenAddress": state.socksListenAddress,
		"lastError":          state.lastError,
		"arq":                arq.GlobalStatsSnapshot(),
		"fec":                fec.GlobalStatsSnapshot(),
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
	listenIP, listenPort, err := splitHostPortDefault(r.socksListenAddress, 18080)
	if err != nil {
		return err
	}

	resolvers, err := masterDNSResolvers(r.profile.Resolvers)
	if err != nil {
		return err
	}

	cfg := config.DefaultClientConfig()
	cfg.ConfigPath = "<mobilebridge>"
	cfg.ConfigDir = "."
	cfg.ProtocolType = "SOCKS5"
	cfg.Domains = []string{r.profile.Domain}
	cfg.ListenIP = listenIP
	cfg.ListenPort = listenPort
	cfg.SOCKS5Auth = false
	cfg.LocalDNSEnabled = false
	cfg.BaseEncodeData = r.profile.MasterDNS.BaseEncodeData
	cfg.DataEncryptionMethod = r.profile.MasterDNS.EncryptionMethod
	cfg.EncryptionKey = r.profile.MasterDNS.EncryptionKey
	cfg.FECEnabled = r.profile.MasterDNS.FECEnabled
	if r.profile.MasterDNS.FECDirection != "" {
		cfg.FECDirection = r.profile.MasterDNS.FECDirection
	}
	if r.profile.MasterDNS.FECGroupSize > 0 {
		cfg.FECGroupSize = r.profile.MasterDNS.FECGroupSize
	}
	if r.profile.MasterDNS.FECOverheadPercent > 0 {
		cfg.FECOverheadPercent = r.profile.MasterDNS.FECOverheadPercent
	}
	if r.profile.MasterDNS.FECSymbolSize > 0 {
		cfg.FECSymbolSize = r.profile.MasterDNS.FECSymbolSize
	}
	if r.profile.MasterDNS.FECFlushTimeoutMS > 0 {
		cfg.FECFlushTimeoutMS = r.profile.MasterDNS.FECFlushTimeoutMS
	}
	cfg.Resolvers = resolvers
	cfg.ResolverMap = resolverMap(resolvers)
	cfg.LogLevel = defaultString(cfg.LogLevel, "INFO")

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("client codec setup failed: %w", err)
	}

	logger := masterlog.NewWithWriter("MasterDnsVPN Mobile", cfg.LogLevel, callbackWriter{callback: r.logCallback})
	app := masterclient.New(cfg, logger, codec)
	if err := app.BuildConnectionMap(); err != nil {
		return err
	}

	r.logf("starting MasterDnsVPN SOCKS5 listener on %s with %d resolver(s)", r.socksListenAddress, len(resolvers))
	return app.Run(r.ctx)
}

func parseAndValidateProfile(raw string) (profile, string, error) {
	var p profile
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, "", fmt.Errorf("invalid profile JSON: %w", err)
	}

	p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	p.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p.Domain)), ".")
	p.Name = strings.TrimSpace(p.Name)
	if p.Version != 1 {
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
		if err := normalizeMasterDNSProfile(p.MasterDNS); err != nil {
			return p, "", err
		}
		if p.MasterDNS.EncryptionKey == "" {
			return p, "", errors.New("masterdns.encryptionKey is required")
		}
		if p.MasterDNS.EncryptionMethod < 3 || p.MasterDNS.EncryptionMethod > 5 {
			return p, "", errors.New("masterdns requires AES-GCM encryption method 3, 4, or 5")
		}
		if _, err := masterDNSResolvers(p.Resolvers); err != nil {
			return p, "", err
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

func normalizeMasterDNSProfile(settings *masterDNSProfile) error {
	if settings == nil {
		return nil
	}

	settings.EncryptionKey = strings.TrimSpace(settings.EncryptionKey)
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
	if settings.EncryptionMethod == 0 {
		settings.EncryptionMethod = 5
	}

	settings.FECLevel = fec.NormalizeLevel(settings.FECLevel)
	if settings.FECLevel != "" {
		params, err := fec.ParamsForLevel(settings.FECLevel)
		if err != nil {
			return fmt.Errorf("invalid masterdns.fecLevel: %q", settings.FECLevel)
		}
		applyFECParams(settings, params)
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
