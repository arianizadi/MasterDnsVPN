package mobilebridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	masterclient "masterdnsvpn-go/internal/client"
)

const (
	nativePacketNICID          tcpip.NICID = 1
	nativePacketMTU            uint32      = 1280
	nativePacketQueueSize                  = 1024
	nativePacketDNSMaxSize                 = 4096
	nativePacketDNSReadTimeout             = 2 * time.Second
	nativePacketICMPHopLimit               = 64
	nativePacketICMPQuoteMax               = 128
	nativePacketIPv4Address                = "198.18.0.1"
	nativePacketIPv4DNSAddress             = "198.18.0.2"
	nativePacketIPv6Address                = "fd7a:7670:6e64::1"

	// The DNS tunnel drains at roughly 100 KB/s up and 1-2 MB/s down, so the
	// bandwidth-delay product per flow is well under 64 KB. Desktop-sized TCP
	// buffers (256 KB x N parallel speedtest flows) are pure jetsam risk on
	// iOS, where the extension is killed at ~50 MB footprint.
	nativePacketTCPBufferMin     = 4 << 10
	nativePacketTCPBufferDefault = 32 << 10
	nativePacketTCPBufferMax     = 64 << 10
	nativePacketTCPMaxInFlight   = 64
)

type nativePacketEngine struct {
	client   *masterclient.Client
	callback PacketCallback
	logs     LogCallback
	stack    *stack.Stack
	linkEP   *channel.Endpoint

	outputStarted atomic.Bool
	closed        atomic.Bool

	inputPackets          atomic.Uint64
	inputBytes            atomic.Uint64
	outputPackets         atomic.Uint64
	outputBytes           atomic.Uint64
	tcpFlowsCreated       atomic.Uint64
	tcpFlowsActive        atomic.Int64
	tcpFlowsClosed        atomic.Uint64
	tcpEndpointErrors     atomic.Uint64
	tcpEndpointResets     atomic.Uint64
	dnsQueries            atomic.Uint64
	dnsCacheHits          atomic.Uint64
	dnsPendingMisses      atomic.Uint64
	dnsResponses          atomic.Uint64
	unsupportedUDP        atomic.Uint64
	unsupportedUDPRejects atomic.Uint64
	malformedPackets      atomic.Uint64
	packetWriteErrors     atomic.Uint64

	unsupportedUDPPortsMu sync.Mutex
	unsupportedUDPPorts   map[uint16]uint64

	mu        sync.Mutex
	lastError string
}

func newNativePacketEngine(client *masterclient.Client, callback PacketCallback, logs LogCallback) (*nativePacketEngine, error) {
	if client == nil {
		return nil, errors.New("native packet engine requires a MasterDnsVPN client")
	}
	if callback == nil {
		return nil, errors.New("native packet engine requires a packet callback")
	}

	n := &nativePacketEngine{
		client:              client,
		callback:            callback,
		logs:                logs,
		unsupportedUDPPorts: make(map[uint16]uint64),
	}

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	if err := configureNativeTCPBuffers(s); err != nil {
		return nil, err
	}

	linkEP := channel.New(nativePacketQueueSize, nativePacketMTU, "")
	if err := s.CreateNIC(nativePacketNICID, linkEP); err != nil {
		return nil, fmt.Errorf("create native packet NIC: %s", err)
	}
	if err := s.SetPromiscuousMode(nativePacketNICID, true); err != nil {
		return nil, fmt.Errorf("enable native packet promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nativePacketNICID, true); err != nil {
		return nil, fmt.Errorf("enable native packet spoofing: %s", err)
	}

	for _, address := range []struct {
		protocol tcpip.NetworkProtocolNumber
		ip       string
		prefix   int
	}{
		{protocol: ipv4.ProtocolNumber, ip: nativePacketIPv4Address, prefix: 24},
		{protocol: ipv4.ProtocolNumber, ip: nativePacketIPv4DNSAddress, prefix: 32},
		{protocol: ipv6.ProtocolNumber, ip: nativePacketIPv6Address, prefix: 64},
	} {
		if err := addNativeProtocolAddress(s, address.protocol, address.ip, address.prefix); err != nil {
			s.Close()
			linkEP.Close()
			return nil, err
		}
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nativePacketNICID},
		{Destination: header.IPv6EmptySubnet, NIC: nativePacketNICID},
	})

	tcpForwarder := tcp.NewForwarder(s, nativePacketTCPBufferMax, nativePacketTCPMaxInFlight, n.handleTCPForward)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := udp.NewForwarder(s, n.handleUDPForward)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	n.stack = s
	n.linkEP = linkEP
	return n, nil
}

func configureNativeTCPBuffers(s *stack.Stack) error {
	sendBuf := tcpip.TCPSendBufferSizeRangeOption{
		Min:     nativePacketTCPBufferMin,
		Default: nativePacketTCPBufferDefault,
		Max:     nativePacketTCPBufferMax,
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sendBuf); err != nil {
		return fmt.Errorf("set native packet TCP send buffer: %s", err)
	}
	recvBuf := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     nativePacketTCPBufferMin,
		Default: nativePacketTCPBufferDefault,
		Max:     nativePacketTCPBufferMax,
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &recvBuf); err != nil {
		return fmt.Errorf("set native packet TCP receive buffer: %s", err)
	}
	moderation := tcpip.TCPModerateReceiveBufferOption(false)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderation); err != nil {
		return fmt.Errorf("disable native packet TCP buffer moderation: %s", err)
	}
	return nil
}

func addNativeProtocolAddress(s *stack.Stack, protocol tcpip.NetworkProtocolNumber, ip string, prefix int) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("parse native packet address %s: %w", ip, err)
	}
	protocolAddress := tcpip.ProtocolAddress{
		Protocol: protocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpipAddressFromAddr(addr),
			PrefixLen: prefix,
		},
	}
	if err := s.AddProtocolAddress(nativePacketNICID, protocolAddress, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("add native packet address %s/%d: %s", ip, prefix, err)
	}
	return nil
}

func tcpipAddressFromAddr(addr netip.Addr) tcpip.Address {
	if addr.Is4() {
		return tcpip.AddrFrom4(addr.As4())
	}
	return tcpip.AddrFrom16(addr.As16())
}

func (n *nativePacketEngine) start(ctx context.Context) {
	if n == nil || !n.outputStarted.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer n.recoverPanic("native packet output loop")
		n.outputLoop(ctx)
	}()
}

func (n *nativePacketEngine) close() {
	if n == nil || !n.closed.CompareAndSwap(false, true) {
		return
	}
	if n.linkEP != nil {
		n.linkEP.Close()
	}
	if n.stack != nil {
		n.stack.Close()
	}
}

func (n *nativePacketEngine) writePacket(packet []byte) error {
	if n == nil || n.closed.Load() {
		return errors.New("native packet engine is closed")
	}
	if len(packet) == 0 {
		n.malformedPackets.Add(1)
		return errors.New("empty packet")
	}

	var protocol tcpip.NetworkProtocolNumber
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		protocol = ipv4.ProtocolNumber
	case header.IPv6Version:
		protocol = ipv6.ProtocolNumber
	default:
		n.malformedPackets.Add(1)
		return fmt.Errorf("unsupported IP packet version: %d", header.IPVersion(packet))
	}

	copied := append([]byte(nil), packet...)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(copied),
	})
	defer pkt.DecRef()
	n.inputPackets.Add(1)
	n.inputBytes.Add(uint64(len(packet)))
	n.linkEP.InjectInbound(protocol, pkt)
	return nil
}

func (n *nativePacketEngine) outputLoop(ctx context.Context) {
	for {
		pkt := n.linkEP.ReadContext(ctx)
		if pkt == nil {
			return
		}
		n.emitPacket(pkt)
		pkt.DecRef()
	}
}

func (n *nativePacketEngine) emitPacket(pkt *stack.PacketBuffer) {
	buf := pkt.ToBuffer()
	data := append([]byte(nil), buf.Flatten()...)
	buf.Release()
	n.emitRawPacket(data)
}

func (n *nativePacketEngine) emitRawPacket(data []byte) {
	if len(data) == 0 {
		return
	}
	n.outputPackets.Add(1)
	n.outputBytes.Add(uint64(len(data)))
	n.callback.WritePacket(data)
}

func (n *nativePacketEngine) handleTCPForward(r *tcp.ForwarderRequest) {
	defer n.recoverPanic("native packet TCP forward")

	id := r.ID()
	target, port, atyp, ok := nativeTargetFromID(id)
	if !ok {
		n.setLastError("native packet TCP flow has unsupported destination address")
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		n.tcpEndpointErrors.Add(1)
		if nativePacketTCPForwardReset(err) {
			n.tcpEndpointResets.Add(1)
		} else {
			n.setLastError("native packet TCP endpoint create failed: " + err.String())
		}
		r.Complete(true)
		return
	}
	r.Complete(false)

	conn := gonet.NewTCPConn(&wq, ep)
	n.tcpFlowsCreated.Add(1)
	n.tcpFlowsActive.Add(1)
	wrapped := &nativeCountingConn{
		Conn: conn,
		onClose: func() {
			n.tcpFlowsClosed.Add(1)
			n.tcpFlowsActive.Add(-1)
		},
	}
	n.client.HandleNativeTCPConnect(context.Background(), wrapped, target, port, atyp)
}

func nativeTargetFromID(id stack.TransportEndpointID) (string, uint16, byte, bool) {
	switch id.LocalAddress.Len() {
	case 4:
		return id.LocalAddress.String(), id.LocalPort, masterclient.SOCKS5_ATYP_IPV4, true
	case 16:
		return id.LocalAddress.String(), id.LocalPort, masterclient.SOCKS5_ATYP_IPV6, true
	default:
		return "", 0, 0, false
	}
}

func (n *nativePacketEngine) handleUDPForward(r *udp.ForwarderRequest) {
	defer n.recoverPanic("native packet UDP forward")

	id := r.ID()
	if id.LocalPort != 53 {
		n.recordUnsupportedUDP(id.LocalPort)
		n.rejectUnsupportedUDP(r)
		r.Release()
		return
	}

	n.dnsQueries.Add(1)
	go n.handleDNSForward(r)
}

func (n *nativePacketEngine) handleDNSForward(r *udp.ForwarderRequest) {
	defer n.recoverPanic("native packet DNS forward")
	defer r.Release()

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		n.setLastError("native packet DNS endpoint create failed: " + err.String())
		return
	}
	conn := gonet.NewUDPConn(n.stack, &wq, ep)
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(nativePacketDNSReadTimeout))
	query := make([]byte, nativePacketDNSMaxSize)
	count, peer, readErr := conn.ReadFrom(query)
	if readErr != nil {
		n.setLastError("native packet DNS read failed: " + readErr.Error())
		return
	}
	query = query[:count]

	hit := n.client.ProcessDNSQuery(query, peer, func(response []byte) {
		if len(response) == 0 {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(nativePacketDNSReadTimeout))
		if _, err := conn.Write(response); err != nil {
			n.packetWriteErrors.Add(1)
			n.setLastError("native packet DNS response write failed: " + err.Error())
			return
		}
		n.dnsResponses.Add(1)
	})
	if hit {
		n.dnsCacheHits.Add(1)
		return
	}
	n.dnsPendingMisses.Add(1)
}

func (n *nativePacketEngine) snapshot() map[string]any {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	lastError := n.lastError
	n.mu.Unlock()
	return map[string]any{
		"inputPackets":           n.inputPackets.Load(),
		"inputBytes":             n.inputBytes.Load(),
		"outputPackets":          n.outputPackets.Load(),
		"outputBytes":            n.outputBytes.Load(),
		"tcpFlowsCreated":        n.tcpFlowsCreated.Load(),
		"tcpFlowsActive":         n.tcpFlowsActive.Load(),
		"tcpFlowsClosed":         n.tcpFlowsClosed.Load(),
		"tcpEndpointErrors":      n.tcpEndpointErrors.Load(),
		"tcpEndpointResets":      n.tcpEndpointResets.Load(),
		"dnsQueries":             n.dnsQueries.Load(),
		"dnsCacheHits":           n.dnsCacheHits.Load(),
		"dnsPendingMisses":       n.dnsPendingMisses.Load(),
		"dnsResponses":           n.dnsResponses.Load(),
		"unsupportedUDP":         n.unsupportedUDP.Load(),
		"unsupportedUDPRejects":  n.unsupportedUDPRejects.Load(),
		"unsupportedUDPTopPorts": n.unsupportedUDPPortSummary(5),
		"malformedPackets":       n.malformedPackets.Load(),
		"packetWriteErrors":      n.packetWriteErrors.Load(),
		"lastError":              lastError,
	}
}

func (n *nativePacketEngine) recordUnsupportedUDP(port uint16) {
	n.unsupportedUDP.Add(1)
	n.unsupportedUDPPortsMu.Lock()
	n.unsupportedUDPPorts[port]++
	n.unsupportedUDPPortsMu.Unlock()
}

func (n *nativePacketEngine) rejectUnsupportedUDP(r *udp.ForwarderRequest) {
	pkt := r.Packet()
	if pkt == nil {
		return
	}
	defer pkt.DecRef()

	buf := pkt.ToBuffer()
	original := append([]byte(nil), buf.Flatten()...)
	buf.Release()

	var response []byte
	var ok bool
	switch header.IPVersion(original) {
	case header.IPv4Version:
		response, ok = nativePacketICMPv4PortUnreachable(original)
	case header.IPv6Version:
		response, ok = nativePacketICMPv6PortUnreachable(original)
	}
	if !ok {
		return
	}
	n.unsupportedUDPRejects.Add(1)
	n.emitRawPacket(response)
}

func nativePacketICMPv4PortUnreachable(original []byte) ([]byte, bool) {
	ip := header.IPv4(original)
	if !ip.IsValid(len(original)) {
		return nil, false
	}

	totalLength := int(ip.TotalLength())
	if totalLength > len(original) {
		totalLength = len(original)
	}
	quoteLength := nativePacketICMPQuoteLength(totalLength)
	if quoteLength == 0 {
		return nil, false
	}

	response := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+quoteLength)
	ipHeader := header.IPv4(response[:header.IPv4MinimumSize])
	ipHeader.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(response)),
		TTL:         nativePacketICMPHopLimit,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     ip.DestinationAddress(),
		DstAddr:     ip.SourceAddress(),
	})
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())

	icmp := header.ICMPv4(response[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4DstUnreachable)
	icmp.SetCode(header.ICMPv4PortUnreachable)
	copy(icmp[header.ICMPv4PayloadOffset:], original[:quoteLength])
	icmp.SetChecksum(header.ICMPv4Checksum(icmp, 0))
	return response, true
}

func nativePacketICMPv6PortUnreachable(original []byte) ([]byte, bool) {
	ip := header.IPv6(original)
	if !ip.IsValid(len(original)) {
		return nil, false
	}

	totalLength := header.IPv6MinimumSize + int(ip.PayloadLength())
	if totalLength > len(original) {
		totalLength = len(original)
	}
	quoteLength := nativePacketICMPQuoteLength(totalLength)
	if quoteLength == 0 {
		return nil, false
	}

	icmpLength := header.ICMPv6MinimumSize + quoteLength
	response := make([]byte, header.IPv6MinimumSize+icmpLength)
	ipHeader := header.IPv6(response[:header.IPv6MinimumSize])
	ipHeader.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(icmpLength),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          nativePacketICMPHopLimit,
		SrcAddr:           ip.DestinationAddress(),
		DstAddr:           ip.SourceAddress(),
	})

	icmp := header.ICMPv6(response[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6DstUnreachable)
	icmp.SetCode(header.ICMPv6PortUnreachable)
	icmp.SetTypeSpecific(0)
	copy(icmp[header.ICMPv6PayloadOffset:], original[:quoteLength])
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    ip.DestinationAddress(),
		Dst:    ip.SourceAddress(),
	}))
	return response, true
}

func nativePacketICMPQuoteLength(totalLength int) int {
	if totalLength <= 0 {
		return 0
	}
	if totalLength < nativePacketICMPQuoteMax {
		return totalLength
	}
	return nativePacketICMPQuoteMax
}

func (n *nativePacketEngine) unsupportedUDPPortSummary(limit int) string {
	n.unsupportedUDPPortsMu.Lock()
	ports := make([]struct {
		port  uint16
		count uint64
	}, 0, len(n.unsupportedUDPPorts))
	for port, count := range n.unsupportedUDPPorts {
		ports = append(ports, struct {
			port  uint16
			count uint64
		}{port: port, count: count})
	}
	n.unsupportedUDPPortsMu.Unlock()

	sort.Slice(ports, func(i, j int) bool {
		if ports[i].count == ports[j].count {
			return ports[i].port < ports[j].port
		}
		return ports[i].count > ports[j].count
	})
	if limit > 0 && len(ports) > limit {
		ports = ports[:limit]
	}

	parts := make([]string, 0, len(ports))
	for _, item := range ports {
		parts = append(parts, fmt.Sprintf("%d=%d", item.port, item.count))
	}
	return strings.Join(parts, ",")
}

func (n *nativePacketEngine) recoverPanic(context string) {
	if value := recover(); value != nil {
		message := fmt.Sprintf("%s panic: %v", context, value)
		n.setLastError(message)
		safeLog(n.logs, message)
		safeLog(n.logs, string(debug.Stack()))
	}
}

func (n *nativePacketEngine) setLastError(message string) {
	n.mu.Lock()
	n.lastError = message
	n.mu.Unlock()
}

func nativePacketTCPForwardReset(err tcpip.Error) bool {
	switch err.(type) {
	case *tcpip.ErrConnectionReset, *tcpip.ErrAborted, *tcpip.ErrClosedForReceive, *tcpip.ErrClosedForSend:
		return true
	default:
		return false
	}
}

type nativeCountingConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *nativeCountingConn) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.Conn.Close()
}

func (c *nativeCountingConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c *nativeCountingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
