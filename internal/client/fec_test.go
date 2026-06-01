package client

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/fec"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestFECDisabledByDefault(t *testing.T) {
	cfg := config.DefaultClientConfig()
	if params := cfg.FECParams(); params.Enabled {
		t.Fatalf("expected FEC disabled by default, got %+v", params)
	}
}

func TestNegotiateFECMissingAckFallsBackToARQ(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.FECEnabled = true
	cfg.MTUTestTimeout = 0.001

	codec, err := security.NewCodec(1, "testkey")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	c := New(cfg, nil, codec)
	c.sessionID = 7
	c.sessionCookie = 9

	c.negotiateFEC(Connection{
		Domain:        "example.com",
		ResolverLabel: "127.0.0.1:9",
	})

	if c.fecNegotiated.Load() {
		t.Fatal("FEC should remain disabled when SESSION_CAPS_ACK is missing")
	}
}

func TestFECRecoveredPacketsAreInjectedThroughARQReceiveData(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.ProtocolType = "SOCKS5"
	cfg.FECEnabled = true
	cfg.FECGroupSize = 4
	cfg.FECOverheadPercent = 100

	c := New(cfg, nil, nil)
	c.sessionID = 1
	c.sessionCookie = 2

	params := cfg.FECParams()
	params.Enabled = true
	c.fecMu.Lock()
	c.fecParams = params
	c.fecReceivers = make(map[uint16]*fec.Receiver)
	c.fecNegotiated.Store(true)
	c.fecMu.Unlock()

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()
	stream := c.new_stream(1, arqConn, nil)
	defer stream.CloseStream(true, 0)
	if arqObj, ok := stream.Stream.(*arq.ARQ); ok {
		arqObj.SetIOReady(true)
	}

	source := []fec.SourcePacket{
		{Sequence: 0, Payload: []byte("zero-")},
		{Sequence: 1, Payload: []byte("one-")},
		{Sequence: 2, Payload: []byte("two-")},
		{Sequence: 3, Payload: []byte("three")},
	}
	symbols, err := fec.BuildRepairSymbols(source, params)
	if err != nil {
		t.Fatalf("BuildRepairSymbols returned error: %v", err)
	}

	for _, idx := range []int{0, 2, 3} {
		if err := c.HandleStreamPacket(VpnProto.Packet{
			SessionID:      c.sessionID,
			SessionCookie:  c.sessionCookie,
			PacketType:     Enums.PACKET_STREAM_DATA,
			StreamID:       stream.StreamID,
			HasStreamID:    true,
			SequenceNum:    source[idx].Sequence,
			HasSequenceNum: true,
			Payload:        source[idx].Payload,
		}); err != nil {
			t.Fatalf("HandleStreamPacket data returned error: %v", err)
		}
	}

	for _, symbol := range symbols {
		payload, err := fec.EncodeSymbolPayload(symbol)
		if err != nil {
			t.Fatalf("EncodeSymbolPayload returned error: %v", err)
		}
		if err := c.HandleStreamPacket(VpnProto.Packet{
			SessionID:      c.sessionID,
			SessionCookie:  c.sessionCookie,
			PacketType:     Enums.PACKET_STREAM_FEC_SYMBOL,
			StreamID:       stream.StreamID,
			HasStreamID:    true,
			SequenceNum:    source[0].Sequence,
			HasSequenceNum: true,
			Payload:        payload,
		}); err != nil {
			t.Fatalf("HandleStreamPacket FEC returned error: %v", err)
		}
	}

	want := bytes.Join([][]byte{
		source[0].Payload,
		source[1].Payload,
		source[2].Payload,
		source[3].Payload,
	}, nil)
	got := make([]byte, len(want))
	_ = localApp.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := io.ReadFull(localApp, got); err != nil {
		t.Fatalf("failed to read recovered ordered payload: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected ordered payload: got=%q want=%q", got, want)
	}
}
