package udpserver

import (
	"testing"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/fec"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestSessionCapsServerDisabledFallsBackToARQ(t *testing.T) {
	s, record := newFECTestServer(config.ServerConfig{FECEnabled: false})

	client := fec.DefaultParams()
	client.Enabled = true
	s.handleSessionCapsRequest(VpnProto.Packet{
		SessionID:  record.ID,
		PacketType: Enums.PACKET_SESSION_CAPS,
		Payload:    fec.EncodeCapsPayload(client),
	})

	if record.FECNegotiated {
		t.Fatal("server-disabled FEC should not mark the session negotiated")
	}

	ack := popFECSessionAck(t, record)
	params, err := fec.DecodeCapsPayload(ack.Payload)
	if err != nil {
		t.Fatalf("DecodeCapsPayload returned error: %v", err)
	}
	if params.Enabled {
		t.Fatal("expected disabled caps ack")
	}
}

func TestSessionCapsNegotiatesConservativeValues(t *testing.T) {
	s, record := newFECTestServer(config.ServerConfig{
		FECEnabled:            true,
		FECMaxGroupSize:       6,
		FECMaxOverheadPercent: 20,
		FECMaxSymbolSize:      512,
		FECMaxFlushTimeoutMS:  30,
	})

	client := fec.DefaultParams()
	client.Enabled = true
	client.GroupSize = 12
	client.OverheadPercent = 40
	client.SymbolSize = 900
	client.FlushTimeoutMS = 80
	s.handleSessionCapsRequest(VpnProto.Packet{
		SessionID:  record.ID,
		PacketType: Enums.PACKET_SESSION_CAPS,
		Payload:    fec.EncodeCapsPayload(client),
	})

	if !record.FECNegotiated {
		t.Fatal("expected session to negotiate FEC")
	}
	if record.FECParams.GroupSize != 6 || record.FECParams.OverheadPercent != 20 ||
		record.FECParams.SymbolSize != 512 || record.FECParams.FlushTimeoutMS != 30 {
		t.Fatalf("unexpected record FEC params: %+v", record.FECParams)
	}

	ack := popFECSessionAck(t, record)
	params, err := fec.DecodeCapsPayload(ack.Payload)
	if err != nil {
		t.Fatalf("DecodeCapsPayload returned error: %v", err)
	}
	if params != record.FECParams {
		t.Fatalf("ack params mismatch: got=%+v want=%+v", params, record.FECParams)
	}
}

func newFECTestServer(cfg config.ServerConfig) (*Server, *sessionRecord) {
	store := newSessionStore(8, 32)
	record := newTestSessionRecord(9)
	record.Cookie = 77
	store.byID[record.ID] = record

	return &Server{
		cfg:      cfg,
		sessions: store,
	}, record
}

func popFECSessionAck(t *testing.T, record *sessionRecord) VpnProto.Packet {
	t.Helper()
	stream, ok := record.getStream(0)
	if !ok || stream == nil {
		t.Fatal("stream 0 missing")
	}
	packet, _, ok := stream.PopNextTXPacket()
	if !ok || packet == nil {
		t.Fatal("expected session caps ack in stream 0 queue")
	}
	defer putTXPacketToPool(packet)
	if packet.PacketType != Enums.PACKET_SESSION_CAPS_ACK {
		t.Fatalf("unexpected packet type: got=%s", Enums.PacketTypeName(packet.PacketType))
	}
	return VpnProto.Packet{
		PacketType: packet.PacketType,
		Payload:    append([]byte(nil), packet.Payload...),
	}
}
