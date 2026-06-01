package vpnproto

import (
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestFECPacketTypesRoundTrip(t *testing.T) {
	tests := []BuildOptions{
		{
			SessionID:     7,
			PacketType:    Enums.PACKET_SESSION_CAPS,
			SessionCookie: 3,
			Payload:       []byte{1, 1, 8, 15, 0, 0, 0, 25},
		},
		{
			SessionID:     7,
			PacketType:    Enums.PACKET_SESSION_CAPS_ACK,
			SessionCookie: 3,
			Payload:       []byte{1, 1, 8, 15, 0, 0, 0, 25},
		},
		{
			SessionID:     7,
			PacketType:    Enums.PACKET_STREAM_FEC_SYMBOL,
			SessionCookie: 3,
			StreamID:      42,
			SequenceNum:   1000,
			Payload:       []byte("fec-symbol"),
		},
	}

	for _, tt := range tests {
		raw, err := BuildRaw(tt)
		if err != nil {
			t.Fatalf("BuildRaw(%s) returned error: %v", Enums.PacketTypeName(tt.PacketType), err)
		}
		parsed, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%s) returned error: %v", Enums.PacketTypeName(tt.PacketType), err)
		}
		if parsed.PacketType != tt.PacketType {
			t.Fatalf("packet type mismatch: got=%d want=%d", parsed.PacketType, tt.PacketType)
		}
		if string(parsed.Payload) != string(tt.Payload) {
			t.Fatalf("payload mismatch for %s", Enums.PacketTypeName(tt.PacketType))
		}
		if tt.PacketType == Enums.PACKET_STREAM_FEC_SYMBOL {
			if !parsed.HasStreamID || !parsed.HasSequenceNum {
				t.Fatal("FEC symbol packet should carry stream ID and group start sequence")
			}
			if parsed.StreamID != tt.StreamID || parsed.SequenceNum != tt.SequenceNum {
				t.Fatalf("FEC symbol identity mismatch: stream=%d seq=%d", parsed.StreamID, parsed.SequenceNum)
			}
			continue
		}
		if parsed.HasStreamID || parsed.HasSequenceNum {
			t.Fatalf("%s should not carry stream or sequence header fields", Enums.PacketTypeName(tt.PacketType))
		}
	}
}
