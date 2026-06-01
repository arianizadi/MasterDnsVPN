package udpserver

import (
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/fec"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (s *Server) handleSessionCapsRequest(vpnPacket VpnProto.Packet) bool {
	if s == nil || vpnPacket.SessionID == 0 {
		return true
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok || record == nil {
		return true
	}

	clientCaps, err := fec.DecodeCapsPayload(vpnPacket.Payload)
	if err != nil {
		return true
	}

	effective := fec.Negotiate(clientCaps, s.cfg.FECPolicy())
	if effective.Enabled {
		record.enableFEC(effective)
		fec.NoteNegotiated()
		if s.log != nil {
			s.log.Infof(
				"FEC negotiated for session %d: group=%d overhead=%d%% symbol=%d flush=%dms",
				vpnPacket.SessionID,
				effective.GroupSize,
				effective.OverheadPercent,
				effective.SymbolSize,
				effective.FlushTimeoutMS,
			)
		}
	}

	ack := VpnProto.Packet{
		PacketType: Enums.PACKET_SESSION_CAPS_ACK,
		Payload:    fec.EncodeCapsPayload(effective),
	}
	_ = s.queueMainSessionPacket(vpnPacket.SessionID, ack)
	return true
}
