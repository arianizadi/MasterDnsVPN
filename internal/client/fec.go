package client

import (
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/fec"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (c *Client) negotiateFEC(conn Connection) {
	if c == nil || c.fecNegotiated.Load() {
		return
	}

	requested := c.cfg.FECParams()
	if !requested.Enabled {
		return
	}

	query, err := c.buildTunnelTXTQueryRaw(conn.Domain, VpnProto.BuildOptions{
		SessionID:     c.sessionID,
		PacketType:    Enums.PACKET_SESSION_CAPS,
		SessionCookie: c.sessionCookie,
		Payload:       fec.EncodeCapsPayload(requested),
	})
	if err != nil {
		return
	}

	timeout := c.mtuTestTimeout
	if timeout <= 0 {
		timeout = time.Second
	}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}

	packet, err := c.exchangeDNSOverConnection(conn, query, timeout)
	if err != nil || packet.PacketType != Enums.PACKET_SESSION_CAPS_ACK || packet.SessionID != c.sessionID {
		if c.log != nil {
			c.log.Debugf("FEC negotiation skipped: ack missing or unsupported")
		}
		return
	}

	params, err := fec.DecodeCapsPayload(packet.Payload)
	if err != nil || !params.Enabled {
		if c.log != nil {
			c.log.Debugf("FEC negotiation disabled by server")
		}
		return
	}

	c.fecMu.Lock()
	c.fecParams = params
	c.fecReceivers = make(map[uint16]*fec.Receiver, 8)
	c.fecNegotiated.Store(true)
	c.fecMu.Unlock()
	fec.NoteNegotiated()

	if c.log != nil {
		c.log.Infof(
			"FEC negotiated for download: group=%d overhead=%d%% symbol=%d flush=%dms",
			params.GroupSize,
			params.OverheadPercent,
			params.SymbolSize,
			params.FlushTimeoutMS,
		)
	}
}

func (c *Client) fecReceiver(streamID uint16) *fec.Receiver {
	if c == nil || !c.fecNegotiated.Load() || streamID == 0 {
		return nil
	}

	c.fecMu.Lock()
	defer c.fecMu.Unlock()
	if c.fecReceivers == nil {
		c.fecReceivers = make(map[uint16]*fec.Receiver, 8)
	}
	receiver := c.fecReceivers[streamID]
	if receiver == nil {
		receiver = fec.NewReceiver(c.fecParams)
		c.fecReceivers[streamID] = receiver
	}
	return receiver
}

func (c *Client) clearFECReceivers(resetNegotiation bool) {
	if c == nil {
		return
	}
	c.fecMu.Lock()
	c.fecReceivers = nil
	if resetNegotiation {
		c.fecNegotiated.Store(false)
		c.fecParams = fec.DefaultParams()
	}
	c.fecMu.Unlock()
}

func (c *Client) observeFECData(packet VpnProto.Packet) ([]fec.RecoveredPacket, error) {
	receiver := c.fecReceiver(packet.StreamID)
	if receiver == nil {
		return nil, nil
	}
	return receiver.ObserveData(packet.SequenceNum, packet.Payload)
}

func (c *Client) handleFECSymbol(packet VpnProto.Packet, arqObj *arq.ARQ) {
	if c == nil || arqObj == nil {
		return
	}
	receiver := c.fecReceiver(packet.StreamID)
	if receiver == nil {
		return
	}

	recovered, err := receiver.AddSymbol(packet.SequenceNum, packet.Payload)
	if err != nil {
		if c.log != nil {
			c.log.Debugf("FEC symbol rejected: %v", err)
		}
		return
	}
	c.injectFECRecovered(arqObj, recovered)
}

func (c *Client) injectFECRecovered(arqObj *arq.ARQ, recovered []fec.RecoveredPacket) {
	if arqObj == nil || len(recovered) == 0 {
		return
	}
	for _, packet := range recovered {
		if len(packet.Payload) == 0 {
			continue
		}
		_ = arqObj.ReceiveData(packet.Sequence, packet.Payload)
	}
}
