package fec

import (
	"bytes"
	"testing"
)

func TestBuildRepairSymbolsRecoverMissingBase(t *testing.T) {
	params := DefaultParams()
	params.Enabled = true
	params.GroupSize = 4
	params.OverheadPercent = 100

	source := []SourcePacket{
		{Sequence: 10, Payload: []byte("alpha")},
		{Sequence: 11, Payload: []byte("bravo-bravo")},
		{Sequence: 12, Payload: []byte("charlie")},
		{Sequence: 13, Payload: []byte("delta")},
	}

	symbols, err := BuildRepairSymbols(source, params)
	if err != nil {
		t.Fatalf("BuildRepairSymbols returned error: %v", err)
	}
	if len(symbols) == 0 {
		t.Fatal("expected repair symbols")
	}

	receiver := NewReceiver(params)
	for _, packet := range []SourcePacket{source[0], source[2], source[3]} {
		if recovered, err := receiver.ObserveData(packet.Sequence, packet.Payload); err != nil || len(recovered) != 0 {
			t.Fatalf("ObserveData recovered=%d err=%v, want no recovery yet", len(recovered), err)
		}
	}

	var recovered []RecoveredPacket
	for _, symbol := range symbols {
		payload, err := EncodeSymbolPayload(symbol)
		if err != nil {
			t.Fatalf("EncodeSymbolPayload returned error: %v", err)
		}
		recovered, err = receiver.AddSymbol(source[0].Sequence, payload)
		if err != nil {
			t.Fatalf("AddSymbol returned error: %v", err)
		}
		if len(recovered) > 0 {
			break
		}
	}

	if len(recovered) != 1 {
		t.Fatalf("expected one recovered packet, got %d", len(recovered))
	}
	if recovered[0].Sequence != source[1].Sequence {
		t.Fatalf("unexpected recovered sequence: got=%d want=%d", recovered[0].Sequence, source[1].Sequence)
	}
	if !bytes.Equal(recovered[0].Payload, source[1].Payload) {
		t.Fatalf("unexpected recovered payload: got=%q want=%q", recovered[0].Payload, source[1].Payload)
	}
}

func TestSymbolPayloadRejectsInvalidAndCorruptMetadata(t *testing.T) {
	if _, err := DecodeSymbolPayload([]byte{Version, 1}); err == nil {
		t.Fatal("expected short symbol payload to be rejected")
	}

	params := DefaultParams()
	params.Enabled = true
	source := []SourcePacket{
		{Sequence: 1, Payload: []byte("one")},
		{Sequence: 2, Payload: []byte("two")},
	}
	symbols, err := BuildRepairSymbols(source, params)
	if err != nil {
		t.Fatalf("BuildRepairSymbols returned error: %v", err)
	}
	payload, err := EncodeSymbolPayload(symbols[0])
	if err != nil {
		t.Fatalf("EncodeSymbolPayload returned error: %v", err)
	}

	payload[0] = 99
	if _, err := DecodeSymbolPayload(payload); err == nil {
		t.Fatal("expected unsupported version to be rejected")
	}
	payload[0] = Version
	payload[3]++
	if _, err := DecodeSymbolPayload(payload); err == nil {
		t.Fatal("expected corrupt original length metadata to be rejected")
	}
}

func TestNegotiateDisabledAndClamped(t *testing.T) {
	client := DefaultParams()
	client.Enabled = true
	client.GroupSize = 12
	client.OverheadPercent = 30
	client.SymbolSize = 900
	client.FlushTimeoutMS = 50

	server := DefaultParams()
	server.Enabled = false
	if got := Negotiate(client, server); got.Enabled {
		t.Fatal("server-disabled negotiation should disable FEC")
	}

	server.Enabled = true
	server.GroupSize = 8
	server.OverheadPercent = 15
	server.SymbolSize = 512
	server.FlushTimeoutMS = 25

	got := Negotiate(client, server)
	if !got.Enabled {
		t.Fatal("expected FEC to negotiate")
	}
	if got.GroupSize != 8 || got.OverheadPercent != 15 || got.SymbolSize != 512 || got.FlushTimeoutMS != 25 {
		t.Fatalf("unexpected negotiated params: %+v", got)
	}
}
