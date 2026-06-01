package fec

import (
	"encoding/binary"
	"errors"
)

const symbolPayloadHeaderSize = 12

var ErrInvalidSymbolPayload = errors.New("invalid fec symbol payload")

type SourcePacket struct {
	Sequence uint16
	Payload  []byte
}

type SymbolPayload struct {
	GroupCount      int
	OriginalLength  int
	BaseSymbolCount uint32
	SymbolID        uint32
	PacketLengths   []int
	Symbol          []byte
}

func EncodeSymbolPayload(symbol SymbolPayload) ([]byte, error) {
	if symbol.GroupCount <= 0 || symbol.GroupCount > 255 {
		return nil, ErrInvalidSymbolPayload
	}
	if len(symbol.PacketLengths) != symbol.GroupCount {
		return nil, ErrInvalidSymbolPayload
	}
	if symbol.OriginalLength < 0 || symbol.OriginalLength > int(^uint32(0)) {
		return nil, ErrInvalidSymbolPayload
	}
	if symbol.BaseSymbolCount == 0 || symbol.BaseSymbolCount > uint32(^uint16(0)) {
		return nil, ErrInvalidSymbolPayload
	}
	if len(symbol.Symbol) == 0 || len(symbol.Symbol) > MaxSymbolSize {
		return nil, ErrInvalidSymbolPayload
	}

	payload := make([]byte, symbolPayloadHeaderSize+symbol.GroupCount*2+len(symbol.Symbol))
	payload[0] = Version
	payload[1] = byte(symbol.GroupCount)
	binary.BigEndian.PutUint32(payload[2:6], uint32(symbol.OriginalLength))
	binary.BigEndian.PutUint16(payload[6:8], uint16(symbol.BaseSymbolCount))
	binary.BigEndian.PutUint32(payload[8:12], symbol.SymbolID)
	offset := symbolPayloadHeaderSize
	for _, packetLen := range symbol.PacketLengths {
		if packetLen < 0 || packetLen > MaxSymbolSize {
			return nil, ErrInvalidSymbolPayload
		}
		binary.BigEndian.PutUint16(payload[offset:offset+2], uint16(packetLen))
		offset += 2
	}
	copy(payload[offset:], symbol.Symbol)
	return payload, nil
}

func DecodeSymbolPayload(payload []byte) (SymbolPayload, error) {
	if len(payload) < symbolPayloadHeaderSize {
		return SymbolPayload{}, ErrInvalidSymbolPayload
	}
	if payload[0] != Version {
		return SymbolPayload{}, ErrUnsupportedCaps
	}
	groupCount := int(payload[1])
	if groupCount <= 0 || groupCount > MaxGroupSize {
		return SymbolPayload{}, ErrInvalidSymbolPayload
	}
	lengthsEnd := symbolPayloadHeaderSize + groupCount*2
	if len(payload) <= lengthsEnd {
		return SymbolPayload{}, ErrInvalidSymbolPayload
	}

	symbol := SymbolPayload{
		GroupCount:      groupCount,
		OriginalLength:  int(binary.BigEndian.Uint32(payload[2:6])),
		BaseSymbolCount: uint32(binary.BigEndian.Uint16(payload[6:8])),
		SymbolID:        binary.BigEndian.Uint32(payload[8:12]),
		PacketLengths:   make([]int, groupCount),
		Symbol:          append([]byte(nil), payload[lengthsEnd:]...),
	}
	if symbol.BaseSymbolCount == 0 || symbol.BaseSymbolCount < uint32(groupCount) {
		return SymbolPayload{}, ErrInvalidSymbolPayload
	}
	if len(symbol.Symbol) == 0 || len(symbol.Symbol) > MaxSymbolSize {
		return SymbolPayload{}, ErrInvalidSymbolPayload
	}

	sum := 0
	offset := symbolPayloadHeaderSize
	for i := range groupCount {
		packetLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		if packetLen > len(symbol.Symbol) {
			return SymbolPayload{}, ErrInvalidSymbolPayload
		}
		symbol.PacketLengths[i] = packetLen
		sum += packetLen
		offset += 2
	}
	if symbol.OriginalLength != sum {
		return SymbolPayload{}, ErrInvalidSymbolPayload
	}
	return symbol, nil
}
