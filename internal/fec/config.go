package fec

import (
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

const (
	Version = 1

	DirectionDownload = "download"

	DefaultGroupSize       = 8
	DefaultOverheadPercent = 15
	DefaultSymbolSize      = 0
	DefaultFlushTimeoutMS  = 25

	MinGroupSize       = 2
	MaxGroupSize       = 64
	MinOverheadPercent = 0
	MaxOverheadPercent = 100
	MaxSymbolSize      = 65535
	MinFlushTimeoutMS  = 1
	MaxFlushTimeoutMS  = 1000

	FlagDownload = 1 << 0

	CapsPayloadSize = 8
)

var (
	ErrInvalidCapsPayload = errors.New("invalid fec caps payload")
	ErrUnsupportedCaps    = errors.New("unsupported fec caps")
)

type Params struct {
	Enabled         bool          `json:"enabled"`
	Direction       string        `json:"direction"`
	GroupSize       int           `json:"groupSize"`
	OverheadPercent int           `json:"overheadPercent"`
	SymbolSize      int           `json:"symbolSize"`
	FlushTimeout    time.Duration `json:"-"`
	FlushTimeoutMS  int           `json:"flushTimeoutMs"`
}

func DefaultParams() Params {
	return Params{
		Direction:       DirectionDownload,
		GroupSize:       DefaultGroupSize,
		OverheadPercent: DefaultOverheadPercent,
		SymbolSize:      DefaultSymbolSize,
		FlushTimeout:    time.Duration(DefaultFlushTimeoutMS) * time.Millisecond,
		FlushTimeoutMS:  DefaultFlushTimeoutMS,
	}
}

func NormalizeParams(params Params) Params {
	direction := strings.ToLower(strings.TrimSpace(params.Direction))
	if direction == "" {
		direction = DirectionDownload
	}

	groupSize := params.GroupSize
	if groupSize <= 0 {
		groupSize = DefaultGroupSize
	}
	groupSize = clampInt(groupSize, MinGroupSize, MaxGroupSize)

	overheadPercent := params.OverheadPercent
	if overheadPercent < 0 {
		overheadPercent = DefaultOverheadPercent
	}
	overheadPercent = clampInt(overheadPercent, MinOverheadPercent, MaxOverheadPercent)

	symbolSize := params.SymbolSize
	if symbolSize < 0 {
		symbolSize = DefaultSymbolSize
	}
	symbolSize = clampInt(symbolSize, 0, MaxSymbolSize)

	flushMS := params.FlushTimeoutMS
	if flushMS <= 0 && params.FlushTimeout > 0 {
		flushMS = int((params.FlushTimeout + time.Millisecond - 1) / time.Millisecond)
	}
	if flushMS <= 0 {
		flushMS = DefaultFlushTimeoutMS
	}
	flushMS = clampInt(flushMS, MinFlushTimeoutMS, MaxFlushTimeoutMS)

	params.Direction = direction
	params.GroupSize = groupSize
	params.OverheadPercent = overheadPercent
	params.SymbolSize = symbolSize
	params.FlushTimeoutMS = flushMS
	params.FlushTimeout = time.Duration(flushMS) * time.Millisecond
	if direction != DirectionDownload {
		params.Enabled = false
	}
	return params
}

func EncodeCapsPayload(params Params) []byte {
	params = NormalizeParams(params)
	payload := make([]byte, CapsPayloadSize)
	payload[0] = Version
	if params.Enabled && params.Direction == DirectionDownload {
		payload[1] = FlagDownload
	}
	payload[2] = byte(params.GroupSize)
	payload[3] = byte(params.OverheadPercent)
	binary.BigEndian.PutUint16(payload[4:6], uint16(params.SymbolSize))
	binary.BigEndian.PutUint16(payload[6:8], uint16(params.FlushTimeoutMS))
	return payload
}

func DecodeCapsPayload(payload []byte) (Params, error) {
	if len(payload) != CapsPayloadSize {
		return Params{}, ErrInvalidCapsPayload
	}
	if payload[0] != Version {
		return Params{}, ErrUnsupportedCaps
	}

	params := Params{
		Enabled:         payload[1]&FlagDownload != 0,
		Direction:       DirectionDownload,
		GroupSize:       int(payload[2]),
		OverheadPercent: int(payload[3]),
		SymbolSize:      int(binary.BigEndian.Uint16(payload[4:6])),
		FlushTimeoutMS:  int(binary.BigEndian.Uint16(payload[6:8])),
	}
	return NormalizeParams(params), nil
}

func Negotiate(client Params, server Params) Params {
	client = NormalizeParams(client)
	server = NormalizeParams(server)

	if !client.Enabled || !server.Enabled ||
		client.Direction != DirectionDownload ||
		server.Direction != DirectionDownload {
		disabled := DefaultParams()
		disabled.Enabled = false
		return disabled
	}

	symbolSize := client.SymbolSize
	if server.SymbolSize > 0 {
		if symbolSize <= 0 || symbolSize > server.SymbolSize {
			symbolSize = server.SymbolSize
		}
	}

	params := Params{
		Enabled:         true,
		Direction:       DirectionDownload,
		GroupSize:       min(client.GroupSize, server.GroupSize),
		OverheadPercent: min(client.OverheadPercent, server.OverheadPercent),
		SymbolSize:      symbolSize,
		FlushTimeoutMS:  min(client.FlushTimeoutMS, server.FlushTimeoutMS),
	}
	return NormalizeParams(params)
}

func clampInt(value int, low int, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}
