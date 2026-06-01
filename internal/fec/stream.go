package fec

import (
	"sync"
	"time"
)

type SendSymbolFunc func(groupStart uint16, symbol SymbolPayload)

type DownstreamEncoder struct {
	mu      sync.Mutex
	params  Params
	current []SourcePacket
	timer   *time.Timer
	closed  bool
	emit    SendSymbolFunc
}

func NewDownstreamEncoder(params Params, emit SendSymbolFunc) *DownstreamEncoder {
	params = NormalizeParams(params)
	return &DownstreamEncoder{
		params: params,
		emit:   emit,
	}
}

func (e *DownstreamEncoder) AddData(sequence uint16, payload []byte) {
	if e == nil || !e.params.Enabled || len(payload) == 0 {
		return
	}

	var flushes [][]SourcePacket

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}

	if len(e.current) > 0 {
		expected := e.current[0].Sequence + uint16(len(e.current))
		if sequence != expected {
			flushes = append(flushes, cloneGroup(e.current))
			e.current = e.current[:0]
			e.stopTimerLocked()
		}
	}

	e.current = append(e.current, SourcePacket{
		Sequence: sequence,
		Payload:  append([]byte(nil), payload...),
	})
	if len(e.current) == 1 {
		e.startTimerLocked()
	}
	if len(e.current) >= e.params.GroupSize {
		flushes = append(flushes, cloneGroup(e.current))
		e.current = e.current[:0]
		e.stopTimerLocked()
	}
	e.mu.Unlock()

	for _, group := range flushes {
		e.emitGroup(group)
	}
}

func (e *DownstreamEncoder) Flush() {
	if e == nil {
		return
	}

	e.mu.Lock()
	if e.closed || len(e.current) == 0 {
		e.mu.Unlock()
		return
	}
	group := cloneGroup(e.current)
	e.current = e.current[:0]
	e.stopTimerLocked()
	e.mu.Unlock()

	e.emitGroup(group)
}

func (e *DownstreamEncoder) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	e.current = nil
	e.stopTimerLocked()
	e.mu.Unlock()
}

func (e *DownstreamEncoder) startTimerLocked() {
	if e.params.FlushTimeout <= 0 {
		return
	}
	if e.timer == nil {
		e.timer = time.AfterFunc(e.params.FlushTimeout, e.onTimer)
		return
	}
	e.timer.Reset(e.params.FlushTimeout)
}

func (e *DownstreamEncoder) stopTimerLocked() {
	if e.timer == nil {
		return
	}
	if !e.timer.Stop() {
		select {
		case <-e.timer.C:
		default:
		}
	}
}

func (e *DownstreamEncoder) onTimer() {
	e.Flush()
}

func (e *DownstreamEncoder) emitGroup(group []SourcePacket) {
	if e == nil || e.emit == nil || len(group) == 0 {
		return
	}
	symbols, err := BuildRepairSymbols(group, e.params)
	if err != nil {
		noteFailedGroup()
		return
	}
	groupStart := group[0].Sequence
	for _, symbol := range symbols {
		e.emit(groupStart, symbol)
	}
}

func cloneGroup(in []SourcePacket) []SourcePacket {
	out := make([]SourcePacket, len(in))
	for i, packet := range in {
		out[i] = SourcePacket{
			Sequence: packet.Sequence,
			Payload:  append([]byte(nil), packet.Payload...),
		}
	}
	return out
}
