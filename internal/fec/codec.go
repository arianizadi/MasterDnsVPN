package fec

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/xssnick/raptorq"
)

var (
	ErrInvalidGroup      = errors.New("invalid fec group")
	ErrSymbolTooSmall    = errors.New("fec symbol size is too small")
	ErrUnsupportedLayout = errors.New("unsupported fec symbol layout")
)

func BuildRepairSymbols(packets []SourcePacket, params Params) ([]SymbolPayload, error) {
	params = NormalizeParams(params)
	if !params.Enabled {
		return nil, nil
	}
	if len(packets) == 0 {
		return nil, nil
	}
	if len(packets) > params.GroupSize || len(packets) > MaxGroupSize {
		return nil, ErrInvalidGroup
	}

	symbolSize := params.SymbolSize
	originalLength := 0
	for _, packet := range packets {
		if len(packet.Payload) == 0 || len(packet.Payload) > MaxSymbolSize {
			return nil, ErrInvalidGroup
		}
		if symbolSize == 0 || len(packet.Payload) > symbolSize {
			symbolSize = len(packet.Payload)
		}
		originalLength += len(packet.Payload)
	}
	if symbolSize <= 0 || symbolSize > MaxSymbolSize {
		return nil, ErrInvalidGroup
	}

	data := make([]byte, len(packets)*symbolSize)
	lengths := make([]int, len(packets))
	for i, packet := range packets {
		if len(packet.Payload) > symbolSize {
			return nil, ErrSymbolTooSmall
		}
		copy(data[i*symbolSize:(i+1)*symbolSize], packet.Payload)
		lengths[i] = len(packet.Payload)
	}

	enc, err := raptorq.NewRaptorQ(uint32(symbolSize)).CreateEncoder(data)
	if err != nil {
		noteFailedGroup()
		return nil, fmt.Errorf("create raptorq encoder: %w", err)
	}
	baseSymbols := enc.BaseSymbolsNum()
	if baseSymbols != uint32(len(packets)) {
		noteFailedGroup()
		return nil, ErrUnsupportedLayout
	}

	repairCount := repairSymbolCount(baseSymbols, params.OverheadPercent)
	if repairCount == 0 {
		return nil, nil
	}

	out := make([]SymbolPayload, 0, repairCount)
	for i := uint32(0); i < repairCount; i++ {
		id := baseSymbols + i
		out = append(out, SymbolPayload{
			GroupCount:      len(packets),
			OriginalLength:  originalLength,
			BaseSymbolCount: baseSymbols,
			SymbolID:        id,
			PacketLengths:   append([]int(nil), lengths...),
			Symbol:          append([]byte(nil), enc.GenSymbol(id)...),
		})
	}
	noteGroupCreated()
	return out, nil
}

func repairSymbolCount(baseSymbols uint32, overheadPercent int) uint32 {
	if baseSymbols == 0 || overheadPercent <= 0 {
		return 0
	}
	count := (baseSymbols*uint32(overheadPercent) + 99) / 100
	if count == 0 {
		count = 1
	}
	return count
}

type RecoveredPacket struct {
	Sequence uint16
	Payload  []byte
}

type Receiver struct {
	params Params

	recentOrder []uint16
	recent      map[uint16][]byte
	groups      map[uint16]*decodeGroup
	maxRecent   int
}

type decodeGroup struct {
	start           uint16
	groupCount      int
	originalLength  int
	baseSymbolCount uint32
	symbolSize      int
	packetLengths   []int
	seenBase        []bool
	decoder         *raptorq.Decoder
	completed       bool
}

func NewReceiver(params Params) *Receiver {
	params = NormalizeParams(params)
	maxRecent := params.GroupSize * 64
	if maxRecent < 128 {
		maxRecent = 128
	}
	return &Receiver{
		params:    params,
		recent:    make(map[uint16][]byte, maxRecent),
		groups:    make(map[uint16]*decodeGroup, 32),
		maxRecent: maxRecent,
	}
}

func (r *Receiver) ObserveData(sequence uint16, payload []byte) ([]RecoveredPacket, error) {
	if r == nil || !r.params.Enabled || len(payload) == 0 {
		return nil, nil
	}
	r.remember(sequence, payload)

	var recovered []RecoveredPacket
	for _, group := range r.groups {
		if group == nil || group.completed || !sequenceInGroup(group.start, group.groupCount, sequence) {
			continue
		}
		if err := r.addBaseToGroup(group, sequence, payload); err != nil {
			return recovered, err
		}
		packets, err := r.tryDecode(group)
		if err != nil {
			return recovered, err
		}
		recovered = append(recovered, packets...)
	}
	return recovered, nil
}

func (r *Receiver) AddSymbol(groupStart uint16, payload []byte) ([]RecoveredPacket, error) {
	if r == nil || !r.params.Enabled {
		return nil, nil
	}
	NoteSymbolsReceived(1)

	symbol, err := DecodeSymbolPayload(payload)
	if err != nil {
		return nil, err
	}
	if symbol.GroupCount > r.params.GroupSize {
		return nil, ErrInvalidSymbolPayload
	}

	group, err := r.groupForSymbol(groupStart, symbol)
	if err != nil {
		return nil, err
	}
	if group.completed {
		return nil, nil
	}

	for i := range group.groupCount {
		seq := groupSequence(group.start, i)
		if data, ok := r.recent[seq]; ok {
			if err := r.addBaseToGroup(group, seq, data); err != nil {
				return nil, err
			}
		}
	}

	canDecode, err := group.decoder.AddSymbol(symbol.SymbolID, symbol.Symbol)
	if err != nil {
		return nil, err
	}
	if !canDecode {
		return nil, nil
	}
	return r.tryDecode(group)
}

func (r *Receiver) remember(sequence uint16, payload []byte) {
	if _, exists := r.recent[sequence]; !exists {
		r.recentOrder = append(r.recentOrder, sequence)
	}
	r.recent[sequence] = append([]byte(nil), payload...)

	for len(r.recentOrder) > r.maxRecent {
		oldest := r.recentOrder[0]
		copy(r.recentOrder, r.recentOrder[1:])
		r.recentOrder = r.recentOrder[:len(r.recentOrder)-1]
		delete(r.recent, oldest)
	}
}

func (r *Receiver) groupForSymbol(groupStart uint16, symbol SymbolPayload) (*decodeGroup, error) {
	if existing := r.groups[groupStart]; existing != nil {
		if !sameGroupMetadata(existing, symbol) {
			return nil, ErrInvalidSymbolPayload
		}
		return existing, nil
	}

	symbolSize := len(symbol.Symbol)
	decoder, err := raptorq.NewRaptorQ(uint32(symbolSize)).CreateDecoder(uint32(symbol.GroupCount * symbolSize))
	if err != nil {
		return nil, fmt.Errorf("create raptorq decoder: %w", err)
	}

	group := &decodeGroup{
		start:           groupStart,
		groupCount:      symbol.GroupCount,
		originalLength:  symbol.OriginalLength,
		baseSymbolCount: symbol.BaseSymbolCount,
		symbolSize:      symbolSize,
		packetLengths:   append([]int(nil), symbol.PacketLengths...),
		seenBase:        make([]bool, symbol.GroupCount),
		decoder:         decoder,
	}
	r.groups[groupStart] = group
	return group, nil
}

func sameGroupMetadata(group *decodeGroup, symbol SymbolPayload) bool {
	return group.groupCount == symbol.GroupCount &&
		group.originalLength == symbol.OriginalLength &&
		group.baseSymbolCount == symbol.BaseSymbolCount &&
		group.symbolSize == len(symbol.Symbol) &&
		slicesEqual(group.packetLengths, symbol.PacketLengths)
}

func slicesEqual(a []int, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (r *Receiver) addBaseToGroup(group *decodeGroup, sequence uint16, payload []byte) error {
	idx, ok := groupIndex(group.start, group.groupCount, sequence)
	if !ok || group.seenBase[idx] {
		return nil
	}
	if len(payload) != group.packetLengths[idx] || len(payload) > group.symbolSize {
		return ErrInvalidSymbolPayload
	}
	symbol := make([]byte, group.symbolSize)
	copy(symbol, payload)
	if _, err := group.decoder.AddSymbol(uint32(idx), symbol); err != nil {
		return err
	}
	group.seenBase[idx] = true
	return nil
}

func (r *Receiver) tryDecode(group *decodeGroup) ([]RecoveredPacket, error) {
	if group == nil || group.completed {
		return nil, nil
	}

	success, data, err := group.decoder.Decode()
	if err != nil {
		if stringsContains(err.Error(), "not enough symbols") {
			return nil, nil
		}
		noteFailedGroup()
		return nil, err
	}
	if !success {
		return nil, nil
	}
	if len(data) < group.groupCount*group.symbolSize {
		noteFailedGroup()
		return nil, ErrInvalidSymbolPayload
	}

	recovered := make([]RecoveredPacket, 0, group.groupCount)
	for i := range group.groupCount {
		if group.seenBase[i] {
			continue
		}
		packetLen := group.packetLengths[i]
		start := i * group.symbolSize
		packet := append([]byte(nil), data[start:start+packetLen]...)
		recovered = append(recovered, RecoveredPacket{
			Sequence: groupSequence(group.start, i),
			Payload:  packet,
		})
	}
	group.completed = true
	delete(r.groups, group.start)
	noteDecodedGroup(len(recovered))
	return recovered, nil
}

func groupSequence(start uint16, index int) uint16 {
	return start + uint16(index)
}

func sequenceInGroup(start uint16, count int, sequence uint16) bool {
	_, ok := groupIndex(start, count, sequence)
	return ok
}

func groupIndex(start uint16, count int, sequence uint16) (int, bool) {
	diff := uint16(sequence - start)
	if int(diff) >= count {
		return 0, false
	}
	return int(diff), true
}

func stringsContains(value string, needle string) bool {
	return bytes.Contains([]byte(value), []byte(needle))
}
