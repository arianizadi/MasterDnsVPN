package fec

import "sync/atomic"

type GlobalStats struct {
	Negotiated       uint64 `json:"negotiated"`
	GroupsCreated    uint64 `json:"groupsCreated"`
	SymbolsSent      uint64 `json:"symbolsSent"`
	SymbolsReceived  uint64 `json:"symbolsReceived"`
	DecodedGroups    uint64 `json:"decodedGroups"`
	RecoveredPackets uint64 `json:"recoveredPackets"`
	FailedGroups     uint64 `json:"failedGroups"`
	OverheadBytes    uint64 `json:"overheadBytes"`
}

var globalStats struct {
	negotiated       atomic.Uint64
	groupsCreated    atomic.Uint64
	symbolsSent      atomic.Uint64
	symbolsReceived  atomic.Uint64
	decodedGroups    atomic.Uint64
	recoveredPackets atomic.Uint64
	failedGroups     atomic.Uint64
	overheadBytes    atomic.Uint64
}

func ResetGlobalStats() {
	globalStats.negotiated.Store(0)
	globalStats.groupsCreated.Store(0)
	globalStats.symbolsSent.Store(0)
	globalStats.symbolsReceived.Store(0)
	globalStats.decodedGroups.Store(0)
	globalStats.recoveredPackets.Store(0)
	globalStats.failedGroups.Store(0)
	globalStats.overheadBytes.Store(0)
}

func GlobalStatsSnapshot() GlobalStats {
	return GlobalStats{
		Negotiated:       globalStats.negotiated.Load(),
		GroupsCreated:    globalStats.groupsCreated.Load(),
		SymbolsSent:      globalStats.symbolsSent.Load(),
		SymbolsReceived:  globalStats.symbolsReceived.Load(),
		DecodedGroups:    globalStats.decodedGroups.Load(),
		RecoveredPackets: globalStats.recoveredPackets.Load(),
		FailedGroups:     globalStats.failedGroups.Load(),
		OverheadBytes:    globalStats.overheadBytes.Load(),
	}
}

func NoteNegotiated() {
	globalStats.negotiated.Add(1)
}

func NoteSymbolsSent(count int, bytes int) {
	if count > 0 {
		globalStats.symbolsSent.Add(uint64(count))
	}
	if bytes > 0 {
		globalStats.overheadBytes.Add(uint64(bytes))
	}
}

func NoteSymbolsReceived(count int) {
	if count > 0 {
		globalStats.symbolsReceived.Add(uint64(count))
	}
}

func noteGroupCreated() {
	globalStats.groupsCreated.Add(1)
}

func noteDecodedGroup(recoveredPackets int) {
	globalStats.decodedGroups.Add(1)
	if recoveredPackets > 0 {
		globalStats.recoveredPackets.Add(uint64(recoveredPackets))
	}
}

func noteFailedGroup() {
	globalStats.failedGroups.Add(1)
}
