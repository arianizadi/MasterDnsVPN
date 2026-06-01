package arq

import "sync/atomic"

// GlobalStats contains real counters emitted by ARQ event hooks. These are
// process-wide because the iOS extension runs one MasterDnsVPN engine at a time.
type GlobalStats struct {
	StreamsCreated uint64 `json:"streamsCreated"`
	StreamsClosed  uint64 `json:"streamsClosed"`
	StreamsActive  uint64 `json:"streamsActive"`

	DataPacketsRead          uint64 `json:"dataPacketsRead"`
	DataPacketsQueued        uint64 `json:"dataPacketsQueued"`
	DataPacketsQueueRejected uint64 `json:"dataPacketsQueueRejected"`
	DataPacketsDequeued      uint64 `json:"dataPacketsDequeued"`
	DataPacketsAcked         uint64 `json:"dataPacketsAcked"`
	DataPacketsReceived      uint64 `json:"dataPacketsReceived"`
	DataAckPacketsSent       uint64 `json:"dataAckPacketsSent"`
	DataAckPacketsRejected   uint64 `json:"dataAckPacketsRejected"`

	DataNackPacketsSent        uint64 `json:"dataNackPacketsSent"`
	DataNackPacketsRejected    uint64 `json:"dataNackPacketsRejected"`
	DataNackPacketsReceived    uint64 `json:"dataNackPacketsReceived"`
	DataResendsQueued          uint64 `json:"dataResendsQueued"`
	DataResendsRejected        uint64 `json:"dataResendsRejected"`
	DataNackResendsQueued      uint64 `json:"dataNackResendsQueued"`
	DataNackResendsRejected    uint64 `json:"dataNackResendsRejected"`
	DataTimeoutResendsQueued   uint64 `json:"dataTimeoutResendsQueued"`
	DataTimeoutResendsRejected uint64 `json:"dataTimeoutResendsRejected"`
	DataMaxRetriesExceeded     uint64 `json:"dataMaxRetriesExceeded"`
	DataTTLExpired             uint64 `json:"dataTTLExpired"`

	ControlPacketsQueued        uint64 `json:"controlPacketsQueued"`
	ControlPacketsQueueRejected uint64 `json:"controlPacketsQueueRejected"`
	ControlPacketsDequeued      uint64 `json:"controlPacketsDequeued"`
	ControlPacketsAcked         uint64 `json:"controlPacketsAcked"`
	ControlResendsQueued        uint64 `json:"controlResendsQueued"`
	ControlResendsRejected      uint64 `json:"controlResendsRejected"`
	ControlMaxRetriesExceeded   uint64 `json:"controlMaxRetriesExceeded"`
	ControlTTLExpired           uint64 `json:"controlTTLExpired"`
}

var globalStats struct {
	streamsCreated atomic.Uint64
	streamsClosed  atomic.Uint64
	streamsActive  atomic.Uint64

	dataPacketsRead          atomic.Uint64
	dataPacketsQueued        atomic.Uint64
	dataPacketsQueueRejected atomic.Uint64
	dataPacketsDequeued      atomic.Uint64
	dataPacketsAcked         atomic.Uint64
	dataPacketsReceived      atomic.Uint64
	dataAckPacketsSent       atomic.Uint64
	dataAckPacketsRejected   atomic.Uint64

	dataNackPacketsSent        atomic.Uint64
	dataNackPacketsRejected    atomic.Uint64
	dataNackPacketsReceived    atomic.Uint64
	dataResendsQueued          atomic.Uint64
	dataResendsRejected        atomic.Uint64
	dataNackResendsQueued      atomic.Uint64
	dataNackResendsRejected    atomic.Uint64
	dataTimeoutResendsQueued   atomic.Uint64
	dataTimeoutResendsRejected atomic.Uint64
	dataMaxRetriesExceeded     atomic.Uint64
	dataTTLExpired             atomic.Uint64

	controlPacketsQueued        atomic.Uint64
	controlPacketsQueueRejected atomic.Uint64
	controlPacketsDequeued      atomic.Uint64
	controlPacketsAcked         atomic.Uint64
	controlResendsQueued        atomic.Uint64
	controlResendsRejected      atomic.Uint64
	controlMaxRetriesExceeded   atomic.Uint64
	controlTTLExpired           atomic.Uint64
}

func ResetGlobalStats() {
	globalStats.streamsCreated.Store(0)
	globalStats.streamsClosed.Store(0)
	globalStats.streamsActive.Store(0)

	globalStats.dataPacketsRead.Store(0)
	globalStats.dataPacketsQueued.Store(0)
	globalStats.dataPacketsQueueRejected.Store(0)
	globalStats.dataPacketsDequeued.Store(0)
	globalStats.dataPacketsAcked.Store(0)
	globalStats.dataPacketsReceived.Store(0)
	globalStats.dataAckPacketsSent.Store(0)
	globalStats.dataAckPacketsRejected.Store(0)

	globalStats.dataNackPacketsSent.Store(0)
	globalStats.dataNackPacketsRejected.Store(0)
	globalStats.dataNackPacketsReceived.Store(0)
	globalStats.dataResendsQueued.Store(0)
	globalStats.dataResendsRejected.Store(0)
	globalStats.dataNackResendsQueued.Store(0)
	globalStats.dataNackResendsRejected.Store(0)
	globalStats.dataTimeoutResendsQueued.Store(0)
	globalStats.dataTimeoutResendsRejected.Store(0)
	globalStats.dataMaxRetriesExceeded.Store(0)
	globalStats.dataTTLExpired.Store(0)

	globalStats.controlPacketsQueued.Store(0)
	globalStats.controlPacketsQueueRejected.Store(0)
	globalStats.controlPacketsDequeued.Store(0)
	globalStats.controlPacketsAcked.Store(0)
	globalStats.controlResendsQueued.Store(0)
	globalStats.controlResendsRejected.Store(0)
	globalStats.controlMaxRetriesExceeded.Store(0)
	globalStats.controlTTLExpired.Store(0)
}

func GlobalStatsSnapshot() GlobalStats {
	return GlobalStats{
		StreamsCreated: globalStats.streamsCreated.Load(),
		StreamsClosed:  globalStats.streamsClosed.Load(),
		StreamsActive:  globalStats.streamsActive.Load(),

		DataPacketsRead:          globalStats.dataPacketsRead.Load(),
		DataPacketsQueued:        globalStats.dataPacketsQueued.Load(),
		DataPacketsQueueRejected: globalStats.dataPacketsQueueRejected.Load(),
		DataPacketsDequeued:      globalStats.dataPacketsDequeued.Load(),
		DataPacketsAcked:         globalStats.dataPacketsAcked.Load(),
		DataPacketsReceived:      globalStats.dataPacketsReceived.Load(),
		DataAckPacketsSent:       globalStats.dataAckPacketsSent.Load(),
		DataAckPacketsRejected:   globalStats.dataAckPacketsRejected.Load(),

		DataNackPacketsSent:        globalStats.dataNackPacketsSent.Load(),
		DataNackPacketsRejected:    globalStats.dataNackPacketsRejected.Load(),
		DataNackPacketsReceived:    globalStats.dataNackPacketsReceived.Load(),
		DataResendsQueued:          globalStats.dataResendsQueued.Load(),
		DataResendsRejected:        globalStats.dataResendsRejected.Load(),
		DataNackResendsQueued:      globalStats.dataNackResendsQueued.Load(),
		DataNackResendsRejected:    globalStats.dataNackResendsRejected.Load(),
		DataTimeoutResendsQueued:   globalStats.dataTimeoutResendsQueued.Load(),
		DataTimeoutResendsRejected: globalStats.dataTimeoutResendsRejected.Load(),
		DataMaxRetriesExceeded:     globalStats.dataMaxRetriesExceeded.Load(),
		DataTTLExpired:             globalStats.dataTTLExpired.Load(),

		ControlPacketsQueued:        globalStats.controlPacketsQueued.Load(),
		ControlPacketsQueueRejected: globalStats.controlPacketsQueueRejected.Load(),
		ControlPacketsDequeued:      globalStats.controlPacketsDequeued.Load(),
		ControlPacketsAcked:         globalStats.controlPacketsAcked.Load(),
		ControlResendsQueued:        globalStats.controlResendsQueued.Load(),
		ControlResendsRejected:      globalStats.controlResendsRejected.Load(),
		ControlMaxRetriesExceeded:   globalStats.controlMaxRetriesExceeded.Load(),
		ControlTTLExpired:           globalStats.controlTTLExpired.Load(),
	}
}

func noteStreamCreated() {
	globalStats.streamsCreated.Add(1)
	globalStats.streamsActive.Add(1)
}

func noteStreamClosed() {
	globalStats.streamsClosed.Add(1)
	for {
		current := globalStats.streamsActive.Load()
		if current == 0 {
			return
		}
		if globalStats.streamsActive.CompareAndSwap(current, current-1) {
			return
		}
	}
}
