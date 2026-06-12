package mobilebridge

import (
	"context"
	"runtime/debug"
	"time"
)

// The iOS packet tunnel provider is killed by jetsam when its physical
// footprint exceeds ~50 MB. The Go runtime's defaults (GOGC=100, no memory
// limit, lazy page release) let RSS grow to several times the live heap under
// packet churn, which is what gets the extension killed mid-speedtest. Keep
// the collector aggressive and return freed pages to the OS promptly.
const (
	mobileGCPercent        = 10
	mobileMemoryLimitBytes = 30 << 20
	memoryReleaseInterval  = 10 * time.Second
)

func init() {
	debug.SetGCPercent(mobileGCPercent)
	debug.SetMemoryLimit(mobileMemoryLimitBytes)
}

// startMemoryReleaseLoop periodically forces a GC and returns freed memory to
// the OS while an engine is running. It stops when ctx is cancelled.
func startMemoryReleaseLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(memoryReleaseInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				debug.FreeOSMemory()
				return
			case <-ticker.C:
				debug.FreeOSMemory()
			}
		}
	}()
}
