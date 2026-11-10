package client

import (
	"time"

	dnsCache "masterdnsvpn-go/internal/dnscache"
	dnsParser "masterdnsvpn-go/internal/dnsparser"
)

// CachedDNSResponse returns the cached answer for query, patched to the
// query's transaction ID, without dispatching anything to the tunnel and
// without logging. Embedders that hold a query open after ProcessDNSQuery
// reported a miss use it to answer as soon as the tunnel reply is cached.
func (c *Client) CachedDNSResponse(query []byte) ([]byte, bool) {
	if c == nil || c.localDNSCache == nil {
		return nil, false
	}
	lite, err := dnsParser.ParseDNSRequestLite(query)
	if err != nil || !lite.HasQuestion {
		return nil, false
	}
	question := lite.FirstQuestion
	key := dnsCache.BuildKey(question.Name, question.Type, question.Class)
	return c.localDNSCache.GetReady(key, query, time.Now())
}
