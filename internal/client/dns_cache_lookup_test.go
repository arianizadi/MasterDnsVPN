package client

import (
	"encoding/binary"
	"testing"
	"time"

	dnsCache "masterdnsvpn-go/internal/dnscache"
	dnsParser "masterdnsvpn-go/internal/dnsparser"
)

func rawAQuery(id uint16, labels ...string) []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:], id)
	binary.BigEndian.PutUint16(query[2:], 0x0100)
	binary.BigEndian.PutUint16(query[4:], 1)
	for _, label := range labels {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, 0, 1, 0, 1)
}

func TestCachedDNSResponseOnlyAnswersReadyEntries(t *testing.T) {
	c := &Client{localDNSCache: dnsCache.New(16, time.Minute, time.Minute)}
	query := rawAQuery(0x1111, "example", "com")

	lite, err := dnsParser.ParseDNSRequestLite(query)
	if err != nil || !lite.HasQuestion {
		t.Fatalf("test query did not parse: %v", err)
	}
	question := lite.FirstQuestion
	key := dnsCache.BuildKey(question.Name, question.Type, question.Class)

	if _, ok := c.CachedDNSResponse(query); ok {
		t.Fatal("empty cache must not answer")
	}

	now := time.Now()
	c.localDNSCache.LookupOrCreatePending(key, question.Name, question.Type, question.Class, now)
	if _, ok := c.CachedDNSResponse(query); ok {
		t.Fatal("pending entry must not answer")
	}

	stored := rawAQuery(0x2222, "example", "com")
	stored[2] |= 0x80
	c.localDNSCache.SetReady(key, question.Name, question.Type, question.Class, stored, now)

	response, ok := c.CachedDNSResponse(query)
	if !ok {
		t.Fatal("ready entry should answer")
	}
	if got := binary.BigEndian.Uint16(response); got != 0x1111 {
		t.Fatalf("response must carry the query's transaction ID: got=%#x", got)
	}

	if _, ok := c.CachedDNSResponse([]byte{1, 2, 3}); ok {
		t.Fatal("unparseable query must not answer")
	}
	var nilClient *Client
	if _, ok := nilClient.CachedDNSResponse(query); ok {
		t.Fatal("nil client must not answer")
	}
}
