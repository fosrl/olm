package dns

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
)

func decodeBlockLog(t *testing.T, data string) []BlockLogEntry {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("zlib: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	var entries []BlockLogEntry
	if err := json.Unmarshal(plain, &entries); err != nil {
		t.Fatalf("json: %v", err)
	}
	return entries
}

type sink struct {
	mu      sync.Mutex
	batches []string
	fail    bool
}

func (s *sink) send(data string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("offline")
	}
	s.batches = append(s.batches, data)
	return nil
}

func TestBlockLogAggregatesAndFlushes(t *testing.T) {
	s := &sink{}
	bl := NewBlockLog(s.send)

	bl.Record("ads.example.com")
	bl.Record("ads.example.com")
	bl.Record("tracker.net")
	if bl.Total() != 3 {
		t.Errorf("Total() = %d, want 3", bl.Total())
	}

	bl.Stop() // final flush

	if len(s.batches) != 1 {
		t.Fatalf("got %d batches, want 1", len(s.batches))
	}
	counts := map[string]int{}
	for _, e := range decodeBlockLog(t, s.batches[0]) {
		counts[e.Domain] = e.Count
		if e.FirstSeen == 0 {
			t.Errorf("%s: firstSeen not set", e.Domain)
		}
	}
	if counts["ads.example.com"] != 2 || counts["tracker.net"] != 1 {
		t.Errorf("unexpected counts: %v", counts)
	}
}

func TestBlockLogNothingToSend(t *testing.T) {
	s := &sink{}
	NewBlockLog(s.send).Stop()
	if len(s.batches) != 0 {
		t.Error("an empty log must not send anything")
	}
}

func TestBlockLogRequeuesOnFailure(t *testing.T) {
	s := &sink{fail: true}
	bl := &BlockLog{send: s.send, entries: map[string]*BlockLogEntry{}}

	bl.Record("ads.example.com")
	bl.flush() // fails, entries go back
	bl.Record("ads.example.com")

	s.fail = false
	bl.flush()

	if len(s.batches) != 1 {
		t.Fatalf("got %d batches, want 1", len(s.batches))
	}
	entries := decodeBlockLog(t, s.batches[0])
	if len(entries) != 1 || entries[0].Count != 2 {
		t.Errorf("expected one entry with count 2 after retry, got %+v", entries)
	}
}

func TestBlockLogCapsDistinctDomains(t *testing.T) {
	bl := &BlockLog{send: func(string) error { return nil }, entries: map[string]*BlockLogEntry{}}
	for i := 0; i < blockLogMaxDistinct+100; i++ {
		bl.Record(fmt.Sprintf("host%d.example.com", i))
	}
	if len(bl.entries) != blockLogMaxDistinct {
		t.Errorf("held %d distinct domains, want cap of %d", len(bl.entries), blockLogMaxDistinct)
	}
	if bl.Total() != uint64(blockLogMaxDistinct+100) {
		t.Errorf("Total() must count dropped domains too, got %d", bl.Total())
	}
}
