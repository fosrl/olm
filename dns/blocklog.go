package dns

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fosrl/newt/logger"
)

const (
	blockLogFlushInterval = 60 * time.Second
	// Flush early once this many distinct domains are waiting.
	blockLogFlushDistinct = 500
	// Hard cap on distinct domains held while sends are failing. New domains
	// beyond it are dropped (counts for known domains keep accumulating).
	blockLogMaxDistinct = 5000
	maxBlockLogDomain   = 253
)

// BlockLogEntry is one aggregated row in a block log batch sent to the server.
type BlockLogEntry struct {
	Domain    string `json:"domain"`
	Count     int    `json:"count"`
	FirstSeen int64  `json:"firstSeen"` // unix seconds
}

// BlockLogSendFunc delivers a batch. data is base64(zlib(JSON array of BlockLogEntry)).
type BlockLogSendFunc func(data string) error

// BlockLog aggregates blocked queries into per-domain counts and sends them to
// the server in batches.
type BlockLog struct {
	send BlockLogSendFunc

	mu      sync.Mutex
	entries map[string]*BlockLogEntry

	total atomic.Uint64 // blocked queries since creation

	flushNow chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewBlockLog creates a BlockLog and starts its flush loop. Call Stop to flush
// what is left and release the goroutine.
func NewBlockLog(send BlockLogSendFunc) *BlockLog {
	ctx, cancel := context.WithCancel(context.Background())
	b := &BlockLog{
		send:     send,
		entries:  make(map[string]*BlockLogEntry),
		flushNow: make(chan struct{}, 1),
		ctx:      ctx,
		cancel:   cancel,
	}
	b.wg.Add(1)
	go b.run()
	return b
}

// Record counts one blocked query for domain.
func (b *BlockLog) Record(domain string) {
	if b == nil {
		return
	}
	b.total.Add(1)

	if len(domain) > maxBlockLogDomain {
		domain = domain[:maxBlockLogDomain]
	}

	b.mu.Lock()
	if e, ok := b.entries[domain]; ok {
		e.Count++
	} else if len(b.entries) < blockLogMaxDistinct {
		b.entries[domain] = &BlockLogEntry{Domain: domain, Count: 1, FirstSeen: time.Now().Unix()}
	}
	full := len(b.entries) >= blockLogFlushDistinct
	b.mu.Unlock()

	if full {
		select {
		case b.flushNow <- struct{}{}:
		default:
		}
	}
}

// Total returns the number of blocked queries recorded since creation.
func (b *BlockLog) Total() uint64 {
	if b == nil {
		return 0
	}
	return b.total.Load()
}

// Stop stops the flush loop and makes a final attempt to send what is pending.
func (b *BlockLog) Stop() {
	if b == nil {
		return
	}
	b.cancel()
	b.wg.Wait()
	b.flush()
}

func (b *BlockLog) run() {
	defer b.wg.Done()
	ticker := time.NewTicker(blockLogFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.flush()
		case <-b.flushNow:
			b.flush()
		}
	}
}

func (b *BlockLog) flush() {
	b.mu.Lock()
	if len(b.entries) == 0 {
		b.mu.Unlock()
		return
	}
	batch := make([]BlockLogEntry, 0, len(b.entries))
	for _, e := range b.entries {
		batch = append(batch, *e)
	}
	b.entries = make(map[string]*BlockLogEntry)
	b.mu.Unlock()

	data, err := encodeBlockLog(batch)
	if err == nil {
		err = b.send(data)
	}
	if err != nil {
		logger.Debug("Failed to send DNS block log, will retry: %v", err)
		b.requeue(batch)
	}
}

// requeue merges a batch that failed to send back into the pending entries.
func (b *BlockLog) requeue(batch []BlockLogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, old := range batch {
		if e, ok := b.entries[old.Domain]; ok {
			e.Count += old.Count
			if old.FirstSeen < e.FirstSeen {
				e.FirstSeen = old.FirstSeen
			}
		} else if len(b.entries) < blockLogMaxDistinct {
			entry := old
			b.entries[old.Domain] = &entry
		}
	}
}

func encodeBlockLog(batch []BlockLogEntry) (string, error) {
	raw, err := json.Marshal(batch)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(raw); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
