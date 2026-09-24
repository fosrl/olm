package monitor

import (
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/websocket"
)

// Batch tuning: each new item added resets a batchDebounce trailing window, so a burst of
// decisions that trickle in over a few hundred ms (e.g. 100 sites each independently
// finishing their own rapid holepunch test after a network-wide blip) still collapses into
// one flush instead of splitting across several. batchMaxWait bounds how long a steady
// trickle of arrivals can keep postponing that flush, so an item is never held back more
// than batchMaxWait past its own arrival. Once sent, items the server hasn't acknowledged
// yet are retried together every batchInterval, up to batchMaxAttempts times, mirroring the
// cadence the previous per-site SendMessageInterval senders used.
const (
	batchDebounce    = 200 * time.Millisecond
	batchMaxWait     = 750 * time.Millisecond
	batchInterval    = 2 * time.Second
	batchMaxAttempts = 10
)

// batchSendItem is a single queued site decision awaiting acknowledgement.
type batchSendItem struct {
	siteID   int
	endpoint string // only populated for the local batcher; ignored otherwise
	attempts int
}

// batchSender coalesces per-site "olm/wg/*" notifications of a single message type into
// periodic batched websocket messages, retrying items the server hasn't acknowledged (via
// cancel) until they succeed or exhaust batchMaxAttempts. When the connected server doesn't
// understand the batched wire format (see websocket.Client.SupportsBatchedSiteMessages),
// it falls back to sending each item as its own message in the pre-batching singular form.
type batchSender struct {
	mu            sync.Mutex
	items         map[string]*batchSendItem // chainId -> item
	messageType   string
	wsClient      *websocket.Client
	debounceTimer *time.Timer
	burstStarted  time.Time
	runOnce       sync.Once
	stopChan      chan struct{}
}

func newBatchSender(wsClient *websocket.Client, messageType string) *batchSender {
	return &batchSender{
		items:       make(map[string]*batchSendItem),
		messageType: messageType,
		wsClient:    wsClient,
		stopChan:    make(chan struct{}),
	}
}

// add queues siteID for the next flush and returns the chainId that identifies it for
// cancel/ack purposes. endpoint is only meaningful for the local batcher.
func (b *batchSender) add(siteID int, endpoint string) string {
	chainId := generateChainId()

	b.mu.Lock()
	b.items[chainId] = &batchSendItem{siteID: siteID, endpoint: endpoint}

	now := time.Now()
	if b.debounceTimer == nil {
		// First item of a new burst: start the trailing window.
		b.burstStarted = now
		b.debounceTimer = time.AfterFunc(batchDebounce, b.flush)
	} else {
		// Extend the window for this new arrival, capped so a burst that keeps trickling
		// in still flushes within batchMaxWait of its first item.
		delay := batchDebounce
		if remaining := batchMaxWait - now.Sub(b.burstStarted); remaining < delay {
			if remaining < 0 {
				remaining = 0
			}
			delay = remaining
		}
		b.debounceTimer.Reset(delay)
	}
	b.mu.Unlock()

	b.runOnce.Do(func() { go b.run() })

	return chainId
}

// cancel removes chainId from the pending set, e.g. once the server has acknowledged it.
// Returns true if it was pending.
func (b *batchSender) cancel(chainId string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.items[chainId]; !ok {
		return false
	}
	delete(b.items, chainId)
	return true
}

// cancelAll clears all pending items, e.g. on shutdown.
func (b *batchSender) cancelAll() {
	b.mu.Lock()
	b.items = make(map[string]*batchSendItem)
	b.mu.Unlock()
}

type readySend struct {
	chainId  string
	siteID   int
	endpoint string
}

// flush sends everything currently pending, dropping items that have exhausted
// batchMaxAttempts. If the server supports the batched wire format it goes out as a single
// message; otherwise each item is sent individually in the pre-batching singular form.
func (b *batchSender) flush() {
	b.mu.Lock()
	b.debounceTimer = nil

	ready := make([]readySend, 0, len(b.items))
	for chainId, item := range b.items {
		item.attempts++
		if item.attempts > batchMaxAttempts {
			logger.Warn("olm: giving up on %s for site %d (chain %s) after %d attempts", b.messageType, item.siteID, chainId, batchMaxAttempts)
			delete(b.items, chainId)
			continue
		}
		ready = append(ready, readySend{chainId: chainId, siteID: item.siteID, endpoint: item.endpoint})
	}
	wsClient := b.wsClient
	messageType := b.messageType
	b.mu.Unlock()

	if len(ready) == 0 || wsClient == nil {
		return
	}

	if !wsClient.SupportsBatchedSiteMessages() {
		b.sendIndividually(wsClient, messageType, ready)
		return
	}

	siteIds := make([]int, len(ready))
	chainIds := make([]string, len(ready))
	endpoints := make([]string, len(ready))
	hasEndpoints := false
	for i, item := range ready {
		siteIds[i] = item.siteID
		chainIds[i] = item.chainId
		endpoints[i] = item.endpoint
		if item.endpoint != "" {
			hasEndpoints = true
		}
	}

	data := map[string]interface{}{
		"siteIds":  siteIds,
		"chainIds": chainIds,
	}
	if hasEndpoints {
		data["endpoints"] = endpoints
	}

	if err := wsClient.SendMessage(messageType, data); err != nil {
		logger.Error("olm: failed to send batched %s: %v", messageType, err)
	} else {
		logger.Info("olm: sent batched %s for %d site(s)", messageType, len(siteIds))
	}
}

// sendIndividually sends each item as its own message in the singular siteId/chainId form,
// for servers that predate the batched wire format.
func (b *batchSender) sendIndividually(wsClient *websocket.Client, messageType string, ready []readySend) {
	for _, item := range ready {
		data := map[string]interface{}{
			"siteId":  item.siteID,
			"chainId": item.chainId,
		}
		if item.endpoint != "" {
			data["endpoint"] = item.endpoint
		}
		if err := wsClient.SendMessage(messageType, data); err != nil {
			logger.Error("olm: failed to send %s for site %d: %v", messageType, item.siteID, err)
		}
	}
}

// run periodically resends any items still awaiting acknowledgement.
func (b *batchSender) run() {
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-b.stopChan:
			return
		case <-ticker.C:
			b.flush()
		}
	}
}

// close stops the background retry loop. The sender must not be used again afterwards.
func (b *batchSender) close() {
	select {
	case <-b.stopChan:
		// already closed
	default:
		close(b.stopChan)
	}
}
