package olm

import (
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/dns"
	"github.com/fosrl/olm/websocket"
)

// handleDNSBlocklist handles "olm/dns/blocklist". The server sends it after
// registration and again whenever the set of domains this user's roles block
// changes. Every message replaces the whole list, and an empty "compressed"
// field clears it. "compressed" is base64(zlib(newline separated domains)).
// "logBlocks" says whether the server wants blocked queries reported back; it is
// only set for orgs that have the DNS block log.
func (o *Olm) handleDNSBlocklist(msg websocket.WSMessage) {
	if !o.tunnelRunning {
		logger.Debug("Tunnel is no longer running, ignoring DNS blocklist")
		return
	}

	var compressed string
	var logBlocks bool
	if m, ok := msg.Data.(map[string]interface{}); ok {
		compressed, _ = m["compressed"].(string)
		logBlocks, _ = m["logBlocks"].(bool)
	} else {
		logger.Error("Invalid DNS blocklist message")
		return
	}

	seq := o.blocklistSeq.Add(1)

	// Message handlers run on the websocket read pump, and decoding a large
	// list takes a moment, so do it off the pump.
	go func() {
		bl, err := decodeDNSBlocklist(compressed)
		if err != nil {
			logger.Error("Failed to decode DNS blocklist: %v", err)
			return
		}

		o.blocklistMu.Lock()
		if o.blocklistSeq.Load() != seq {
			// A newer message arrived while this one was decoding.
			o.blocklistMu.Unlock()
			return
		}
		o.blocklist = bl
		logChanged := o.blockLogEnabled != logBlocks
		o.blockLogEnabled = logBlocks
		proxy := o.dnsProxy
		o.blocklistMu.Unlock()

		if proxy != nil {
			proxy.SetBlocklist(bl)
			if logChanged {
				o.applyBlockLogSender(proxy, logBlocks)
			}
		}
		logger.Info("DNS blocklist updated: %d domains", bl.Len())
	}()
}

// decodeDNSBlocklist decodes a "compressed" blocklist payload. An empty payload
// is an empty (nil) blocklist.
func decodeDNSBlocklist(compressed string) (*dns.Blocklist, error) {
	if compressed == "" {
		return nil, nil
	}
	zr, err := zlib.NewReader(base64.NewDecoder(base64.StdEncoding, strings.NewReader(compressed)))
	if err != nil {
		return nil, fmt.Errorf("inflate: %w", err)
	}
	defer zr.Close()
	return dns.LoadBlocklist(zr)
}

// setupDNSBlocking prepares a freshly created DNS proxy for blocking: it applies
// any blocklist that arrived before the proxy existed, and starts reporting
// blocked queries if the server asked for that.
func (o *Olm) setupDNSBlocking() {
	proxy := o.dnsProxy
	o.apiServer.SetDNSBlockedProvider(proxy.BlockedCount)

	o.blocklistMu.Lock()
	bl := o.blocklist
	logBlocks := o.blockLogEnabled
	o.blocklistMu.Unlock()
	if bl != nil {
		proxy.SetBlocklist(bl)
	}
	o.applyBlockLogSender(proxy, logBlocks)
}

// applyBlockLogSender turns reporting of blocked queries on or off. Reporting is
// off unless the server asks for it, so servers without a block log are never
// sent messages they cannot handle.
func (o *Olm) applyBlockLogSender(proxy *dns.DNSProxy, enabled bool) {
	if enabled {
		proxy.SetBlockLogSender(o.sendDNSBlockLog)
	} else {
		proxy.SetBlockLogSender(nil)
	}
}

// sendDNSBlockLog sends a batch of aggregated blocked queries to the server.
func (o *Olm) sendDNSBlockLog(data string) error {
	if o.websocket == nil {
		return fmt.Errorf("not connected")
	}
	return o.websocket.SendMessageNoLog("olm/dns/blocklog", map[string]interface{}{
		"compressed": data,
	})
}

// clearDNSBlocklist drops the stored blocklist and invalidates any decode that
// is still running, so a stale list can't reappear on the next tunnel.
func (o *Olm) clearDNSBlocklist() {
	o.blocklistMu.Lock()
	o.blocklistSeq.Add(1)
	o.blocklist = nil
	o.blockLogEnabled = false
	o.blocklistMu.Unlock()
}
