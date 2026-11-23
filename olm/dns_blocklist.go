package olm

import (
	"compress/zlib"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/api"
	"github.com/fosrl/olm/blockpage"
	"github.com/fosrl/olm/dns"
	"github.com/fosrl/olm/websocket"
)

// handleDNSBlocklist handles "olm/dns/blocklist". The server sends it after
// registration and again whenever the set of domains this user's roles block
// changes. Every message replaces the whole list, and an empty "compressed"
// field clears it. "compressed" is base64(zlib(newline separated domains)).
// "logBlocks" says whether the server wants blocked queries reported back; it is
// only set for orgs that have the DNS block log.
//
// "pageCompressed" (same encoding) holds blocked domains that browsers are sent
// to the block page at "pageUrl" for, rather than failing the lookup. The
// server leaves them out of "compressed". Both are absent when no domain gets
// the block page.
func (o *Olm) handleDNSBlocklist(msg websocket.WSMessage) {
	if !o.tunnelRunning {
		logger.Debug("Tunnel is no longer running, ignoring DNS blocklist")
		return
	}

	var compressed, pageCompressed, pageURL string
	var logBlocks bool
	if m, ok := msg.Data.(map[string]interface{}); ok {
		compressed, _ = m["compressed"].(string)
		pageCompressed, _ = m["pageCompressed"].(string)
		pageURL, _ = m["pageUrl"].(string)
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
		pageBl, err := decodeDNSBlocklist(pageCompressed)
		if err != nil {
			logger.Error("Failed to decode DNS block page list: %v", err)
			return
		}

		o.blocklistMu.Lock()
		if o.blocklistSeq.Load() != seq {
			// A newer message arrived while this one was decoding.
			o.blocklistMu.Unlock()
			return
		}
		o.blocklist = bl
		o.pageBlocklist = pageBl
		o.pageURL = pageURL
		logChanged := o.blockLogEnabled != logBlocks
		o.blockLogEnabled = logBlocks
		proxy := o.dnsProxy
		o.blocklistMu.Unlock()

		if proxy != nil {
			proxy.SetBlocklist(bl)
			proxy.SetPageBlocklist(pageBl)
			if logChanged {
				o.applyBlockLogSender(proxy, logBlocks)
			}
			o.applyBlockPage(proxy)
		}
		logger.Info("DNS blocklist updated: %d domains, %d with block page", bl.Len(), pageBl.Len())
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
	o.apiServer.SetBlockPageProviders(o.blockPageStatus, o.blockPageCAPEM, o.recheckBlockPage)

	o.blocklistMu.Lock()
	bl := o.blocklist
	pageBl := o.pageBlocklist
	logBlocks := o.blockLogEnabled
	o.blocklistMu.Unlock()
	if bl != nil {
		proxy.SetBlocklist(bl)
	}
	if pageBl != nil {
		proxy.SetPageBlocklist(pageBl)
	}
	// May add the CA to the trust store, which can take a while. With no
	// page list yet it clears browser policies a previous run left behind.
	go o.applyBlockPage(proxy)
	o.applyBlockLogSender(proxy, logBlocks)
}

// applyBlockPage starts or stops the block page server on proxy to match the
// current page list. The server only runs while the system trusts this
// device's block page CA; otherwise the domains on the page list fail to
// resolve like any other blocked domain.
//
// Browser policies only carry the CA while a page list is in use; otherwise
// they are taken out again.
func (o *Olm) applyBlockPage(proxy *dns.DNSProxy) {
	o.blockPageMu.Lock()
	defer o.blockPageMu.Unlock()

	// Read under blockPageMu so that of several calls racing, the last one to
	// run sees the newest list.
	o.blocklistMu.Lock()
	pageBl := o.pageBlocklist
	pageURL := o.pageURL
	o.blocklistMu.Unlock()

	if proxy.Stopped() {
		return
	}
	if pageBl.Len() == 0 || pageURL == "" || o.olmConfig.DisableBlockPage {
		o.stopBlockPageLocked()
		o.releaseBrowsersLocked()
		return
	}

	if o.blockPage == nil {
		o.blockPage = blockpage.NewManager(o.blockPageDir())
		o.blockPage.SetHostInstallsTrust(o.olmConfig.BlockPageTrustByHost)
	}
	ca, err := o.blockPage.Prepare()
	if err != nil {
		// Logged once per distinct reason, not on every list update.
		if msg := err.Error(); msg != o.blockPageLastErr {
			o.blockPageLastErr = msg
			if errors.Is(err, blockpage.ErrDisabled) || errors.Is(err, blockpage.ErrAwaitingHostTrust) {
				// Expected where olm cannot add a trusted root itself
				// (mobile), or leaves that to the app (macOS).
				logger.Info("Block page is off, blocked sites fail to load instead: %v", err)
			} else {
				logger.Warn("Block page is off, blocked sites fail to load instead: %v", err)
			}
		}
		o.stopBlockPageLocked()
		return
	}
	o.blockPageLastErr = ""

	if o.blockPageServer != nil && o.blockPageProxy == proxy {
		proxy.SetBlockPageActive(true)
		return
	}
	o.stopBlockPageLocked()

	httpLn, err := proxy.ListenTCP(80)
	if err != nil {
		logger.Error("Failed to start block page server: %v", err)
		return
	}
	httpsLn, err := proxy.ListenTCP(443)
	if err != nil {
		_ = httpLn.Close()
		logger.Error("Failed to start block page server: %v", err)
		return
	}

	srv := blockpage.NewServer(ca, proxy.PageBlocked, o.currentPageURL)
	srv.Serve(httpLn, httpsLn)
	o.blockPageServer = srv
	o.blockPageProxy = proxy
	proxy.SetBlockPageActive(true)
	logger.Info("Block page server listening on %s", proxy.GetProxyIP())
}

// stopBlockPage stops the block page server, if it runs, and takes the CA out
// of browser policies. Called when the tunnel goes down.
func (o *Olm) stopBlockPage() {
	o.blockPageMu.Lock()
	defer o.blockPageMu.Unlock()
	o.stopBlockPageLocked()
	o.releaseBrowsersLocked()
}

func (o *Olm) blockPageDir() string {
	if o.olmConfig.BlockPageDir != "" {
		return o.olmConfig.BlockPageDir
	}
	return blockpage.DefaultDir()
}

// releaseBrowsersLocked takes the CA out of browser policies. Without a CA
// directory olm never wrote any (and, not being root, could not remove
// them), so there is nothing to do.
func (o *Olm) releaseBrowsersLocked() {
	if o.blockPageDir() == "" {
		return
	}
	if o.blockPage != nil {
		o.blockPage.ReleaseBrowsers()
	} else {
		blockpage.RemoveBrowserTrust()
	}
}

func (o *Olm) stopBlockPageLocked() {
	if o.blockPageProxy != nil {
		o.blockPageProxy.SetBlockPageActive(false)
	}
	if o.blockPageServer != nil {
		o.blockPageServer.Close()
		logger.Info("Block page server stopped")
	}
	o.blockPageServer = nil
	o.blockPageProxy = nil
}

func (o *Olm) currentPageURL() string {
	o.blocklistMu.Lock()
	defer o.blocklistMu.Unlock()
	return o.pageURL
}

// blockPageStatus reports the block page state for the local API, or nil
// while the server sends no domains that get the page.
func (o *Olm) blockPageStatus() *api.BlockPageStatus {
	o.blocklistMu.Lock()
	inUse := o.pageBlocklist.Len() > 0 && o.pageURL != ""
	o.blocklistMu.Unlock()
	if !inUse {
		return nil
	}

	// TryLock: status requests must not wait on a trust store install.
	if !o.blockPageMu.TryLock() {
		return &api.BlockPageStatus{Error: "checking the block page certificate"}
	}
	defer o.blockPageMu.Unlock()

	st := &api.BlockPageStatus{Active: o.blockPageServer != nil}
	if o.olmConfig.DisableBlockPage {
		st.Error = "block page disabled in the client configuration"
		return st
	}
	if o.blockPage != nil {
		ms := o.blockPage.Status()
		st.Trusted = ms.Trusted
		st.CAPath = ms.CAPath
		st.Error = ms.Error
		st.NeedsTrust = ms.NeedsTrust
	}
	return st
}

// recheckBlockPage checks the CA's trust again, for a host app that just
// added it to the trust store, and returns the new status (nil when the block
// page is not in use).
func (o *Olm) recheckBlockPage() *api.BlockPageStatus {
	o.blocklistMu.Lock()
	proxy := o.dnsProxy
	o.blocklistMu.Unlock()
	if proxy != nil {
		o.applyBlockPage(proxy)
	}
	return o.blockPageStatus()
}

func (o *Olm) blockPageCAPEM() []byte {
	o.blockPageMu.Lock()
	m := o.blockPage
	o.blockPageMu.Unlock()
	if m == nil {
		return nil
	}
	return m.CertPEM()
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
	o.pageBlocklist = nil
	o.pageURL = ""
	o.blockLogEnabled = false
	o.blocklistMu.Unlock()
}
