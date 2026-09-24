package olm

import (
	"fmt"
	"net/url"

	"github.com/fosrl/newt/logger"
)

// SelectGateway designates siteIds as the gateway (full-tunnel/default-route)
// candidate set. Requires the tunnel to already be registered/connected;
// rejects otherwise. Every site ID must already be a tracked peer, or the
// call is rejected outright by the peer manager.
func (o *Olm) SelectGateway(siteIds []int) error {
	if !o.registered {
		return fmt.Errorf("cannot select gateway: not registered/connected")
	}
	return o.applySelectGateway(siteIds)
}

// DisableGateway fully clears gateway state. Requires the tunnel to already
// be registered/connected; rejects otherwise.
func (o *Olm) DisableGateway() error {
	if !o.registered {
		return fmt.Errorf("cannot disable gateway: not registered/connected")
	}
	pm := o.getPeerManager()
	if pm == nil {
		return fmt.Errorf("cannot disable gateway: tunnel not running")
	}
	if err := pm.ClearGateway(); err != nil {
		return err
	}
	o.apiServer.SetGatewayStatus(false, nil)
	return nil
}

// applySelectGateway resolves the control-plane endpoint host and delegates
// to the peer manager. Shared by SelectGateway (API-invoked, already
// registered-checked by the caller) and applyPendingGatewayConfig
// (StartTunnel-time, called after registration completes).
func (o *Olm) applySelectGateway(siteIds []int) error {
	pm := o.getPeerManager()
	if pm == nil {
		return fmt.Errorf("cannot select gateway: tunnel not running")
	}
	if err := pm.SetGateway(siteIds, extractControlEndpointHost(o.tunnelConfig.Endpoint)); err != nil {
		return err
	}
	o.apiServer.SetGatewayStatus(true, siteIds)
	return nil
}

// applyPendingGatewayConfig applies TunnelConfig.GatewaySiteIds once sites
// are tracked peers (called from handleConnect after o.registered is set
// true). IDs that never showed up as tracked peers are logged and dropped;
// if none show up at all, gateway is not established and this is logged
// clearly, without failing tunnel startup.
func (o *Olm) applyPendingGatewayConfig(requestedSiteIds []int) {
	pm := o.getPeerManager()
	if pm == nil {
		return
	}

	var tracked []int
	for _, id := range requestedSiteIds {
		if _, ok := pm.GetPeer(id); ok {
			tracked = append(tracked, id)
		} else {
			logger.Warn("Gateway site %d requested at connect time was not found among tracked peers; skipping", id)
		}
	}

	if len(tracked) == 0 {
		logger.Warn("None of the requested gateway site IDs were found among tracked peers; gateway not established")
		return
	}

	if err := o.applySelectGateway(tracked); err != nil {
		logger.Error("Failed to establish gateway from StartTunnel config: %v", err)
	}
}

// flushPendingHolepunchBypassEndpoints re-registers every currently-known
// hole-punch bypass endpoint (see the OnTokenUpdate handler in olm.go) with
// the peer manager. OnTokenUpdate typically fires before the peer manager
// exists - it runs during the initial token/auth fetch in
// websocket.Client.establishConnection, well before the server's
// "olm/wg/connect" message creates the peer manager here in handleConnect -
// so anything recorded into o.hpBypassEndpoints while pm was nil needs to be
// pushed in once it becomes available. AddGatewayBypassEndpoint is
// idempotent, so calling it again for an endpoint OnTokenUpdate already
// managed to register directly (e.g. a later token refresh, once the peer
// manager already existed) is harmless.
func (o *Olm) flushPendingHolepunchBypassEndpoints() {
	pm := o.getPeerManager()
	if pm == nil {
		return
	}

	o.hpBypassMu.Lock()
	defer o.hpBypassMu.Unlock()
	for hostport := range o.hpBypassEndpoints {
		pm.AddGatewayBypassEndpoint(hostport)
	}
}

// extractControlEndpointHost returns the bare host (no scheme/port) of the
// Pangolin server olm is registered against, for gateway bypass-route
// purposes. Falls back to the raw endpoint string on parse failure -
// resolveEndpointIPLocked/net.SplitHostPort tolerate a bare host - rather
// than failing the whole gateway activation over a cosmetic parse issue.
func extractControlEndpointHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return endpoint
	}
	return u.Hostname()
}
