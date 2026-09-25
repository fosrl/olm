package olm

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/peers"
	"github.com/fosrl/olm/websocket"
)

// GatewaySitesUpdateData is the payload of the server's
// "olm/wg/gateway/sites/update" message: sites that were added to / removed
// from the gateway site resource SiteResourceId.
type GatewaySitesUpdateData struct {
	SiteResourceId int   `json:"siteResourceId"`
	AddedSiteIds   []int `json:"addedSiteIds"`
	RemovedSiteIds []int `json:"removedSiteIds"`
}

// GatewayDisableData is the payload of the server's "olm/wg/gateway/disable"
// message: the gateway site resource SiteResourceId can no longer be used as
// the gateway (deleted, disabled, or this client lost access to it).
type GatewayDisableData struct {
	SiteResourceId int `json:"siteResourceId"`
}

// SelectGateway designates siteIds as the gateway (full-tunnel/default-route)
// candidate set, selected from the gateway site resource siteResourceId.
// Requires the tunnel to already be registered/connected; rejects otherwise.
// Every site ID must already be a tracked peer, or the call is rejected
// outright by the peer manager.
func (o *Olm) SelectGateway(siteResourceId int, siteIds []int) error {
	if !o.registered {
		return fmt.Errorf("cannot select gateway: not registered/connected")
	}
	return o.applySelectGateway(siteResourceId, siteIds)
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
	o.apiServer.SetGatewayStatus(false, 0, nil)
	return nil
}

// applySelectGateway resolves the control-plane endpoint host and delegates
// to the peer manager. Shared by SelectGateway (API-invoked, already
// registered-checked by the caller) and applyPendingGatewayConfig
// (StartTunnel-time, called after registration completes).
func (o *Olm) applySelectGateway(siteResourceId int, siteIds []int) error {
	pm := o.getPeerManager()
	if pm == nil {
		return fmt.Errorf("cannot select gateway: tunnel not running")
	}
	if err := pm.SetGateway(siteResourceId, siteIds, extractControlEndpointHost(o.tunnelConfig.Endpoint)); err != nil {
		return err
	}
	o.apiServer.SetGatewayStatus(true, siteResourceId, siteIds)
	return nil
}

// refreshGatewayStatus re-publishes the peer manager's current gateway state
// to the status endpoint after a server-pushed change.
func (o *Olm) refreshGatewayStatus(pm *peers.PeerManager) {
	active, siteResourceId, siteIds := pm.GetGatewayState()
	if !active {
		o.apiServer.SetGatewayStatus(false, 0, nil)
		return
	}
	o.apiServer.SetGatewayStatus(true, siteResourceId, siteIds)
}

// handleGatewaySitesUpdate handles the server's "olm/wg/gateway/sites/update"
// message, sent when sites are added to or removed from a gateway site
// resource (via the API or a blueprint). The message is ignored unless it is
// for the same site resource the current gateway was selected from - a site
// added to some other gateway resource must not join our candidate set.
func (o *Olm) handleGatewaySitesUpdate(msg websocket.WSMessage) {
	logger.Debug("Received gateway sites update message: %v", msg.Data)

	if !o.tunnelRunning || !o.registered {
		logger.Debug("Tunnel not running/registered, ignoring gateway sites update message")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var data GatewaySitesUpdateData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		logger.Error("Error unmarshaling gateway sites update data: %v", err)
		return
	}

	pm := o.getPeerManager()
	if pm == nil {
		logger.Debug("Ignoring gateway sites update message: peerManager is nil (shutdown in progress)")
		return
	}

	matched, _, _ := pm.UpdateGatewaySites(data.SiteResourceId, data.AddedSiteIds, data.RemovedSiteIds)
	if !matched {
		logger.Debug("Ignoring gateway sites update for site resource %d: not the active gateway resource", data.SiteResourceId)
		return
	}
	o.refreshGatewayStatus(pm)
}

// handleGatewayDisable handles the server's "olm/wg/gateway/disable" message,
// sent when the gateway site resource is deleted, disabled, changed to a
// different mode, or this client loses access to it. Ignored unless it is for
// the site resource the current gateway was selected from.
func (o *Olm) handleGatewayDisable(msg websocket.WSMessage) {
	logger.Debug("Received gateway disable message: %v", msg.Data)

	if !o.tunnelRunning || !o.registered {
		logger.Debug("Tunnel not running/registered, ignoring gateway disable message")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var data GatewayDisableData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		logger.Error("Error unmarshaling gateway disable data: %v", err)
		return
	}

	pm := o.getPeerManager()
	if pm == nil {
		logger.Debug("Ignoring gateway disable message: peerManager is nil (shutdown in progress)")
		return
	}

	if !pm.ClearGatewayForResource(data.SiteResourceId) {
		logger.Debug("Ignoring gateway disable for site resource %d: not the active gateway resource", data.SiteResourceId)
		return
	}
	logger.Info("Gateway disabled: site resource %d is no longer available", data.SiteResourceId)
	o.refreshGatewayStatus(pm)
}

// applyPendingGatewayConfig applies TunnelConfig.GatewaySiteIds (selected from
// the gateway site resource siteResourceId) once sites
// are tracked peers (called from handleConnect after o.registered is set
// true). IDs that never showed up as tracked peers are logged and dropped;
// if none show up at all, gateway is not established and this is logged
// clearly, without failing tunnel startup.
func (o *Olm) applyPendingGatewayConfig(siteResourceId int, requestedSiteIds []int) {
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

	if err := o.applySelectGateway(siteResourceId, tracked); err != nil {
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
