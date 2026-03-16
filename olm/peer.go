package olm

import (
	"encoding/json"
	"time"

	"github.com/fosrl/newt/holepunch"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/peers"
	"github.com/fosrl/olm/websocket"
)

func (o *Olm) handleWgPeerAdd(msg websocket.WSMessage) {
	logger.Debug("Received add-peer message: %v", msg.Data)

	// Check if tunnel is still running
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring add-peer message")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var siteConfigMsg struct {
		peers.SiteConfig
		ChainId string `json:"chainId"`
	}
	if err := json.Unmarshal(jsonData, &siteConfigMsg); err != nil {
		logger.Error("Error unmarshaling add data: %v", err)
		return
	}

	if siteConfigMsg.ChainId != "" {
		o.peerSendMu.Lock()
		if stop, ok := o.stopPeerSends[siteConfigMsg.ChainId]; ok {
			stop()
			delete(o.stopPeerSends, siteConfigMsg.ChainId)
		}
		o.peerSendMu.Unlock()
	} else {
		// stop all of the stopPeerSends
		o.peerSendMu.Lock()
		for _, stop := range o.stopPeerSends {
			stop()
		}
		o.stopPeerSends = make(map[string]func())
		o.peerSendMu.Unlock()
	}

	if siteConfigMsg.PublicKey == "" {
		logger.Warn("Skipping add-peer for site %d (%s): no public key available (site may not be connected)", siteConfigMsg.SiteId, siteConfigMsg.Name)
		return
	}

	_ = o.holePunchManager.TriggerHolePunch() // Trigger immediate hole punch attempt so that if the peer decides to relay we have already punched close to when we need it

	if err := o.peerManager.AddPeer(siteConfigMsg.SiteConfig); err != nil {
		logger.Error("Failed to add peer: %v", err)
		return
	}

	logger.Info("Successfully added peer for site %d", siteConfigMsg.SiteId)
}

func (o *Olm) handleWgPeerRemove(msg websocket.WSMessage) {
	logger.Debug("Received remove-peer message: %v", msg.Data)

	// Check if tunnel is still running
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring remove-peer message")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var removeData peers.PeerRemove
	if err := json.Unmarshal(jsonData, &removeData); err != nil {
		logger.Error("Error unmarshaling remove data: %v", err)
		return
	}

	if err := o.peerManager.RemovePeer(removeData.SiteId); err != nil {
		logger.Error("Failed to remove peer: %v", err)
		return
	}

	// Remove any exit nodes associated with this peer from hole punching
	if o.holePunchManager != nil {
		removed := o.holePunchManager.RemoveExitNodesByPeer(removeData.SiteId)
		if removed > 0 {
			logger.Info("Removed %d exit nodes associated with peer %d from hole punch rotation", removed, removeData.SiteId)
		}
	}

	logger.Info("Successfully removed peer for site %d", removeData.SiteId)
}

func (o *Olm) handleWgPeerUpdate(msg websocket.WSMessage) {
	logger.Debug("Received update-peer message: %v", msg.Data)

	// Check if tunnel is still running
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring update-peer message")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var updateData peers.SiteConfig
	if err := json.Unmarshal(jsonData, &updateData); err != nil {
		logger.Error("Error unmarshaling update data: %v", err)
		return
	}

	// Get existing peer from PeerManager
	existingPeer, exists := o.peerManager.GetPeer(updateData.SiteId)
	if !exists {
		logger.Warn("Peer with site ID %d not found", updateData.SiteId)
		return
	}

	// Create updated site config by merging with existing data
	siteConfig := existingPeer

	if updateData.Endpoint != "" {
		siteConfig.Endpoint = updateData.Endpoint
	}
	if updateData.RelayEndpoint != "" {
		siteConfig.RelayEndpoint = updateData.RelayEndpoint
	}
	if updateData.PublicKey != "" {
		siteConfig.PublicKey = updateData.PublicKey
	}
	if updateData.ServerIP != "" {
		siteConfig.ServerIP = updateData.ServerIP
	}
	if updateData.ServerPort != 0 {
		siteConfig.ServerPort = updateData.ServerPort
	}
	if updateData.RemoteSubnets != nil {
		siteConfig.RemoteSubnets = updateData.RemoteSubnets
	}

	if err := o.peerManager.UpdatePeer(siteConfig); err != nil {
		logger.Error("Failed to update peer: %v", err)
		return
	}

	// If the endpoint changed, trigger holepunch to refresh NAT mappings
	if updateData.Endpoint != "" && updateData.Endpoint != existingPeer.Endpoint {
		logger.Info("Endpoint changed for site %d, triggering holepunch to refresh NAT mappings", updateData.SiteId)
		_ = o.holePunchManager.TriggerHolePunch()
		o.holePunchManager.ResetServerHolepunchInterval()
	}

	logger.Info("Successfully updated peer for site %d", updateData.SiteId)
}

func (o *Olm) handleWgPeerRelay(msg websocket.WSMessage) {
	logger.Debug("Received relay-peer message: %v", msg.Data)

	// Check if peerManager is still valid (may be nil during shutdown)
	if o.peerManager == nil {
		logger.Debug("Ignoring relay message: peerManager is nil (shutdown in progress)")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var relayData struct {
		peers.RelayPeerData
		ChainId string `json:"chainId"`
	}
	if err := json.Unmarshal(jsonData, &relayData); err != nil {
		logger.Error("Error unmarshaling relay data: %v", err)
		return
	}

	if monitor := o.peerManager.GetPeerMonitor(); monitor != nil {
		monitor.CancelRelaySend(relayData.ChainId)
	}

	primaryRelay, err := util.ResolveDomainUpstream(relayData.RelayEndpoint, o.tunnelConfig.PublicDNS)

	if err != nil {
		logger.Error("Failed to resolve primary relay endpoint: %v", err)
		return
	}

	// Update HTTP server to mark this peer as using relay
	o.apiServer.UpdatePeerRelayStatus(relayData.SiteId, relayData.RelayEndpoint, true)

	o.peerManager.RelayPeer(relayData.SiteId, primaryRelay, relayData.RelayPort)
}

func (o *Olm) handleWgPeerUnrelay(msg websocket.WSMessage) {
	logger.Debug("Received unrelay-peer message: %v", msg.Data)

	// Check if peerManager is still valid (may be nil during shutdown)
	if o.peerManager == nil {
		logger.Debug("Ignoring unrelay message: peerManager is nil (shutdown in progress)")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var relayData struct {
		peers.UnRelayPeerData
		ChainId string `json:"chainId"`
	}
	if err := json.Unmarshal(jsonData, &relayData); err != nil {
		logger.Error("Error unmarshaling relay data: %v", err)
		return
	}

	if monitor := o.peerManager.GetPeerMonitor(); monitor != nil {
		monitor.CancelRelaySend(relayData.ChainId)
	}

	primaryRelay, err := util.ResolveDomainUpstream(relayData.Endpoint, o.tunnelConfig.PublicDNS)

	if err != nil {
		logger.Warn("Failed to resolve primary relay endpoint: %v", err)
	}

	// Update HTTP server to mark this peer as using relay
	o.apiServer.UpdatePeerRelayStatus(relayData.SiteId, relayData.Endpoint, false)

	o.peerManager.UnRelayPeer(relayData.SiteId, primaryRelay)
}

func (o *Olm) handleWgPeerHolepunchAddSite(msg websocket.WSMessage) {
	logger.Debug("Received peer-handshake message: %v", msg.Data)

	// Check if tunnel is still running
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring peer-handshake message")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling handshake data: %v", err)
		return
	}

	var handshakeData struct {
		SiteId   int    `json:"siteId"`
		ChainId  string `json:"chainId"`
		ExitNode struct {
			PublicKey string `json:"publicKey"`
			Endpoint  string `json:"endpoint"`
			RelayPort uint16 `json:"relayPort"`
		} `json:"exitNode"`
	}

	if err := json.Unmarshal(jsonData, &handshakeData); err != nil {
		logger.Error("Error unmarshaling handshake data: %v", err)
		return
	}

	// Stop the peer init sender for this chain, if any
	if handshakeData.ChainId != "" {
		o.peerSendMu.Lock()
		if stop, ok := o.stopPeerInits[handshakeData.ChainId]; ok {
			stop()
			delete(o.stopPeerInits, handshakeData.ChainId)
		}
		// If this chain was initiated by a DNS-triggered JIT request, clear the
		// pending entry so the site can be re-triggered if needed in the future.
		delete(o.jitPendingSites, handshakeData.SiteId)
		o.peerSendMu.Unlock()
	} else {
		// Stop all of the stopPeerInits
		o.peerSendMu.Lock()
		for _, stop := range o.stopPeerInits {
			stop()
		}
		o.stopPeerInits = make(map[string]func())
		o.peerSendMu.Unlock()
	}

	// Get existing peer from PeerManager
	_, exists := o.peerManager.GetPeer(handshakeData.SiteId)
	if exists {
		logger.Warn("Peer with site ID %d already added", handshakeData.SiteId)
		return
	}

	relayPort := handshakeData.ExitNode.RelayPort
	if relayPort == 0 {
		relayPort = 21820 // default relay port
	}

	siteId := handshakeData.SiteId
	exitNode := holepunch.ExitNode{
		Endpoint:  handshakeData.ExitNode.Endpoint,
		RelayPort: relayPort,
		PublicKey: handshakeData.ExitNode.PublicKey,
		SiteIds:   []int{siteId},
	}

	added := o.holePunchManager.AddExitNode(exitNode)
	if added {
		logger.Info("Added exit node %s to holepunch rotation for handshake", exitNode.Endpoint)
	} else {
		logger.Debug("Exit node %s already in holepunch rotation", exitNode.Endpoint)
	}

	o.holePunchManager.TriggerHolePunch()             // Trigger immediate hole punch attempt
	o.holePunchManager.ResetServerHolepunchInterval() // start sending immediately again so we fill in the endpoint on the cloud

	// Send handshake acknowledgment back to server with retry, keyed by chainId
	chainId := handshakeData.ChainId
	if chainId == "" {
		chainId = generateChainId()
	}
	o.peerSendMu.Lock()
	stopFunc, _ := o.websocket.SendMessageInterval("olm/wg/server/peer/add", map[string]interface{}{
		"siteId":  handshakeData.SiteId,
		"chainId": chainId,
	}, 2*time.Second, 10)
	o.stopPeerSends[chainId] = stopFunc
	o.peerSendMu.Unlock()

	logger.Info("Initiated handshake for site %d with exit node %s", handshakeData.SiteId, handshakeData.ExitNode.Endpoint)
}

func (o *Olm) handleCancelChain(msg websocket.WSMessage) {
	logger.Debug("Received cancel-chain message: %v", msg.Data)

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling cancel-chain data: %v", err)
		return
	}

	var cancelData struct {
		ChainId string `json:"chainId"`
	}
	if err := json.Unmarshal(jsonData, &cancelData); err != nil {
		logger.Error("Error unmarshaling cancel-chain data: %v", err)
		return
	}

	if cancelData.ChainId == "" {
		logger.Warn("Received cancel-chain message with no chainId")
		return
	}

	o.peerSendMu.Lock()
	defer o.peerSendMu.Unlock()

	found := false

	if stop, ok := o.stopPeerInits[cancelData.ChainId]; ok {
		stop()
		delete(o.stopPeerInits, cancelData.ChainId)
		found = true
	}
	// If this chain was a DNS-triggered JIT request, clear the pending entry so
	// the site can be re-triggered on the next DNS lookup.
	for siteId, chainId := range o.jitPendingSites {
		if chainId == cancelData.ChainId {
			delete(o.jitPendingSites, siteId)
			break
		}
	}

	if stop, ok := o.stopPeerSends[cancelData.ChainId]; ok {
		stop()
		delete(o.stopPeerSends, cancelData.ChainId)
		found = true
	}

	if found {
		logger.Info("Cancelled chain %s", cancelData.ChainId)
	} else {
		logger.Warn("Cancel-chain: no active sender found for chain %s", cancelData.ChainId)
	}
}
