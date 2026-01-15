package olm

import (
	"encoding/json"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/peers"
	"github.com/fosrl/olm/websocket"
)

func (o *Olm) handleWgPeerAdd(msg websocket.WSMessage) {
	logger.Debug("Received add-peer message: %v", msg.Data)

	if o.stopPeerSend != nil {
		o.stopPeerSend()
		o.stopPeerSend = nil
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var siteConfig peers.SiteConfig
	if err := json.Unmarshal(jsonData, &siteConfig); err != nil {
		logger.Error("Error unmarshaling add data: %v", err)
		return
	}

	_ = o.holePunchManager.TriggerHolePunch() // Trigger immediate hole punch attempt so that if the peer decides to relay we have already punched close to when we need it

	if err := o.peerManager.AddPeer(siteConfig); err != nil {
		logger.Error("Failed to add peer: %v", err)
		return
	}

	logger.Info("Successfully added peer for site %d", siteConfig.SiteId)
}

func (o *Olm) handleWgPeerRemove(msg websocket.WSMessage) {
	logger.Debug("Received remove-peer message: %v", msg.Data)

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

	var relayData peers.RelayPeerData
	if err := json.Unmarshal(jsonData, &relayData); err != nil {
		logger.Error("Error unmarshaling relay data: %v", err)
		return
	}

	primaryRelay, err := util.ResolveDomain(relayData.RelayEndpoint)
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

	var relayData peers.UnRelayPeerData
	if err := json.Unmarshal(jsonData, &relayData); err != nil {
		logger.Error("Error unmarshaling relay data: %v", err)
		return
	}

	primaryRelay, err := util.ResolveDomain(relayData.Endpoint)
	if err != nil {
		logger.Warn("Failed to resolve primary relay endpoint: %v", err)
	}

	// Update HTTP server to mark this peer as using relay
	o.apiServer.UpdatePeerRelayStatus(relayData.SiteId, relayData.Endpoint, false)

	o.peerManager.UnRelayPeer(relayData.SiteId, primaryRelay)
}
