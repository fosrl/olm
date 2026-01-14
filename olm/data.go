package olm

import (
	"encoding/json"
	"time"

	"github.com/fosrl/newt/holepunch"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/peers"
	"github.com/fosrl/olm/websocket"
)

func (o *Olm) handleWgPeerAddData(msg websocket.WSMessage) {
	logger.Debug("Received add-remote-subnets-aliases message: %v", msg.Data)

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var addSubnetsData peers.PeerAdd
	if err := json.Unmarshal(jsonData, &addSubnetsData); err != nil {
		logger.Error("Error unmarshaling add-remote-subnets data: %v", err)
		return
	}

	if _, exists := o.peerManager.GetPeer(addSubnetsData.SiteId); !exists {
		logger.Debug("Peer %d not found for removing remote subnets and aliases", addSubnetsData.SiteId)
		return
	}

	// Add new subnets
	for _, subnet := range addSubnetsData.RemoteSubnets {
		if err := o.peerManager.AddRemoteSubnet(addSubnetsData.SiteId, subnet); err != nil {
			logger.Error("Failed to add allowed IP %s: %v", subnet, err)
		}
	}

	// Add new aliases
	for _, alias := range addSubnetsData.Aliases {
		if err := o.peerManager.AddAlias(addSubnetsData.SiteId, alias); err != nil {
			logger.Error("Failed to add alias %s: %v", alias.Alias, err)
		}
	}
}

func (o *Olm) handleWgPeerRemoveData(msg websocket.WSMessage) {
	logger.Debug("Received remove-remote-subnets-aliases message: %v", msg.Data)

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var removeSubnetsData peers.RemovePeerData
	if err := json.Unmarshal(jsonData, &removeSubnetsData); err != nil {
		logger.Error("Error unmarshaling remove-remote-subnets data: %v", err)
		return
	}

	if _, exists := o.peerManager.GetPeer(removeSubnetsData.SiteId); !exists {
		logger.Debug("Peer %d not found for removing remote subnets and aliases", removeSubnetsData.SiteId)
		return
	}

	// Remove subnets
	for _, subnet := range removeSubnetsData.RemoteSubnets {
		if err := o.peerManager.RemoveRemoteSubnet(removeSubnetsData.SiteId, subnet); err != nil {
			logger.Error("Failed to remove allowed IP %s: %v", subnet, err)
		}
	}

	// Remove aliases
	for _, alias := range removeSubnetsData.Aliases {
		if err := o.peerManager.RemoveAlias(removeSubnetsData.SiteId, alias.Alias); err != nil {
			logger.Error("Failed to remove alias %s: %v", alias.Alias, err)
		}
	}
}

func (o *Olm) handleWgPeerUpdateData(msg websocket.WSMessage) {
	logger.Debug("Received update-remote-subnets-aliases message: %v", msg.Data)

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling data: %v", err)
		return
	}

	var updateSubnetsData peers.UpdatePeerData
	if err := json.Unmarshal(jsonData, &updateSubnetsData); err != nil {
		logger.Error("Error unmarshaling update-remote-subnets data: %v", err)
		return
	}

	if _, exists := o.peerManager.GetPeer(updateSubnetsData.SiteId); !exists {
		logger.Debug("Peer %d not found for updating remote subnets and aliases", updateSubnetsData.SiteId)
		return
	}

	// Add new subnets BEFORE removing old ones to preserve shared subnets
	// This ensures that if an old and new subnet are the same on different peers,
	// the route won't be temporarily removed
	for _, subnet := range updateSubnetsData.NewRemoteSubnets {
		if err := o.peerManager.AddRemoteSubnet(updateSubnetsData.SiteId, subnet); err != nil {
			logger.Error("Failed to add allowed IP %s: %v", subnet, err)
		}
	}

	// Remove old subnets after new ones are added
	for _, subnet := range updateSubnetsData.OldRemoteSubnets {
		if err := o.peerManager.RemoveRemoteSubnet(updateSubnetsData.SiteId, subnet); err != nil {
			logger.Error("Failed to remove allowed IP %s: %v", subnet, err)
		}
	}

	// Add new aliases BEFORE removing old ones to preserve shared IP addresses
	// This ensures that if an old and new alias share the same IP, the IP won't be
	// temporarily removed from the allowed IPs list
	for _, alias := range updateSubnetsData.NewAliases {
		if err := o.peerManager.AddAlias(updateSubnetsData.SiteId, alias); err != nil {
			logger.Error("Failed to add alias %s: %v", alias.Alias, err)
		}
	}

	// Remove old aliases after new ones are added
	for _, alias := range updateSubnetsData.OldAliases {
		if err := o.peerManager.RemoveAlias(updateSubnetsData.SiteId, alias.Alias); err != nil {
			logger.Error("Failed to remove alias %s: %v", alias.Alias, err)
		}
	}

	logger.Info("Successfully updated remote subnets and aliases for peer %d", updateSubnetsData.SiteId)
}

func (o *Olm) handleWgPeerHolepunchAddSite(msg websocket.WSMessage) {
	logger.Debug("Received peer-handshake message: %v", msg.Data)

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling handshake data: %v", err)
		return
	}

	var handshakeData struct {
		SiteId   int `json:"siteId"`
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

	o.holePunchManager.TriggerHolePunch() // Trigger immediate hole punch attempt
	o.holePunchManager.ResetInterval()    // start sending immediately again so we fill in the endpoint on the cloud

	// Send handshake acknowledgment back to server with retry
	o.stopPeerSend, _ = o.websocket.SendMessageInterval("olm/wg/server/peer/add", map[string]interface{}{
		"siteId": handshakeData.SiteId,
	}, 1*time.Second, 10)

	logger.Info("Initiated handshake for site %d with exit node %s", handshakeData.SiteId, handshakeData.ExitNode.Endpoint)
}
