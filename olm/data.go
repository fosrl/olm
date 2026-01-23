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

	// Check if tunnel is still running
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring add-remote-subnets-aliases message")
		return
	}

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

	// Check if tunnel is still running
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring remove-remote-subnets-aliases message")
		return
	}

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

	// Check if tunnel is still running
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring update-remote-subnets-aliases message")
		return
	}

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

// Handler for syncing peer configuration - reconciles expected state with actual state
func (o *Olm) handleSync(msg websocket.WSMessage) {
	logger.Debug("Received sync message: %v", msg.Data)

	if !o.connected {
		logger.Warn("Not connected, ignoring sync request")
		return
	}

	if o.peerManager == nil {
		logger.Warn("Peer manager not initialized, ignoring sync request")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling sync data: %v", err)
		return
	}

	var syncData SyncData
	if err := json.Unmarshal(jsonData, &syncData); err != nil {
		logger.Error("Error unmarshaling sync data: %v", err)
		return
	}

	// Sync exit nodes for hole punching
	o.syncExitNodes(syncData.ExitNodes)

	// Build a map of expected peers from the incoming data
	expectedPeers := make(map[int]peers.SiteConfig)
	for _, site := range syncData.Sites {
		expectedPeers[site.SiteId] = site
	}

	// Get all current peers
	currentPeers := o.peerManager.GetAllPeers()
	currentPeerMap := make(map[int]peers.SiteConfig)
	for _, peer := range currentPeers {
		currentPeerMap[peer.SiteId] = peer
	}

	// Find peers to remove (in current but not in expected)
	for siteId := range currentPeerMap {
		if _, exists := expectedPeers[siteId]; !exists {
			logger.Info("Sync: Removing peer for site %d (no longer in expected config)", siteId)
			if err := o.peerManager.RemovePeer(siteId); err != nil {
				logger.Error("Sync: Failed to remove peer %d: %v", siteId, err)
			} else {
				// Remove any exit nodes associated with this peer from hole punching
				if o.holePunchManager != nil {
					removed := o.holePunchManager.RemoveExitNodesByPeer(siteId)
					if removed > 0 {
						logger.Info("Sync: Removed %d exit nodes associated with peer %d from hole punch rotation", removed, siteId)
					}
				}
			}
		}
	}

	// Find peers to add (in expected but not in current) and peers to update
	for siteId, expectedSite := range expectedPeers {
		if _, exists := currentPeerMap[siteId]; !exists {
			// New peer - add it using the add flow (with holepunch)
			logger.Info("Sync: Adding new peer for site %d", siteId)

			o.holePunchManager.TriggerHolePunch()

			// // TODO: do we need to send the message to the cloud to add the peer that way?
			// if err := o.peerManager.AddPeer(expectedSite); err != nil {
			// 	logger.Error("Sync: Failed to add peer %d: %v", siteId, err)
			// } else {
			// 	logger.Info("Sync: Successfully added peer for site %d", siteId)
			// }

			// add the peer via the server
			// this is important because newt needs to get triggered as well to add the peer once the hp is complete
			o.stopPeerSend, _ = o.websocket.SendMessageInterval("olm/wg/server/peer/add", map[string]interface{}{
				"siteId": expectedSite.SiteId,
			}, 1*time.Second, 10)

		} else {
			// Existing peer - check if update is needed
			currentSite := currentPeerMap[siteId]
			needsUpdate := false

			// Check if any fields have changed
			if expectedSite.Endpoint != "" && expectedSite.Endpoint != currentSite.Endpoint {
				needsUpdate = true
			}
			if expectedSite.RelayEndpoint != "" && expectedSite.RelayEndpoint != currentSite.RelayEndpoint {
				needsUpdate = true
			}
			if expectedSite.PublicKey != "" && expectedSite.PublicKey != currentSite.PublicKey {
				needsUpdate = true
			}
			if expectedSite.ServerIP != "" && expectedSite.ServerIP != currentSite.ServerIP {
				needsUpdate = true
			}
			if expectedSite.ServerPort != 0 && expectedSite.ServerPort != currentSite.ServerPort {
				needsUpdate = true
			}
			// Check remote subnets
			if expectedSite.RemoteSubnets != nil && !slicesEqual(expectedSite.RemoteSubnets, currentSite.RemoteSubnets) {
				needsUpdate = true
			}
			// Check aliases
			if expectedSite.Aliases != nil && !aliasesEqual(expectedSite.Aliases, currentSite.Aliases) {
				needsUpdate = true
			}

			if needsUpdate {
				logger.Info("Sync: Updating peer for site %d", siteId)

				// Merge expected data with current data
				siteConfig := currentSite
				if expectedSite.Endpoint != "" {
					siteConfig.Endpoint = expectedSite.Endpoint
				}
				if expectedSite.RelayEndpoint != "" {
					siteConfig.RelayEndpoint = expectedSite.RelayEndpoint
				}
				if expectedSite.PublicKey != "" {
					siteConfig.PublicKey = expectedSite.PublicKey
				}
				if expectedSite.ServerIP != "" {
					siteConfig.ServerIP = expectedSite.ServerIP
				}
				if expectedSite.ServerPort != 0 {
					siteConfig.ServerPort = expectedSite.ServerPort
				}
				if expectedSite.RemoteSubnets != nil {
					siteConfig.RemoteSubnets = expectedSite.RemoteSubnets
				}
				if expectedSite.Aliases != nil {
					siteConfig.Aliases = expectedSite.Aliases
				}

				if err := o.peerManager.UpdatePeer(siteConfig); err != nil {
					logger.Error("Sync: Failed to update peer %d: %v", siteId, err)
				} else {
					// If the endpoint changed, trigger holepunch to refresh NAT mappings
					if expectedSite.Endpoint != "" && expectedSite.Endpoint != currentSite.Endpoint {
						logger.Info("Sync: Endpoint changed for site %d, triggering holepunch to refresh NAT mappings", siteId)
						o.holePunchManager.TriggerHolePunch()
						o.holePunchManager.ResetServerHolepunchInterval()
					}
					logger.Info("Sync: Successfully updated peer for site %d", siteId)
				}
			}
		}
	}

	logger.Info("Sync completed: processed %d expected peers, had %d current peers", len(expectedPeers), len(currentPeers))
}

// syncExitNodes reconciles the expected exit nodes with the current ones in the hole punch manager
func (o *Olm) syncExitNodes(expectedExitNodes []SyncExitNode) {
	if o.holePunchManager == nil {
		logger.Warn("Hole punch manager not initialized, skipping exit node sync")
		return
	}

	// Build a map of expected exit nodes by endpoint
	expectedExitNodeMap := make(map[string]SyncExitNode)
	for _, exitNode := range expectedExitNodes {
		expectedExitNodeMap[exitNode.Endpoint] = exitNode
	}

	// Get current exit nodes from hole punch manager
	currentExitNodes := o.holePunchManager.GetExitNodes()
	currentExitNodeMap := make(map[string]holepunch.ExitNode)
	for _, exitNode := range currentExitNodes {
		currentExitNodeMap[exitNode.Endpoint] = exitNode
	}

	// Find exit nodes to remove (in current but not in expected)
	for endpoint := range currentExitNodeMap {
		if _, exists := expectedExitNodeMap[endpoint]; !exists {
			logger.Info("Sync: Removing exit node %s (no longer in expected config)", endpoint)
			o.holePunchManager.RemoveExitNode(endpoint)
		}
	}

	// Find exit nodes to add (in expected but not in current)
	for endpoint, expectedExitNode := range expectedExitNodeMap {
		if _, exists := currentExitNodeMap[endpoint]; !exists {
			logger.Info("Sync: Adding new exit node %s", endpoint)

			relayPort := expectedExitNode.RelayPort
			if relayPort == 0 {
				relayPort = 21820 // default relay port
			}

			hpExitNode := holepunch.ExitNode{
				Endpoint:  expectedExitNode.Endpoint,
				RelayPort: relayPort,
				PublicKey: expectedExitNode.PublicKey,
				SiteIds:   expectedExitNode.SiteIds,
			}

			if o.holePunchManager.AddExitNode(hpExitNode) {
				logger.Info("Sync: Successfully added exit node %s", endpoint)
			}
			o.holePunchManager.TriggerHolePunch()
		}
	}

	logger.Info("Sync exit nodes completed: processed %d expected exit nodes, had %d current exit nodes", len(expectedExitNodeMap), len(currentExitNodeMap))
}
