package olm

import (
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/olm/peers"
	"github.com/fosrl/olm/websocket"
)

func sendPing(olm *websocket.Client) error {
	err := olm.SendMessage("olm/ping", map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"userToken": olm.GetConfig().UserToken,
	})
	if err != nil {
		logger.Error("Failed to send ping message: %v", err)
		return err
	}
	logger.Debug("Sent ping message")
	return nil
}

func keepSendingPing(olm *websocket.Client) {
	// Send ping immediately on startup
	if err := sendPing(olm); err != nil {
		logger.Error("Failed to send initial ping: %v", err)
	} else {
		logger.Info("Sent initial ping message")
	}

	// Set up ticker for one minute intervals
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stopPing:
			logger.Info("Stopping ping messages")
			return
		case <-ticker.C:
			if err := sendPing(olm); err != nil {
				logger.Error("Failed to send periodic ping: %v", err)
			}
		}
	}
}

func GetNetworkSettingsJSON() (string, error) {
	return network.GetJSON()
}

func GetNetworkSettingsIncrementor() int {
	return network.GetIncrementor()
}

// slicesEqual compares two string slices for equality (order-independent)
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	// Create a map to count occurrences in slice a
	counts := make(map[string]int)
	for _, v := range a {
		counts[v]++
	}
	// Check if slice b has the same elements
	for _, v := range b {
		counts[v]--
		if counts[v] < 0 {
			return false
		}
	}
	return true
}

// aliasesEqual compares two Alias slices for equality (order-independent)
func aliasesEqual(a, b []peers.Alias) bool {
	if len(a) != len(b) {
		return false
	}
	// Create a map to count occurrences in slice a (using alias+address as key)
	counts := make(map[string]int)
	for _, v := range a {
		key := v.Alias + "|" + v.AliasAddress
		counts[key]++
	}
	// Check if slice b has the same elements
	for _, v := range b {
		key := v.Alias + "|" + v.AliasAddress
		counts[key]--
		if counts[key] < 0 {
			return false
		}
	}
	return true
}
