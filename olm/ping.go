package olm

import (
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/olm/websocket"
)

func sendPing(olm *websocket.Client) error {
	err := olm.SendMessage("olm/ping", map[string]any{
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

func (o *Olm) keepSendingPing(olm *websocket.Client) {
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
		case <-o.stopPing:
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
