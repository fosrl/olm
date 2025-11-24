package olm

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/network"
	"github.com/fosrl/olm/websocket"
)

// Helper function to format endpoints correctly
func formatEndpoint(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	// Check if it's already a valid host:port that SplitHostPort can parse (e.g., [::1]:8080 or 1.2.3.4:8080)
	_, _, err := net.SplitHostPort(endpoint)
	if err == nil {
		return endpoint // Already valid, no change needed
	}

	// If it failed, it might be our malformed "ipv6:port" string. Let's check and fix it.
	lastColon := strings.LastIndex(endpoint, ":")
	if lastColon > 0 { // Ensure there is a colon and it's not the first character
		hostPart := endpoint[:lastColon]
		// Check if the host part is a literal IPv6 address
		if ip := net.ParseIP(hostPart); ip != nil && ip.To4() == nil {
			// It is! Reformat it with brackets.
			portPart := endpoint[lastColon+1:]
			return fmt.Sprintf("[%s]:%s", hostPart, portPart)
		}
	}

	// If it's not the specific malformed case, return it as is.
	return endpoint
}

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

// stringSlicesEqual compares two string slices for equality
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
