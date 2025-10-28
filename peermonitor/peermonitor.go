package peermonitor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/websocket"
	"github.com/fosrl/olm/wgtester"
	"golang.zx2c4.com/wireguard/device"
)

// PeerMonitorCallback is the function type for connection status change callbacks
type PeerMonitorCallback func(siteID int, connected bool, rtt time.Duration)

// WireGuardConfig holds the WireGuard configuration for a peer
type WireGuardConfig struct {
	SiteID       int
	PublicKey    string
	ServerIP     string
	Endpoint     string
	PrimaryRelay string // The primary relay endpoint
}

// PeerMonitor handles monitoring the connection status to multiple WireGuard peers
type PeerMonitor struct {
	monitors          map[int]*wgtester.Client
	configs           map[int]*WireGuardConfig
	callback          PeerMonitorCallback
	mutex             sync.Mutex
	running           bool
	interval          time.Duration
	timeout           time.Duration
	maxAttempts       int
	privateKey        string
	wsClient          *websocket.Client
	device            *device.Device
	handleRelaySwitch bool // Whether to handle relay switching
}

// NewPeerMonitor creates a new peer monitor with the given callback
func NewPeerMonitor(callback PeerMonitorCallback, privateKey string, wsClient *websocket.Client, device *device.Device, handleRelaySwitch bool) *PeerMonitor {
	return &PeerMonitor{
		monitors:          make(map[int]*wgtester.Client),
		configs:           make(map[int]*WireGuardConfig),
		callback:          callback,
		interval:          1 * time.Second, // Default check interval
		timeout:           2500 * time.Millisecond,
		maxAttempts:       8,
		privateKey:        privateKey,
		wsClient:          wsClient,
		device:            device,
		handleRelaySwitch: handleRelaySwitch,
	}
}

// SetInterval changes how frequently peers are checked
func (pm *PeerMonitor) SetInterval(interval time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.interval = interval

	// Update interval for all existing monitors
	for _, client := range pm.monitors {
		client.SetPacketInterval(interval)
	}
}

// SetTimeout changes the timeout for waiting for responses
func (pm *PeerMonitor) SetTimeout(timeout time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.timeout = timeout

	// Update timeout for all existing monitors
	for _, client := range pm.monitors {
		client.SetTimeout(timeout)
	}
}

// SetMaxAttempts changes the maximum number of attempts for TestConnection
func (pm *PeerMonitor) SetMaxAttempts(attempts int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.maxAttempts = attempts

	// Update max attempts for all existing monitors
	for _, client := range pm.monitors {
		client.SetMaxAttempts(attempts)
	}
}

// AddPeer adds a new peer to monitor
func (pm *PeerMonitor) AddPeer(siteID int, endpoint string, wgConfig *WireGuardConfig) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Check if we're already monitoring this peer
	if _, exists := pm.monitors[siteID]; exists {
		// Update the endpoint instead of creating a new monitor
		pm.removePeerUnlocked(siteID)
	}

	client, err := wgtester.NewClient(endpoint)
	if err != nil {
		return err
	}

	// Configure the client with our settings
	client.SetPacketInterval(pm.interval)
	client.SetTimeout(pm.timeout)
	client.SetMaxAttempts(pm.maxAttempts)

	// Store the client and config
	pm.monitors[siteID] = client
	pm.configs[siteID] = wgConfig

	// If monitor is already running, start monitoring this peer
	if pm.running {
		siteIDCopy := siteID // Create a copy for the closure
		err = client.StartMonitor(func(status wgtester.ConnectionStatus) {
			pm.handleConnectionStatusChange(siteIDCopy, status)
		})
	}

	return err
}

// removePeerUnlocked stops monitoring a peer and removes it from the monitor
// This function assumes the mutex is already held by the caller
func (pm *PeerMonitor) removePeerUnlocked(siteID int) {
	client, exists := pm.monitors[siteID]
	if !exists {
		return
	}

	client.StopMonitor()
	client.Close()
	delete(pm.monitors, siteID)
	delete(pm.configs, siteID)
}

// RemovePeer stops monitoring a peer and removes it from the monitor
func (pm *PeerMonitor) RemovePeer(siteID int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.removePeerUnlocked(siteID)
}

// Start begins monitoring all peers
func (pm *PeerMonitor) Start() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if pm.running {
		return // Already running
	}

	pm.running = true

	// Start monitoring all peers
	for siteID, client := range pm.monitors {
		siteIDCopy := siteID // Create a copy for the closure
		err := client.StartMonitor(func(status wgtester.ConnectionStatus) {
			pm.handleConnectionStatusChange(siteIDCopy, status)
		})
		if err != nil {
			logger.Error("Failed to start monitoring peer %d: %v\n", siteID, err)
			continue
		}
		logger.Info("Started monitoring peer %d\n", siteID)
	}
}

// handleConnectionStatusChange is called when a peer's connection status changes
func (pm *PeerMonitor) handleConnectionStatusChange(siteID int, status wgtester.ConnectionStatus) {
	// Call the user-provided callback first
	if pm.callback != nil {
		pm.callback(siteID, status.Connected, status.RTT)
	}

	// If disconnected, handle failover
	if !status.Connected {
		// Send relay message to the server
		if pm.wsClient != nil {
			pm.sendRelay(siteID)
		}
	}
}

// handleFailover handles failover to the relay server when a peer is disconnected
func (pm *PeerMonitor) HandleFailover(siteID int, relayEndpoint string) {
	pm.mutex.Lock()
	config, exists := pm.configs[siteID]
	pm.mutex.Unlock()

	if !exists {
		return
	}

	// Check for IPv6 and format the endpoint correctly
	formattedEndpoint := relayEndpoint
	if strings.Contains(relayEndpoint, ":") {
		formattedEndpoint = fmt.Sprintf("[%s]", relayEndpoint)
	}

	// Configure WireGuard to use the relay
	wgConfig := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s:21820
persistent_keepalive_interval=1`, pm.privateKey, config.PublicKey, config.ServerIP, formattedEndpoint)

	err := pm.device.IpcSet(wgConfig)
	if err != nil {
		logger.Error("Failed to configure WireGuard device: %v\n", err)
		return
	}

	logger.Info("Adjusted peer %d to point to relay!\n", siteID)
}

// sendRelay sends a relay message to the server
func (pm *PeerMonitor) sendRelay(siteID int) error {
	if !pm.handleRelaySwitch {
		return nil
	}

	if pm.wsClient == nil {
		return fmt.Errorf("websocket client is nil")
	}

	err := pm.wsClient.SendMessage("olm/wg/relay", map[string]interface{}{
		"siteId": siteID,
	})
	if err != nil {
		logger.Error("Failed to send registration message: %v", err)
		return err
	}
	logger.Info("Sent relay message")
	return nil
}

// Stop stops monitoring all peers
func (pm *PeerMonitor) Stop() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.running {
		return
	}

	pm.running = false

	// Stop all monitors
	for _, client := range pm.monitors {
		client.StopMonitor()
	}
}

// Close stops monitoring and cleans up resources
func (pm *PeerMonitor) Close() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Stop and close all clients
	for siteID, client := range pm.monitors {
		client.StopMonitor()
		client.Close()
		delete(pm.monitors, siteID)
	}

	pm.running = false
}

// TestPeer tests connectivity to a specific peer
func (pm *PeerMonitor) TestPeer(siteID int) (bool, time.Duration, error) {
	pm.mutex.Lock()
	client, exists := pm.monitors[siteID]
	pm.mutex.Unlock()

	if !exists {
		return false, 0, fmt.Errorf("peer with siteID %d not found", siteID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), pm.timeout*time.Duration(pm.maxAttempts))
	defer cancel()

	connected, rtt := client.TestConnection(ctx)
	return connected, rtt, nil
}

// TestAllPeers tests connectivity to all peers
func (pm *PeerMonitor) TestAllPeers() map[int]struct {
	Connected bool
	RTT       time.Duration
} {
	pm.mutex.Lock()
	peers := make(map[int]*wgtester.Client, len(pm.monitors))
	for siteID, client := range pm.monitors {
		peers[siteID] = client
	}
	pm.mutex.Unlock()

	results := make(map[int]struct {
		Connected bool
		RTT       time.Duration
	})
	for siteID, client := range peers {
		ctx, cancel := context.WithTimeout(context.Background(), pm.timeout*time.Duration(pm.maxAttempts))
		connected, rtt := client.TestConnection(ctx)
		cancel()

		results[siteID] = struct {
			Connected bool
			RTT       time.Duration
		}{
			Connected: connected,
			RTT:       rtt,
		}
	}

	return results
}
