package olm

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/updates"
	"github.com/fosrl/olm/api"
	"github.com/fosrl/olm/peermonitor"
	"github.com/fosrl/olm/websocket"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	// Connection settings
	Endpoint string
	ID       string
	Secret   string

	// Network settings
	MTU           int
	DNS           string
	InterfaceName string

	// Logging
	LogLevel string

	// HTTP server
	EnableAPI  bool
	HTTPAddr   string
	SocketPath string

	// Advanced
	Holepunch     bool
	TlsClientCert string

	// Parsed values (not in JSON)
	PingIntervalDuration time.Duration
	PingTimeoutDuration  time.Duration

	// Source tracking (not in JSON)
	sources map[string]string

	Version string
	OrgID   string
}

var (
	privateKey    wgtypes.Key
	connected     bool
	dev           *device.Device
	wgData        WgData
	holePunchData HolePunchData
	uapiListener  net.Listener
	tdev          tun.Device
	apiServer     *api.API
	olmClient     *websocket.Client
	tunnelCancel  context.CancelFunc
)

func Run(ctx context.Context, config Config) {
	// Create a cancellable context for internal shutdown control
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	logger.GetLogger().SetLevel(parseLogLevel(config.LogLevel))

	if err := updates.CheckForUpdate("fosrl", "olm", config.Version); err != nil {
		logger.Debug("Failed to check for updates: %v", err)
	}

	if config.Holepunch {
		logger.Warn("Hole punching is enabled. This is EXPERIMENTAL and may not work in all environments.")
	}

	if config.HTTPAddr != "" {
		apiServer = api.NewAPI(config.HTTPAddr)
	} else if config.SocketPath != "" {
		apiServer = api.NewAPISocket(config.SocketPath)
	}

	apiServer.SetVersion(config.Version)
	apiServer.SetOrgID(config.OrgID)

	if err := apiServer.Start(); err != nil {
		logger.Fatal("Failed to start HTTP server: %v", err)
	}

	// Listen for shutdown requests from the API
	go func() {
		<-apiServer.GetShutdownChannel()
		logger.Info("Shutdown requested via API")
		// Cancel the context to trigger graceful shutdown
		cancel()
	}()

	var (
		id       = config.ID
		secret   = config.Secret
		endpoint = config.Endpoint
	)

	// Main event loop that handles connect, disconnect, and reconnect
	for {
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled while waiting for credentials")
			goto shutdown

		case req := <-apiServer.GetConnectionChannel():
			logger.Info("Received connection request via HTTP: id=%s, endpoint=%s", req.ID, req.Endpoint)

			// Stop any existing tunnel before starting a new one
			if olmClient != nil {
				logger.Info("Stopping existing tunnel before starting new connection")
				StopTunnel()
			}

			// Set the connection parameters
			id = req.ID
			secret = req.Secret
			endpoint = req.Endpoint

			// Start the tunnel process with the new credentials
			if id != "" && secret != "" && endpoint != "" {
				logger.Info("Starting tunnel with new credentials")
				go TunnelProcess(ctx, config, id, secret, endpoint)
			}

		case <-apiServer.GetDisconnectChannel():
			logger.Info("Received disconnect request via API")
			StopTunnel()
			// Clear credentials so we wait for new connect call
			id = ""
			secret = ""
			endpoint = ""

		default:
			// If we have credentials and no tunnel is running, start it
			if id != "" && secret != "" && endpoint != "" && olmClient == nil {
				logger.Info("Starting tunnel process with initial credentials")
				go TunnelProcess(ctx, config, id, secret, endpoint)
			} else if id == "" || secret == "" || endpoint == "" {
				// If we don't have credentials, check if API is enabled
				if !config.EnableAPI {
					missing := []string{}
					if id == "" {
						missing = append(missing, "id")
					}
					if secret == "" {
						missing = append(missing, "secret")
					}
					if endpoint == "" {
						missing = append(missing, "endpoint")
					}
					// exit the application because there is no way to provide the missing parameters
					logger.Fatal("Missing required parameters: %v and API is not enabled to provide them", missing)
					goto shutdown
				}
			}

			// Sleep briefly to prevent tight loop
			time.Sleep(100 * time.Millisecond)
		}
	}

shutdown:
	Stop()
	apiServer.Stop()
	logger.Info("Olm service shutting down")
}

func TunnelProcess(ctx context.Context, config Config, id string, secret string, endpoint string) {
	// Create a cancellable context for this tunnel process
	tunnelCtx, cancel := context.WithCancel(ctx)
	tunnelCancel = cancel
	defer func() {
		tunnelCancel = nil
	}()

	// Recreate channels for this tunnel session
	stopHolepunch = make(chan struct{})
	stopPing = make(chan struct{})

	var (
		interfaceName = config.InterfaceName
		loggerLevel   = parseLogLevel(config.LogLevel)
	)

	// Create a new olm client using the provided credentials
	olm, err := websocket.NewClient(
		"olm",
		id,       // Use provided ID
		secret,   // Use provided secret
		endpoint, // Use provided endpoint
		config.PingIntervalDuration,
		config.PingTimeoutDuration,
	)
	if err != nil {
		logger.Error("Failed to create olm: %v", err)
		return
	}

	// Store the client reference globally
	olmClient = olm

	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Error("Failed to generate private key: %v", err)
		return
	}

	sourcePort, err := FindAvailableUDPPort(49152, 65535)
	if err != nil {
		logger.Error("Error finding available port: %v", err)
		return
	}

	olm.RegisterHandler("olm/wg/holepunch/all", func(msg websocket.WSMessage) {
		logger.Debug("Received message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &holePunchData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		// Create a new stopHolepunch channel for the new set of goroutines
		stopHolepunch = make(chan struct{})

		// Start a single hole punch goroutine for all exit nodes
		logger.Info("Starting hole punch for %d exit nodes", len(holePunchData.ExitNodes))
		go keepSendingUDPHolePunchToMultipleExitNodes(holePunchData.ExitNodes, id, sourcePort)
	})

	olm.RegisterHandler("olm/wg/holepunch", func(msg websocket.WSMessage) {
		// THIS ENDPOINT IS FOR BACKWARD COMPATIBILITY
		logger.Debug("Received message: %v", msg.Data)

		type LegacyHolePunchData struct {
			ServerPubKey string `json:"serverPubKey"`
			Endpoint     string `json:"endpoint"`
		}

		var legacyHolePunchData LegacyHolePunchData

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &legacyHolePunchData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		// Stop any existing hole punch goroutines by closing the current channel
		select {
		case <-stopHolepunch:
			// Channel already closed
		default:
			close(stopHolepunch)
		}

		// Create a new stopHolepunch channel for the new set of goroutines
		stopHolepunch = make(chan struct{})

		// Start hole punching for each exit node
		logger.Info("Starting hole punch for exit node: %s with public key: %s", legacyHolePunchData.Endpoint, legacyHolePunchData.ServerPubKey)
		go keepSendingUDPHolePunch(legacyHolePunchData.Endpoint, id, sourcePort, legacyHolePunchData.ServerPubKey)
	})

	olm.RegisterHandler("olm/wg/connect", func(msg websocket.WSMessage) {
		logger.Debug("Received message: %v", msg.Data)

		if connected {
			logger.Info("Already connected. Ignoring new connection request.")
			return
		}

		if stopRegister != nil {
			stopRegister()
			stopRegister = nil
		}

		close(stopHolepunch)

		// wait 10 milliseconds to ensure the previous connection is closed
		logger.Debug("Waiting 500 milliseconds to ensure previous connection is closed")
		time.Sleep(500 * time.Millisecond)

		// if there is an existing tunnel then close it
		if dev != nil {
			logger.Info("Got new message. Closing existing tunnel!")
			dev.Close()
		}

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		tdev, err = func() (tun.Device, error) {
			if runtime.GOOS == "darwin" {
				interfaceName, err := findUnusedUTUN()
				if err != nil {
					return nil, err
				}
				return tun.CreateTUN(interfaceName, config.MTU)
			}
			if tunFdStr := os.Getenv(ENV_WG_TUN_FD); tunFdStr != "" {
				return createTUNFromFD(tunFdStr, config.MTU)
			}
			return tun.CreateTUN(interfaceName, config.MTU)
		}()

		if err != nil {
			logger.Error("Failed to create TUN device: %v", err)
			return
		}

		if realInterfaceName, err2 := tdev.Name(); err2 == nil {
			interfaceName = realInterfaceName
		}

		fileUAPI, err := func() (*os.File, error) {
			if uapiFdStr := os.Getenv(ENV_WG_UAPI_FD); uapiFdStr != "" {
				fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
				if err != nil {
					return nil, err
				}
				return os.NewFile(uintptr(fd), ""), nil
			}
			return uapiOpen(interfaceName)
		}()
		if err != nil {
			logger.Error("UAPI listen error: %v", err)
			os.Exit(1)
			return
		}

		dev = device.NewDevice(tdev, NewFixedPortBind(uint16(sourcePort)), device.NewLogger(mapToWireGuardLogLevel(loggerLevel), "wireguard: "))

		uapiListener, err = uapiListen(interfaceName, fileUAPI)
		if err != nil {
			logger.Error("Failed to listen on uapi socket: %v", err)
			os.Exit(1)
		}

		go func() {
			for {
				conn, err := uapiListener.Accept()
				if err != nil {
					return
				}
				go dev.IpcHandle(conn)
			}
		}()
		logger.Info("UAPI listener started")

		if err = dev.Up(); err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}
		if err = ConfigureInterface(interfaceName, wgData); err != nil {
			logger.Error("Failed to configure interface: %v", err)
		}
		apiServer.SetTunnelIP(wgData.TunnelIP)

		peerMonitor = peermonitor.NewPeerMonitor(
			func(siteID int, connected bool, rtt time.Duration) {
				// Find the site config to get endpoint information
				var endpoint string
				var isRelay bool
				for _, site := range wgData.Sites {
					if site.SiteId == siteID {
						endpoint = site.Endpoint
						// TODO: We'll need to track relay status separately
						// For now, assume not using relay unless we get relay data
						isRelay = !config.Holepunch
						break
					}
				}
				apiServer.UpdatePeerStatus(siteID, connected, rtt, endpoint, isRelay)
				if connected {
					logger.Info("Peer %d is now connected (RTT: %v)", siteID, rtt)
				} else {
					logger.Warn("Peer %d is disconnected", siteID)
				}
			},
			fixKey(privateKey.String()),
			olm,
			dev,
			config.Holepunch,
		)

		for i := range wgData.Sites {
			site := &wgData.Sites[i] // Use a pointer to modify the struct in the slice
			apiServer.UpdatePeerStatus(site.SiteId, false, 0, site.Endpoint, false)

			// Format the endpoint before configuring the peer.
			site.Endpoint = formatEndpoint(site.Endpoint)

			if err := ConfigurePeer(dev, *site, privateKey, endpoint); err != nil {
				logger.Error("Failed to configure peer: %v", err)
				return
			}
			if err := addRouteForServerIP(site.ServerIP, interfaceName); err != nil {
				logger.Error("Failed to add route for peer: %v", err)
				return
			}
			if err := addRoutesForRemoteSubnets(site.RemoteSubnets, interfaceName); err != nil {
				logger.Error("Failed to add routes for remote subnets: %v", err)
				return
			}

			logger.Info("Configured peer %s", site.PublicKey)
		}

		peerMonitor.Start()

		apiServer.SetRegistered(true)

		connected = true

		logger.Info("WireGuard device created.")
	})

	olm.RegisterHandler("olm/wg/peer/update", func(msg websocket.WSMessage) {
		logger.Debug("Received update-peer message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var updateData UpdatePeerData
		if err := json.Unmarshal(jsonData, &updateData); err != nil {
			logger.Error("Error unmarshaling update data: %v", err)
			return
		}

		// Convert to SiteConfig
		siteConfig := SiteConfig{
			SiteId:        updateData.SiteId,
			Endpoint:      updateData.Endpoint,
			PublicKey:     updateData.PublicKey,
			ServerIP:      updateData.ServerIP,
			ServerPort:    updateData.ServerPort,
			RemoteSubnets: updateData.RemoteSubnets,
		}

		// Update the peer in WireGuard
		if dev != nil {
			// Find the existing peer to get old data
			var oldRemoteSubnets string
			var oldPublicKey string
			for _, site := range wgData.Sites {
				if site.SiteId == updateData.SiteId {
					oldRemoteSubnets = site.RemoteSubnets
					oldPublicKey = site.PublicKey
					break
				}
			}

			// If the public key has changed, remove the old peer first
			if oldPublicKey != "" && oldPublicKey != updateData.PublicKey {
				logger.Info("Public key changed for site %d, removing old peer with key %s", updateData.SiteId, oldPublicKey)
				if err := RemovePeer(dev, updateData.SiteId, oldPublicKey); err != nil {
					logger.Error("Failed to remove old peer: %v", err)
					return
				}
			}

			// Format the endpoint before updating the peer.
			siteConfig.Endpoint = formatEndpoint(siteConfig.Endpoint)

			if err := ConfigurePeer(dev, siteConfig, privateKey, endpoint); err != nil {
				logger.Error("Failed to update peer: %v", err)
				return
			}

			// Remove old remote subnet routes if they changed
			if oldRemoteSubnets != siteConfig.RemoteSubnets {
				if err := removeRoutesForRemoteSubnets(oldRemoteSubnets); err != nil {
					logger.Error("Failed to remove old remote subnet routes: %v", err)
					// Continue anyway to add new routes
				}

				// Add new remote subnet routes
				if err := addRoutesForRemoteSubnets(siteConfig.RemoteSubnets, interfaceName); err != nil {
					logger.Error("Failed to add new remote subnet routes: %v", err)
					return
				}
			}

			// Update successful
			logger.Info("Successfully updated peer for site %d", updateData.SiteId)
			for i := range wgData.Sites {
				if wgData.Sites[i].SiteId == updateData.SiteId {
					wgData.Sites[i] = siteConfig
					break
				}
			}
		} else {
			logger.Error("WireGuard device not initialized")
		}
	})

	// Handler for adding a new peer
	olm.RegisterHandler("olm/wg/peer/add", func(msg websocket.WSMessage) {
		logger.Debug("Received add-peer message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var addData AddPeerData
		if err := json.Unmarshal(jsonData, &addData); err != nil {
			logger.Error("Error unmarshaling add data: %v", err)
			return
		}

		// Convert to SiteConfig
		siteConfig := SiteConfig{
			SiteId:        addData.SiteId,
			Endpoint:      addData.Endpoint,
			PublicKey:     addData.PublicKey,
			ServerIP:      addData.ServerIP,
			ServerPort:    addData.ServerPort,
			RemoteSubnets: addData.RemoteSubnets,
		}

		// Add the peer to WireGuard
		if dev != nil {
			// Format the endpoint before adding the new peer.
			siteConfig.Endpoint = formatEndpoint(siteConfig.Endpoint)

			if err := ConfigurePeer(dev, siteConfig, privateKey, endpoint); err != nil {
				logger.Error("Failed to add peer: %v", err)
				return
			}
			if err := addRouteForServerIP(siteConfig.ServerIP, interfaceName); err != nil {
				logger.Error("Failed to add route for new peer: %v", err)
				return
			}
			if err := addRoutesForRemoteSubnets(siteConfig.RemoteSubnets, interfaceName); err != nil {
				logger.Error("Failed to add routes for remote subnets: %v", err)
				return
			}

			// Add successful
			logger.Info("Successfully added peer for site %d", addData.SiteId)

			// Update WgData with the new peer
			wgData.Sites = append(wgData.Sites, siteConfig)
		} else {
			logger.Error("WireGuard device not initialized")
		}
	})

	// Handler for removing a peer
	olm.RegisterHandler("olm/wg/peer/remove", func(msg websocket.WSMessage) {
		logger.Debug("Received remove-peer message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var removeData RemovePeerData
		if err := json.Unmarshal(jsonData, &removeData); err != nil {
			logger.Error("Error unmarshaling remove data: %v", err)
			return
		}

		// Find the peer to remove
		var peerToRemove *SiteConfig
		var newSites []SiteConfig

		for _, site := range wgData.Sites {
			if site.SiteId == removeData.SiteId {
				peerToRemove = &site
			} else {
				newSites = append(newSites, site)
			}
		}

		if peerToRemove == nil {
			logger.Error("Peer with site ID %d not found", removeData.SiteId)
			return
		}

		// Remove the peer from WireGuard
		if dev != nil {
			if err := RemovePeer(dev, removeData.SiteId, peerToRemove.PublicKey); err != nil {
				logger.Error("Failed to remove peer: %v", err)
				// Send error response if needed
				return
			}

			// Remove route for the peer
			err = removeRouteForServerIP(peerToRemove.ServerIP)
			if err != nil {
				logger.Error("Failed to remove route for peer: %v", err)
				return
			}

			// Remove routes for remote subnets
			if err := removeRoutesForRemoteSubnets(peerToRemove.RemoteSubnets); err != nil {
				logger.Error("Failed to remove routes for remote subnets: %v", err)
				return
			}

			// Remove successful
			logger.Info("Successfully removed peer for site %d", removeData.SiteId)

			// Update WgData to remove the peer
			wgData.Sites = newSites
		} else {
			logger.Error("WireGuard device not initialized")
		}
	})

	olm.RegisterHandler("olm/wg/peer/relay", func(msg websocket.WSMessage) {
		logger.Debug("Received relay-peer message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var relayData RelayPeerData
		if err := json.Unmarshal(jsonData, &relayData); err != nil {
			logger.Error("Error unmarshaling relay data: %v", err)
			return
		}

		primaryRelay, err := resolveDomain(relayData.Endpoint)
		if err != nil {
			logger.Warn("Failed to resolve primary relay endpoint: %v", err)
		}

		// Update HTTP server to mark this peer as using relay
		apiServer.UpdatePeerRelayStatus(relayData.SiteId, relayData.Endpoint, true)

		peerMonitor.HandleFailover(relayData.SiteId, primaryRelay)
	})

	olm.RegisterHandler("olm/register/no-sites", func(msg websocket.WSMessage) {
		logger.Info("Received no-sites message - no sites available for connection")

		// if stopRegister != nil {
		// 	stopRegister()
		// 	stopRegister = nil
		// }

		// select {
		// case <-stopHolepunch:
		// 	// Channel already closed, do nothing
		// default:
		// 	close(stopHolepunch)
		// }

		logger.Info("No sites available - stopped registration and holepunch processes")
	})

	olm.RegisterHandler("olm/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received terminate message")
		olm.Close()
	})

	olm.OnConnect(func() error {
		logger.Info("Websocket Connected")

		apiServer.SetConnectionStatus(true)

		if connected {
			logger.Debug("Already connected, skipping registration")
			return nil
		}

		publicKey := privateKey.PublicKey()

		logger.Debug("Sending registration message to server with public key: %s and relay: %v", publicKey, !config.Holepunch)

		stopRegister = olm.SendMessageInterval("olm/wg/register", map[string]interface{}{
			"publicKey":  publicKey.String(),
			"relay":      !config.Holepunch,
			"olmVersion": config.Version,
			"orgId":      config.OrgID,
		}, 1*time.Second)

		go keepSendingPing(olm)

		logger.Info("Sent registration message")
		return nil
	})

	olm.OnTokenUpdate(func(token string) {
		olmToken = token
	})

	// Connect to the WebSocket server
	if err := olm.Connect(); err != nil {
		logger.Error("Failed to connect to server: %v", err)
		return
	}
	defer olm.Close()

	// Listen for org switch requests from the API
	go func() {
		for req := range apiServer.GetSwitchOrgChannel() {
			logger.Info("Processing org switch request to orgId: %s", req.OrgID)

			// Update the config with the new orgId
			config.OrgID = req.OrgID

			// Mark as not connected to trigger re-registration
			connected = false

			Stop()

			// Clear peer statuses in API
			apiServer.SetRegistered(false)
			apiServer.SetTunnelIP("")
			apiServer.SetOrgID(config.OrgID)

			stopHolepunch = make(chan struct{})
			// Trigger re-registration with new orgId
			logger.Info("Re-registering with new orgId: %s", config.OrgID)
			publicKey := privateKey.PublicKey()
			stopRegister = olm.SendMessageInterval("olm/wg/register", map[string]interface{}{
				"publicKey":  publicKey.String(),
				"relay":      !config.Holepunch,
				"olmVersion": config.Version,
				"orgId":      config.OrgID,
			}, 1*time.Second)
		}
	}()

	// Wait for context cancellation
	<-tunnelCtx.Done()
	logger.Info("Tunnel process context cancelled, cleaning up")
}

func Stop() {
	select {
	case <-stopHolepunch:
		// Channel already closed, do nothing
	default:
		close(stopHolepunch)
	}

	select {
	case <-stopPing:
		// Channel already closed
	default:
		close(stopPing)
	}

	if stopRegister != nil {
		stopRegister()
		stopRegister = nil
	}

	if peerMonitor != nil {
		peerMonitor.Stop()
		peerMonitor = nil
	}

	if uapiListener != nil {
		uapiListener.Close()
		uapiListener = nil
	}
	if dev != nil {
		dev.Close()
		dev = nil
	}
	// Close TUN device
	if tdev != nil {
		tdev.Close()
		tdev = nil
	}

	logger.Info("Olm service stopped")
}

// StopTunnel stops just the tunnel process and websocket connection
// without shutting down the entire application
func StopTunnel() {
	logger.Info("Stopping tunnel process")

	// Cancel the tunnel context if it exists
	if tunnelCancel != nil {
		tunnelCancel()
		// Give it a moment to clean up
		time.Sleep(200 * time.Millisecond)
	}

	// Close the websocket connection
	if olmClient != nil {
		olmClient.Close()
		olmClient = nil
	}

	Stop()

	// Reset the connected state
	connected = false

	// Update API server status
	apiServer.SetConnectionStatus(false)
	apiServer.SetRegistered(false)
	apiServer.SetTunnelIP("")

	logger.Info("Tunnel process stopped")
}
