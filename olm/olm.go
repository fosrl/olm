package olm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/updates"
	"github.com/fosrl/olm/httpserver"
	"github.com/fosrl/olm/peermonitor"
	"github.com/fosrl/olm/websocket"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func olm(ctx context.Context, args []string) {
	// Load configuration from file, env vars, and CLI args
	// Priority: CLI args > Env vars > Config file > Defaults
	config, showVersion, showConfig, err := LoadConfig(args)
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		return
	}

	// Handle --show-config flag
	if showConfig {
		config.ShowConfig()
		os.Exit(0)
	}

	// Extract commonly used values from config for convenience
	var (
		endpoint      = config.Endpoint
		id            = config.ID
		secret        = config.Secret
		mtu           = config.MTU
		logLevel      = config.LogLevel
		interfaceName = config.InterfaceName
		enableHTTP    = config.EnableHTTP
		httpAddr      = config.HTTPAddr
		pingInterval  = config.PingIntervalDuration
		pingTimeout   = config.PingTimeoutDuration
		doHolepunch   = config.Holepunch
		privateKey    wgtypes.Key
		connected     bool
	)

	stopHolepunch = make(chan struct{})
	stopPing = make(chan struct{})

	loggerLevel := parseLogLevel(logLevel)
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	olmVersion := "version_replaceme"
	if showVersion {
		fmt.Println("Olm version " + olmVersion)
		os.Exit(0)
	}
	logger.Info("Olm version " + olmVersion)

	if err := updates.CheckForUpdate("fosrl", "olm", olmVersion); err != nil {
		logger.Debug("Failed to check for updates: %v", err)
	}

	// Log startup information
	logger.Debug("Olm service starting...")
	logger.Debug("Parameters: endpoint='%s', id='%s', secret='%s'", endpoint, id, secret)
	logger.Debug("HTTP enabled: %v, HTTP addr: %s", enableHTTP, httpAddr)

	if doHolepunch {
		logger.Warn("Hole punching is enabled. This is EXPERIMENTAL and may not work in all environments.")
	}

	var httpServer *httpserver.HTTPServer
	if enableHTTP {
		httpServer = httpserver.NewHTTPServer(httpAddr)
		httpServer.SetVersion(olmVersion)
		if err := httpServer.Start(); err != nil {
			logger.Fatal("Failed to start HTTP server: %v", err)
		}

		// Use a goroutine to handle connection requests
		go func() {
			for req := range httpServer.GetConnectionChannel() {
				logger.Info("Received connection request via HTTP: id=%s, endpoint=%s", req.ID, req.Endpoint)

				// Set the connection parameters
				id = req.ID
				secret = req.Secret
				endpoint = req.Endpoint
			}
		}()
	}

	// // Check if required parameters are missing and provide helpful guidance
	// missingParams := []string{}
	// if id == "" {
	// 	missingParams = append(missingParams, "id (use -id flag or OLM_ID env var)")
	// }
	// if secret == "" {
	// 	missingParams = append(missingParams, "secret (use -secret flag or OLM_SECRET env var)")
	// }
	// if endpoint == "" {
	// 	missingParams = append(missingParams, "endpoint (use -endpoint flag or PANGOLIN_ENDPOINT env var)")
	// }

	// if len(missingParams) > 0 {
	// 	logger.Error("Missing required parameters: %v", missingParams)
	// 	logger.Error("Either provide them as command line flags or set as environment variables")
	// 	fmt.Printf("ERROR: Missing required parameters: %v\n", missingParams)
	// 	fmt.Printf("Please provide them as command line flags or set as environment variables\n")
	// 	if !enableHTTP {
	// 		logger.Error("HTTP server is disabled, cannot receive parameters via API")
	// 		fmt.Printf("HTTP server is disabled, cannot receive parameters via API\n")
	// 		return
	// 	}
	// }

	// Create a new olm
	olm, err := websocket.NewClient(
		"olm",
		id,     // CLI arg takes precedence
		secret, // CLI arg takes precedence
		endpoint,
		pingInterval,
		pingTimeout,
	)
	if err != nil {
		logger.Fatal("Failed to create olm: %v", err)
	}

	// wait until we have a client id and secret and endpoint
	waitCount := 0
	for id == "" || secret == "" || endpoint == "" {
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled while waiting for credentials")
			return
		default:
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
			waitCount++
			if waitCount%10 == 1 { // Log every 10 seconds instead of every second
				logger.Debug("Waiting for missing parameters: %v (waiting %d seconds)", missing, waitCount)
			}
			time.Sleep(1 * time.Second)
		}
	}

	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Fatal("Failed to generate private key: %v", err)
	}

	// Create TUN device and network stack
	var dev *device.Device
	var wgData WgData
	var holePunchData HolePunchData
	var uapiListener net.Listener
	var tdev tun.Device

	sourcePort, err := FindAvailableUDPPort(49152, 65535)
	if err != nil {
		fmt.Printf("Error finding available port: %v\n", err)
		os.Exit(1)
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
				return tun.CreateTUN(interfaceName, mtu)
			}
			if tunFdStr := os.Getenv(ENV_WG_TUN_FD); tunFdStr != "" {
				return createTUNFromFD(tunFdStr, mtu)
			}
			return tun.CreateTUN(interfaceName, mtu)
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
		if httpServer != nil {
			httpServer.SetTunnelIP(wgData.TunnelIP)
		}

		peerMonitor = peermonitor.NewPeerMonitor(
			func(siteID int, connected bool, rtt time.Duration) {
				if httpServer != nil {
					// Find the site config to get endpoint information
					var endpoint string
					var isRelay bool
					for _, site := range wgData.Sites {
						if site.SiteId == siteID {
							endpoint = site.Endpoint
							// TODO: We'll need to track relay status separately
							// For now, assume not using relay unless we get relay data
							isRelay = !doHolepunch
							break
						}
					}
					httpServer.UpdatePeerStatus(siteID, connected, rtt, endpoint, isRelay)
				}
				if connected {
					logger.Info("Peer %d is now connected (RTT: %v)", siteID, rtt)
				} else {
					logger.Warn("Peer %d is disconnected", siteID)
				}
			},
			fixKey(privateKey.String()),
			olm,
			dev,
			doHolepunch,
		)

		for i := range wgData.Sites {
			site := &wgData.Sites[i] // Use a pointer to modify the struct in the slice
			if httpServer != nil {
				httpServer.UpdatePeerStatus(site.SiteId, false, 0, site.Endpoint, false)
			}

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
		if httpServer != nil {
			httpServer.UpdatePeerRelayStatus(relayData.SiteId, relayData.Endpoint, true)
		}

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

		if httpServer != nil {
			httpServer.SetConnectionStatus(true)
		}

		// CRITICAL: Save our full config AFTER websocket saves its limited config
		// This ensures all 13 fields are preserved, not just the 4 that websocket saves
		if err := SaveConfig(config); err != nil {
			logger.Error("Failed to save full olm config: %v", err)
		} else {
			logger.Debug("Saved full olm config with all options")
		}

		if connected {
			logger.Debug("Already connected, skipping registration")
			return nil
		}

		publicKey := privateKey.PublicKey()

		logger.Debug("Sending registration message to server with public key: %s and relay: %v", publicKey, !doHolepunch)

		stopRegister = olm.SendMessageInterval("olm/wg/register", map[string]interface{}{
			"publicKey":  publicKey.String(),
			"relay":      !doHolepunch,
			"olmVersion": olmVersion,
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
		logger.Fatal("Failed to connect to server: %v", err)
	}
	defer olm.Close()

	// Wait for interrupt signal or context cancellation
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		logger.Info("Received interrupt signal")
	case <-ctx.Done():
		logger.Info("Context cancelled")
	}

	select {
	case <-stopHolepunch:
		// Channel already closed, do nothing
	default:
		close(stopHolepunch)
	}

	if stopRegister != nil {
		stopRegister()
		stopRegister = nil
	}

	select {
	case <-stopPing:
		// Channel already closed
	default:
		close(stopPing)
	}

	if uapiListener != nil {
		uapiListener.Close()
	}
	if dev != nil {
		dev.Close()
	}

	logger.Info("runOlmMain() exiting")
	fmt.Printf("runOlmMain() exiting\n")
}
