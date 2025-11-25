package olm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fosrl/newt/bind"
	"github.com/fosrl/newt/holepunch"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/api"
	olmDevice "github.com/fosrl/olm/device"
	"github.com/fosrl/olm/dns"
	dnsOverride "github.com/fosrl/olm/dns/override"
	"github.com/fosrl/olm/network"
	"github.com/fosrl/olm/peermonitor"
	"github.com/fosrl/olm/peers"
	"github.com/fosrl/olm/websocket"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	privateKey       wgtypes.Key
	connected        bool
	dev              *device.Device
	wgData           WgData
	holePunchData    HolePunchData
	uapiListener     net.Listener
	tdev             tun.Device
	middleDev        *olmDevice.MiddleDevice
	dnsProxy         *dns.DNSProxy
	apiServer        *api.API
	olmClient        *websocket.Client
	tunnelCancel     context.CancelFunc
	tunnelRunning    bool
	sharedBind       *bind.SharedBind
	holePunchManager *holepunch.Manager
	peerMonitor      *peermonitor.PeerMonitor
	globalConfig     GlobalConfig
	globalCtx        context.Context
	stopRegister     func()
	stopPing         chan struct{}
	peerManager      *peers.PeerManager
)

func Init(ctx context.Context, config GlobalConfig) {
	globalConfig = config
	globalCtx = ctx

	// Create a cancellable context for internal shutdown control
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	logger.GetLogger().SetLevel(util.ParseLogLevel(config.LogLevel))

	if config.HTTPAddr != "" {
		apiServer = api.NewAPI(config.HTTPAddr)
	} else if config.SocketPath != "" {
		apiServer = api.NewAPISocket(config.SocketPath)
	}

	apiServer.SetVersion(config.Version)

	// Set up API handlers
	apiServer.SetHandlers(
		// onConnect
		func(req api.ConnectionRequest) error {
			logger.Info("Received connection request via HTTP: id=%s, endpoint=%s", req.ID, req.Endpoint)

			// Stop any existing tunnel before starting a new one
			if olmClient != nil {
				logger.Info("Stopping existing tunnel before starting new connection")
				StopTunnel()
			}

			tunnelConfig := TunnelConfig{
				Endpoint:      req.Endpoint,
				ID:            req.ID,
				Secret:        req.Secret,
				UserToken:     req.UserToken,
				MTU:           req.MTU,
				DNS:           req.DNS,
				UpstreamDNS:   req.UpstreamDNS,
				InterfaceName: req.InterfaceName,
				Holepunch:     req.Holepunch,
				TlsClientCert: req.TlsClientCert,
				OrgID:         req.OrgID,
			}

			var err error
			// Parse ping interval
			if req.PingInterval != "" {
				tunnelConfig.PingIntervalDuration, err = time.ParseDuration(req.PingInterval)
				if err != nil {
					logger.Warn("Invalid PING_INTERVAL value: %s, using default 3 seconds", req.PingInterval)
					tunnelConfig.PingIntervalDuration = 3 * time.Second
				}
			} else {
				tunnelConfig.PingIntervalDuration = 3 * time.Second
			}
			// Parse ping timeout
			if req.PingTimeout != "" {
				tunnelConfig.PingTimeoutDuration, err = time.ParseDuration(req.PingTimeout)
				if err != nil {
					logger.Warn("Invalid PING_TIMEOUT value: %s, using default 5 seconds", req.PingTimeout)
					tunnelConfig.PingTimeoutDuration = 5 * time.Second
				}
			} else {
				tunnelConfig.PingTimeoutDuration = 5 * time.Second
			}
			if req.MTU == 0 {
				tunnelConfig.MTU = 1420
			}
			if req.DNS == "" {
				tunnelConfig.DNS = "9.9.9.9"
			}
			// DNSProxyIP has no default - it must be provided if DNS proxy is desired
			// UpstreamDNS defaults to 8.8.8.8 if not provided
			if len(req.UpstreamDNS) == 0 {
				tunnelConfig.UpstreamDNS = []string{"8.8.8.8:53"}
			}
			if req.InterfaceName == "" {
				tunnelConfig.InterfaceName = "olm"
			}

			// Start the tunnel process with the new credentials
			if tunnelConfig.ID != "" && tunnelConfig.Secret != "" && tunnelConfig.Endpoint != "" {
				logger.Info("Starting tunnel with new credentials")
				go StartTunnel(tunnelConfig)
			}

			return nil
		},
		// onSwitchOrg
		func(req api.SwitchOrgRequest) error {
			logger.Info("Received switch organization request via HTTP: orgID=%s", req.OrgID)
			return SwitchOrg(req.OrgID)
		},
		// onDisconnect
		func() error {
			logger.Info("Processing disconnect request via API")
			return StopTunnel()
		},
		// onExit
		func() error {
			logger.Info("Processing shutdown request via API")
			cancel()
			return nil
		},
	)
}

func StartTunnel(config TunnelConfig) {
	if tunnelRunning {
		logger.Info("Tunnel already running")
		return
	}

	tunnelRunning = true // Also set it here in case it is called externally

	if config.Holepunch {
		logger.Warn("Hole punching is enabled. This is EXPERIMENTAL and may not work in all environments.")
	}

	// Create a cancellable context for this tunnel process
	tunnelCtx, cancel := context.WithCancel(globalCtx)
	tunnelCancel = cancel
	defer func() {
		tunnelCancel = nil
	}()

	// Recreate channels for this tunnel session
	stopPing = make(chan struct{})

	var (
		interfaceName = config.InterfaceName
		id            = config.ID
		secret        = config.Secret
		endpoint      = config.Endpoint
		userToken     = config.UserToken
	)

	apiServer.SetOrgID(config.OrgID)

	// Create a new olm client using the provided credentials
	olm, err := websocket.NewClient(
		id,        // Use provided ID
		secret,    // Use provided secret
		userToken, // Use provided user token OPTIONAL
		endpoint,  // Use provided endpoint
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

	// Create shared UDP socket for both holepunch and WireGuard
	sourcePort, err := util.FindAvailableUDPPort(49152, 65535)
	if err != nil {
		logger.Error("Error finding available port: %v", err)
		return
	}

	localAddr := &net.UDPAddr{
		Port: int(sourcePort),
		IP:   net.IPv4zero,
	}

	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		logger.Error("Failed to create shared UDP socket: %v", err)
		return
	}

	sharedBind, err = bind.New(udpConn)
	if err != nil {
		logger.Error("Failed to create shared bind: %v", err)
		udpConn.Close()
		return
	}

	// Add a reference for the hole punch senders (creator already has one reference for WireGuard)
	sharedBind.AddRef()

	logger.Info("Created shared UDP socket on port %d (refcount: %d)", sourcePort, sharedBind.GetRefCount())

	// Create the holepunch manager
	holePunchManager = holepunch.NewManager(sharedBind, id, "olm")

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

		// Convert HolePunchData.ExitNodes to holepunch.ExitNode slice
		exitNodes := make([]holepunch.ExitNode, len(holePunchData.ExitNodes))
		for i, node := range holePunchData.ExitNodes {
			exitNodes[i] = holepunch.ExitNode{
				Endpoint:  node.Endpoint,
				PublicKey: node.PublicKey,
			}
		}

		// Start hole punching using the manager
		logger.Info("Starting hole punch for %d exit nodes", len(exitNodes))
		if err := holePunchManager.StartMultipleExitNodes(exitNodes); err != nil {
			logger.Warn("Failed to start hole punch: %v", err)
		}
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

		// Stop any existing hole punch operations
		if holePunchManager != nil {
			holePunchManager.Stop()
		}

		// Start hole punching for the exit node
		logger.Info("Starting hole punch for exit node: %s with public key: %s", legacyHolePunchData.Endpoint, legacyHolePunchData.ServerPubKey)
		if err := holePunchManager.StartSingleEndpoint(legacyHolePunchData.Endpoint, legacyHolePunchData.ServerPubKey); err != nil {
			logger.Warn("Failed to start hole punch: %v", err)
		}
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
			if config.FileDescriptorTun != 0 {
				return olmDevice.CreateTUNFromFD(config.FileDescriptorTun, config.MTU)
			}
			var ifName = interfaceName
			if runtime.GOOS == "darwin" { // this is if we dont pass a fd
				ifName, err = network.FindUnusedUTUN()
				if err != nil {
					return nil, err
				}
			}
			return tun.CreateTUN(ifName, config.MTU)
		}()

		if err != nil {
			logger.Error("Failed to create TUN device: %v", err)
			return
		}

		if config.FileDescriptorTun == 0 {
			if realInterfaceName, err2 := tdev.Name(); err2 == nil {
				interfaceName = realInterfaceName
			}
		}

		// Wrap TUN device with packet filter for DNS proxy
		middleDev = olmDevice.NewMiddleDevice(tdev)

		wgLogger := logger.GetLogger().GetWireGuardLogger("wireguard: ")
		// Use filtered device instead of raw TUN device
		dev = device.NewDevice(middleDev, sharedBind, (*device.Logger)(wgLogger))

		if config.EnableUAPI {
			fileUAPI, err := func() (*os.File, error) {
				if config.FileDescriptorUAPI != 0 {
					fd, err := strconv.ParseUint(fmt.Sprintf("%d", config.FileDescriptorUAPI), 10, 32)
					if err != nil {
						return nil, fmt.Errorf("invalid UAPI file descriptor: %v", err)
					}
					return os.NewFile(uintptr(fd), ""), nil
				}
				return olmDevice.UapiOpen(interfaceName)
			}()
			if err != nil {
				logger.Error("UAPI listen error: %v", err)
				os.Exit(1)
				return
			}

			uapiListener, err = olmDevice.UapiListen(interfaceName, fileUAPI)
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
		}

		if err = dev.Up(); err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}

		// Create and start DNS proxy
		dnsProxy, err = dns.NewDNSProxy(tdev, middleDev, config.MTU, wgData.UtilitySubnet, config.UpstreamDNS)
		if err != nil {
			logger.Error("Failed to create DNS proxy: %v", err)
		}

		if err = network.ConfigureInterface(interfaceName, wgData.TunnelIP, config.MTU); err != nil {
			logger.Error("Failed to configure interface: %v", err)
		}

		if network.AddRoutes([]string{wgData.UtilitySubnet}, interfaceName); err != nil { // also route the utility subnet
			logger.Error("Failed to add route for utility subnet: %v", err)
		}

		// TODO: seperate adding the callback to this so we can init it above with the interface
		interfaceIP := wgData.TunnelIP
		if strings.Contains(interfaceIP, "/") {
			interfaceIP = strings.Split(interfaceIP, "/")[0]
		}

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
			util.FixKey(privateKey.String()),
			olm,
			dev,
			config.Holepunch,
			middleDev,
			interfaceIP,
		)

		peerManager = peers.NewPeerManager(dev, peerMonitor, dnsProxy, interfaceName, privateKey)

		for i := range wgData.Sites {
			site := wgData.Sites[i]
			apiServer.UpdatePeerStatus(site.SiteId, false, 0, site.Endpoint, false)

			if err := peerManager.AddPeer(site, endpoint); err != nil {
				logger.Error("Failed to add peer: %v", err)
				return
			}

			logger.Info("Configured peer %s", site.PublicKey)
		}

		peerMonitor.Start()

		// Set up DNS override to use our DNS proxy
		if err := dnsOverride.SetupDNSOverride(interfaceName, dnsProxy); err != nil {
			logger.Error("Failed to setup DNS override: %v", err)
			return
		}

		if err := dnsProxy.Start(); err != nil {
			logger.Error("Failed to start DNS proxy: %v", err)
		}

		apiServer.SetRegistered(true)

		connected = true

		// Invoke onConnected callback if configured
		if globalConfig.OnConnected != nil {
			go globalConfig.OnConnected()
		}

		logger.Info("WireGuard device created.")
	})

	olm.RegisterHandler("olm/wg/peer/update", func(msg websocket.WSMessage) {
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
		existingPeer, exists := peerManager.GetPeer(updateData.SiteId)
		if !exists {
			logger.Error("Peer with site ID %d not found", updateData.SiteId)
			return
		}

		// Create updated site config by merging with existing data
		siteConfig := existingPeer

		if updateData.Endpoint != "" {
			siteConfig.Endpoint = updateData.Endpoint
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

		if err := peerManager.UpdatePeer(siteConfig, endpoint); err != nil {
			logger.Error("Failed to update peer: %v", err)
			return
		}

		// Update successful
		logger.Info("Successfully updated peer for site %d", updateData.SiteId)
	})

	// Handler for adding a new peer
	olm.RegisterHandler("olm/wg/peer/add", func(msg websocket.WSMessage) {
		logger.Debug("Received add-peer message: %v", msg.Data)

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

		if err := peerManager.AddPeer(siteConfig, endpoint); err != nil {
			logger.Error("Failed to add peer: %v", err)
			return
		}

		// Add successful
		logger.Info("Successfully added peer for site %d", siteConfig.SiteId)
	})

	// Handler for removing a peer
	olm.RegisterHandler("olm/wg/peer/remove", func(msg websocket.WSMessage) {
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

		if err := peerManager.RemovePeer(removeData.SiteId); err != nil {
			logger.Error("Failed to remove peer: %v", err)
			return
		}

		// Remove successful
		logger.Info("Successfully removed peer for site %d", removeData.SiteId)
	})

	// Handler for adding remote subnets to a peer
	olm.RegisterHandler("olm/wg/peer/data/add", func(msg websocket.WSMessage) {
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

		// Add new subnets
		for _, subnet := range addSubnetsData.RemoteSubnets {
			if err := peerManager.AddRemoteSubnet(addSubnetsData.SiteId, subnet); err != nil {
				logger.Error("Failed to add allowed IP %s: %v", subnet, err)
			}
		}

		// Add new aliases
		for _, alias := range addSubnetsData.Aliases {
			if err := peerManager.AddAlias(addSubnetsData.SiteId, alias); err != nil {
				logger.Error("Failed to add alias %s: %v", alias.Alias, err)
			}
		}
	})

	// Handler for removing remote subnets from a peer
	olm.RegisterHandler("olm/wg/peer/data/remove", func(msg websocket.WSMessage) {
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

		// Remove subnets
		for _, subnet := range removeSubnetsData.RemoteSubnets {
			if err := peerManager.RemoveRemoteSubnet(removeSubnetsData.SiteId, subnet); err != nil {
				logger.Error("Failed to remove allowed IP %s: %v", subnet, err)
			}
		}

		// Remove aliases
		for _, alias := range removeSubnetsData.Aliases {
			if err := peerManager.RemoveAlias(removeSubnetsData.SiteId, alias.Alias); err != nil {
				logger.Error("Failed to remove alias %s: %v", alias.Alias, err)
			}
		}
	})

	// Handler for updating remote subnets of a peer (remove old, add new in one operation)
	olm.RegisterHandler("olm/wg/peer/data/update", func(msg websocket.WSMessage) {
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

		// Remove old subnets
		for _, subnet := range updateSubnetsData.OldRemoteSubnets {
			if err := peerManager.RemoveRemoteSubnet(updateSubnetsData.SiteId, subnet); err != nil {
				logger.Error("Failed to remove allowed IP %s: %v", subnet, err)
			}
		}

		// Add new subnets
		for _, subnet := range updateSubnetsData.NewRemoteSubnets {
			if err := peerManager.AddRemoteSubnet(updateSubnetsData.SiteId, subnet); err != nil {
				logger.Error("Failed to add allowed IP %s: %v", subnet, err)
			}
		}

		// Remove old aliases
		for _, alias := range updateSubnetsData.OldAliases {
			if err := peerManager.RemoveAlias(updateSubnetsData.SiteId, alias.Alias); err != nil {
				logger.Error("Failed to remove alias %s: %v", alias.Alias, err)
			}
		}

		// Add new aliases
		for _, alias := range updateSubnetsData.NewAliases {
			if err := peerManager.AddAlias(updateSubnetsData.SiteId, alias); err != nil {
				logger.Error("Failed to add alias %s: %v", alias.Alias, err)
			}
		}

		logger.Info("Successfully updated remote subnets and aliases for peer %d", updateSubnetsData.SiteId)
	})

	olm.RegisterHandler("olm/wg/peer/relay", func(msg websocket.WSMessage) {
		logger.Debug("Received relay-peer message: %v", msg.Data)

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

		primaryRelay, err := util.ResolveDomain(relayData.Endpoint)
		if err != nil {
			logger.Warn("Failed to resolve primary relay endpoint: %v", err)
		}

		// Update HTTP server to mark this peer as using relay
		apiServer.UpdatePeerRelayStatus(relayData.SiteId, relayData.Endpoint, true)

		peerMonitor.HandleFailover(relayData.SiteId, primaryRelay)
	})

	olm.RegisterHandler("olm/register/no-sites", func(msg websocket.WSMessage) {
		logger.Info("Received no-sites message - no sites available for connection")

		if stopRegister != nil {
			stopRegister()
			stopRegister = nil
		}

		logger.Info("No sites available - stopped registration and holepunch processes")
	})

	olm.RegisterHandler("olm/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received terminate message")
		Close()

		if globalConfig.OnTerminated != nil {
			go globalConfig.OnTerminated()
		}
	})

	olm.OnConnect(func() error {
		logger.Info("Websocket Connected")

		apiServer.SetConnectionStatus(true)

		if connected {
			logger.Debug("Already connected, skipping registration")
			return nil
		}

		publicKey := privateKey.PublicKey()

		if stopRegister == nil {
			logger.Debug("Sending registration message to server with public key: %s and relay: %v", publicKey, !config.Holepunch)
			stopRegister = olm.SendMessageInterval("olm/wg/register", map[string]interface{}{
				"publicKey":  publicKey.String(),
				"relay":      !config.Holepunch,
				"olmVersion": globalConfig.Version,
				"orgId":      config.OrgID,
				// "doNotCreateNewClient": config.DoNotCreateNewClient,
			}, 1*time.Second)

			// Invoke onRegistered callback if configured
			if globalConfig.OnRegistered != nil {
				go globalConfig.OnRegistered()
			}
		}

		go keepSendingPing(olm)

		return nil
	})

	olm.OnTokenUpdate(func(token string) {
		if holePunchManager != nil {
			holePunchManager.SetToken(token)
		}
	})

	// Connect to the WebSocket server
	if err := olm.Connect(); err != nil {
		logger.Error("Failed to connect to server: %v", err)
		return
	}
	defer olm.Close()

	// Wait for context cancellation
	<-tunnelCtx.Done()
	logger.Info("Tunnel process context cancelled, cleaning up")
}

func Close() {
	// Restore original DNS configuration
	// we do this first to avoid any DNS issues if something else gets stuck
	if err := dnsOverride.RestoreDNSOverride(); err != nil {
		logger.Error("Failed to restore DNS: %v", err)
	}

	// Stop hole punch manager
	if holePunchManager != nil {
		holePunchManager.Stop()
		holePunchManager = nil
	}

	if stopPing != nil {
		select {
		case <-stopPing:
			// Channel already closed
		default:
			close(stopPing)
		}
	}

	if stopRegister != nil {
		stopRegister()
		stopRegister = nil
	}

	if peerMonitor != nil {
		peerMonitor.Close() // Close() also calls Stop() internally
		peerMonitor = nil
	}

	if uapiListener != nil {
		uapiListener.Close()
		uapiListener = nil
	}

	// Close TUN device first to unblock any reads
	logger.Debug("Closing TUN device")
	if tdev != nil {
		tdev.Close()
		tdev = nil
	}

	// Close filtered device (this will close the closed channel and stop pump goroutine)
	logger.Debug("Closing MiddleDevice")
	if middleDev != nil {
		middleDev.Close()
		middleDev = nil
	}

	// Stop DNS proxy
	logger.Debug("Stopping DNS proxy")
	if dnsProxy != nil {
		dnsProxy.Stop()
		dnsProxy = nil
	}

	// Now close WireGuard device
	logger.Debug("Closing WireGuard device")
	if dev != nil {
		dev.Close() // This will call sharedBind.Close() which releases WireGuard's reference
		dev = nil
	}

	// Release the hole punch reference to the shared bind
	if sharedBind != nil {
		// Release hole punch reference (WireGuard already released its reference via dev.Close())
		logger.Debug("Releasing shared bind (refcount before release: %d)", sharedBind.GetRefCount())
		sharedBind.Release()
		sharedBind = nil
		logger.Info("Released shared UDP bind")
	}

	logger.Info("Olm service stopped")
}

// StopTunnel stops just the tunnel process and websocket connection
// without shutting down the entire application
func StopTunnel() error {
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

	Close()

	// Reset the connected state
	connected = false
	tunnelRunning = false

	// Update API server status
	apiServer.SetConnectionStatus(false)
	apiServer.SetRegistered(false)

	network.ClearNetworkSettings()

	logger.Info("Tunnel process stopped")

	return nil
}

func StopApi() error {
	if apiServer != nil {
		err := apiServer.Stop()
		if err != nil {
			return fmt.Errorf("failed to stop API server: %w", err)
		}
	}
	return nil
}

func StartApi() error {
	if apiServer != nil {
		err := apiServer.Start()
		if err != nil {
			return fmt.Errorf("failed to start API server: %w", err)
		}
	}
	return nil
}

func GetStatus() api.StatusResponse {
	return apiServer.GetStatus()
}

func SwitchOrg(orgID string) error {
	logger.Info("Processing org switch request to orgId: %s", orgID)

	// Ensure we have an active olmClient
	if olmClient == nil {
		return fmt.Errorf("no active connection to switch organizations")
	}

	// Update the orgID in the API server
	apiServer.SetOrgID(orgID)

	// Mark as not connected to trigger re-registration
	connected = false

	Close()

	// Clear peer statuses in API
	apiServer.SetRegistered(false)

	// Trigger re-registration with new orgId
	logger.Info("Re-registering with new orgId: %s", orgID)
	publicKey := privateKey.PublicKey()
	stopRegister = olmClient.SendMessageInterval("olm/wg/register", map[string]interface{}{
		"publicKey":  publicKey.String(),
		"relay":      true, // Default to relay mode for org switch
		"olmVersion": globalConfig.Version,
		"orgId":      orgID,
	}, 1*time.Second)

	return nil
}
