package olm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/fosrl/newt/bind"
	"github.com/fosrl/newt/holepunch"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/api"
	middleDevice "github.com/fosrl/olm/device"
	"github.com/fosrl/olm/dns"
	"github.com/fosrl/olm/network"
	"github.com/fosrl/olm/peermonitor"
	"github.com/fosrl/olm/websocket"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type GlobalConfig struct {
	// Logging
	LogLevel string

	// HTTP server
	EnableAPI  bool
	HTTPAddr   string
	SocketPath string
	Version    string

	// Callbacks
	OnRegistered func()
	OnConnected  func()

	// Source tracking (not in JSON)
	sources map[string]string
}

type TunnelConfig struct {
	// Connection settings
	Endpoint  string
	ID        string
	Secret    string
	UserToken string

	// Network settings
	MTU           int
	DNS           string
	DNSProxyIP    string
	UpstreamDNS   []string
	InterfaceName string

	// Advanced
	Holepunch     bool
	TlsClientCert string

	// Parsed values (not in JSON)
	PingIntervalDuration time.Duration
	PingTimeoutDuration  time.Duration

	OrgID string
	// DoNotCreateNewClient bool

	FileDescriptorTun  uint32
	FileDescriptorUAPI uint32
}

var (
	privateKey       wgtypes.Key
	connected        bool
	dev              *device.Device
	wgData           WgData
	holePunchData    HolePunchData
	uapiListener     net.Listener
	tdev             tun.Device
	middleDev        *middleDevice.MiddleDevice
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
				DNSProxyIP:    req.DNSProxyIP,
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
				tunnelConfig.UpstreamDNS = []string{"8.8.8.8"}
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
			logger.Info("Processing org switch request to orgId: %s", req.OrgID)

			// Ensure we have an active olmClient
			if olmClient == nil {
				return fmt.Errorf("no active connection to switch organizations")
			}

			// Update the orgID in the API server
			apiServer.SetOrgID(req.OrgID)

			// Mark as not connected to trigger re-registration
			connected = false

			Close()

			// Clear peer statuses in API
			apiServer.SetRegistered(false)
			apiServer.SetTunnelIP("")

			// Trigger re-registration with new orgId
			logger.Info("Re-registering with new orgId: %s", req.OrgID)
			publicKey := privateKey.PublicKey()
			stopRegister = olmClient.SendMessageInterval("olm/wg/register", map[string]interface{}{
				"publicKey":  publicKey.String(),
				"relay":      true, // Default to relay mode for org switch
				"olmVersion": globalConfig.Version,
				"orgId":      req.OrgID,
			}, 1*time.Second)

			return nil
		},
		// onDisconnect
		func() error {
			logger.Info("Processing disconnect request via API")
			StopTunnel()
			return nil
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
				return createTUNFromFD(config.FileDescriptorTun, config.MTU)
			}
			var ifName = interfaceName
			if runtime.GOOS == "darwin" { // this is if we dont pass a fd
				ifName, err = findUnusedUTUN()
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

		// fileUAPI, err := func() (*os.File, error) {
		// 	if config.FileDescriptorUAPI != 0 {
		// 		fd, err := strconv.ParseUint(fmt.Sprintf("%d", config.FileDescriptorUAPI), 10, 32)
		// 		if err != nil {
		// 			return nil, fmt.Errorf("invalid UAPI file descriptor: %v", err)
		// 		}
		// 		return os.NewFile(uintptr(fd), ""), nil
		// 	}
		// 	return uapiOpen(interfaceName)
		// }()
		// if err != nil {
		// 	logger.Error("UAPI listen error: %v", err)
		// 	os.Exit(1)
		// 	return
		// }

		// Wrap TUN device with packet filter for DNS proxy
		middleDev = middleDevice.NewMiddleDevice(tdev)

		wgLogger := logger.GetLogger().GetWireGuardLogger("wireguard: ")
		// Use filtered device instead of raw TUN device
		dev = device.NewDevice(middleDev, sharedBind, (*device.Logger)(wgLogger))

		// uapiListener, err = uapiListen(interfaceName, fileUAPI)
		// if err != nil {
		// 	logger.Error("Failed to listen on uapi socket: %v", err)
		// 	os.Exit(1)
		// }

		// go func() {
		// 	for {
		// 		conn, err := uapiListener.Accept()
		// 		if err != nil {

		// 			return
		// 		}
		// 		go dev.IpcHandle(conn)
		// 	}
		// }()
		// logger.Info("UAPI listener started")

		if err = dev.Up(); err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}

		if config.DNSProxyIP != "" {
			// Create and start DNS proxy
			dnsProxy, err = dns.NewDNSProxy(tdev, middleDev, config.MTU, config.DNSProxyIP, config.UpstreamDNS)
			if err != nil {
				logger.Error("Failed to create DNS proxy: %v", err)
			}

			if err := dnsProxy.Start(); err != nil {
				logger.Error("Failed to start DNS proxy: %v", err)
			}
		}

		if err = ConfigureInterface(interfaceName, wgData, config.MTU); err != nil {
			logger.Error("Failed to configure interface: %v", err)
		}

		if config.DNSProxyIP != "" {
			if addRoutes([]string{config.DNSProxyIP + "/32"}, interfaceName); err != nil {
				logger.Error("Failed to add route for DNS server: %v", err)
			}
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

		for i := range wgData.Sites {
			site := &wgData.Sites[i] // Use a pointer to modify the struct in the slice
			apiServer.UpdatePeerStatus(site.SiteId, false, 0, site.Endpoint, false)

			// Format the endpoint before configuring the peer.
			site.Endpoint = formatEndpoint(site.Endpoint)

			if err := ConfigurePeer(dev, *site, privateKey, endpoint); err != nil {
				logger.Error("Failed to configure peer: %v", err)
				return
			}
			if err := addRouteForServerIP(site.ServerIP, interfaceName); err != nil { // this is something for darwin only thats required
				logger.Error("Failed to add route for peer: %v", err)
				return
			}
			if err := addRoutes(site.RemoteSubnets, interfaceName); err != nil {
				logger.Error("Failed to add routes for remote subnets: %v", err)
				return
			}

			for _, alias := range site.Aliases {
				if dnsProxy != nil { // some times this is not initialized
					// try to parse the alias address into net.IP
					address := net.ParseIP(alias.AliasAddress)
					if address == nil {
						logger.Warn("Invalid alias address for %s: %s", alias.Alias, alias.AliasAddress)
						continue
					}

					dnsProxy.AddDNSRecord(alias.Alias, address)
				}
			}

			logger.Info("Configured peer %s", site.PublicKey)
		}

		peerMonitor.Start()

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

		var updateData SiteConfig
		if err := json.Unmarshal(jsonData, &updateData); err != nil {
			logger.Error("Error unmarshaling update data: %v", err)
			return
		}

		// Update the peer in WireGuard
		if dev == nil {
			logger.Error("WireGuard device not initialized")
			return
		}

		// Find the existing peer to merge updates with
		var existingPeer *SiteConfig
		var peerIndex int
		for i, site := range wgData.Sites {
			if site.SiteId == updateData.SiteId {
				existingPeer = &wgData.Sites[i]
				peerIndex = i
				break
			}
		}

		if existingPeer == nil {
			logger.Error("Peer with site ID %d not found", updateData.SiteId)
			return
		}

		// Store old values for comparison
		oldRemoteSubnets := existingPeer.RemoteSubnets
		oldPublicKey := existingPeer.PublicKey

		// Create updated site config by merging with existing data
		// Only update fields that are provided (non-empty/non-zero)
		siteConfig := *existingPeer // Start with existing data

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

		// If the public key has changed, remove the old peer first
		if siteConfig.PublicKey != oldPublicKey {
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

		// Handle remote subnet route changes
		if !stringSlicesEqual(oldRemoteSubnets, siteConfig.RemoteSubnets) {
			if err := removeRoutesForRemoteSubnets(oldRemoteSubnets); err != nil {
				logger.Error("Failed to remove old remote subnet routes: %v", err)
				// Continue anyway to add new routes
			}

			// Add new remote subnet routes
			if err := addRoutes(siteConfig.RemoteSubnets, interfaceName); err != nil {
				logger.Error("Failed to add new remote subnet routes: %v", err)
				return
			}
		}

		// Update successful
		logger.Info("Successfully updated peer for site %d", updateData.SiteId)
		wgData.Sites[peerIndex] = siteConfig
	})

	// Handler for adding a new peer
	olm.RegisterHandler("olm/wg/peer/add", func(msg websocket.WSMessage) {
		logger.Debug("Received add-peer message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var siteConfig SiteConfig
		if err := json.Unmarshal(jsonData, &siteConfig); err != nil {
			logger.Error("Error unmarshaling add data: %v", err)
			return
		}

		// Add the peer to WireGuard
		if dev == nil {
			logger.Error("WireGuard device not initialized")
			return
		}
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
		if err := addRoutes(siteConfig.RemoteSubnets, interfaceName); err != nil {
			logger.Error("Failed to add routes for remote subnets: %v", err)
			return
		}

		// Add successful
		logger.Info("Successfully added peer for site %d", siteConfig.SiteId)

		// Update WgData with the new peer
		wgData.Sites = append(wgData.Sites, siteConfig)
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
		if dev == nil {
			logger.Error("WireGuard device not initialized")
			return
		}
		if err := RemovePeer(dev, removeData.SiteId, peerToRemove.PublicKey); err != nil {
			logger.Error("Failed to remove peer: %v", err)
			// Send error response if needed
			return
		}

		// Remove route for the peer
		err = removeRouteForServerIP(peerToRemove.ServerIP, interfaceName)
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
	})

	// Handler for adding remote subnets to a peer
	olm.RegisterHandler("olm/wg/peer/add-remote-subnets", func(msg websocket.WSMessage) {
		logger.Debug("Received add-remote-subnets message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var addSubnetsData AddRemoteSubnetsData
		if err := json.Unmarshal(jsonData, &addSubnetsData); err != nil {
			logger.Error("Error unmarshaling add-remote-subnets data: %v", err)
			return
		}

		// Find the peer to update
		var peerIndex = -1
		for i, site := range wgData.Sites {
			if site.SiteId == addSubnetsData.SiteId {
				peerIndex = i
				break
			}
		}

		if peerIndex == -1 {
			logger.Error("Peer with site ID %d not found", addSubnetsData.SiteId)
			return
		}

		// Add new subnets to the peer's remote subnets (avoiding duplicates)
		existingSubnets := make(map[string]bool)
		for _, subnet := range wgData.Sites[peerIndex].RemoteSubnets {
			existingSubnets[subnet] = true
		}

		var newSubnets []string
		for _, subnet := range addSubnetsData.RemoteSubnets {
			if !existingSubnets[subnet] {
				newSubnets = append(newSubnets, subnet)
				wgData.Sites[peerIndex].RemoteSubnets = append(wgData.Sites[peerIndex].RemoteSubnets, subnet)
			}
		}

		if len(newSubnets) == 0 {
			logger.Info("No new subnets to add for site %d (all already exist)", addSubnetsData.SiteId)
			return
		}

		// Add routes for the new subnets
		if err := addRoutes(newSubnets, interfaceName); err != nil {
			logger.Error("Failed to add routes for new remote subnets: %v", err)
			return
		}

		logger.Info("Successfully added %d remote subnet(s) to peer %d", len(newSubnets), addSubnetsData.SiteId)
	})

	// Handler for removing remote subnets from a peer
	olm.RegisterHandler("olm/wg/peer/remove-remote-subnets", func(msg websocket.WSMessage) {
		logger.Debug("Received remove-remote-subnets message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var removeSubnetsData RemoveRemoteSubnetsData
		if err := json.Unmarshal(jsonData, &removeSubnetsData); err != nil {
			logger.Error("Error unmarshaling remove-remote-subnets data: %v", err)
			return
		}

		// Find the peer to update
		var peerIndex = -1
		for i, site := range wgData.Sites {
			if site.SiteId == removeSubnetsData.SiteId {
				peerIndex = i
				break
			}
		}

		if peerIndex == -1 {
			logger.Error("Peer with site ID %d not found", removeSubnetsData.SiteId)
			return
		}

		// Create a map of subnets to remove for quick lookup
		subnetsToRemove := make(map[string]bool)
		for _, subnet := range removeSubnetsData.RemoteSubnets {
			subnetsToRemove[subnet] = true
		}

		// Filter out the subnets to remove
		var updatedSubnets []string
		var removedSubnets []string
		for _, subnet := range wgData.Sites[peerIndex].RemoteSubnets {
			if subnetsToRemove[subnet] {
				removedSubnets = append(removedSubnets, subnet)
			} else {
				updatedSubnets = append(updatedSubnets, subnet)
			}
		}

		if len(removedSubnets) == 0 {
			logger.Info("No subnets to remove for site %d (none matched)", removeSubnetsData.SiteId)
			return
		}

		// Remove routes for the removed subnets
		if err := removeRoutesForRemoteSubnets(removedSubnets); err != nil {
			logger.Error("Failed to remove routes for remote subnets: %v", err)
			return
		}

		// Update the peer's remote subnets
		wgData.Sites[peerIndex].RemoteSubnets = updatedSubnets

		logger.Info("Successfully removed %d remote subnet(s) from peer %d", len(removedSubnets), removeSubnetsData.SiteId)
	})

	// Handler for updating remote subnets of a peer (remove old, add new in one operation)
	olm.RegisterHandler("olm/wg/peer/update-remote-subnets", func(msg websocket.WSMessage) {
		logger.Debug("Received update-remote-subnets message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var updateSubnetsData UpdateRemoteSubnetsData
		if err := json.Unmarshal(jsonData, &updateSubnetsData); err != nil {
			logger.Error("Error unmarshaling update-remote-subnets data: %v", err)
			return
		}

		// Find the peer to update
		var peerIndex = -1
		for i, site := range wgData.Sites {
			if site.SiteId == updateSubnetsData.SiteId {
				peerIndex = i
				break
			}
		}

		if peerIndex == -1 {
			logger.Error("Peer with site ID %d not found", updateSubnetsData.SiteId)
			return
		}

		// First, remove routes for old subnets
		if len(updateSubnetsData.OldRemoteSubnets) > 0 {
			if err := removeRoutesForRemoteSubnets(updateSubnetsData.OldRemoteSubnets); err != nil {
				logger.Error("Failed to remove routes for old remote subnets: %v", err)
				return
			}
			logger.Info("Removed %d old remote subnet(s) from peer %d", len(updateSubnetsData.OldRemoteSubnets), updateSubnetsData.SiteId)
		}

		// Then, add routes for new subnets
		if len(updateSubnetsData.NewRemoteSubnets) > 0 {
			if err := addRoutes(updateSubnetsData.NewRemoteSubnets, interfaceName); err != nil {
				logger.Error("Failed to add routes for new remote subnets: %v", err)
				// Attempt to rollback by re-adding old routes
				if rollbackErr := addRoutes(updateSubnetsData.OldRemoteSubnets, interfaceName); rollbackErr != nil {
					logger.Error("Failed to rollback old routes: %v", rollbackErr)
				}
				return
			}
			logger.Info("Added %d new remote subnet(s) to peer %d", len(updateSubnetsData.NewRemoteSubnets), updateSubnetsData.SiteId)
		}

		// Finally, update the peer's remote subnets in wgData
		wgData.Sites[peerIndex].RemoteSubnets = updateSubnetsData.NewRemoteSubnets

		logger.Info("Successfully updated remote subnets for peer %d (removed %d, added %d)",
			updateSubnetsData.SiteId, len(updateSubnetsData.OldRemoteSubnets), len(updateSubnetsData.NewRemoteSubnets))
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

	Close()

	// Reset the connected state
	connected = false
	tunnelRunning = false

	// Update API server status
	apiServer.SetConnectionStatus(false)
	apiServer.SetRegistered(false)
	apiServer.SetTunnelIP("")

	network.ClearNetworkSettings()

	logger.Info("Tunnel process stopped")
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
