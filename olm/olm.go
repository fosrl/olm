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
	"github.com/fosrl/newt/clients/permissions"
	"github.com/fosrl/newt/holepunch"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/api"
	olmDevice "github.com/fosrl/olm/device"
	"github.com/fosrl/olm/dns"
	dnsOverride "github.com/fosrl/olm/dns/override"
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
	uapiListener     net.Listener
	tdev             tun.Device
	middleDev        *olmDevice.MiddleDevice
	interfaceName    string
	dnsProxy         *dns.DNSProxy
	apiServer        *api.API
	olmClient        *websocket.Client
	tunnelCancel     context.CancelFunc
	tunnelRunning    bool
	sharedBind       *bind.SharedBind
	holePunchManager *holepunch.Manager
	globalConfig     GlobalConfig
	tunnelConfig     TunnelConfig
	globalCtx        context.Context
	stopRegister     func()
	stopPeerSend     func()
	updateRegister   func(newData interface{})
	stopPing         chan struct{}
	peerManager      *peers.PeerManager
)

// initTunnelInfo creates the shared UDP socket and holepunch manager.
// This is used during initial tunnel setup and when switching organizations.
func initTunnelInfo(clientID string) error {
	var err error
	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Error("Failed to generate private key: %v", err)
		return err
	}

	sourcePort, err := util.FindAvailableUDPPort(49152, 65535)
	if err != nil {
		return fmt.Errorf("failed to find available UDP port: %w", err)
	}

	localAddr := &net.UDPAddr{
		Port: int(sourcePort),
		IP:   net.IPv4zero,
	}

	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}

	sharedBind, err = bind.New(udpConn)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("failed to create shared bind: %w", err)
	}

	// Add a reference for the hole punch senders (creator already has one reference for WireGuard)
	sharedBind.AddRef()

	logger.Info("Created shared UDP socket on port %d (refcount: %d)", sourcePort, sharedBind.GetRefCount())

	// Create the holepunch manager
	holePunchManager = holepunch.NewManager(sharedBind, clientID, "olm", privateKey.PublicKey().String())

	return nil
}

func Init(ctx context.Context, config GlobalConfig) {
	globalConfig = config
	globalCtx = ctx

	logger.GetLogger().SetLevel(util.ParseLogLevel(config.LogLevel))

	logger.Debug("Checking permissions for native interface")
	err := permissions.CheckNativeInterfacePermissions()
	if err != nil {
		logger.Fatal("Insufficient permissions to create native TUN interface: %v", err)
		return
	}

	if config.HTTPAddr != "" {
		apiServer = api.NewAPI(config.HTTPAddr)
	} else if config.SocketPath != "" {
		apiServer = api.NewAPISocket(config.SocketPath)
	} else {
		// this is so is not null but it cant be started without either the socket path or http addr
		apiServer = api.NewAPIStub()
	}

	apiServer.SetVersion(config.Version)
	apiServer.SetAgent(config.Agent)

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
			Close()
			if globalConfig.OnExit != nil {
				globalConfig.OnExit()
			}
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
	tunnelConfig = config

	// Reset terminated status when tunnel starts
	apiServer.SetTerminated(false)

	// debug print out the whole config
	logger.Debug("Starting tunnel with config: %+v", config)

	// Create a cancellable context for this tunnel process
	tunnelCtx, cancel := context.WithCancel(globalCtx)
	tunnelCancel = cancel
	defer func() {
		tunnelCancel = nil
	}()

	// Recreate channels for this tunnel session
	stopPing = make(chan struct{})

	var (
		id        = config.ID
		secret    = config.Secret
		userToken = config.UserToken
	)
	interfaceName = config.InterfaceName

	apiServer.SetOrgID(config.OrgID)

	// Create a new olm client using the provided credentials
	olm, err := websocket.NewClient(
		id,        // Use provided ID
		secret,    // Use provided secret
		userToken, // Use provided user token OPTIONAL
		config.OrgID,
		config.Endpoint, // Use provided endpoint
		config.PingIntervalDuration,
		config.PingTimeoutDuration,
	)
	if err != nil {
		logger.Error("Failed to create olm: %v", err)
		return
	}

	// Store the client reference globally
	olmClient = olm

	// Create shared UDP socket and holepunch manager
	if err := initTunnelInfo(id); err != nil {
		logger.Error("%v", err)
		return
	}

	olm.RegisterHandler("olm/wg/connect", func(msg websocket.WSMessage) {
		logger.Debug("Received message: %v", msg.Data)

		var wgData WgData

		if connected {
			logger.Info("Already connected. Ignoring new connection request.")
			return
		}

		if stopRegister != nil {
			stopRegister()
			stopRegister = nil
		}

		if updateRegister != nil {
			updateRegister = nil
		}

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

		// if config.FileDescriptorTun == 0 {
		if realInterfaceName, err2 := tdev.Name(); err2 == nil { // if the interface is defined then this should not really do anything?
			interfaceName = realInterfaceName
		}
		// }

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

		// Extract interface IP (strip CIDR notation if present)
		interfaceIP := wgData.TunnelIP
		if strings.Contains(interfaceIP, "/") {
			interfaceIP = strings.Split(interfaceIP, "/")[0]
		}

		// Create and start DNS proxy
		dnsProxy, err = dns.NewDNSProxy(middleDev, config.MTU, wgData.UtilitySubnet, config.UpstreamDNS, config.TunnelDNS, interfaceIP)
		if err != nil {
			logger.Error("Failed to create DNS proxy: %v", err)
		}

		if err = network.ConfigureInterface(interfaceName, wgData.TunnelIP, config.MTU); err != nil {
			logger.Error("Failed to configure interface: %v", err)
		}

		if network.AddRoutes([]string{wgData.UtilitySubnet}, interfaceName); err != nil { // also route the utility subnet
			logger.Error("Failed to add route for utility subnet: %v", err)
		}

		// Create peer manager with integrated peer monitoring
		peerManager = peers.NewPeerManager(peers.PeerManagerConfig{
			Device:        dev,
			DNSProxy:      dnsProxy,
			InterfaceName: interfaceName,
			PrivateKey:    privateKey,
			MiddleDev:     middleDev,
			LocalIP:       interfaceIP,
			SharedBind:    sharedBind,
			WSClient:      olm,
			APIServer:     apiServer,
		})

		for i := range wgData.Sites {
			site := wgData.Sites[i]
			var siteEndpoint string
			// here we are going to take the relay endpoint if it exists which means we requested a relay for this peer
			if site.RelayEndpoint != "" {
				siteEndpoint = site.RelayEndpoint
			} else {
				siteEndpoint = site.Endpoint
			}

			apiServer.AddPeerStatus(site.SiteId, site.Name, false, 0, siteEndpoint, false)

			if err := peerManager.AddPeer(site); err != nil {
				logger.Error("Failed to add peer: %v", err)
				return
			}

			logger.Info("Configured peer %s", site.PublicKey)
		}

		peerManager.Start()

		if err := dnsProxy.Start(); err != nil { // start DNS proxy first so there is no downtime
			logger.Error("Failed to start DNS proxy: %v", err)
		}

		if config.OverrideDNS {
			// Set up DNS override to use our DNS proxy
			if err := dnsOverride.SetupDNSOverride(interfaceName, dnsProxy); err != nil {
				logger.Error("Failed to setup DNS override: %v", err)
				return
			}
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
			logger.Warn("Peer with site ID %d not found", updateData.SiteId)
			return
		}

		// Create updated site config by merging with existing data
		siteConfig := existingPeer

		if updateData.Endpoint != "" {
			siteConfig.Endpoint = updateData.Endpoint
		}
		if updateData.RelayEndpoint != "" {
			siteConfig.RelayEndpoint = updateData.RelayEndpoint
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

		if err := peerManager.UpdatePeer(siteConfig); err != nil {
			logger.Error("Failed to update peer: %v", err)
			return
		}

		// If the endpoint changed, trigger holepunch to refresh NAT mappings
		if updateData.Endpoint != "" && updateData.Endpoint != existingPeer.Endpoint {
			logger.Info("Endpoint changed for site %d, triggering holepunch to refresh NAT mappings", updateData.SiteId)
			holePunchManager.TriggerHolePunch()
			holePunchManager.ResetInterval()
		}

		// Update successful
		logger.Info("Successfully updated peer for site %d", updateData.SiteId)
	})

	// Handler for adding a new peer
	olm.RegisterHandler("olm/wg/peer/add", func(msg websocket.WSMessage) {
		logger.Debug("Received add-peer message: %v", msg.Data)

		if stopPeerSend != nil {
			stopPeerSend()
			stopPeerSend = nil
		}

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

		holePunchManager.TriggerHolePunch() // Trigger immediate hole punch attempt so that if the peer decides to relay we have already punched close to when we need it

		if err := peerManager.AddPeer(siteConfig); err != nil {
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

		// Remove any exit nodes associated with this peer from hole punching
		if holePunchManager != nil {
			removed := holePunchManager.RemoveExitNodesByPeer(removeData.SiteId)
			if removed > 0 {
				logger.Info("Removed %d exit nodes associated with peer %d from hole punch rotation", removed, removeData.SiteId)
			}
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

		if _, exists := peerManager.GetPeer(addSubnetsData.SiteId); !exists {
			logger.Debug("Peer %d not found for removing remote subnets and aliases", addSubnetsData.SiteId)
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

		if _, exists := peerManager.GetPeer(removeSubnetsData.SiteId); !exists {
			logger.Debug("Peer %d not found for removing remote subnets and aliases", removeSubnetsData.SiteId)
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

		if _, exists := peerManager.GetPeer(updateSubnetsData.SiteId); !exists {
			logger.Debug("Peer %d not found for removing remote subnets and aliases", updateSubnetsData.SiteId)
			return
		}

		// Add new subnets BEFORE removing old ones to preserve shared subnets
		// This ensures that if an old and new subnet are the same on different peers,
		// the route won't be temporarily removed
		for _, subnet := range updateSubnetsData.NewRemoteSubnets {
			if err := peerManager.AddRemoteSubnet(updateSubnetsData.SiteId, subnet); err != nil {
				logger.Error("Failed to add allowed IP %s: %v", subnet, err)
			}
		}

		// Remove old subnets after new ones are added
		for _, subnet := range updateSubnetsData.OldRemoteSubnets {
			if err := peerManager.RemoveRemoteSubnet(updateSubnetsData.SiteId, subnet); err != nil {
				logger.Error("Failed to remove allowed IP %s: %v", subnet, err)
			}
		}

		// Add new aliases BEFORE removing old ones to preserve shared IP addresses
		// This ensures that if an old and new alias share the same IP, the IP won't be
		// temporarily removed from the allowed IPs list
		for _, alias := range updateSubnetsData.NewAliases {
			if err := peerManager.AddAlias(updateSubnetsData.SiteId, alias); err != nil {
				logger.Error("Failed to add alias %s: %v", alias.Alias, err)
			}
		}

		// Remove old aliases after new ones are added
		for _, alias := range updateSubnetsData.OldAliases {
			if err := peerManager.RemoveAlias(updateSubnetsData.SiteId, alias.Alias); err != nil {
				logger.Error("Failed to remove alias %s: %v", alias.Alias, err)
			}
		}

		logger.Info("Successfully updated remote subnets and aliases for peer %d", updateSubnetsData.SiteId)
	})

	olm.RegisterHandler("olm/wg/peer/relay", func(msg websocket.WSMessage) {
		logger.Debug("Received relay-peer message: %v", msg.Data)

		// Check if peerManager is still valid (may be nil during shutdown)
		if peerManager == nil {
			logger.Debug("Ignoring relay message: peerManager is nil (shutdown in progress)")
			return
		}

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

		primaryRelay, err := util.ResolveDomain(relayData.RelayEndpoint)
		if err != nil {
			logger.Warn("Failed to resolve primary relay endpoint: %v", err)
		}

		// Update HTTP server to mark this peer as using relay
		apiServer.UpdatePeerRelayStatus(relayData.SiteId, relayData.RelayEndpoint, true)

		peerManager.RelayPeer(relayData.SiteId, primaryRelay, relayData.RelayPort)
	})

	olm.RegisterHandler("olm/wg/peer/unrelay", func(msg websocket.WSMessage) {
		logger.Debug("Received unrelay-peer message: %v", msg.Data)

		// Check if peerManager is still valid (may be nil during shutdown)
		if peerManager == nil {
			logger.Debug("Ignoring unrelay message: peerManager is nil (shutdown in progress)")
			return
		}

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling data: %v", err)
			return
		}

		var relayData peers.UnRelayPeerData
		if err := json.Unmarshal(jsonData, &relayData); err != nil {
			logger.Error("Error unmarshaling relay data: %v", err)
			return
		}

		primaryRelay, err := util.ResolveDomain(relayData.Endpoint)
		if err != nil {
			logger.Warn("Failed to resolve primary relay endpoint: %v", err)
		}

		// Update HTTP server to mark this peer as using relay
		apiServer.UpdatePeerRelayStatus(relayData.SiteId, relayData.Endpoint, false)

		peerManager.UnRelayPeer(relayData.SiteId, primaryRelay)
	})

	// Handler for peer handshake - adds exit node to holepunch rotation and notifies server
	olm.RegisterHandler("olm/wg/peer/holepunch/site/add", func(msg websocket.WSMessage) {
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
		_, exists := peerManager.GetPeer(handshakeData.SiteId)
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

		added := holePunchManager.AddExitNode(exitNode)
		if added {
			logger.Info("Added exit node %s to holepunch rotation for handshake", exitNode.Endpoint)
		} else {
			logger.Debug("Exit node %s already in holepunch rotation", exitNode.Endpoint)
		}

		holePunchManager.TriggerHolePunch() // Trigger immediate hole punch attempt
		holePunchManager.ResetInterval()    // start sending immediately again so we fill in the endpoint on the cloud

		// Send handshake acknowledgment back to server with retry
		stopPeerSend, _ = olm.SendMessageInterval("olm/wg/server/peer/add", map[string]interface{}{
			"siteId": handshakeData.SiteId,
		}, 1*time.Second)

		logger.Info("Initiated handshake for site %d with exit node %s", handshakeData.SiteId, handshakeData.ExitNode.Endpoint)
	})

	olm.RegisterHandler("olm/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received terminate message")
		apiServer.SetTerminated(true)
		apiServer.SetConnectionStatus(false)
		apiServer.SetRegistered(false)
		apiServer.ClearPeerStatuses()
		network.ClearNetworkSettings()
		Close()

		if globalConfig.OnTerminated != nil {
			go globalConfig.OnTerminated()
		}
	})

	olm.RegisterHandler("pong", func(msg websocket.WSMessage) {
		logger.Debug("Received pong message")
	})

	olm.OnConnect(func() error {
		logger.Info("Websocket Connected")

		apiServer.SetConnectionStatus(true)

		if connected {
			logger.Debug("Already connected, skipping registration")
			return nil
		}

		publicKey := privateKey.PublicKey()

		// delay for 500ms to allow for time for the hp to get processed
		time.Sleep(500 * time.Millisecond)

		if stopRegister == nil {
			logger.Debug("Sending registration message to server with public key: %s and relay: %v", publicKey, !config.Holepunch)
			stopRegister, updateRegister = olm.SendMessageInterval("olm/wg/register", map[string]interface{}{
				"publicKey":  publicKey.String(),
				"relay":      !config.Holepunch,
				"olmVersion": globalConfig.Version,
				"olmAgent":   globalConfig.Agent,
				"orgId":      config.OrgID,
				"userToken":  userToken,
			}, 1*time.Second)

			// Invoke onRegistered callback if configured
			if globalConfig.OnRegistered != nil {
				go globalConfig.OnRegistered()
			}
		}

		go keepSendingPing(olm)

		return nil
	})

	olm.OnTokenUpdate(func(token string, exitNodes []websocket.ExitNode) {
		holePunchManager.SetToken(token)

		logger.Debug("Got exit nodes for hole punching: %v", exitNodes)

		// Convert websocket.ExitNode to holepunch.ExitNode
		hpExitNodes := make([]holepunch.ExitNode, len(exitNodes))
		for i, node := range exitNodes {
			relayPort := node.RelayPort
			if relayPort == 0 {
				relayPort = 21820 // default relay port
			}

			hpExitNodes[i] = holepunch.ExitNode{
				Endpoint:  node.Endpoint,
				RelayPort: relayPort,
				PublicKey: node.PublicKey,
				SiteIds:   node.SiteIds,
			}
		}

		logger.Debug("Updated hole punch exit nodes: %v", hpExitNodes)

		// Start hole punching using the manager
		logger.Info("Starting hole punch for %d exit nodes", len(exitNodes))
		if err := holePunchManager.StartMultipleExitNodes(hpExitNodes); err != nil {
			logger.Warn("Failed to start hole punch: %v", err)
		}
	})

	olm.OnAuthError(func(statusCode int, message string) {
		logger.Error("Authentication error (status %d): %s. Terminating tunnel.", statusCode, message)
		apiServer.SetTerminated(true)
		apiServer.SetConnectionStatus(false)
		apiServer.SetRegistered(false)
		apiServer.ClearPeerStatuses()
		network.ClearNetworkSettings()

		Close()

		if globalConfig.OnAuthError != nil {
			go globalConfig.OnAuthError(statusCode, message)
		}

		if globalConfig.OnTerminated != nil {
			go globalConfig.OnTerminated()
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

func AddDevice(fd uint32) error {
	if middleDev == nil {
		return fmt.Errorf("middle device is not initialized")
	}

	if tunnelConfig.MTU == 0 {
		// error
		return fmt.Errorf("tunnel MTU is not set")
	}

	tdev, err := olmDevice.CreateTUNFromFD(fd, tunnelConfig.MTU)

	if err != nil {
		return fmt.Errorf("failed to create TUN device from fd: %v", err)
	}

	// if config.FileDescriptorTun == 0 {
	if realInterfaceName, err2 := tdev.Name(); err2 == nil { // if the interface is defined then this should not really do anything?
		interfaceName = realInterfaceName
	}

	// Here we replace the existing TUN device in the middle device with the new one
	middleDev.AddDevice(tdev)
	
	return nil
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

	if updateRegister != nil {
		updateRegister = nil
	}

	if peerManager != nil {
		peerManager.Close() // Close() also calls Stop() internally
		peerManager = nil
	}

	if uapiListener != nil {
		uapiListener.Close()
		uapiListener = nil
	}

	// Stop DNS proxy first - it uses the middleDev for packet filtering
	logger.Debug("Stopping DNS proxy")
	if dnsProxy != nil {
		dnsProxy.Stop()
		dnsProxy = nil
	}

	// Close MiddleDevice first - this closes the TUN and signals the closed channel
	// This unblocks the pump goroutine and allows WireGuard's TUN reader to exit
	logger.Debug("Closing MiddleDevice")
	if middleDev != nil {
		middleDev.Close()
		middleDev = nil
	}
	// Note: tdev is closed by middleDev.Close() since middleDev wraps it
	tdev = nil

	// Now close WireGuard device - its TUN reader should have exited by now
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
	apiServer.ClearPeerStatuses()

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
	// stop the tunnel
	if err := StopTunnel(); err != nil {
		return fmt.Errorf("failed to stop existing tunnel: %w", err)
	}

	// Update the org ID in the API server and global config
	apiServer.SetOrgID(orgID)

	tunnelConfig.OrgID = orgID

	// Restart the tunnel with the same config but new org ID
	go StartTunnel(tunnelConfig)

	return nil
}
