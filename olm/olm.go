package olm

import (
	"context"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
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

type Olm struct {
	privateKey wgtypes.Key
	logFile    *os.File

	connected     bool
	tunnelRunning bool

	uapiListener net.Listener
	dev          *device.Device
	tdev         tun.Device
	middleDev    *olmDevice.MiddleDevice
	sharedBind   *bind.SharedBind

	dnsProxy         *dns.DNSProxy
	apiServer        *api.API
	websocket        *websocket.Client
	holePunchManager *holepunch.Manager
	peerManager      *peers.PeerManager
	// Power mode management
	currentPowerMode string
	powerModeMu      sync.Mutex
	wakeUpTimer      *time.Timer
	wakeUpDebounce   time.Duration

	olmCtx       context.Context
	tunnelCancel context.CancelFunc

	olmConfig    OlmConfig
	tunnelConfig TunnelConfig

	// Metadata to send alongside pings
	fingerprint map[string]any
	postures    map[string]any
	metaMu      sync.Mutex

	stopRegister   func()
	updateRegister func(newData any)

	stopServerPing func()

	stopPeerSend func()
}

// initTunnelInfo creates the shared UDP socket and holepunch manager.
// This is used during initial tunnel setup and when switching organizations.
func (o *Olm) initTunnelInfo(clientID string) error {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Error("Failed to generate private key: %v", err)
		return err
	}

	o.privateKey = privateKey

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

	sharedBind, err := bind.New(udpConn)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("failed to create shared bind: %w", err)
	}

	o.sharedBind = sharedBind

	// Add a reference for the hole punch senders (creator already has one reference for WireGuard)
	sharedBind.AddRef()

	logger.Info("Created shared UDP socket on port %d (refcount: %d)", sourcePort, sharedBind.GetRefCount())

	// Create the holepunch manager
	o.holePunchManager = holepunch.NewManager(sharedBind, clientID, "olm", privateKey.PublicKey().String())

	return nil
}

func Init(ctx context.Context, config OlmConfig) (*Olm, error) {
	logger.GetLogger().SetLevel(util.ParseLogLevel(config.LogLevel))

	// Start pprof server if enabled
	if config.PprofAddr != "" {
		go func() {
			logger.Info("Starting pprof server on %s", config.PprofAddr)
			if err := http.ListenAndServe(config.PprofAddr, nil); err != nil {
				logger.Error("Failed to start pprof server: %v", err)
			}
		}()
	}

	var logFile *os.File
	if config.LogFilePath != "" {
		file, err := os.OpenFile(config.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			logger.Fatal("Failed to open log file: %v", err)
			return nil, err
		}

		logger.SetOutput(file)
		logFile = file
	}

	if config.WakeUpDebounce == 0 {
		config.WakeUpDebounce = 3 * time.Second
	}

	logger.Debug("Checking permissions for native interface")
	err := permissions.CheckNativeInterfacePermissions()
	if err != nil {
		logger.Fatal("Insufficient permissions to create native TUN interface: %v", err)
		return nil, err
	}

	var apiServer *api.API
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

	newOlm := &Olm{
		logFile:   logFile,
		olmCtx:    ctx,
		apiServer: apiServer,
		olmConfig: config,
	}

	newOlm.registerAPICallbacks()

	return newOlm, nil
}

func (o *Olm) registerAPICallbacks() {
	o.apiServer.SetHandlers(
		// onConnect
		func(req api.ConnectionRequest) error {
			logger.Info("Received connection request via HTTP: id=%s, endpoint=%s", req.ID, req.Endpoint)

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
				go o.StartTunnel(tunnelConfig)
			}

			return nil
		},
		// onSwitchOrg
		func(req api.SwitchOrgRequest) error {
			logger.Info("Received switch organization request via HTTP: orgID=%s", req.OrgID)
			return o.SwitchOrg(req.OrgID)
		},
		// onMetadataChange
		func(req api.MetadataChangeRequest) error {
			logger.Info("Received change metadata request via API")

			if req.Fingerprint != nil {
				o.SetFingerprint(req.Fingerprint)
			}

			if req.Postures != nil {
				o.SetPostures(req.Postures)
			}

			return nil
		},
		// onDisconnect
		func() error {
			logger.Info("Processing disconnect request via API")
			return o.StopTunnel()
		},
		// onExit
		func() error {
			logger.Info("Processing shutdown request via API")
			o.Close()
			if o.olmConfig.OnExit != nil {
				o.olmConfig.OnExit()
			}
			return nil
		},
	)
}

func (o *Olm) StartTunnel(config TunnelConfig) {
	if o.tunnelRunning {
		logger.Info("Tunnel already running")
		return
	}

	o.tunnelRunning = true // Also set it here in case it is called externally
	o.tunnelConfig = config

	// Reset terminated status when tunnel starts
	o.apiServer.SetTerminated(false)

	// debug print out the whole config
	logger.Debug("Starting tunnel with config: %+v", config)

	// Create a cancellable context for this tunnel process
	tunnelCtx, cancel := context.WithCancel(o.olmCtx)
	o.tunnelCancel = cancel

	var (
		id        = config.ID
		secret    = config.Secret
		userToken = config.UserToken
	)

	o.tunnelConfig.InterfaceName = config.InterfaceName

	o.apiServer.SetOrgID(config.OrgID)

	// Create a new olmClient client using the provided credentials
	olmClient, err := websocket.NewClient(
		id,
		secret,
		userToken,
		config.OrgID,
		config.Endpoint,
		config.PingIntervalDuration,
		config.PingTimeoutDuration,
	)
	if err != nil {
		logger.Error("Failed to create olm: %v", err)
		return
	}

	// Create shared UDP socket and holepunch manager
	if err := o.initTunnelInfo(id); err != nil {
		logger.Error("%v", err)
		return
	}

	// Handlers for managing connection status
	olmClient.RegisterHandler("olm/wg/connect", o.handleConnect)
	olmClient.RegisterHandler("olm/terminate", o.handleTerminate)

	// Handlers for managing peers
	olmClient.RegisterHandler("olm/wg/peer/add", o.handleWgPeerAdd)
	olmClient.RegisterHandler("olm/wg/peer/remove", o.handleWgPeerRemove)
	olmClient.RegisterHandler("olm/wg/peer/update", o.handleWgPeerUpdate)
	olmClient.RegisterHandler("olm/wg/peer/relay", o.handleWgPeerRelay)
	olmClient.RegisterHandler("olm/wg/peer/unrelay", o.handleWgPeerUnrelay)

	// Handlers for managing remote subnets to a peer
	olmClient.RegisterHandler("olm/wg/peer/data/add", o.handleWgPeerAddData)
	olmClient.RegisterHandler("olm/wg/peer/data/remove", o.handleWgPeerRemoveData)
	olmClient.RegisterHandler("olm/wg/peer/data/update", o.handleWgPeerUpdateData)

	// Handler for peer handshake - adds exit node to holepunch rotation and notifies server
	olmClient.RegisterHandler("olm/wg/peer/holepunch/site/add", o.handleWgPeerHolepunchAddSite)

	olmClient.OnConnect(func() error {
		logger.Info("Websocket Connected")

		o.apiServer.SetConnectionStatus(true)

		// restart the ping if we need to
		if o.stopServerPing == nil {
			o.stopServerPing, _ = olmClient.SendMessageInterval("olm/ping", map[string]any{
				"timestamp": time.Now().Unix(),
				"userToken": olmClient.GetConfig().UserToken,
			}, 30*time.Second, -1) // -1 means dont time out with the max attempts
		}

		if o.connected {
			logger.Debug("Already connected, skipping registration")
			return nil
		}

		publicKey := o.privateKey.PublicKey()

		// delay for 500ms to allow for time for the hp to get processed
		time.Sleep(500 * time.Millisecond)

		if o.stopRegister == nil {
			logger.Debug("Sending registration message to server with public key: %s and relay: %v", publicKey, !config.Holepunch)
			o.stopRegister, o.updateRegister = olmClient.SendMessageInterval("olm/wg/register", map[string]any{
				"publicKey":   publicKey.String(),
				"relay":       !config.Holepunch,
				"olmVersion":  o.olmConfig.Version,
				"olmAgent":    o.olmConfig.Agent,
				"orgId":       config.OrgID,
				"userToken":   userToken,
				"fingerprint": o.fingerprint,
				"postures":    o.postures,
			}, 1*time.Second, 10)

			// Invoke onRegistered callback if configured
			if o.olmConfig.OnRegistered != nil {
				go o.olmConfig.OnRegistered()
			}
		}

		return nil
	})

	olmClient.OnTokenUpdate(func(token string, exitNodes []websocket.ExitNode) {
		o.holePunchManager.SetToken(token)

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
		if err := o.holePunchManager.StartMultipleExitNodes(hpExitNodes); err != nil {
			logger.Warn("Failed to start hole punch: %v", err)
		}
	})

	olmClient.OnAuthError(func(statusCode int, message string) {
		logger.Error("Authentication error (status %d): %s. Terminating tunnel.", statusCode, message)
		o.apiServer.SetTerminated(true)
		o.apiServer.SetConnectionStatus(false)
		o.apiServer.SetRegistered(false)
		o.apiServer.ClearPeerStatuses()
		network.ClearNetworkSettings()

		o.Close()

		if o.olmConfig.OnAuthError != nil {
			go o.olmConfig.OnAuthError(statusCode, message)
		}

		if o.olmConfig.OnTerminated != nil {
			go o.olmConfig.OnTerminated()
		}
	})

	fingerprint := config.InitialFingerprint
	if fingerprint == nil {
		fingerprint = make(map[string]any)
	}

	postures := config.InitialPostures
	if postures == nil {
		postures = make(map[string]any)
	}

	o.SetFingerprint(fingerprint)
	o.SetPostures(postures)

	// Connect to the WebSocket server
	if err := olmClient.Connect(); err != nil {
		logger.Error("Failed to connect to server: %v", err)
		return
	}
	defer func() { _ = olmClient.Close() }()

	o.websocket = olmClient

	// Wait for context cancellation
	<-tunnelCtx.Done()
	logger.Info("Tunnel process context cancelled, cleaning up")
}

func (o *Olm) Close() {
	// Restore original DNS configuration
	// we do this first to avoid any DNS issues if something else gets stuck
	if err := dnsOverride.RestoreDNSOverride(); err != nil {
		logger.Error("Failed to restore DNS: %v", err)
	}

	if o.holePunchManager != nil {
		o.holePunchManager.Stop()
		o.holePunchManager = nil
	}

	if o.stopServerPing != nil {
		o.stopServerPing()
		o.stopServerPing = nil
	}

	if o.stopRegister != nil {
		o.stopRegister()
		o.stopRegister = nil
	}

	// Close() also calls Stop() internally
	if o.peerManager != nil {
		o.peerManager.Close()
		o.peerManager = nil
	}

	if o.uapiListener != nil {
		_ = o.uapiListener.Close()
		o.uapiListener = nil
	}

	if o.logFile != nil {
		_ = o.logFile.Close()
		o.logFile = nil
	}

	// Stop DNS proxy first - it uses the middleDev for packet filtering
	if o.dnsProxy != nil {
		logger.Debug("Stopping DNS proxy")
		o.dnsProxy.Stop()
		o.dnsProxy = nil
	}

	// Close MiddleDevice first - this closes the TUN and signals the closed channel
	// This unblocks the pump goroutine and allows WireGuard's TUN reader to exit
	// Note: o.tdev is closed by o.middleDev.Close() since middleDev wraps it
	if o.middleDev != nil {
		logger.Debug("Closing MiddleDevice")
		_ = o.middleDev.Close()
		o.middleDev = nil
	}

	// Now close WireGuard device - its TUN reader should have exited by now
	// This will call sharedBind.Close() which releases WireGuard's reference
	if o.dev != nil {
		logger.Debug("Closing WireGuard device")
		o.dev.Close()
		o.dev = nil
	}

	// Release the hole punch reference to the shared bind (WireGuard already
	// released its reference via dev.Close())
	if o.sharedBind != nil {
		logger.Debug("Releasing shared bind (refcount before release: %d)", o.sharedBind.GetRefCount())
		_ = o.sharedBind.Release()
		logger.Info("Released shared UDP bind")
		o.sharedBind = nil
	}

	logger.Info("Olm service stopped")
}

// StopTunnel stops just the tunnel process and websocket connection
// without shutting down the entire application
func (o *Olm) StopTunnel() error {
	logger.Info("Stopping tunnel process")

	if !o.tunnelRunning {
		logger.Debug("Tunnel not running, nothing to stop")
		return nil
	}

	// Cancel the tunnel context if it exists
	if o.tunnelCancel != nil {
		o.tunnelCancel()
		// Give it a moment to clean up
		time.Sleep(200 * time.Millisecond)
	}

	// Close the websocket connection
	if o.websocket != nil {
		_ = o.websocket.Close()
		o.websocket = nil
	}

	o.Close()

	// Reset the connected state
	o.connected = false
	o.tunnelRunning = false

	// Update API server status
	o.apiServer.SetConnectionStatus(false)
	o.apiServer.SetRegistered(false)

	network.ClearNetworkSettings()
	o.apiServer.ClearPeerStatuses()

	logger.Info("Tunnel process stopped")

	return nil
}

func (o *Olm) StopApi() error {
	if o.apiServer != nil {
		err := o.apiServer.Stop()
		if err != nil {
			return fmt.Errorf("failed to stop API server: %w", err)
		}
	}

	return nil
}

func (o *Olm) StartApi() error {
	if o.apiServer != nil {
		err := o.apiServer.Start()
		if err != nil {
			return fmt.Errorf("failed to start API server: %w", err)
		}
	}

	return nil
}

func (o *Olm) GetStatus() api.StatusResponse {
	return o.apiServer.GetStatus()
}

func (o *Olm) SwitchOrg(orgID string) error {
	logger.Info("Processing org switch request to orgId: %s", orgID)
	// stop the tunnel
	if err := o.StopTunnel(); err != nil {
		return fmt.Errorf("failed to stop existing tunnel: %w", err)
	}

	// Update the org ID in the API server and global config
	o.apiServer.SetOrgID(orgID)

	o.tunnelConfig.OrgID = orgID

	// Restart the tunnel with the same config but new org ID
	go o.StartTunnel(o.tunnelConfig)

	return nil
}

func (o *Olm) SetFingerprint(data map[string]any) {
	o.metaMu.Lock()
	defer o.metaMu.Unlock()

	o.fingerprint = data
}

func (o *Olm) SetPostures(data map[string]any) {
	o.metaMu.Lock()
	defer o.metaMu.Unlock()

	o.postures = data
}

// SetPowerMode switches between normal and low power modes
// In low power mode: websocket is closed (stopping pings) and monitoring intervals are set to 10 minutes
// In normal power mode: websocket is reconnected (restarting pings) and monitoring intervals are restored
// Wake-up has a 3-second debounce to prevent rapid flip-flopping; sleep is immediate
func (o *Olm) SetPowerMode(mode string) error {
	// Validate mode
	if mode != "normal" && mode != "low" {
		return fmt.Errorf("invalid power mode: %s (must be 'normal' or 'low')", mode)
	}

	o.powerModeMu.Lock()
	defer o.powerModeMu.Unlock()

	// If already in the requested mode, return early
	if o.currentPowerMode == mode {
		// Cancel any pending wake-up timer if we're already in normal mode
		if mode == "normal" && o.wakeUpTimer != nil {
			o.wakeUpTimer.Stop()
			o.wakeUpTimer = nil
		}
		logger.Debug("Already in %s power mode", mode)
		return nil
	}

	if mode == "low" {
		// Low Power Mode: Cancel any pending wake-up and immediately go to sleep

		// Cancel pending wake-up timer if any
		if o.wakeUpTimer != nil {
			logger.Debug("Cancelling pending wake-up timer")
			o.wakeUpTimer.Stop()
			o.wakeUpTimer = nil
		}

		logger.Info("Switching to low power mode")

		if o.websocket != nil {
			logger.Info("Disconnecting websocket for low power mode")
			if err := o.websocket.Disconnect(); err != nil {
				logger.Error("Error disconnecting websocket: %v", err)
			}
		}

		lowPowerInterval := 10 * time.Minute
		
		if o.peerManager != nil {
			peerMonitor := o.peerManager.GetPeerMonitor()
			if peerMonitor != nil {
				peerMonitor.SetPeerInterval(lowPowerInterval, lowPowerInterval)
				peerMonitor.SetPeerHolepunchInterval(lowPowerInterval, lowPowerInterval)
				logger.Info("Set monitoring intervals to 10 minutes for low power mode")
			}
			o.peerManager.UpdateAllPeersPersistentKeepalive(0) // disable
		}

		if o.holePunchManager != nil {
			o.holePunchManager.SetServerHolepunchInterval(lowPowerInterval, lowPowerInterval)
		}

		o.currentPowerMode = "low"
		logger.Info("Switched to low power mode")

	} else {
		// Normal Power Mode: Start debounce timer before actually waking up

		// If there's already a pending wake-up timer, don't start another
		if o.wakeUpTimer != nil {
			logger.Debug("Wake-up already pending, ignoring duplicate request")
			return nil
		}

		logger.Info("Wake-up requested, starting %v debounce timer", o.wakeUpDebounce)

		o.wakeUpTimer = time.AfterFunc(o.wakeUpDebounce, func() {
			o.powerModeMu.Lock()
			defer o.powerModeMu.Unlock()

			// Clear the timer reference
			o.wakeUpTimer = nil

			// Double-check we're still in low power mode (could have changed)
			if o.currentPowerMode == "normal" {
				logger.Debug("Already in normal mode after debounce, skipping wake-up")
				return
			}

			logger.Info("Debounce complete, switching to normal power mode")
			
			logger.Info("Reconnecting websocket for normal power mode")
			if o.websocket != nil {
				if err := o.websocket.Connect(); err != nil {
					logger.Error("Failed to reconnect websocket: %v", err)
					return
				}
			}

			// Restore intervals and reconnect websocket
			if o.peerManager != nil {
				peerMonitor := o.peerManager.GetPeerMonitor()
				if peerMonitor != nil {
					peerMonitor.ResetPeerHolepunchInterval()
					peerMonitor.ResetPeerInterval()
				}

				o.peerManager.UpdateAllPeersPersistentKeepalive(5)
			}

			if o.holePunchManager != nil {
				o.holePunchManager.ResetServerHolepunchInterval()
			}

			o.currentPowerMode = "normal"
			logger.Info("Switched to normal power mode")
		})
	}

	return nil
}

func (o *Olm) AddDevice(fd uint32) error {
	if o.middleDev == nil {
		return fmt.Errorf("middle device is not initialized")
	}

	if o.tunnelConfig.MTU == 0 {
		return fmt.Errorf("tunnel MTU is not set")
	}

	tdev, err := olmDevice.CreateTUNFromFD(fd, o.tunnelConfig.MTU)
	if err != nil {
		return fmt.Errorf("failed to create TUN device from fd: %v", err)
	}

	// Update interface name if available
	if realInterfaceName, err2 := tdev.Name(); err2 == nil {
		o.tunnelConfig.InterfaceName = realInterfaceName
	}

	// Replace the existing TUN device in the middle device with the new one
	o.middleDev.AddDevice(tdev)

	logger.Info("Added device from file descriptor %d", fd)

	return nil
}

func GetNetworkSettingsJSON() (string, error) {
	return network.GetJSON()
}

func GetNetworkSettingsIncrementor() int {
	return network.GetIncrementor()
}
