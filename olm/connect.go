package olm

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/util"
	olmDevice "github.com/fosrl/olm/device"
	"github.com/fosrl/olm/dns"
	"github.com/fosrl/olm/peers"
	"github.com/fosrl/olm/subnetrouter"
	"github.com/fosrl/olm/websocket"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// OlmErrorData represents the error data sent from the server
type OlmErrorData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (o *Olm) handleConnect(msg websocket.WSMessage) {
	logger.Debug("Received message: %v", msg.Data)

	// Check if tunnel is still running
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring connect message")
		return
	}

	var wgData WgData

	if o.registered {
		logger.Info("Already connected. Ignoring new connection request.")
		return
	}

	if o.stopRegister != nil {
		o.stopRegister()
		o.stopRegister = nil
	}

	if o.updateRegister != nil {
		o.updateRegister = nil
	}

	if o.stopPingRequest != nil {
		o.stopPingRequest()
		o.stopPingRequest = nil
	}

	// if there is an existing tunnel then close it
	if o.dev != nil {
		logger.Info("Got new message. Closing existing tunnel!")
		o.dev.Close()
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

	// A server-provided DNS config always overrides the client's own local
	// config (from CLI flags / API connect request) - see applyDNSConfigUpdate.
	if wgData.DNSConfig != nil {
		o.applyDNSConfigUpdate(*wgData.DNSConfig)
	}

	// When handed an already-open FD (mobile/NetworkExtension platforms), the
	// TUN device's addresses and routes are owned and reconciled by the host
	// platform from NetworkSettings (e.g. Apple's NEPacketTunnelProvider via
	// setTunnelNetworkSettings) - our own ifconfig/route subprocess calls must
	// not also run against the same interface, or the two end up installing
	// competing routes to the same destination. On macOS specifically this
	// package's darwin code paths would otherwise run for real here (the NE
	// build shares GOOS=darwin with the CLI), unlike iOS where they're already
	// no-ops via a GOOS check.
	network.NativeConfigDisabled = o.tunnelConfig.FileDescriptorTun != 0

	o.tdev, err = func() (tun.Device, error) {
		if o.tunnelConfig.FileDescriptorTun != 0 {
			return olmDevice.CreateTUNFromFD(o.tunnelConfig.FileDescriptorTun, o.tunnelConfig.MTU)
		}
		ifName := o.tunnelConfig.InterfaceName
		if runtime.GOOS == "darwin" { // this is if we dont pass a fd
			ifName, err = network.FindUnusedUTUN()
			if err != nil {
				return nil, err
			}
		}
		return tun.CreateTUN(ifName, o.tunnelConfig.MTU)
	}()
	if err != nil {
		logger.Error("Failed to create TUN device: %v", err)
		return
	}

	// if config.FileDescriptorTun == 0 {
	if realInterfaceName, err2 := o.tdev.Name(); err2 == nil { // if the interface is defined then this should not really do anything?
		o.tunnelConfig.InterfaceName = realInterfaceName
	}
	// }

	// Wrap TUN device with packet filter for DNS proxy
	o.middleDev = olmDevice.NewMiddleDevice(o.tdev)

	wgLogger := logger.GetLogger().GetWireGuardLogger("wireguard: ")
	// Use filtered device instead of raw TUN device
	o.dev = device.NewDevice(o.middleDev, o.sharedBind, (*device.Logger)(wgLogger))

	if o.tunnelConfig.EnableUAPI {
		fileUAPI, err := func() (*os.File, error) {
			if o.tunnelConfig.FileDescriptorUAPI != 0 {
				fd, err := strconv.ParseUint(fmt.Sprintf("%d", o.tunnelConfig.FileDescriptorUAPI), 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid UAPI file descriptor: %v", err)
				}
				return os.NewFile(uintptr(fd), ""), nil
			}
			return olmDevice.UapiOpen(o.tunnelConfig.InterfaceName)
		}()
		if err != nil {
			logger.Error("UAPI listen error: %v", err)
			os.Exit(1)
			return
		}

		o.uapiListener, err = olmDevice.UapiListen(o.tunnelConfig.InterfaceName, fileUAPI)
		if err != nil {
			logger.Error("Failed to listen on uapi socket: %v", err)
			os.Exit(1)
		}

		go func() {
			for {
				conn, err := o.uapiListener.Accept()
				if err != nil {
					return
				}
				go o.dev.IpcHandle(conn)
			}
		}()
		logger.Info("UAPI listener started")
	}

	if err = o.dev.Up(); err != nil {
		logger.Error("Failed to bring up WireGuard device: %v", err)
	}

	// Set the private key unconditionally, since it's otherwise only ever set as a
	// side effect of configuring a site peer (see peers.ConfigurePeer) - if there are
	// no sites (e.g. an exit-node-only connection), the interface would otherwise be
	// brought up with no private key configured at all.
	if err := o.dev.IpcSet(fmt.Sprintf("private_key=%s\n", util.FixKey(o.privateKey.String()))); err != nil {
		logger.Error("Failed to set private key on WireGuard device: %v", err)
	}

	// Extract interface IP (strip CIDR notation if present)
	interfaceIP := wgData.TunnelIP
	if strings.Contains(interfaceIP, "/") {
		interfaceIP = strings.Split(interfaceIP, "/")[0]
	}
	if addr, err := netip.ParseAddr(interfaceIP); err == nil {
		o.primaryTunnelIP = addr
	} else {
		logger.Warn("Failed to parse tunnel IP %q: %v", interfaceIP, err)
	}

	// Create and start DNS proxy
	o.dnsProxy, err = dns.NewDNSProxy(o.middleDev, o.tunnelConfig.MTU, wgData.UtilitySubnet, o.tunnelConfig.UpstreamDNS, o.tunnelConfig.TunnelDNS, interfaceIP, o.tunnelConfig.MatchDomains, o.tunnelConfig.PublicDNS)
	if err != nil {
		logger.Error("Failed to create DNS proxy: %v", err)
	}

	// Tell the system DNS monitor to exclude the proxy IP so that subsequent
	// polls never mistake the proxy for a real upstream server (on Linux the OS
	// DNS is overridden to point at this IP, which would otherwise feed back
	// into UpstreamDNS or PublicDNS on the next poll).
	if o.dnsMonitor != nil && o.dnsProxy != nil {
		o.dnsMonitor.SetExcludeIP(o.dnsProxy.GetProxyIP())
	}

	if err = network.ConfigureInterface(o.tunnelConfig.InterfaceName, wgData.TunnelIP, o.tunnelConfig.MTU); err != nil {
		logger.Error("Failed to o.tunnelConfigure interface: %v", err)
	}

	if o.tunnelConfig.SubnetRouter {
		if err := subnetrouter.Enable(o.tunnelConfig.InterfaceName, o.primaryTunnelIP); err != nil {
			logger.Error("Failed to enable subnet router: %v", err)
		} else {
			logger.Info("Subnet router enabled on %s (SNAT to %s)", o.tunnelConfig.InterfaceName, o.primaryTunnelIP)
		}
	}

	if err := network.AddRoutesWithSource([]string{wgData.UtilitySubnet}, o.tunnelConfig.InterfaceName, interfaceIP); err != nil { // also route the utility subnet
		logger.Error("Failed to add route for utility subnet: %v", err)
	}

	// Create peer manager with integrated peer monitoring
	o.peerManager = peers.NewPeerManager(peers.PeerManagerConfig{
		Device:        o.dev,
		DNSProxy:      o.dnsProxy,
		InterfaceName: o.tunnelConfig.InterfaceName,
		PrivateKey:    o.privateKey,
		MiddleDev:     o.middleDev,
		LocalIP:       interfaceIP,
		SharedBind:    o.sharedBind,
		WSClient:      o.websocket,
		APIServer:     o.apiServer,
		PublicDNS:     o.tunnelConfig.PublicDNS,
	})

	for i := range wgData.Sites {
		site := wgData.Sites[i]

		if site.PublicKey != "" {
			var siteEndpoint string
			// here we are going to take the relay endpoint if it exists which means we requested a relay for this peer
			if site.RelayEndpoint != "" {
				siteEndpoint = site.RelayEndpoint
			} else {
				siteEndpoint = site.Endpoint
			}

			o.apiServer.AddPeerStatus(site.SiteId, site.Name, false, 0, siteEndpoint, false, false)
		}

		// we still call this to add the aliases for jit lookup but we just do that then pass inside. need to skip the above so we dont add to the api
		if err := o.peerManager.AddPeer(site); err != nil {
			logger.Error("Failed to add peer: %v", err)
			return
		}

		logger.Info("Configured peer %s", site.PublicKey)
	}

	o.peerManager.Start()

	if err := o.dnsProxy.Start(); err != nil { // start DNS proxy first so there is no downtime
		logger.Error("Failed to start DNS proxy: %v", err)
	}

	// Register JIT handler: when the DNS proxy resolves a local record, check whether
	// the owning site is already connected and, if not, initiate a JIT connection.
	o.dnsProxy.SetJITHandler(func(siteId int) {
		pm := o.getPeerManager()
		if pm == nil || o.websocket == nil {
			return
		}

		// Site already has an active peer connection - nothing to do.
		if _, exists := pm.GetPeer(siteId); exists {
			return
		}

		o.peerSendMu.Lock()
		defer o.peerSendMu.Unlock()

		// A JIT request for this site is already in-flight - avoid duplicate sends.
		if _, pending := o.jitPendingSites[siteId]; pending {
			return
		}

		chainId := generateChainId()
		logger.Info("DNS-triggered JIT connect for site %d (chainId=%s)", siteId, chainId)
		stopFunc, _ := o.websocket.SendMessageInterval("olm/wg/server/peer/init", map[string]interface{}{
			"siteId":  siteId,
			"chainId": chainId,
		}, 2*time.Second, 10)
		o.stopPeerInits[chainId] = stopFunc
		o.jitPendingSites[siteId] = chainId
	})

	if o.tunnelConfig.OverrideDNS {
		if err := o.applyDNSOverride(true); err != nil {
			logger.Error("%v", err)
			return
		}
	}

	if wgData.ExitNode != nil && wgData.ExitNode.Connect {
		if err := o.connectExitNode(*wgData.ExitNode); err != nil {
			logger.Error("Failed to connect to exit node: %v", err)
		}
	} else {
		logger.Debug("No exit node to connect to (not provided, or connect flag is false)")
	}

	o.apiServer.SetRegistered(true)

	o.registered = true

	// Start ping monitor now that we are registered and connected
	o.websocket.StartPingMonitor()

	// Invoke onConnected callback if configured
	if o.olmConfig.OnConnected != nil {
		go o.olmConfig.OnConnected()
	}

	logger.Info("WireGuard device created.")
}

func (o *Olm) handleOlmError(msg websocket.WSMessage) {
	logger.Debug("Received olm error message: %v", msg.Data)

	// Check if tunnel is still running
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring olm error message")
		return
	}

	var errorData OlmErrorData

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling olm error data: %v", err)
		return
	}

	if err := json.Unmarshal(jsonData, &errorData); err != nil {
		logger.Error("Error unmarshaling olm error data: %v", err)
		return
	}

	logger.Error("Olm error (code: %s): %s", errorData.Code, errorData.Message)

	// Set the olm error in the API server so it can be exposed via status
	o.apiServer.SetOlmError(errorData.Code, errorData.Message)

	// Invoke onOlmError callback if configured
	if o.olmConfig.OnOlmError != nil {
		go o.olmConfig.OnOlmError(errorData.Code, errorData.Message)
	}
}

func (o *Olm) handleTerminate(msg websocket.WSMessage) {
	logger.Info("Received terminate message")

	// Check if tunnel is still running
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring terminate message")
		return
	}

	var errorData OlmErrorData

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling terminate error data: %v", err)
	} else {
		if err := json.Unmarshal(jsonData, &errorData); err != nil {
			logger.Error("Error unmarshaling terminate error data: %v", err)
		} else {
			logger.Info("Terminate reason (code: %s): %s", errorData.Code, errorData.Message)

			if errorData.Code == "TERMINATED_INACTIVITY" {
				logger.Info("Ignoring...")
				return
			}

			// Set the olm error in the API server so it can be exposed via status
			o.apiServer.SetOlmError(errorData.Code, errorData.Message)
		}
	}

	o.apiServer.SetTerminated(true)
	o.apiServer.SetConnectionStatus(false)
	o.apiServer.SetRegistered(false)
	o.apiServer.ClearPeerStatuses()

	network.ClearNetworkSettings()

	o.Close()

	if o.olmConfig.OnTerminated != nil {
		go o.olmConfig.OnTerminated()
	}
}
