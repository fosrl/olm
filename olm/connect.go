package olm

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	olmDevice "github.com/fosrl/olm/device"
	"github.com/fosrl/olm/dns"
	dnsOverride "github.com/fosrl/olm/dns/override"
	"github.com/fosrl/olm/peers"
	"github.com/fosrl/olm/websocket"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func (o *Olm) handleConnect(msg websocket.WSMessage) {
	logger.Debug("Received message: %v", msg.Data)

	var wgData WgData

	if o.connected {
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

	// Extract interface IP (strip CIDR notation if present)
	interfaceIP := wgData.TunnelIP
	if strings.Contains(interfaceIP, "/") {
		interfaceIP = strings.Split(interfaceIP, "/")[0]
	}

	// Create and start DNS proxy
	o.dnsProxy, err = dns.NewDNSProxy(o.middleDev, o.tunnelConfig.MTU, wgData.UtilitySubnet, o.tunnelConfig.UpstreamDNS, o.tunnelConfig.TunnelDNS, interfaceIP)
	if err != nil {
		logger.Error("Failed to create DNS proxy: %v", err)
	}

	if err = network.ConfigureInterface(o.tunnelConfig.InterfaceName, wgData.TunnelIP, o.tunnelConfig.MTU); err != nil {
		logger.Error("Failed to o.tunnelConfigure interface: %v", err)
	}

	if network.AddRoutes([]string{wgData.UtilitySubnet}, o.tunnelConfig.InterfaceName); err != nil { // also route the utility subnet
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

		o.apiServer.AddPeerStatus(site.SiteId, site.Name, false, 0, siteEndpoint, false)

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

	if o.tunnelConfig.OverrideDNS {
		// Set up DNS override to use our DNS proxy
		if err := dnsOverride.SetupDNSOverride(o.tunnelConfig.InterfaceName, o.dnsProxy.GetProxyIP()); err != nil {
			logger.Error("Failed to setup DNS override: %v", err)
			return
		}

		network.SetDNSServers([]string{o.dnsProxy.GetProxyIP().String()})
	}

	o.apiServer.SetRegistered(true)

	o.connected = true

	// Start ping monitor now that we are registered and connected
	o.websocket.StartPingMonitor()

	// Invoke onConnected callback if configured
	if o.olmConfig.OnConnected != nil {
		go o.olmConfig.OnConnected()
	}

	logger.Info("WireGuard device created.")
}

func (o *Olm) handleTerminate(msg websocket.WSMessage) {
	logger.Info("Received terminate message")
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
