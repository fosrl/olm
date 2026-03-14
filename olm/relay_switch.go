package olm

import (
	"fmt"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/peers"
	wgConn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

func (o *Olm) getRelayTunnelURL() string {
	o.relayURLMu.RLock()
	defer o.relayURLMu.RUnlock()
	return o.relayTunnelURL
}

func (o *Olm) resolveRelayTunnelURL() (string, error) {
	if cached := o.getRelayTunnelURL(); cached != "" {
		return cached, nil
	}
	if o.websocket == nil {
		return "", fmt.Errorf("websocket client is nil")
	}

	token, exitNodes := o.websocket.GetTokenState()
	if token == "" {
		return "", fmt.Errorf("missing relay token")
	}

	var relayEndpointWss string
	for _, node := range exitNodes {
		if node.RelayEndpointWss != "" {
			relayEndpointWss = node.RelayEndpointWss
			break
		}
	}
	if relayEndpointWss == "" {
		return "", fmt.Errorf("missing relay endpoint wss")
	}

	relayURL, err := buildRelayTunnelURL(relayEndpointWss, token, o.websocket.GetUserToken())
	if err != nil {
		return "", err
	}

	o.relayURLMu.Lock()
	o.relayTunnelURL = relayURL
	o.relayURLMu.Unlock()

	return relayURL, nil
}

func (o *Olm) requestRelayPreflight(pm *peers.PeerManager) {
	monitor := pm.GetPeerMonitor()
	if monitor == nil {
		return
	}
	for _, peer := range pm.GetAllPeers() {
		if monitor.IsPeerRelayed(peer.SiteId) {
			continue
		}
		if err := monitor.RequestRelay(peer.SiteId); err != nil {
			logger.Warn("Failed relay preflight for site %d: %v", peer.SiteId, err)
		}
	}
	time.Sleep(300 * time.Millisecond)
}

func (o *Olm) createWireGuardDevice(bind wgConn.Bind) (*device.Device, error) {
	if o.middleDev == nil {
		return nil, fmt.Errorf("middle device is nil")
	}
	wgLogger := logger.GetLogger().GetWireGuardLogger("wireguard: ")
	dev := device.NewDevice(o.middleDev, bind, (*device.Logger)(wgLogger))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s", util.FixKey(o.privateKey.String()))); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure private key: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring up wireguard device: %w", err)
	}
	return dev, nil
}

func (o *Olm) restoreSharedBindDevice(pm *peers.PeerManager) error {
	if o.sharedBind == nil {
		return fmt.Errorf("shared bind is nil")
	}
	dev, err := o.createWireGuardDevice(o.sharedBind)
	if err != nil {
		return err
	}
	if err := pm.ReplaceDevice(dev); err != nil {
		dev.Close()
		return err
	}
	o.dev = dev
	o.wssRelayActive = false
	return nil
}

func (o *Olm) switchToWebSocketRelay() error {
	o.relaySwitchMu.Lock()
	defer o.relaySwitchMu.Unlock()

	if o.wssRelayActive {
		return nil
	}
	if !o.tunnelRunning {
		return fmt.Errorf("tunnel is not running")
	}

	pm := o.getPeerManager()
	if pm == nil {
		return fmt.Errorf("peer manager is nil")
	}

	relayURL, err := o.resolveRelayTunnelURL()
	if err != nil {
		return err
	}
	o.requestRelayPreflight(pm)

	oldDev := o.dev
	if oldDev != nil {
		oldDev.Close()
	}

	wsBind := NewWebSocketRelayBind(relayURL, nil)
	newDev, err := o.createWireGuardDevice(wsBind)
	if err != nil {
		_ = wsBind.Shutdown()
		if restoreErr := o.restoreSharedBindDevice(pm); restoreErr != nil {
			return fmt.Errorf("switch to websocket relay failed: %w (restore failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("switch to websocket relay failed: %w", err)
	}
	if err := pm.ReplaceDevice(newDev); err != nil {
		newDev.Close()
		_ = wsBind.Shutdown()
		if restoreErr := o.restoreSharedBindDevice(pm); restoreErr != nil {
			return fmt.Errorf("replace device failed: %w (restore failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("replace device failed: %w", err)
	}

	if o.wsRelayBind != nil {
		_ = o.wsRelayBind.Shutdown()
	}
	o.dev = newDev
	o.wsRelayBind = wsBind
	o.wssRelayActive = true
	if o.relaySwitchTimer != nil {
		o.relaySwitchTimer.Stop()
		o.relaySwitchTimer = nil
	}

	logger.Info("Switched WireGuard transport to WSS relay bind")
	return nil
}

func (o *Olm) scheduleRelaySwitch(delay time.Duration) {
	o.relaySwitchMu.Lock()
	if o.relaySwitchTimer != nil {
		o.relaySwitchTimer.Stop()
	}
	o.relaySwitchTimer = time.AfterFunc(delay, func() {
		if err := o.switchToWebSocketRelay(); err != nil {
			logger.Warn("WSS relay switch failed: %v", err)
		}
	})
	o.relaySwitchMu.Unlock()
}

func (o *Olm) cancelRelaySwitchTimer() {
	o.relaySwitchMu.Lock()
	defer o.relaySwitchMu.Unlock()
	if o.relaySwitchTimer != nil {
		o.relaySwitchTimer.Stop()
		o.relaySwitchTimer = nil
	}
}
