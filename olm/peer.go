package olm

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/peermonitor"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ConfigurePeer sets up or updates a peer within the WireGuard device
func ConfigurePeer(dev *device.Device, siteConfig SiteConfig, privateKey wgtypes.Key, endpoint string) error {
	siteHost, err := util.ResolveDomain(siteConfig.Endpoint)
	if err != nil {
		return fmt.Errorf("failed to resolve endpoint for site %d: %v", siteConfig.SiteId, err)
	}

	// Split off the CIDR of the server IP which is just a string and add /32 for the allowed IP
	allowedIp := strings.Split(siteConfig.ServerIP, "/")
	if len(allowedIp) > 1 {
		allowedIp[1] = "32"
	} else {
		allowedIp = append(allowedIp, "32")
	}
	allowedIpStr := strings.Join(allowedIp, "/")

	// Collect all allowed IPs in a slice
	var allowedIPs []string
	allowedIPs = append(allowedIPs, allowedIpStr)

	// If we have anything in remoteSubnets, add those as well
	if len(siteConfig.RemoteSubnets) > 0 {
		// Add each remote subnet
		for _, subnet := range siteConfig.RemoteSubnets {
			subnet = strings.TrimSpace(subnet)
			if subnet != "" {
				allowedIPs = append(allowedIPs, subnet)
			}
		}
	}

	// Construct WireGuard config for this peer
	var configBuilder strings.Builder
	configBuilder.WriteString(fmt.Sprintf("private_key=%s\n", util.FixKey(privateKey.String())))
	configBuilder.WriteString(fmt.Sprintf("public_key=%s\n", util.FixKey(siteConfig.PublicKey)))

	// Add each allowed IP separately
	for _, allowedIP := range allowedIPs {
		configBuilder.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIP))
	}

	configBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", siteHost))
	configBuilder.WriteString("persistent_keepalive_interval=1\n")

	config := configBuilder.String()
	logger.Debug("Configuring peer with config: %s", config)

	err = dev.IpcSet(config)
	if err != nil {
		return fmt.Errorf("failed to configure WireGuard peer: %v", err)
	}

	// Set up peer monitoring
	if peerMonitor != nil {
		monitorAddress := strings.Split(siteConfig.ServerIP, "/")[0]
		monitorPeer := net.JoinHostPort(monitorAddress, strconv.Itoa(int(siteConfig.ServerPort+1))) // +1 for the monitor port
		logger.Debug("Setting up peer monitor for site %d at %s", siteConfig.SiteId, monitorPeer)
		logger.Debug("Resolving primary relay %s for peer", endpoint)
		primaryRelay, err := util.ResolveDomain(endpoint) // Using global endpoint variable
		if err != nil {
			logger.Warn("Failed to resolve primary relay endpoint for peer: %v", err)
		}

		wgConfig := &peermonitor.WireGuardConfig{
			SiteID:       siteConfig.SiteId,
			PublicKey:    util.FixKey(siteConfig.PublicKey),
			ServerIP:     strings.Split(siteConfig.ServerIP, "/")[0],
			Endpoint:     siteConfig.Endpoint,
			PrimaryRelay: primaryRelay,
		}

		err = peerMonitor.AddPeer(siteConfig.SiteId, monitorPeer, wgConfig)
		if err != nil {
			logger.Warn("Failed to setup monitoring for site %d: %v", siteConfig.SiteId, err)
		} else {
			logger.Info("Started monitoring for site %d at %s", siteConfig.SiteId, monitorPeer)
		}
	}

	return nil
}

// RemovePeer removes a peer from the WireGuard device
func RemovePeer(dev *device.Device, siteId int, publicKey string) error {
	// Construct WireGuard config to remove the peer
	var configBuilder strings.Builder
	configBuilder.WriteString(fmt.Sprintf("public_key=%s\n", util.FixKey(publicKey)))
	configBuilder.WriteString("remove=true\n")

	config := configBuilder.String()
	logger.Debug("Removing peer with config: %s", config)

	err := dev.IpcSet(config)
	if err != nil {
		return fmt.Errorf("failed to remove WireGuard peer: %v", err)
	}

	// Stop monitoring this peer
	if peerMonitor != nil {
		peerMonitor.RemovePeer(siteId)
		logger.Info("Stopped monitoring for site %d", siteId)
	}

	return nil
}
