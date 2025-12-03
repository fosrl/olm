package peers

import (
	"fmt"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ConfigurePeer sets up or updates a peer within the WireGuard device
func ConfigurePeer(dev *device.Device, siteConfig SiteConfig, privateKey wgtypes.Key, relay bool) error {
	var endpoint string
	if relay && siteConfig.RelayEndpoint != "" {
		endpoint = formatEndpoint(siteConfig.RelayEndpoint)
	} else {
		endpoint = formatEndpoint(siteConfig.Endpoint)
	}
	siteHost, err := util.ResolveDomain(endpoint)
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

	// Use AllowedIps if available, otherwise fall back to RemoteSubnets for backwards compatibility
	subnetsToAdd := siteConfig.AllowedIps

	// If we have anything to add, process them
	if len(subnetsToAdd) > 0 {
		// Add each subnet
		for _, subnet := range subnetsToAdd {
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

	return nil
}

// AddAllowedIP adds a single allowed IP to an existing peer without reconfiguring the entire peer
func AddAllowedIP(dev *device.Device, publicKey string, allowedIP string) error {
	var configBuilder strings.Builder
	configBuilder.WriteString(fmt.Sprintf("public_key=%s\n", util.FixKey(publicKey)))
	configBuilder.WriteString("update_only=true\n")
	configBuilder.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIP))

	config := configBuilder.String()
	logger.Debug("Adding allowed IP to peer with config: %s", config)

	err := dev.IpcSet(config)
	if err != nil {
		return fmt.Errorf("failed to add allowed IP to WireGuard peer: %v", err)
	}

	return nil
}

// RemoveAllowedIP removes a single allowed IP from an existing peer by replacing the allowed IPs list
// This requires providing all the allowed IPs that should remain after removal
func RemoveAllowedIP(dev *device.Device, publicKey string, remainingAllowedIPs []string) error {
	var configBuilder strings.Builder
	configBuilder.WriteString(fmt.Sprintf("public_key=%s\n", util.FixKey(publicKey)))
	configBuilder.WriteString("update_only=true\n")
	configBuilder.WriteString("replace_allowed_ips=true\n")

	// Add each remaining allowed IP
	for _, allowedIP := range remainingAllowedIPs {
		configBuilder.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIP))
	}

	config := configBuilder.String()
	logger.Debug("Removing allowed IP from peer with config: %s", config)

	err := dev.IpcSet(config)
	if err != nil {
		return fmt.Errorf("failed to remove allowed IP from WireGuard peer: %v", err)
	}

	return nil
}

func formatEndpoint(endpoint string) string {
	if strings.Contains(endpoint, ":") {
		return endpoint
	}
	return endpoint + ":51820"
}
