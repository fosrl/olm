package olm

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/network"
)

func DarwinAddRoute(destination string, gateway string, interfaceName string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	var cmd *exec.Cmd

	if gateway != "" {
		// Route with specific gateway
		cmd = exec.Command("route", "-q", "-n", "add", "-inet", destination, "-gateway", gateway)
	} else if interfaceName != "" {
		// Route via interface
		cmd = exec.Command("route", "-q", "-n", "add", "-inet", destination, "-interface", interfaceName)
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route command failed: %v, output: %s", err, out)
	}

	return nil
}

func DarwinRemoveRoute(destination string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	cmd := exec.Command("route", "-q", "-n", "delete", "-inet", destination)
	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete command failed: %v, output: %s", err, out)
	}

	return nil
}

func LinuxAddRoute(destination string, gateway string, interfaceName string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	var cmd *exec.Cmd

	if gateway != "" {
		// Route with specific gateway
		cmd = exec.Command("ip", "route", "add", destination, "via", gateway)
	} else if interfaceName != "" {
		// Route via interface
		cmd = exec.Command("ip", "route", "add", destination, "dev", interfaceName)
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route command failed: %v, output: %s", err, out)
	}

	return nil
}

func LinuxRemoveRoute(destination string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	cmd := exec.Command("ip", "route", "del", destination)
	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route delete command failed: %v, output: %s", err, out)
	}

	return nil
}

func WindowsAddRoute(destination string, gateway string, interfaceName string) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	var cmd *exec.Cmd

	// Parse destination to get the IP and subnet
	ip, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	// Calculate the subnet mask
	maskBits, _ := ipNet.Mask.Size()
	mask := net.CIDRMask(maskBits, 32)
	maskIP := net.IP(mask)

	if gateway != "" {
		// Route with specific gateway
		cmd = exec.Command("route", "add",
			ip.String(),
			"mask", maskIP.String(),
			gateway,
			"metric", "1")
	} else if interfaceName != "" {
		// First, get the interface index
		indexCmd := exec.Command("netsh", "interface", "ipv4", "show", "interfaces")
		output, err := indexCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to get interface index: %v, output: %s", err, output)
		}

		// Parse the output to find the interface index
		lines := strings.Split(string(output), "\n")
		var ifIndex string
		for _, line := range lines {
			if strings.Contains(line, interfaceName) {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					ifIndex = fields[0]
					break
				}
			}
		}

		if ifIndex == "" {
			return fmt.Errorf("could not find index for interface %s", interfaceName)
		}

		// Convert to integer to validate
		idx, err := strconv.Atoi(ifIndex)
		if err != nil {
			return fmt.Errorf("invalid interface index: %v", err)
		}

		// Route via interface using the index
		cmd = exec.Command("route", "add",
			ip.String(),
			"mask", maskIP.String(),
			"0.0.0.0",
			"if", strconv.Itoa(idx))
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	logger.Info("Running command: %v", cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route command failed: %v, output: %s", err, out)
	}

	return nil
}

func WindowsRemoveRoute(destination string) error {
	// Parse destination to get the IP
	ip, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	// Calculate the subnet mask
	maskBits, _ := ipNet.Mask.Size()
	mask := net.CIDRMask(maskBits, 32)
	maskIP := net.IP(mask)

	cmd := exec.Command("route", "delete",
		ip.String(),
		"mask", maskIP.String())

	logger.Info("Running command: %v", cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete command failed: %v, output: %s", err, out)
	}

	return nil
}

// addRouteForServerIP adds an OS-specific route for the server IP
func addRouteForServerIP(serverIP, interfaceName string) error {
	if err := addRouteForNetworkConfig(serverIP); err != nil {
		return err
	}
	if interfaceName == "" {
		return nil
	}
	if runtime.GOOS == "darwin" {
		return DarwinAddRoute(serverIP, "", interfaceName)
	}
	// else if runtime.GOOS == "windows" {
	//	return WindowsAddRoute(serverIP, "", interfaceName)
	// } else if runtime.GOOS == "linux" {
	//	return LinuxAddRoute(serverIP, "", interfaceName)
	// }
	return nil
}

// removeRouteForServerIP removes an OS-specific route for the server IP
func removeRouteForServerIP(serverIP string, interfaceName string) error {
	if err := removeRouteForNetworkConfig(serverIP); err != nil {
		return err
	}
	if interfaceName == "" {
		return nil
	}
	if runtime.GOOS == "darwin" {
		return DarwinRemoveRoute(serverIP)
	}
	// else if runtime.GOOS == "windows" {
	// 	return WindowsRemoveRoute(serverIP)
	// } else if runtime.GOOS == "linux" {
	// 	return LinuxRemoveRoute(serverIP)
	// }
	return nil
}

func addRouteForNetworkConfig(destination string) error {
	// Parse the subnet to extract IP and mask
	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("failed to parse subnet %s: %v", destination, err)
	}

	// Convert CIDR mask to dotted decimal format (e.g., 255.255.255.0)
	mask := net.IP(ipNet.Mask).String()
	destinationAddress := ipNet.IP.String()

	network.AddIPv4IncludedRoute(network.IPv4Route{DestinationAddress: destinationAddress, SubnetMask: mask})

	return nil
}

func removeRouteForNetworkConfig(destination string) error {
	// Parse the subnet to extract IP and mask
	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("failed to parse subnet %s: %v", destination, err)
	}

	// Convert CIDR mask to dotted decimal format (e.g., 255.255.255.0)
	mask := net.IP(ipNet.Mask).String()
	destinationAddress := ipNet.IP.String()

	network.RemoveIPv4IncludedRoute(network.IPv4Route{DestinationAddress: destinationAddress, SubnetMask: mask})

	return nil
}

// addRoutesForRemoteSubnets adds routes for each subnet in RemoteSubnets
func addRoutesForRemoteSubnets(remoteSubnets []string, interfaceName string) error {
	if len(remoteSubnets) == 0 {
		return nil
	}

	// Add routes for each subnet
	for _, subnet := range remoteSubnets {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}

		if err := addRouteForNetworkConfig(subnet); err != nil {
			logger.Error("Failed to add network config for subnet %s: %v", subnet, err)
			continue
		}

		// Add route based on operating system
		if interfaceName == "" {
			continue
		}

		if runtime.GOOS == "darwin" {
			if err := DarwinAddRoute(subnet, "", interfaceName); err != nil {
				logger.Error("Failed to add Darwin route for subnet %s: %v", subnet, err)
				return err
			}
		} else if runtime.GOOS == "windows" {
			if err := WindowsAddRoute(subnet, "", interfaceName); err != nil {
				logger.Error("Failed to add Windows route for subnet %s: %v", subnet, err)
				return err
			}
		} else if runtime.GOOS == "linux" {
			if err := LinuxAddRoute(subnet, "", interfaceName); err != nil {
				logger.Error("Failed to add Linux route for subnet %s: %v", subnet, err)
				return err
			}
		}

		logger.Info("Added route for remote subnet: %s", subnet)
	}
	return nil
}

// removeRoutesForRemoteSubnets removes routes for each subnet in RemoteSubnets
func removeRoutesForRemoteSubnets(remoteSubnets []string) error {
	if len(remoteSubnets) == 0 {
		return nil
	}

	// Remove routes for each subnet
	for _, subnet := range remoteSubnets {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}

		if err := removeRouteForNetworkConfig(subnet); err != nil {
			logger.Error("Failed to remove network config for subnet %s: %v", subnet, err)
			continue
		}

		// Remove route based on operating system
		if runtime.GOOS == "darwin" {
			if err := DarwinRemoveRoute(subnet); err != nil {
				logger.Error("Failed to remove Darwin route for subnet %s: %v", subnet, err)
				return err
			}
		} else if runtime.GOOS == "windows" {
			if err := WindowsRemoveRoute(subnet); err != nil {
				logger.Error("Failed to remove Windows route for subnet %s: %v", subnet, err)
				return err
			}
		} else if runtime.GOOS == "linux" {
			if err := LinuxRemoveRoute(subnet); err != nil {
				logger.Error("Failed to remove Linux route for subnet %s: %v", subnet, err)
				return err
			}
		}

		logger.Info("Removed route for remote subnet: %s", subnet)
	}

	return nil
}
