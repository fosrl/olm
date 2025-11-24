//go:build windows

package dns

import "fmt"

// DetectBestConfigurator returns the Windows DNS configurator
// ifaceName should be the network interface GUID on Windows
func DetectBestConfigurator(ifaceName string) (DNSConfigurator, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("interface GUID is required for Windows")
	}
	return newWindowsDNSConfiguratorFromGUID(ifaceName)
}

// GetSystemDNS returns the current system DNS servers for the given interface
func GetSystemDNS(ifaceName string) ([]string, error) {
	configurator, err := newWindowsDNSConfiguratorFromGUID(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("create configurator: %w", err)
	}

	servers, err := configurator.GetCurrentDNS()
	if err != nil {
		return nil, fmt.Errorf("get current DNS: %w", err)
	}

	var result []string
	for _, server := range servers {
		result = append(result, server.String())
	}

	return result, nil
}
