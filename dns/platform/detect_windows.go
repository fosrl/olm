//go:build windows

package dns

import "fmt"

// DetectBestConfigurator returns the Windows DNS configurator
// guid is the network interface GUID
func DetectBestConfigurator(guid string) (DNSConfigurator, error) {
	if guid == "" {
		return nil, fmt.Errorf("interface GUID is required for Windows")
	}
	return NewWindowsDNSConfigurator(guid)
}

// GetSystemDNS returns the current system DNS servers for the given interface
func GetSystemDNS(guid string) ([]string, error) {
	configurator, err := NewWindowsDNSConfigurator(guid)
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
