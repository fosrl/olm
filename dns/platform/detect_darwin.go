//go:build darwin && !ios

package dns

import "fmt"

// DetectBestConfigurator returns the macOS DNS configurator
func DetectBestConfigurator(ifaceName string) (DNSConfigurator, error) {
	return NewDarwinDNSConfigurator()
}

// GetSystemDNS returns the current system DNS servers
func GetSystemDNS() ([]string, error) {
	configurator, err := NewDarwinDNSConfigurator()
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
