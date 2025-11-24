package dns

import "net/netip"

// DNSConfigurator provides an interface for managing system DNS settings
// across different platforms and implementations
type DNSConfigurator interface {
	// SetDNS overrides the system DNS servers with the specified ones
	// Returns the original DNS servers that were replaced
	SetDNS(servers []netip.Addr) ([]netip.Addr, error)

	// RestoreDNS restores the original DNS servers
	RestoreDNS() error

	// GetCurrentDNS returns the currently configured DNS servers
	GetCurrentDNS() ([]netip.Addr, error)

	// Name returns the name of this configurator implementation
	Name() string
}

// DNSConfig contains the configuration for DNS override
type DNSConfig struct {
	// Servers is the list of DNS servers to use
	Servers []netip.Addr

	// SearchDomains is an optional list of search domains
	SearchDomains []string
}

// DNSState represents the saved state of DNS configuration
type DNSState struct {
	// OriginalServers are the DNS servers before override
	OriginalServers []netip.Addr

	// OriginalSearchDomains are the search domains before override
	OriginalSearchDomains []string

	// ConfiguratorName is the name of the configurator that saved this state
	ConfiguratorName string
}
