package olm

import (
	"time"

	"github.com/fosrl/olm/peers"
)

type WgData struct {
	Sites         []peers.SiteConfig `json:"sites"`
	TunnelIP      string             `json:"tunnelIP"`
	UtilitySubnet string             `json:"utilitySubnet"` // this is for things like the DNS server, and alias addresses
}

type GlobalConfig struct {
	// Logging
	LogLevel    string
	LogFilePath string

	// HTTP server
	EnableAPI  bool
	HTTPAddr   string
	SocketPath string
	Version    string
	Agent      string

	// Callbacks
	OnRegistered func()
	OnConnected  func()
	OnTerminated func()
	OnAuthError  func(statusCode int, message string) // Called when auth fails (401/403)
	OnExit       func()                               // Called when exit is requested via API
}

type TunnelConfig struct {
	// Connection settings
	Endpoint  string
	ID        string
	Secret    string
	UserToken string

	// Network settings
	MTU           int
	DNS           string
	UpstreamDNS   []string
	InterfaceName string

	// Advanced
	Holepunch     bool
	TlsClientCert string

	// Parsed values (not in JSON)
	PingIntervalDuration time.Duration
	PingTimeoutDuration  time.Duration

	OrgID string
	// DoNotCreateNewClient bool

	FileDescriptorTun  uint32
	FileDescriptorUAPI uint32

	EnableUAPI bool

	OverrideDNS bool
	TunnelDNS   bool

	DisableRelay bool
}
