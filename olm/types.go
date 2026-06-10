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

type SyncData struct {
	Sites     []peers.SiteConfig `json:"sites"`
	ExitNodes []SyncExitNode     `json:"exitNodes"`
}

type SyncExitNode struct {
	Endpoint  string `json:"endpoint"`
	RelayPort uint16 `json:"relayPort"`
	PublicKey string `json:"publicKey"`
	SiteIds   []int  `json:"siteIds"`
}

type OlmConfig struct {
	// Logging
	LogLevel    string
	LogFilePath string

	// HTTP server
	EnableAPI  bool
	HTTPAddr   string
	SocketPath string
	Version    string
	Agent      string

	WakeUpDebounce time.Duration

	// Debugging
	PprofAddr string // Address to serve pprof on (e.g., "localhost:6060")

	// Callbacks
	OnRegistered func()
	OnConnected  func()
	OnTerminated func()
	OnAuthError  func(statusCode int, message string) // Called when auth fails (401/403)
	OnOlmError   func(code string, message string)    // Called when registration fails
	OnExit       func()                               // Called when exit is requested via API

	// DNS watchdog (optional). When WatchdogSubcommand is non-empty, the
	// olm package will spawn an external watchdog subprocess after a DNS
	// override is installed. The watchdog will reset the system DNS if
	// this process dies before it can call RestoreDNSOverride.
	//
	// The watchdog is launched as:
	//   <WatchdogExecutable> <WatchdogSubcommand...> \
	//       --parent-pid=<pid> --interface=<name> [--socket=<path>]
	//
	// When WatchdogExecutable is empty, os.Executable() of the calling
	// process is used. WatchdogLogFile defaults to /dev/null.
	WatchdogExecutable string
	WatchdogSubcommand []string
	WatchdogLogFile    string
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
	PublicDNS     []string
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

	InitialFingerprint map[string]any
	InitialPostures    map[string]any

	DisableRelay bool
}
