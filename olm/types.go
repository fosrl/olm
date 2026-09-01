package olm

import (
	"time"

	"github.com/fosrl/olm/peers"
)

type WgData struct {
	Sites         []peers.SiteConfig `json:"sites"`
	TunnelIP      string             `json:"tunnelIP"`
	UtilitySubnet string             `json:"utilitySubnet"` // this is for things like the DNS server, and alias addresses
	ExitNode      *ExitNodeConfig    `json:"exitNode,omitempty"`
}

// ExitNodeConfig describes an exit node the olm client can connect to for
// resources (e.g. inference) hosted on that node, separate from the site
// peers. It lives in a different address space than the site tunnel - the
// client is assigned TunnelIP (within the exit node's subnet) to reach the
// node at ServerIP. It arrives on the initial "olm/wg/connect" message and can
// also be sent later via "olm/wg/exitnode/connect" / "olm/wg/exitnode/disconnect"
// so the server can direct a client to connect/disconnect after registration.
type ExitNodeConfig struct {
	Connect   bool     `json:"connect"`
	Endpoint  string   `json:"endpoint"`
	RelayPort uint16   `json:"relayPort"`
	PublicKey string   `json:"publicKey"`
	ServerIP  string   `json:"serverIP"`
	TunnelIP  string   `json:"tunnelIP"`
	Aliases   []string `json:"aliases,omitempty"`
}

// ExitNodeUpdateData describes a change to data associated with the currently
// connected exit node, e.g. when a resource's alias is renamed on the server.
// Aliases have no per-alias address here since every exit node alias resolves
// to the exit node's own ServerIP. More fields can be added here in the
// future as other exit node data becomes updatable.
type ExitNodeUpdateData struct {
	OldAliases []string `json:"oldAliases,omitempty"`
	NewAliases []string `json:"newAliases,omitempty"`
}

type SyncData struct {
	Sites     []peers.SiteConfig `json:"sites"`
	ExitNodes []SyncExitNode     `json:"exitNodes"`
	// ExitNode is the exit node the client itself is assigned to (for site
	// resources hosted on it, e.g. inference), mirroring the ExitNode field
	// on WgData sent at registration. It is separate from ExitNodes above,
	// which is only the set of exit nodes used for hole punching.
	ExitNode *ExitNodeConfig `json:"exitNode,omitempty"`
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

	// MatchDomains lists FQDN wildcard patterns (using * and ? wildcards) that
	// olm should check against local records / resolve via UpstreamDNS. Queries
	// that don't match any pattern are sent directly to the host's own system
	// DNS servers (PublicDNS) instead of being handled by the DNS proxy at all.
	// An empty MatchDomains matches every query, preserving prior behavior.
	MatchDomains []string

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

	// NativeDNSManaged indicates the DNS override is already applied natively by
	// the host platform (e.g. NEDNSSettings on macOS/iOS), scoped to the tunnel
	// session and auto-cleaned by the OS regardless of how the session ends. When
	// true, olm skips installing its own raw scutil-based override (and the
	// subprocess watchdog that guards it) since there is nothing for it to add
	// and nothing that can leak.
	NativeDNSManaged bool

	InitialFingerprint map[string]any
	InitialPostures    map[string]any

	DisableRelay bool

	// PreferLocalRoutes, when enabled, adds tunnel routes with an explicit
	// high metric/priority so that an overlapping local/connected route to
	// the same destination always takes precedence over the VPN route,
	// rather than the two racing based on insertion order. Defaults to
	// false, preserving the routing behavior from before this option was
	// introduced.
	PreferLocalRoutes bool
}
