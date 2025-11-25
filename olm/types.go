package olm

import "time"

type WgData struct {
	Sites         []SiteConfig `json:"sites"`
	TunnelIP      string       `json:"tunnelIP"`
	UtilitySubnet string       `json:"utilitySubnet"` // this is for things like the DNS server, and alias addresses
}

type HolePunchMessage struct {
	NewtID string `json:"newtId"`
}

type ExitNode struct {
	Endpoint  string `json:"endpoint"`
	PublicKey string `json:"publicKey"`
}

type HolePunchData struct {
	ExitNodes []ExitNode `json:"exitNodes"`
}

type EncryptedHolePunchMessage struct {
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Nonce              []byte `json:"nonce"`
	Ciphertext         []byte `json:"ciphertext"`
}

// PeerAction represents a request to add, update, or remove a peer
type PeerAction struct {
	Action   string     `json:"action"`   // "add", "update", or "remove"
	SiteInfo SiteConfig `json:"siteInfo"` // Site configuration information
}

// UpdatePeerData represents the data needed to update a peer
type SiteConfig struct {
	SiteId        int      `json:"siteId"`
	Endpoint      string   `json:"endpoint,omitempty"`
	PublicKey     string   `json:"publicKey,omitempty"`
	ServerIP      string   `json:"serverIP,omitempty"`
	ServerPort    uint16   `json:"serverPort,omitempty"`
	RemoteSubnets []string `json:"remoteSubnets,omitempty"` // optional, array of subnets that this site can access
	Aliases       []Alias  `json:"aliases,omitempty"`       // optional, array of alias configurations
}

type Alias struct {
	Alias        string `json:"alias"`        // the alias name
	AliasAddress string `json:"aliasAddress"` // the alias IP address
}

// RemovePeer represents the data needed to remove a peer
type PeerRemove struct {
	SiteId int `json:"siteId"`
}

type RelayPeerData struct {
	SiteId    int    `json:"siteId"`
	Endpoint  string `json:"endpoint"`
	PublicKey string `json:"publicKey"`
}

// PeerAdd represents the data needed to add remote subnets to a peer
type PeerAdd struct {
	SiteId        int      `json:"siteId"`
	RemoteSubnets []string `json:"remoteSubnets"`     // subnets to add
	Aliases       []Alias  `json:"aliases,omitempty"` // aliases to add
}

// RemovePeerData represents the data needed to remove remote subnets from a peer
type RemovePeerData struct {
	SiteId        int      `json:"siteId"`
	RemoteSubnets []string `json:"remoteSubnets"`     // subnets to remove
	Aliases       []Alias  `json:"aliases,omitempty"` // aliases to remove
}

type UpdatePeerData struct {
	SiteId           int      `json:"siteId"`
	OldRemoteSubnets []string `json:"oldRemoteSubnets"`     // old list of remote subnets
	NewRemoteSubnets []string `json:"newRemoteSubnets"`     // new list of remote subnets
	OldAliases       []Alias  `json:"oldAliases,omitempty"` // old list of aliases
	NewAliases       []Alias  `json:"newAliases,omitempty"` // new list of aliases
}

type GlobalConfig struct {
	// Logging
	LogLevel string

	// HTTP server
	EnableAPI  bool
	HTTPAddr   string
	SocketPath string
	Version    string

	// Callbacks
	OnRegistered func()
	OnConnected  func()
	OnTerminated func()

	// Source tracking (not in JSON)
	sources map[string]string
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
}
