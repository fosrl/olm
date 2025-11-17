package olm

import "github.com/fosrl/olm/peermonitor"

type WgData struct {
	Sites    []SiteConfig `json:"sites"`
	TunnelIP string       `json:"tunnelIP"`
}

type SiteConfig struct {
	SiteId        int    `json:"siteId"`
	Endpoint      string `json:"endpoint"`
	PublicKey     string `json:"publicKey"`
	ServerIP      string `json:"serverIP"`
	ServerPort    uint16 `json:"serverPort"`
	RemoteSubnets string `json:"remoteSubnets,omitempty"` // optional, comma-separated list of subnets that this site can access
}

type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

type TargetData struct {
	Targets []string `json:"targets"`
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

var (
	peerMonitor      *peermonitor.PeerMonitor
	stopHolepunch    chan struct{}
	stopRegister     func()
	stopPing         chan struct{}
	olmToken         string
	holePunchRunning bool
)

// PeerAction represents a request to add, update, or remove a peer
type PeerAction struct {
	Action   string     `json:"action"`   // "add", "update", or "remove"
	SiteInfo SiteConfig `json:"siteInfo"` // Site configuration information
}

// UpdatePeerData represents the data needed to update a peer
type UpdatePeerData struct {
	SiteId        int    `json:"siteId"`
	Endpoint      string `json:"endpoint"`
	PublicKey     string `json:"publicKey"`
	ServerIP      string `json:"serverIP"`
	ServerPort    uint16 `json:"serverPort"`
	RemoteSubnets string `json:"remoteSubnets,omitempty"` // optional, comma-separated list of subnets that this site can access
}

// AddPeerData represents the data needed to add a peer
type AddPeerData struct {
	SiteId        int    `json:"siteId"`
	Endpoint      string `json:"endpoint"`
	PublicKey     string `json:"publicKey"`
	ServerIP      string `json:"serverIP"`
	ServerPort    uint16 `json:"serverPort"`
	RemoteSubnets string `json:"remoteSubnets,omitempty"` // optional, comma-separated list of subnets that this site can access
}

// RemovePeerData represents the data needed to remove a peer
type RemovePeerData struct {
	SiteId int `json:"siteId"`
}

type RelayPeerData struct {
	SiteId    int    `json:"siteId"`
	Endpoint  string `json:"endpoint"`
	PublicKey string `json:"publicKey"`
}
