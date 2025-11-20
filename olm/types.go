package olm

type WgData struct {
	Sites    []SiteConfig `json:"sites"`
	TunnelIP string       `json:"tunnelIP"`
}

type SiteConfig struct {
	SiteId        int      `json:"siteId"`
	Endpoint      string   `json:"endpoint"`
	PublicKey     string   `json:"publicKey"`
	ServerIP      string   `json:"serverIP"`
	ServerPort    uint16   `json:"serverPort"`
	RemoteSubnets []string `json:"remoteSubnets,omitempty"` // optional, array of subnets that this site can access
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
type UpdatePeerData struct {
	SiteId        int      `json:"siteId"`
	Endpoint      string   `json:"endpoint,omitempty"`
	PublicKey     string   `json:"publicKey,omitempty"`
	ServerIP      string   `json:"serverIP,omitempty"`
	ServerPort    uint16   `json:"serverPort,omitempty"`
	RemoteSubnets []string `json:"remoteSubnets,omitempty"` // optional, array of subnets that this site can access
}

// AddPeerData represents the data needed to add a peer
type AddPeerData struct {
	SiteId        int      `json:"siteId"`
	Endpoint      string   `json:"endpoint"`
	PublicKey     string   `json:"publicKey"`
	ServerIP      string   `json:"serverIP"`
	ServerPort    uint16   `json:"serverPort"`
	RemoteSubnets []string `json:"remoteSubnets,omitempty"` // optional, array of subnets that this site can access
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
