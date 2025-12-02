package peers

// PeerAction represents a request to add, update, or remove a peer
type PeerAction struct {
	Action   string     `json:"action"`   // "add", "update", or "remove"
	SiteInfo SiteConfig `json:"siteInfo"` // Site configuration information
}

// UpdatePeerData represents the data needed to update a peer
type SiteConfig struct {
	SiteId        int      `json:"siteId"`
	Endpoint      string   `json:"endpoint,omitempty"`
	RelayEndpoint string   `json:"relayEndpoint,omitempty"`
	PublicKey     string   `json:"publicKey,omitempty"`
	ServerIP      string   `json:"serverIP,omitempty"`
	ServerPort    uint16   `json:"serverPort,omitempty"`
	RemoteSubnets []string `json:"remoteSubnets,omitempty"` // optional, array of subnets that this site can access
	AllowedIps    []string `json:"allowedIps,omitempty"`    // optional, array of allowed IPs for the peer
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
	SiteId        int    `json:"siteId"`
	RelayEndpoint string `json:"relayEndpoint"`
}

type UnRelayPeerData struct {
	SiteId   int    `json:"siteId"`
	Endpoint string `json:"endpoint"`
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
