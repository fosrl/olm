package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
)

// ConnectionRequest defines the structure for an incoming connection request.
// GatewaySiteResourceId is the numeric ID of the gateway-mode site resource
// GatewaySiteIds were selected from; it is required when GatewaySiteIds is
// non-empty, and is how olm later matches server-pushed gateway updates to the
// resource the user actually connected through.
type ConnectionRequest struct {
	ID                                string   `json:"id"`
	Secret                            string   `json:"secret"`
	Endpoint                          string   `json:"endpoint"`
	UserToken                         string   `json:"userToken,omitempty"`
	MTU                               int      `json:"mtu,omitempty"`
	DNS                               string   `json:"dns,omitempty"`
	DNSProxyIP                        string   `json:"dnsProxyIP,omitempty"`
	UpstreamDNS                       []string `json:"upstreamDNS,omitempty"`
	InterfaceName                     string   `json:"interfaceName,omitempty"`
	Holepunch                         bool     `json:"holepunch,omitempty"`
	TlsClientCert                     string   `json:"tlsClientCert,omitempty"`
	PingInterval                      string   `json:"pingInterval,omitempty"`
	PingTimeout                       string   `json:"pingTimeout,omitempty"`
	OrgID                             string   `json:"orgId,omitempty"`
	MatchDomains                      []string `json:"matchDomains,omitempty"`
	SubnetRouter                      bool     `json:"subnetRouter,omitempty"`
	DisableRoutesAndAliasesOnExitNode bool     `json:"disableRoutesAndAliasesOnExitNode,omitempty"`
	GatewaySiteResourceId             int      `json:"gatewaySiteResourceId,omitempty"`
	GatewaySiteIds                    []int    `json:"gatewaySiteIds,omitempty"`
}

// SwitchOrgRequest defines the structure for switching organizations
type SwitchOrgRequest struct {
	OrgID string `json:"org_id"`
}

// GatewayRequest defines the structure for a "select gateway" request: the
// set of site IDs that should act as the gateway (full-tunnel/default-route)
// for all tunnel traffic, plus the numeric ID of the gateway site resource
// they were selected from (used to match later server-pushed updates). Every
// site ID must already be a tracked/connected peer.
type GatewayRequest struct {
	SiteResourceId int   `json:"siteResourceId"`
	SiteIds        []int `json:"siteIds"`
}

// PowerModeRequest represents a request to change power mode
type PowerModeRequest struct {
	Mode string `json:"mode"` // "normal" or "low"
}

// PeerStatus represents the status of a peer connection
type PeerStatus struct {
	SiteID             int           `json:"siteId"`
	Name               string        `json:"name"`
	Connected          bool          `json:"connected"`
	RTT                time.Duration `json:"rtt"`
	LastSeen           time.Time     `json:"lastSeen"`
	Endpoint           string        `json:"endpoint,omitempty"`
	IsRelay            bool          `json:"isRelay"`
	IsLocal            bool          `json:"isLocal"` // true when connected via a local network endpoint, bypassing both the public endpoint and relay
	PeerIP             string        `json:"peerAddress,omitempty"`
	HolepunchConnected bool          `json:"holepunchConnected"`
}

// OlmError holds error information from registration failures
type OlmError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ExitNodeStatus represents the connectivity status of the client's own exit
// node connection (used for site resources hosted on the exit node).
type ExitNodeStatus struct {
	Connected bool          `json:"connected"`
	RTT       time.Duration `json:"rtt"`
	LastSeen  time.Time     `json:"lastSeen"`
	Endpoint  string        `json:"endpoint,omitempty"`
}

// StatusResponse is returned by the status endpoint
type StatusResponse struct {
	Connected       bool                    `json:"connected"`
	Registered      bool                    `json:"registered"`
	Terminated      bool                    `json:"terminated"`
	Restarting      bool                    `json:"restarting,omitempty"` // a server-requested restart is underway (olm/restart until registered again)
	OlmError        *OlmError               `json:"error,omitempty"`
	Version         string                  `json:"version,omitempty"`
	Agent           string                  `json:"agent,omitempty"`
	OrgID           string                  `json:"orgId,omitempty"`
	PeerStatuses    map[int]*PeerStatus     `json:"peers,omitempty"`
	NetworkSettings network.NetworkSettings `json:"networkSettings,omitempty"`
	ExitNodeStatus  *ExitNodeStatus         `json:"exitNode,omitempty"`
	GatewayActive   bool                    `json:"gatewayActive,omitempty"`
	GatewaySiteIds  []int                   `json:"gatewaySiteIds,omitempty"`
	DNSBlocked      uint64                  `json:"dnsBlocked,omitempty"` // DNS queries refused by the blocklist since the tunnel started
	BlockPage       *BlockPageStatus        `json:"blockPage,omitempty"`  // set while the server sends domains that get a block page

	GatewaySiteResourceId int `json:"gatewaySiteResourceId,omitempty"` // the gateway site resource the selection belongs to; 0 when inactive
}

// BlockPageStatus describes whether olm can show the block page for blocked
// domains. Browsers only accept it over HTTPS when the system trusts this
// device's block page certificate authority.
type BlockPageStatus struct {
	// Active is whether blocked domains are sent to the block page. When
	// false, their lookups fail instead.
	Active bool `json:"active"`
	// Trusted is whether the system trusts the block page CA.
	Trusted bool `json:"trusted"`
	// CAPath is the CA certificate file, for installing it by hand or with
	// MDM. GET /blockpage/ca returns the same certificate.
	CAPath string `json:"caPath,omitempty"`
	// Error is why the CA is not trusted, if known.
	Error string `json:"error,omitempty"`
	// NeedsTrust is whether the CA exists but is not trusted. A host app can
	// then fetch it from GET /blockpage/ca, add it to the trust store with
	// the user's approval, and call POST /blockpage/recheck.
	NeedsTrust bool `json:"needsTrust,omitempty"`
}

type MetadataChangeRequest struct {
	Fingerprint map[string]any `json:"fingerprint"`
	Postures    map[string]any `json:"postures"`
}

// JITConnectionRequest defines the structure for a dynamic Just-In-Time connection request.
// Either SiteID or ResourceID must be provided (but not necessarily both).
type JITConnectionRequest struct {
	Site     string `json:"site,omitempty"`
	Resource string `json:"resource,omitempty"`
}

// API represents the HTTP server and its state
type API struct {
	addr       string
	socketPath string
	listener   net.Listener
	server     *http.Server

	onConnect        func(ConnectionRequest) error
	onSwitchOrg      func(SwitchOrgRequest) error
	onMetadataChange func(MetadataChangeRequest) error
	onDisconnect     func() error
	onExit           func() error
	onRebind         func() error
	onPowerMode      func(PowerModeRequest) error
	onJITConnect     func(JITConnectionRequest) error
	onSelectGateway  func(GatewayRequest) error
	onDisableGateway func() error

	statusMu       sync.RWMutex
	peerStatuses   map[int]*PeerStatus
	exitNodeStatus *ExitNodeStatus
	connectedAt    time.Time
	isConnected    bool
	isRegistered   bool
	isTerminated   bool
	isRestarting   bool
	olmError       *OlmError
	gatewayActive  bool
	gatewaySiteIds []int

	gatewaySiteResourceId int

	// dnsBlockedProvider reports the blocked query count. It is a callback
	// because the count changes on every blocked query.
	dnsBlockedProvider func() uint64
	// blockPageProvider reports the block page status (nil when it is not in
	// use) and blockPageCAProvider the CA certificate in PEM form (nil when
	// there is none). blockPageRecheck checks the CA's trust again and
	// returns the new status.
	blockPageProvider   func() *BlockPageStatus
	blockPageCAProvider func() []byte
	blockPageRecheck    func() *BlockPageStatus

	version string
	agent   string
	orgID   string
}

// NewAPI creates a new HTTP server that listens on a TCP address
func NewAPI(addr string) *API {
	s := &API{
		addr:         addr,
		peerStatuses: make(map[int]*PeerStatus),
	}

	return s
}

// NewAPISocket creates a new HTTP server that listens on a Unix socket or Windows named pipe
func NewAPISocket(socketPath string) *API {
	s := &API{
		socketPath:   socketPath,
		peerStatuses: make(map[int]*PeerStatus),
	}

	return s
}

func NewAPIStub() *API {
	s := &API{
		peerStatuses: make(map[int]*PeerStatus),
	}

	return s
}

// SetHandlers sets the callback functions for handling API requests
func (s *API) SetHandlers(
	onConnect func(ConnectionRequest) error,
	onSwitchOrg func(SwitchOrgRequest) error,
	onMetadataChange func(MetadataChangeRequest) error,
	onDisconnect func() error,
	onExit func() error,
	onRebind func() error,
	onPowerMode func(PowerModeRequest) error,
	onJITConnect func(JITConnectionRequest) error,
	onSelectGateway func(GatewayRequest) error,
	onDisableGateway func() error,
) {
	s.onConnect = onConnect
	s.onSwitchOrg = onSwitchOrg
	s.onMetadataChange = onMetadataChange
	s.onDisconnect = onDisconnect
	s.onExit = onExit
	s.onRebind = onRebind
	s.onPowerMode = onPowerMode
	s.onJITConnect = onJITConnect
	s.onSelectGateway = onSelectGateway
	s.onDisableGateway = onDisableGateway
}

// Start starts the HTTP server
func (s *API) Start() error {
	if s.socketPath == "" && s.addr == "" {
		return fmt.Errorf("either socketPath or addr must be provided to start the API server")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/connect", s.handleConnect)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/switch-org", s.handleSwitchOrg)
	mux.HandleFunc("/metadata", s.handleMetadataChange)
	mux.HandleFunc("/disconnect", s.handleDisconnect)
	mux.HandleFunc("/exit", s.handleExit)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/rebind", s.handleRebind)
	mux.HandleFunc("/power-mode", s.handlePowerMode)
	mux.HandleFunc("/jit-connect", s.handleJITConnect)
	mux.HandleFunc("/gateway/select", s.handleSelectGateway)
	mux.HandleFunc("/gateway/disable", s.handleDisableGateway)
	mux.HandleFunc("/blockpage/ca", s.handleBlockPageCA)
	mux.HandleFunc("/blockpage/recheck", s.handleBlockPageRecheck)

	s.server = &http.Server{
		Handler: mux,
	}

	var err error
	if s.socketPath != "" {
		// Use platform-specific socket listener
		s.listener, err = createSocketListener(s.socketPath)
		if err != nil {
			return fmt.Errorf("failed to create socket listener: %w", err)
		}
		logger.Info("Starting HTTP server on socket %s", s.socketPath)
	} else {
		// Use TCP listener
		s.listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
		logger.Info("Starting HTTP server on %s", s.addr)
	}

	go func() {
		if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the HTTP server
func (s *API) Stop() error {
	logger.Info("Stopping api server")

	// Close the server first, which will also close the listener gracefully
	if s.server != nil {
		_ = s.server.Close()
	}

	// Clean up socket file if using Unix socket
	if s.socketPath != "" {
		cleanupSocket(s.socketPath)
	}

	return nil
}

func (s *API) AddPeerStatus(siteID int, siteName string, connected bool, rtt time.Duration, endpoint string, isRelay bool, isLocal bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()

	status, exists := s.peerStatuses[siteID]
	if !exists {
		status = &PeerStatus{
			SiteID: siteID,
		}
		s.peerStatuses[siteID] = status
	}

	status.Name = siteName
	status.Connected = connected
	status.RTT = rtt
	status.LastSeen = time.Now()
	status.Endpoint = endpoint
	status.IsRelay = isRelay
	status.IsLocal = isLocal
}

// UpdatePeerStatus updates the status of a peer including endpoint, relay, and local info
func (s *API) UpdatePeerStatus(siteID int, connected bool, rtt time.Duration, endpoint string, isRelay bool, isLocal bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()

	status, exists := s.peerStatuses[siteID]
	if !exists {
		status = &PeerStatus{
			SiteID: siteID,
		}
		s.peerStatuses[siteID] = status
	}

	status.Connected = connected
	status.RTT = rtt
	status.LastSeen = time.Now()
	status.Endpoint = endpoint
	status.IsRelay = isRelay
	status.IsLocal = isLocal
}

func (s *API) RemovePeerStatus(siteID int) { // remove the peer from the status map
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	delete(s.peerStatuses, siteID)
}

// SetConnectionStatus sets the overall connection status
func (s *API) SetConnectionStatus(isConnected bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()

	s.isConnected = isConnected

	if isConnected {
		s.connectedAt = time.Now()
	}
}

func (s *API) SetRegistered(registered bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.isRegistered = registered
	// Clear any registration error when successfully registered
	if registered {
		s.olmError = nil
	}
}

// SetOlmError sets the registration error
func (s *API) SetOlmError(code string, message string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.olmError = &OlmError{
		Code:    code,
		Message: message,
	}
}

// ClearOlmError clears any registration error
func (s *API) ClearOlmError() {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.olmError = nil
}

func (s *API) SetTerminated(terminated bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.isTerminated = terminated
}

// SetRestarting sets whether a server-requested restart is in progress
func (s *API) SetRestarting(restarting bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.isRestarting = restarting
}

// ClearPeerStatuses clears all peer statuses
func (s *API) ClearPeerStatuses() {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.peerStatuses = make(map[int]*PeerStatus)
}

// SetVersion sets the olm version
func (s *API) SetVersion(version string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.version = version
}

// SetAgent sets the olm agent
func (s *API) SetAgent(agent string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.agent = agent
}

// SetDNSBlockedProvider sets the function that reports how many DNS queries
// the blocklist has refused. Pass nil to clear it.
func (s *API) SetDNSBlockedProvider(fn func() uint64) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.dnsBlockedProvider = fn
}

func (s *API) dnsBlocked() uint64 {
	if s.dnsBlockedProvider == nil {
		return 0
	}
	return s.dnsBlockedProvider()
}

// SetBlockPageProviders sets the functions that report the block page status
// and its CA certificate, and that check the CA's trust again. Pass nils to
// clear them.
func (s *API) SetBlockPageProviders(status func() *BlockPageStatus, caPEM func() []byte, recheck func() *BlockPageStatus) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.blockPageProvider = status
	s.blockPageCAProvider = caPEM
	s.blockPageRecheck = recheck
}

// handleBlockPageRecheck checks again whether the system trusts the block
// page CA and turns the block page on if it now does. A host app calls it
// after adding the CA to the trust store. It returns the new status.
func (s *API) handleBlockPageRecheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.statusMu.RLock()
	recheck := s.blockPageRecheck
	s.statusMu.RUnlock()

	if recheck == nil {
		http.Error(w, "Block page not in use", http.StatusNotFound)
		return
	}
	st := recheck()
	if st == nil {
		http.Error(w, "Block page not in use", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func (s *API) blockPage() *BlockPageStatus {
	if s.blockPageProvider == nil {
		return nil
	}
	return s.blockPageProvider()
}

// handleBlockPageCA returns the block page CA certificate (PEM), so a host app
// or an administrator can add it to the trust store when olm could not.
func (s *API) handleBlockPageCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.statusMu.RLock()
	provider := s.blockPageCAProvider
	s.statusMu.RUnlock()

	var pem []byte
	if provider != nil {
		pem = provider()
	}
	if len(pem) == 0 {
		http.Error(w, "No block page certificate", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Length", strconv.Itoa(len(pem)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pem)
}

// SetOrgID sets the organization ID
func (s *API) SetOrgID(orgID string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.orgID = orgID
}

// UpdatePeerRelayStatus updates only the relay status of a peer
func (s *API) UpdatePeerRelayStatus(siteID int, endpoint string, isRelay bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()

	status, exists := s.peerStatuses[siteID]
	if !exists {
		status = &PeerStatus{
			SiteID: siteID,
		}
		s.peerStatuses[siteID] = status
	}

	status.Endpoint = endpoint
	status.IsRelay = isRelay
	if isRelay {
		// Relay and local are mutually exclusive; local always wins when viable.
		status.IsLocal = false
	}
}

// UpdatePeerLocalStatus updates only the local-connection status of a peer. A peer using a
// local connection is never simultaneously relayed.
func (s *API) UpdatePeerLocalStatus(siteID int, endpoint string, isLocal bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()

	status, exists := s.peerStatuses[siteID]
	if !exists {
		status = &PeerStatus{
			SiteID: siteID,
		}
		s.peerStatuses[siteID] = status
	}

	status.Endpoint = endpoint
	status.IsLocal = isLocal
	if isLocal {
		status.IsRelay = false
	}
}

// UpdatePeerHolepunchStatus updates the holepunch connection status of a peer
func (s *API) UpdatePeerHolepunchStatus(siteID int, holepunchConnected bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()

	status, exists := s.peerStatuses[siteID]
	if !exists {
		status = &PeerStatus{
			SiteID: siteID,
		}
		s.peerStatuses[siteID] = status
	}

	status.HolepunchConnected = holepunchConnected
}

// SetExitNodeStatus sets the connectivity status of the client's own exit node connection
func (s *API) SetExitNodeStatus(connected bool, rtt time.Duration, endpoint string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.exitNodeStatus = &ExitNodeStatus{
		Connected: connected,
		RTT:       rtt,
		LastSeen:  time.Now(),
		Endpoint:  endpoint,
	}
}

// ClearExitNodeStatus removes the exit node status, e.g. when disconnecting from it
func (s *API) ClearExitNodeStatus() {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.exitNodeStatus = nil
}

// SetGatewayStatus records the current gateway (full-tunnel/default-route)
// state for exposure via the status endpoint.
func (s *API) SetGatewayStatus(active bool, siteResourceId int, siteIds []int) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.gatewayActive = active
	s.gatewaySiteResourceId = siteResourceId
	s.gatewaySiteIds = siteIds
}

// handleConnect handles the /connect endpoint
func (s *API) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// if we are already connected, reject new connection requests
	s.statusMu.RLock()
	alreadyConnected := s.isConnected
	s.statusMu.RUnlock()
	if alreadyConnected {
		http.Error(w, "Already connected to a server. Disconnect first before connecting again.", http.StatusConflict)
		return
	}

	var req ConnectionRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.ID == "" || req.Secret == "" || req.Endpoint == "" {
		http.Error(w, "Missing required fields: id, secret, and endpoint must be provided", http.StatusBadRequest)
		return
	}
	if len(req.GatewaySiteIds) > 0 && req.GatewaySiteResourceId <= 0 {
		http.Error(w, "Missing required field: gatewaySiteResourceId must be provided with gatewaySiteIds", http.StatusBadRequest)
		return
	}

	// Call the connect handler if set
	if s.onConnect != nil {
		if err := s.onConnect(req); err != nil {
			http.Error(w, fmt.Sprintf("Connection failed: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "connection request accepted",
	})
}

// handleStatus handles the /status endpoint
func (s *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.statusMu.RLock()

	resp := StatusResponse{
		Connected:       s.isConnected,
		Registered:      s.isRegistered,
		Terminated:      s.isTerminated,
		Restarting:      s.isRestarting,
		OlmError:        s.olmError,
		Version:         s.version,
		Agent:           s.agent,
		OrgID:           s.orgID,
		PeerStatuses:    s.peerStatuses,
		NetworkSettings: network.GetSettings(),
		ExitNodeStatus:  s.exitNodeStatus,
		GatewayActive:   s.gatewayActive,
		GatewaySiteIds:  s.gatewaySiteIds,
		DNSBlocked:      s.dnsBlocked(),
		BlockPage:       s.blockPage(),

		GatewaySiteResourceId: s.gatewaySiteResourceId,
	}

	s.statusMu.RUnlock()

	data, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleHealth handles the /health endpoint
func (s *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

// handleExit handles the /exit endpoint
func (s *API) handleExit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Info("Received exit request via API")

	// Return a success response first
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "shutdown initiated",
	})

	// Call the exit handler after responding, in a goroutine with a small delay
	// to ensure the response is fully sent before shutdown begins
	if s.onExit != nil {
		go func() {
			time.Sleep(100 * time.Millisecond)
			if err := s.onExit(); err != nil {
				logger.Error("Exit handler failed: %v", err)
			}
		}()
	}
}

// handleSwitchOrg handles the /switch-org endpoint
func (s *API) handleSwitchOrg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SwitchOrgRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.OrgID == "" {
		http.Error(w, "Missing required field: orgId must be provided", http.StatusBadRequest)
		return
	}

	logger.Info("Received org switch request to orgId: %s", req.OrgID)

	// Call the switch org handler if set
	if s.onSwitchOrg != nil {
		if err := s.onSwitchOrg(req); err != nil {
			http.Error(w, fmt.Sprintf("Org switch failed: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "org switch request accepted",
	})
}

// handleDisconnect handles the /disconnect endpoint
func (s *API) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// if we are already disconnected, reject new disconnect requests
	s.statusMu.RLock()
	alreadyDisconnected := !s.isConnected
	s.statusMu.RUnlock()
	if alreadyDisconnected {
		http.Error(w, "Not currently connected to a server.", http.StatusConflict)
		return
	}

	logger.Info("Received disconnect request via API")

	// Call the disconnect handler if set
	if s.onDisconnect != nil {
		if err := s.onDisconnect(); err != nil {
			http.Error(w, fmt.Sprintf("Disconnect failed: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "disconnect initiated",
	})
}

// handleMetadataChange handles the /metadata endpoint
func (s *API) handleMetadataChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req MetadataChangeRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	logger.Info("Received metadata change request via API: %v", req)

	_ = s.onMetadataChange(req)

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "metadata updated",
	})
}

func (s *API) GetStatus() StatusResponse {
	return StatusResponse{
		Connected:       s.isConnected,
		Registered:      s.isRegistered,
		Terminated:      s.isTerminated,
		Restarting:      s.isRestarting,
		OlmError:        s.olmError,
		Version:         s.version,
		Agent:           s.agent,
		OrgID:           s.orgID,
		PeerStatuses:    s.peerStatuses,
		NetworkSettings: network.GetSettings(),
		ExitNodeStatus:  s.exitNodeStatus,
		GatewayActive:   s.gatewayActive,
		GatewaySiteIds:  s.gatewaySiteIds,
		DNSBlocked:      s.dnsBlocked(),
		BlockPage:       s.blockPage(),

		GatewaySiteResourceId: s.gatewaySiteResourceId,
	}
}

// handleRebind handles the /rebind endpoint
// This triggers a socket rebind, which is necessary when network connectivity changes
// (e.g., WiFi to cellular transition on macOS/iOS) and the old socket becomes stale.
func (s *API) handleRebind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Info("Received rebind request via API")

	// Call the rebind handler if set
	if s.onRebind != nil {
		if err := s.onRebind(); err != nil {
			http.Error(w, fmt.Sprintf("Rebind failed: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Rebind handler not configured", http.StatusNotImplemented)
		return
	}

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "socket rebound successfully",
	})
}

// handleJITConnect handles the /jit-connect endpoint.
// It initiates a dynamic Just-In-Time connection to a site identified by either
// a site or a resource. Exactly one of the two must be provided.
func (s *API) handleJITConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req JITConnectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate that exactly one of site or resource is provided
	if req.Site == "" && req.Resource == "" {
		http.Error(w, "Missing required field: either site or resource must be provided", http.StatusBadRequest)
		return
	}
	if req.Site != "" && req.Resource != "" {
		http.Error(w, "Ambiguous request: provide either site or resource, not both", http.StatusBadRequest)
		return
	}

	if req.Site != "" {
		logger.Info("Received JIT connection request via API: site=%s", req.Site)
	} else {
		logger.Info("Received JIT connection request via API: resource=%s", req.Resource)
	}

	if s.onJITConnect != nil {
		if err := s.onJITConnect(req); err != nil {
			http.Error(w, fmt.Sprintf("JIT connection failed: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "JIT connect handler not configured", http.StatusNotImplemented)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "JIT connection request accepted",
	})
}

// handleSelectGateway handles the /gateway/select endpoint. It designates
// the given site IDs as the gateway (full-tunnel/default-route) candidate
// set - the onSelectGateway handler is responsible for rejecting the call if
// the tunnel isn't registered/connected or any site ID isn't a tracked peer.
func (s *API) handleSelectGateway(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req GatewayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if req.SiteResourceId <= 0 {
		http.Error(w, "Missing required field: siteResourceId must be provided", http.StatusBadRequest)
		return
	}
	if len(req.SiteIds) == 0 {
		http.Error(w, "Missing required field: siteIds must be provided", http.StatusBadRequest)
		return
	}

	logger.Info("Received select-gateway request via API: siteResourceId=%d siteIds=%v", req.SiteResourceId, req.SiteIds)

	if s.onSelectGateway != nil {
		if err := s.onSelectGateway(req); err != nil {
			http.Error(w, fmt.Sprintf("Select gateway failed: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Select gateway handler not configured", http.StatusNotImplemented)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "gateway selection accepted",
	})
}

// handleDisableGateway handles the /gateway/disable endpoint. It fully clears
// gateway state; no request body is needed.
func (s *API) handleDisableGateway(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Info("Received disable-gateway request via API")

	if s.onDisableGateway != nil {
		if err := s.onDisableGateway(); err != nil {
			http.Error(w, fmt.Sprintf("Disable gateway failed: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Disable gateway handler not configured", http.StatusNotImplemented)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "gateway disabled",
	})
}

// handlePowerMode handles the /power-mode endpoint
// This allows changing the power mode between "normal" and "low"
func (s *API) handlePowerMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PowerModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate power mode
	if req.Mode != "normal" && req.Mode != "low" {
		http.Error(w, "Invalid power mode: must be 'normal' or 'low'", http.StatusBadRequest)
		return
	}

	logger.Info("Received power mode change request via API: mode=%s", req.Mode)

	// Call the power mode handler if set
	if s.onPowerMode != nil {
		if err := s.onPowerMode(req); err != nil {
			http.Error(w, fmt.Sprintf("Power mode change failed: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Power mode handler not configured", http.StatusNotImplemented)
		return
	}

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": fmt.Sprintf("power mode changed to %s successfully", req.Mode),
	})
}
