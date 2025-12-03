package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
)

// ConnectionRequest defines the structure for an incoming connection request
type ConnectionRequest struct {
	ID            string   `json:"id"`
	Secret        string   `json:"secret"`
	Endpoint      string   `json:"endpoint"`
	UserToken     string   `json:"userToken,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	DNS           string   `json:"dns,omitempty"`
	DNSProxyIP    string   `json:"dnsProxyIP,omitempty"`
	UpstreamDNS   []string `json:"upstreamDNS,omitempty"`
	InterfaceName string   `json:"interfaceName,omitempty"`
	Holepunch     bool     `json:"holepunch,omitempty"`
	TlsClientCert string   `json:"tlsClientCert,omitempty"`
	PingInterval  string   `json:"pingInterval,omitempty"`
	PingTimeout   string   `json:"pingTimeout,omitempty"`
	OrgID         string   `json:"orgId,omitempty"`
}

// SwitchOrgRequest defines the structure for switching organizations
type SwitchOrgRequest struct {
	OrgID string `json:"orgId"`
}

// PeerStatus represents the status of a peer connection
type PeerStatus struct {
	SiteID             int           `json:"siteId"`
	Connected          bool          `json:"connected"`
	RTT                time.Duration `json:"rtt"`
	LastSeen           time.Time     `json:"lastSeen"`
	Endpoint           string        `json:"endpoint,omitempty"`
	IsRelay            bool          `json:"isRelay"`
	PeerIP             string        `json:"peerAddress,omitempty"`
	HolepunchConnected bool          `json:"holepunchConnected"`
}

// StatusResponse is returned by the status endpoint
type StatusResponse struct {
	Connected       bool                    `json:"connected"`
	Registered      bool                    `json:"registered"`
	Terminated      bool                    `json:"terminated"`
	Version         string                  `json:"version,omitempty"`
	OrgID           string                  `json:"orgId,omitempty"`
	PeerStatuses    map[int]*PeerStatus     `json:"peers,omitempty"`
	NetworkSettings network.NetworkSettings `json:"networkSettings,omitempty"`
}

// API represents the HTTP server and its state
type API struct {
	addr         string
	socketPath   string
	listener     net.Listener
	server       *http.Server
	onConnect    func(ConnectionRequest) error
	onSwitchOrg  func(SwitchOrgRequest) error
	onDisconnect func() error
	onExit       func() error
	statusMu     sync.RWMutex
	peerStatuses map[int]*PeerStatus
	connectedAt  time.Time
	isConnected  bool
	isRegistered bool
	isTerminated bool
	version      string
	orgID        string
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

// SetHandlers sets the callback functions for handling API requests
func (s *API) SetHandlers(
	onConnect func(ConnectionRequest) error,
	onSwitchOrg func(SwitchOrgRequest) error,
	onDisconnect func() error,
	onExit func() error,
) {
	s.onConnect = onConnect
	s.onSwitchOrg = onSwitchOrg
	s.onDisconnect = onDisconnect
	s.onExit = onExit
}

// Start starts the HTTP server
func (s *API) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/connect", s.handleConnect)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/switch-org", s.handleSwitchOrg)
	mux.HandleFunc("/disconnect", s.handleDisconnect)
	mux.HandleFunc("/exit", s.handleExit)
	mux.HandleFunc("/health", s.handleHealth)

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
		s.server.Close()
	}

	// Clean up socket file if using Unix socket
	if s.socketPath != "" {
		cleanupSocket(s.socketPath)
	}

	return nil
}

// UpdatePeerStatus updates the status of a peer including endpoint and relay info
func (s *API) UpdatePeerStatus(siteID int, connected bool, rtt time.Duration, endpoint string, isRelay bool) {
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
}

// SetConnectionStatus sets the overall connection status
func (s *API) SetConnectionStatus(isConnected bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()

	s.isConnected = isConnected

	if isConnected {
		s.connectedAt = time.Now()
	} else {
		// Clear peer statuses when disconnected
		s.peerStatuses = make(map[int]*PeerStatus)
	}
}

func (s *API) SetRegistered(registered bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.isRegistered = registered
}

func (s *API) SetTerminated(terminated bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.isTerminated = terminated
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
	json.NewEncoder(w).Encode(map[string]string{
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
	defer s.statusMu.RUnlock()

	resp := StatusResponse{
		Connected:       s.isConnected,
		Registered:      s.isRegistered,
		Terminated:      s.isTerminated,
		Version:         s.version,
		OrgID:           s.orgID,
		PeerStatuses:    s.peerStatuses,
		NetworkSettings: network.GetSettings(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleHealth handles the /health endpoint
func (s *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
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

	// Call the exit handler if set
	if s.onExit != nil {
		if err := s.onExit(); err != nil {
			http.Error(w, fmt.Sprintf("Exit failed: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "shutdown initiated",
	})
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
	json.NewEncoder(w).Encode(map[string]string{
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
	json.NewEncoder(w).Encode(map[string]string{
		"status": "disconnect initiated",
	})
}

func (s *API) GetStatus() StatusResponse {
	return StatusResponse{
		Connected:       s.isConnected,
		Registered:      s.isRegistered,
		Terminated:      s.isTerminated,
		Version:         s.version,
		OrgID:           s.orgID,
		PeerStatuses:    s.peerStatuses,
		NetworkSettings: network.GetSettings(),
	}
}
