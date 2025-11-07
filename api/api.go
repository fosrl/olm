package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

// ConnectionRequest defines the structure for an incoming connection request
type ConnectionRequest struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	Endpoint  string `json:"endpoint"`
	UserToken string `json:"userToken,omitempty"`
}

// SwitchOrgRequest defines the structure for switching organizations
type SwitchOrgRequest struct {
	OrgID string `json:"orgId"`
}

// PeerStatus represents the status of a peer connection
type PeerStatus struct {
	SiteID    int           `json:"siteId"`
	Connected bool          `json:"connected"`
	RTT       time.Duration `json:"rtt"`
	LastSeen  time.Time     `json:"lastSeen"`
	Endpoint  string        `json:"endpoint,omitempty"`
	IsRelay   bool          `json:"isRelay"`
	PeerIP    string        `json:"peerAddress,omitempty"`
}

// StatusResponse is returned by the status endpoint
type StatusResponse struct {
	Connected    bool                `json:"connected"`
	Registered   bool                `json:"registered"`
	TunnelIP     string              `json:"tunnelIP,omitempty"`
	Version      string              `json:"version,omitempty"`
	OrgID        string              `json:"orgId,omitempty"`
	PeerStatuses map[int]*PeerStatus `json:"peers,omitempty"`
}

// API represents the HTTP server and its state
type API struct {
	addr           string
	socketPath     string
	listener       net.Listener
	server         *http.Server
	connectionChan chan ConnectionRequest
	switchOrgChan  chan SwitchOrgRequest
	shutdownChan   chan struct{}
	disconnectChan chan struct{}
	statusMu       sync.RWMutex
	peerStatuses   map[int]*PeerStatus
	connectedAt    time.Time
	isConnected    bool
	isRegistered   bool
	tunnelIP       string
	version        string
	orgID          string
}

// NewAPI creates a new HTTP server that listens on a TCP address
func NewAPI(addr string) *API {
	s := &API{
		addr:           addr,
		connectionChan: make(chan ConnectionRequest, 1),
		switchOrgChan:  make(chan SwitchOrgRequest, 1),
		shutdownChan:   make(chan struct{}, 1),
		disconnectChan: make(chan struct{}, 1),
		peerStatuses:   make(map[int]*PeerStatus),
	}

	return s
}

// NewAPISocket creates a new HTTP server that listens on a Unix socket or Windows named pipe
func NewAPISocket(socketPath string) *API {
	s := &API{
		socketPath:     socketPath,
		connectionChan: make(chan ConnectionRequest, 1),
		switchOrgChan:  make(chan SwitchOrgRequest, 1),
		shutdownChan:   make(chan struct{}, 1),
		disconnectChan: make(chan struct{}, 1),
		peerStatuses:   make(map[int]*PeerStatus),
	}

	return s
}

// Start starts the HTTP server
func (s *API) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/connect", s.handleConnect)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/switch-org", s.handleSwitchOrg)
	mux.HandleFunc("/disconnect", s.handleDisconnect)
	mux.HandleFunc("/exit", s.handleExit)

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

// GetConnectionChannel returns the channel for receiving connection requests
func (s *API) GetConnectionChannel() <-chan ConnectionRequest {
	return s.connectionChan
}

// GetSwitchOrgChannel returns the channel for receiving org switch requests
func (s *API) GetSwitchOrgChannel() <-chan SwitchOrgRequest {
	return s.switchOrgChan
}

// GetShutdownChannel returns the channel for receiving shutdown requests
func (s *API) GetShutdownChannel() <-chan struct{} {
	return s.shutdownChan
}

// GetDisconnectChannel returns the channel for receiving disconnect requests
func (s *API) GetDisconnectChannel() <-chan struct{} {
	return s.disconnectChan
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

// SetTunnelIP sets the tunnel IP address
func (s *API) SetTunnelIP(tunnelIP string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.tunnelIP = tunnelIP
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

// handleConnect handles the /connect endpoint
func (s *API) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

	// Send the request to the main goroutine
	s.connectionChan <- req

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
		Connected:    s.isConnected,
		Registered:   s.isRegistered,
		TunnelIP:     s.tunnelIP,
		Version:      s.version,
		OrgID:        s.orgID,
		PeerStatuses: s.peerStatuses,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleExit handles the /exit endpoint
func (s *API) handleExit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Info("Received exit request via API")

	// Send shutdown signal
	select {
	case s.shutdownChan <- struct{}{}:
		// Signal sent successfully
	default:
		// Channel already has a signal, don't block
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

	// Send the request to the main goroutine
	select {
	case s.switchOrgChan <- req:
		// Signal sent successfully
	default:
		// Channel already has a pending request
		http.Error(w, "Org switch already in progress", http.StatusConflict)
		return
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

	logger.Info("Received disconnect request via API")

	// Send disconnect signal
	select {
	case s.disconnectChan <- struct{}{}:
		// Signal sent successfully
	default:
		// Channel already has a signal, don't block
	}

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "disconnect initiated",
	})
}
