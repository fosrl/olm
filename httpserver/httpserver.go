package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

// ConnectionRequest defines the structure for an incoming connection request
type ConnectionRequest struct {
	ID       string `json:"id"`
	Secret   string `json:"secret"`
	Endpoint string `json:"endpoint"`
}

// PeerStatus represents the status of a peer connection
type PeerStatus struct {
	SiteID    int           `json:"siteId"`
	Connected bool          `json:"connected"`
	RTT       time.Duration `json:"rtt"`
	LastSeen  time.Time     `json:"lastSeen"`
	Endpoint  string        `json:"endpoint,omitempty"`
	IsRelay   bool          `json:"isRelay"`
}

// StatusResponse is returned by the status endpoint
type StatusResponse struct {
	Status       string              `json:"status"`
	Connected    bool                `json:"connected"`
	TunnelIP     string              `json:"tunnelIP,omitempty"`
	Version      string              `json:"version,omitempty"`
	PeerStatuses map[int]*PeerStatus `json:"peers,omitempty"`
}

// HTTPServer represents the HTTP server and its state
type HTTPServer struct {
	addr           string
	server         *http.Server
	connectionChan chan ConnectionRequest
	statusMu       sync.RWMutex
	peerStatuses   map[int]*PeerStatus
	connectedAt    time.Time
	isConnected    bool
	tunnelIP       string
	version        string
}

// NewHTTPServer creates a new HTTP server
func NewHTTPServer(addr string) *HTTPServer {
	s := &HTTPServer{
		addr:           addr,
		connectionChan: make(chan ConnectionRequest, 1),
		peerStatuses:   make(map[int]*PeerStatus),
	}

	return s
}

// Start starts the HTTP server
func (s *HTTPServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/connect", s.handleConnect)
	mux.HandleFunc("/status", s.handleStatus)

	s.server = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	logger.Info("Starting HTTP server on %s", s.addr)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the HTTP server
func (s *HTTPServer) Stop() error {
	logger.Info("Stopping HTTP server")
	return s.server.Close()
}

// GetConnectionChannel returns the channel for receiving connection requests
func (s *HTTPServer) GetConnectionChannel() <-chan ConnectionRequest {
	return s.connectionChan
}

// UpdatePeerStatus updates the status of a peer including endpoint and relay info
func (s *HTTPServer) UpdatePeerStatus(siteID int, connected bool, rtt time.Duration, endpoint string, isRelay bool) {
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
func (s *HTTPServer) SetConnectionStatus(isConnected bool) {
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

// SetTunnelIP sets the tunnel IP address
func (s *HTTPServer) SetTunnelIP(tunnelIP string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.tunnelIP = tunnelIP
}

// SetVersion sets the olm version
func (s *HTTPServer) SetVersion(version string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.version = version
}

// UpdatePeerRelayStatus updates only the relay status of a peer
func (s *HTTPServer) UpdatePeerRelayStatus(siteID int, endpoint string, isRelay bool) {
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
func (s *HTTPServer) handleConnect(w http.ResponseWriter, r *http.Request) {
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
func (s *HTTPServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.statusMu.RLock()
	defer s.statusMu.RUnlock()

	resp := StatusResponse{
		Connected:    s.isConnected,
		TunnelIP:     s.tunnelIP,
		Version:      s.version,
		PeerStatuses: s.peerStatuses,
	}

	if s.isConnected {
		resp.Status = "connected"
	} else {
		resp.Status = "disconnected"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
