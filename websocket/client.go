package websocket

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/fosrl/newt/logger"
	"github.com/gorilla/websocket"
)

// AuthError represents an authentication/authorization error (401/403)
type AuthError struct {
	StatusCode int
	Message    string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("authentication error (status %d): %s", e.StatusCode, e.Message)
}

// IsAuthError checks if an error is an authentication error
func IsAuthError(err error) bool {
	_, ok := err.(*AuthError)
	return ok
}

type TokenResponse struct {
	Data struct {
		Token         string     `json:"token"`
		ExitNodes     []ExitNode `json:"exitNodes"`
		ServerVersion string     `json:"serverVersion"`
	} `json:"data"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type ExitNode struct {
	Endpoint  string `json:"endpoint"`
	RelayPort uint16 `json:"relayPort"`
	PublicKey string `json:"publicKey"`
	SiteIds   []int  `json:"siteIds"`
}

type WSMessage struct {
	Type          string      `json:"type"`
	Data          interface{} `json:"data"`
	ConfigVersion int         `json:"configVersion,omitempty"`
}

// this is not json anymore
type Config struct {
	ID            string
	Secret        string
	Endpoint      string
	TlsClientCert string // legacy PKCS12 file path
	UserToken     string // optional user token for websocket authentication
	OrgID         string // optional organization ID for websocket authentication
}

type Client struct {
	config            *Config
	conn              *websocket.Conn
	baseURL           string
	handlers          map[string]MessageHandler
	done              chan struct{}
	handlersMux       sync.RWMutex
	reconnectInterval time.Duration
	isConnected       bool
	isDisconnected    bool // Flag to track if client is intentionally disconnected
	reconnectMux      sync.RWMutex
	pingInterval      time.Duration
	pingTimeout       time.Duration
	onConnect         func() error
	onTokenUpdate     func(token string, exitNodes []ExitNode)
	onAuthError       func(statusCode int, message string) // Callback for auth errors
	writeMux          sync.Mutex
	clientType        string // Type of client (e.g., "newt", "olm")
	tlsConfig         TLSConfig
	configNeedsSave   bool // Flag to track if config needs to be saved
	configVersion     int  // Latest config version received from server
	configVersionMux  sync.RWMutex
	token             string       // Cached authentication token
	exitNodes         []ExitNode   // Cached exit nodes from token response
	tokenMux          sync.RWMutex // Protects token and exitNodes
	forceNewToken     bool         // Flag to force fetching a new token on next connection
	processingMessage bool         // Flag to track if a message is currently being processed
	processingMux     sync.RWMutex // Protects processingMessage
	processingWg      sync.WaitGroup // WaitGroup to wait for message processing to complete
}

type ClientOption func(*Client)

type MessageHandler func(message WSMessage)

// TLSConfig holds TLS configuration options
type TLSConfig struct {
	// New separate certificate support
	ClientCertFile string
	ClientKeyFile  string
	CAFiles        []string

	// Existing PKCS12 support (deprecated)
	PKCS12File string
}

// WithBaseURL sets the base URL for the client
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithTLSConfig sets the TLS configuration for the client
func WithTLSConfig(config TLSConfig) ClientOption {
	return func(c *Client) {
		c.tlsConfig = config
		// For backward compatibility, also set the legacy field
		if config.PKCS12File != "" {
			c.config.TlsClientCert = config.PKCS12File
		}
	}
}

func (c *Client) OnConnect(callback func() error) {
	c.onConnect = callback
}

func (c *Client) OnTokenUpdate(callback func(token string, exitNodes []ExitNode)) {
	c.onTokenUpdate = callback
}

func (c *Client) OnAuthError(callback func(statusCode int, message string)) {
	c.onAuthError = callback
}

// NewClient creates a new websocket client
func NewClient(ID, secret, userToken, orgId, endpoint string, pingInterval time.Duration, pingTimeout time.Duration, opts ...ClientOption) (*Client, error) {
	config := &Config{
		ID:        ID,
		Secret:    secret,
		Endpoint:  endpoint,
		UserToken: userToken,
		OrgID:     orgId,
	}

	client := &Client{
		config:            config,
		baseURL:           endpoint, // default value
		handlers:          make(map[string]MessageHandler),
		done:              make(chan struct{}),
		reconnectInterval: 3 * time.Second,
		isConnected:       false,
		pingInterval:      pingInterval,
		pingTimeout:       pingTimeout,
		clientType:        "olm",
	}

	// Apply options before loading config
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(client)
	}

	return client, nil
}

func (c *Client) GetConfig() *Config {
	return c.config
}

// Connect establishes the WebSocket connection
func (c *Client) Connect() error {
	if c.isDisconnected {
		c.isDisconnected = false
	}
	go c.connectWithRetry()
	return nil
}

// Close closes the WebSocket connection gracefully
func (c *Client) Close() error {
	// Signal shutdown to all goroutines first
	select {
	case <-c.done:
		// Already closed
		return nil
	default:
		close(c.done)
	}

	// Set connection status to false
	c.setConnected(false)

	// Close the WebSocket connection gracefully
	if c.conn != nil {
		// Send close message
		c.writeMux.Lock()
		c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.writeMux.Unlock()

		// Close the connection
		return c.conn.Close()
	}

	return nil
}

// Disconnect cleanly closes the websocket connection and suspends message intervals, but allows reconnecting later.
func (c *Client) Disconnect() error {
	c.isDisconnected = true
	c.setConnected(false)

	// Wait for any message currently being processed to complete
	c.processingWg.Wait()

	if c.conn != nil {
		c.writeMux.Lock()
		c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.writeMux.Unlock()
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// SendMessage sends a message through the WebSocket connection
func (c *Client) SendMessage(messageType string, data interface{}) error {
	if c.isDisconnected || c.conn == nil {
		return fmt.Errorf("not connected")
	}

	msg := WSMessage{
		Type: messageType,
		Data: data,
	}

	logger.Debug("websocket: Sending message: %s, data: %+v", messageType, data)

	c.writeMux.Lock()
	defer c.writeMux.Unlock()
	return c.conn.WriteJSON(msg)
}

func (c *Client) SendMessageInterval(messageType string, data interface{}, interval time.Duration, maxAttempts int) (stop func(), update func(newData interface{})) {
	stopChan := make(chan struct{})
	updateChan := make(chan interface{})
	var dataMux sync.Mutex
	currentData := data

	go func() {
		count := 0

		send := func() {
			if c.isDisconnected || c.conn == nil {
				return
			}
			err := c.SendMessage(messageType, currentData)
			if err != nil {
				logger.Error("websocket: Failed to send message: %v", err)
			}
			count++
		}

		send() // Send immediately

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if maxAttempts != -1 && count >= maxAttempts {
					logger.Info("websocket: SendMessageInterval timed out after %d attempts for message type: %s", maxAttempts, messageType)
					return
				}
				dataMux.Lock()
				send()
				dataMux.Unlock()
			case newData := <-updateChan:
				dataMux.Lock()
				// Merge newData into currentData if both are maps
				if currentMap, ok := currentData.(map[string]interface{}); ok {
					if newMap, ok := newData.(map[string]interface{}); ok {
						// Update or add keys from newData
						for key, value := range newMap {
							currentMap[key] = value
						}
						currentData = currentMap
					} else {
						// If newData is not a map, replace entirely
						currentData = newData
					}
				} else {
					// If currentData is not a map, replace entirely
					currentData = newData
				}
				dataMux.Unlock()
			case <-stopChan:
				return
			}
			// Suspend sending if disconnected
			for c.isDisconnected {
				select {
				case <-stopChan:
					return
				case <-time.After(500 * time.Millisecond):
				}
			}
		}
	}()
	return func() {
			close(stopChan)
		}, func(newData interface{}) {
			select {
			case updateChan <- newData:
			case <-stopChan:
				// Channel is closed, ignore update
			}
		}
}

// RegisterHandler registers a handler for a specific message type
func (c *Client) RegisterHandler(messageType string, handler MessageHandler) {
	c.handlersMux.Lock()
	defer c.handlersMux.Unlock()
	c.handlers[messageType] = handler
}

func (c *Client) getToken() (string, []ExitNode, error) {
	// Parse the base URL to ensure we have the correct hostname
	baseURL, err := url.Parse(c.baseURL)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Ensure we have the base URL without trailing slashes
	baseEndpoint := strings.TrimRight(baseURL.String(), "/")

	var tlsConfig *tls.Config = nil

	// Use new TLS configuration method
	if c.tlsConfig.ClientCertFile != "" || c.tlsConfig.ClientKeyFile != "" || len(c.tlsConfig.CAFiles) > 0 || c.tlsConfig.PKCS12File != "" {
		tlsConfig, err = c.setupTLS()
		if err != nil {
			return "", nil, fmt.Errorf("failed to setup TLS configuration: %w", err)
		}
	}

	// Check for environment variable to skip TLS verification
	if os.Getenv("SKIP_TLS_VERIFY") == "true" {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}
		tlsConfig.InsecureSkipVerify = true
		logger.Debug("websocket: TLS certificate verification disabled via SKIP_TLS_VERIFY environment variable")
	}

	tokenData := map[string]interface{}{
		"olmId":  c.config.ID,
		"secret": c.config.Secret,
		"orgId":  c.config.OrgID,
	}
	jsonData, err := json.Marshal(tokenData)

	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal token request data: %w", err)
	}

	// Create a new request
	req, err := http.NewRequest(
		"POST",
		baseEndpoint+"/api/v1/auth/"+c.clientType+"/get-token",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "x-csrf-protection")

	// print out the request for debugging
	logger.Debug("websocket: Requesting token from %s with body: %s", req.URL.String(), string(jsonData))

	// Make the request
	client := &http.Client{}
	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to request new token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.Error("websocket: Failed to get token with status code: %d, body: %s", resp.StatusCode, string(body))

		// Return AuthError for 401/403 status codes
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "", nil, &AuthError{
				StatusCode: resp.StatusCode,
				Message:    string(body),
			}
		}

		// For other errors (5xx, network issues, etc.), return regular error
		return "", nil, fmt.Errorf("failed to get token with status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logger.Error("websocket: Failed to decode token response.")
		return "", nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if !tokenResp.Success {
		return "", nil, fmt.Errorf("failed to get token: %s", tokenResp.Message)
	}

	if tokenResp.Data.Token == "" {
		return "", nil, fmt.Errorf("received empty token from server")
	}

	logger.Debug("websocket: Received token: %s", tokenResp.Data.Token)

	return tokenResp.Data.Token, tokenResp.Data.ExitNodes, nil
}

func (c *Client) connectWithRetry() {
	for {
		select {
		case <-c.done:
			return
		default:
			err := c.establishConnection()
			if err != nil {
				// Check if this is an auth error (401/403)
				var authErr *AuthError
				if errors.As(err, &authErr) {
					logger.Error("Authentication failed: %v. Terminating tunnel and retrying...", authErr)
					// Trigger auth error callback if set (this should terminate the tunnel)
					if c.onAuthError != nil {
						c.onAuthError(authErr.StatusCode, authErr.Message)
					}
					// Continue retrying after auth error
					time.Sleep(c.reconnectInterval)
					continue
				}
				// For other errors (5xx, network issues), continue retrying
				logger.Error("websocket: Failed to connect: %v. Retrying in %v...", err, c.reconnectInterval)
				time.Sleep(c.reconnectInterval)
				continue
			}
			return
		}
	}
}

func (c *Client) establishConnection() error {
	// Get token for authentication - reuse cached token unless forced to get new one
	c.tokenMux.Lock()
	needNewToken := c.token == "" || c.forceNewToken
	if needNewToken {
		token, exitNodes, err := c.getToken()
		if err != nil {
			c.tokenMux.Unlock()
			return fmt.Errorf("failed to get token: %w", err)
		}
		c.token = token
		c.exitNodes = exitNodes
		c.forceNewToken = false

		if c.onTokenUpdate != nil {
			c.onTokenUpdate(token, exitNodes)
		}
	}
	token := c.token
	c.tokenMux.Unlock()

	// Parse the base URL to determine protocol and hostname
	baseURL, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Determine WebSocket protocol based on HTTP protocol
	wsProtocol := "wss"
	if baseURL.Scheme == "http" {
		wsProtocol = "ws"
	}

	// Create WebSocket URL
	wsURL := fmt.Sprintf("%s://%s/api/v1/ws", wsProtocol, baseURL.Host)
	u, err := url.Parse(wsURL)
	if err != nil {
		return fmt.Errorf("failed to parse WebSocket URL: %w", err)
	}

	// Add token to query parameters
	q := u.Query()
	q.Set("token", token)
	q.Set("clientType", c.clientType)
	if c.config.UserToken != "" {
		q.Set("userToken", c.config.UserToken)
	}
	u.RawQuery = q.Encode()

	// Connect to WebSocket
	dialer := websocket.DefaultDialer

	// Use new TLS configuration method
	if c.tlsConfig.ClientCertFile != "" || c.tlsConfig.ClientKeyFile != "" || len(c.tlsConfig.CAFiles) > 0 || c.tlsConfig.PKCS12File != "" {
		logger.Info("websocket: Setting up TLS configuration for WebSocket connection")
		tlsConfig, err := c.setupTLS()
		if err != nil {
			return fmt.Errorf("failed to setup TLS configuration: %w", err)
		}
		dialer.TLSClientConfig = tlsConfig
	}

	// Check for environment variable to skip TLS verification for WebSocket connection
	if os.Getenv("SKIP_TLS_VERIFY") == "true" {
		if dialer.TLSClientConfig == nil {
			dialer.TLSClientConfig = &tls.Config{}
		}
		dialer.TLSClientConfig.InsecureSkipVerify = true
		logger.Debug("websocket: WebSocket TLS certificate verification disabled via SKIP_TLS_VERIFY environment variable")
	}

	conn, resp, err := dialer.Dial(u.String(), nil)
	if err != nil {
		// Check if this is an unauthorized error (401)
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			logger.Error("websocket: WebSocket connection rejected with 401 Unauthorized")
			// Force getting a new token on next reconnect attempt
			c.tokenMux.Lock()
			c.forceNewToken = true
			c.tokenMux.Unlock()
			return &AuthError{
				StatusCode: http.StatusUnauthorized,
				Message:    "WebSocket connection unauthorized",
			}
		}
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	c.conn = conn
	c.setConnected(true)

	// Start the ping monitor
	go c.pingMonitor()
	// Start the read pump with disconnect detection
	go c.readPumpWithDisconnectDetection()

	if c.onConnect != nil {
		if err := c.onConnect(); err != nil {
			logger.Error("websocket: OnConnect callback failed: %v", err)
		}
	}

	return nil
}

// setupTLS configures TLS based on the TLS configuration
func (c *Client) setupTLS() (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	// Handle new separate certificate configuration
	if c.tlsConfig.ClientCertFile != "" && c.tlsConfig.ClientKeyFile != "" {
		logger.Info("websocket: Loading separate certificate files for mTLS")
		logger.Debug("websocket: Client cert: %s", c.tlsConfig.ClientCertFile)
		logger.Debug("websocket: Client key: %s", c.tlsConfig.ClientKeyFile)

		// Load client certificate and key
		cert, err := tls.LoadX509KeyPair(c.tlsConfig.ClientCertFile, c.tlsConfig.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		// Load CA certificates for remote validation if specified
		if len(c.tlsConfig.CAFiles) > 0 {
			logger.Debug("websocket: Loading CA certificates: %v", c.tlsConfig.CAFiles)
			caCertPool := x509.NewCertPool()
			for _, caFile := range c.tlsConfig.CAFiles {
				caCert, err := os.ReadFile(caFile)
				if err != nil {
					return nil, fmt.Errorf("failed to read CA file %s: %w", caFile, err)
				}

				// Try to parse as PEM first, then DER
				if !caCertPool.AppendCertsFromPEM(caCert) {
					// If PEM parsing failed, try DER
					cert, err := x509.ParseCertificate(caCert)
					if err != nil {
						return nil, fmt.Errorf("failed to parse CA certificate from %s: %w", caFile, err)
					}
					caCertPool.AddCert(cert)
				}
			}
			tlsConfig.RootCAs = caCertPool
		}

		return tlsConfig, nil
	}

	// Fallback to existing PKCS12 implementation for backward compatibility
	if c.tlsConfig.PKCS12File != "" {
		logger.Info("websocket: Loading PKCS12 certificate for mTLS (deprecated)")
		return c.setupPKCS12TLS()
	}

	// Legacy fallback using config.TlsClientCert
	if c.config.TlsClientCert != "" {
		logger.Info("websocket: Loading legacy PKCS12 certificate for mTLS (deprecated)")
		return loadClientCertificate(c.config.TlsClientCert)
	}

	return nil, nil
}

// setupPKCS12TLS loads TLS configuration from PKCS12 file
func (c *Client) setupPKCS12TLS() (*tls.Config, error) {
	return loadClientCertificate(c.tlsConfig.PKCS12File)
}

// pingMonitor sends pings at a short interval and triggers reconnect on failure
func (c *Client) pingMonitor() {
	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if c.isDisconnected || c.conn == nil {
				return
			}
			// Skip ping if a message is currently being processed
			c.processingMux.RLock()
			isProcessing := c.processingMessage
			c.processingMux.RUnlock()
			if isProcessing {
				logger.Debug("websocket: Skipping ping, message is being processed")
				continue
			}
			// Send application-level ping with config version
			c.configVersionMux.RLock()
			configVersion := c.configVersion
			c.configVersionMux.RUnlock()

			pingMsg := WSMessage{
				Type: "olm/ping",
				Data: map[string]any{
					"timestamp": time.Now().Unix(),
					"userToken": c.config.UserToken,
				},
				ConfigVersion: configVersion,
			}

			logger.Debug("websocket: Sending ping: %+v", pingMsg)

			c.writeMux.Lock()
			err := c.conn.WriteJSON(pingMsg)
			c.writeMux.Unlock()
			if err != nil {
				// Check if we're shutting down before logging error and reconnecting
				select {
				case <-c.done:
					// Expected during shutdown
					return
				default:
					logger.Error("websocket: Ping failed: %v", err)
					c.reconnect()
					return
				}
			}
		}
	}
}

// GetConfigVersion returns the current config version
func (c *Client) GetConfigVersion() int {
	c.configVersionMux.RLock()
	defer c.configVersionMux.RUnlock()
	return c.configVersion
}

// setConfigVersion updates the config version if the new version is higher
func (c *Client) setConfigVersion(version int) {
	c.configVersionMux.Lock()
	defer c.configVersionMux.Unlock()
	logger.Debug("websocket: setting config version to %d", version)
	c.configVersion = version
}

// readPumpWithDisconnectDetection reads messages and triggers reconnect on error
func (c *Client) readPumpWithDisconnectDetection() {
	defer func() {
		if c.conn != nil {
			c.conn.Close()
		}
		// Only attempt reconnect if we're not shutting down
		select {
		case <-c.done:
			// Shutting down, don't reconnect
			return
		default:
			c.reconnect()
		}
	}()

	for {
		select {
		case <-c.done:
			return
		default:
			var msg WSMessage
			err := c.conn.ReadJSON(&msg)
			if err != nil {
				// Check if we're shutting down or explicitly disconnected before logging error
				select {
				case <-c.done:
					// Expected during shutdown, don't log as error
					logger.Debug("websocket: connection closed during shutdown")
					return
				default:
					// Check if explicitly disconnected
					if c.isDisconnected {
						logger.Debug("websocket:  connection closed: client was explicitly disconnected")
						return
					}

					// Unexpected error during normal operation
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
						logger.Error("websocket: read error: %v", err)
					} else {
						logger.Debug("websocket: connection closed: %v", err)
					}
					return // triggers reconnect via defer
				}
			}

			// Update config version from incoming message
			c.setConfigVersion(msg.ConfigVersion)

			c.handlersMux.RLock()
			if handler, ok := c.handlers[msg.Type]; ok {
				// Mark that we're processing a message
				c.processingMux.Lock()
				c.processingMessage = true
				c.processingMux.Unlock()
				c.processingWg.Add(1)

				handler(msg)

				// Mark that we're done processing
				c.processingWg.Done()
				c.processingMux.Lock()
				c.processingMessage = false
				c.processingMux.Unlock()
			}
			c.handlersMux.RUnlock()
		}
	}
}

func (c *Client) reconnect() {
	c.setConnected(false)
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	// Don't reconnect if explicitly disconnected
	if c.isDisconnected {
		logger.Debug("websocket: websocket: Not reconnecting: client was explicitly disconnected")
		return
	}

	// Only reconnect if we're not shutting down
	select {
	case <-c.done:
		return
	default:
		go c.connectWithRetry()
	}
}

func (c *Client) setConnected(status bool) {
	c.reconnectMux.Lock()
	defer c.reconnectMux.Unlock()
	c.isConnected = status
}

// LoadClientCertificate Helper method to load client certificates (PKCS12 format)
func loadClientCertificate(p12Path string) (*tls.Config, error) {
	logger.Info("websocket: Loading tls-client-cert %s", p12Path)
	// Read the PKCS12 file
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PKCS12 file: %w", err)
	}

	// Parse PKCS12 with empty password for non-encrypted files
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(p12Data, "")
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS12: %w", err)
	}

	// Create certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certificate.Raw},
		PrivateKey:  privateKey,
	}

	// Optional: Add CA certificates if present
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system cert pool: %w", err)
	}
	if len(caCerts) > 0 {
		for _, caCert := range caCerts {
			rootCAs.AddCert(caCert)
		}
	}

	// Create TLS configuration
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
	}, nil
}
