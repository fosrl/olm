package monitor

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

const (
	// Magic bytes to identify our packets
	magicHeader uint32 = 0xDEADBEEF
	// Request packet type
	packetTypeRequest uint8 = 1
	// Response packet type
	packetTypeResponse uint8 = 2
	// Packet format:
	// - 4 bytes: magic header (0xDEADBEEF)
	// - 1 byte: packet type (1 = request, 2 = response)
	// - 8 bytes: timestamp (for round-trip timing)
	packetSize = 13
)

// Client handles checking connectivity to a server
type Client struct {
	conn           net.Conn
	serverAddr     string
	monitorRunning bool
	monitorLock    sync.Mutex
	connLock       sync.Mutex // Protects connection operations
	shutdownCh     chan struct{}
	packetInterval time.Duration
	timeout        time.Duration
	maxAttempts    int
	dialer         Dialer
}

// Dialer is a function that creates a connection
type Dialer func(network, addr string) (net.Conn, error)

// ConnectionStatus represents the current connection state
type ConnectionStatus struct {
	Connected bool
	RTT       time.Duration
}

// NewClient creates a new connection test client
func NewClient(serverAddr string, dialer Dialer) (*Client, error) {
	return &Client{
		serverAddr:     serverAddr,
		shutdownCh:     make(chan struct{}),
		packetInterval: 2 * time.Second,
		timeout:        500 * time.Millisecond, // Timeout for individual packets
		maxAttempts:    3,                      // Default max attempts
		dialer:         dialer,
	}, nil
}

// SetPacketInterval changes how frequently packets are sent in monitor mode
func (c *Client) SetPacketInterval(interval time.Duration) {
	c.packetInterval = interval
}

// SetTimeout changes the timeout for waiting for responses
func (c *Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// SetMaxAttempts changes the maximum number of attempts for TestConnection
func (c *Client) SetMaxAttempts(attempts int) {
	c.maxAttempts = attempts
}

// UpdateServerAddr updates the server address and resets the connection
func (c *Client) UpdateServerAddr(serverAddr string) {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	// Close existing connection if any
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	c.serverAddr = serverAddr
}

// Close cleans up client resources
func (c *Client) Close() {
	c.StopMonitor()

	c.connLock.Lock()
	defer c.connLock.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// ensureConnection makes sure we have an active UDP connection
func (c *Client) ensureConnection() error {
	c.connLock.Lock()
	defer c.connLock.Unlock()

	if c.conn != nil {
		return nil
	}

	var err error
	if c.dialer != nil {
		c.conn, err = c.dialer("udp", c.serverAddr)
	} else {
		// Fallback to standard net.Dial
		c.conn, err = net.Dial("udp", c.serverAddr)
	}

	if err != nil {
		return err
	}

	return nil
}

// TestConnection checks if the connection to the server is working
// Returns true if connected, false otherwise
func (c *Client) TestConnection(ctx context.Context) (bool, time.Duration) {
	if err := c.ensureConnection(); err != nil {
		logger.Warn("Failed to ensure connection: %v", err)
		return false, 0
	}

	// Prepare packet buffer
	packet := make([]byte, packetSize)
	binary.BigEndian.PutUint32(packet[0:4], magicHeader)
	packet[4] = packetTypeRequest

	// Send multiple attempts as specified
	for attempt := 0; attempt < c.maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return false, 0
		default:
			// Add current timestamp to packet
			timestamp := time.Now().UnixNano()
			binary.BigEndian.PutUint64(packet[5:13], uint64(timestamp))

			// Lock the connection for the entire send/receive operation
			c.connLock.Lock()

			// Check if connection is still valid after acquiring lock
			if c.conn == nil {
				c.connLock.Unlock()
				return false, 0
			}

			// logger.Debug("Attempting to send monitor packet to %s", c.serverAddr)
			_, err := c.conn.Write(packet)
			if err != nil {
				c.connLock.Unlock()
				logger.Info("Error sending packet: %v", err)
				continue
			}
			// logger.Debug("Successfully sent monitor packet")

			// Set read deadline
			c.conn.SetReadDeadline(time.Now().Add(c.timeout))

			// Wait for response
			responseBuffer := make([]byte, packetSize)
			n, err := c.conn.Read(responseBuffer)
			c.connLock.Unlock()

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout, try next attempt
					time.Sleep(100 * time.Millisecond) // Brief pause between attempts
					continue
				}
				logger.Error("Error reading response: %v", err)
				continue
			}

			if n != packetSize {
				continue // Malformed packet
			}

			// Verify response
			magic := binary.BigEndian.Uint32(responseBuffer[0:4])
			packetType := responseBuffer[4]
			if magic != magicHeader || packetType != packetTypeResponse {
				continue // Not our response
			}

			// Extract the original timestamp and calculate RTT
			sentTimestamp := int64(binary.BigEndian.Uint64(responseBuffer[5:13]))
			rtt := time.Duration(time.Now().UnixNano() - sentTimestamp)

			return true, rtt
		}
	}

	return false, 0
}

// TestConnectionWithTimeout tries to test connection with a timeout
// Returns true if connected, false otherwise
func (c *Client) TestConnectionWithTimeout(timeout time.Duration) (bool, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.TestConnection(ctx)
}

// MonitorCallback is the function type for connection status change callbacks
type MonitorCallback func(status ConnectionStatus)

// StartMonitor begins monitoring the connection and calls the callback
// when the connection status changes
func (c *Client) StartMonitor(callback MonitorCallback) error {
	c.monitorLock.Lock()
	defer c.monitorLock.Unlock()

	if c.monitorRunning {
		logger.Info("Monitor already running")
		return nil // Already running
	}

	if err := c.ensureConnection(); err != nil {
		return err
	}

	c.monitorRunning = true
	c.shutdownCh = make(chan struct{})

	go func() {
		var lastConnected bool
		firstRun := true

		ticker := time.NewTicker(c.packetInterval)
		defer ticker.Stop()

		for {
			select {
			case <-c.shutdownCh:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
				connected, rtt := c.TestConnection(ctx)
				cancel()

				// Callback if status changed or it's the first check
				if connected != lastConnected || firstRun {
					callback(ConnectionStatus{
						Connected: connected,
						RTT:       rtt,
					})
					lastConnected = connected
					firstRun = false
				}
			}
		}
	}()

	return nil
}

// StopMonitor stops the connection monitoring
func (c *Client) StopMonitor() {
	c.monitorLock.Lock()
	defer c.monitorLock.Unlock()

	if !c.monitorRunning {
		return
	}

	close(c.shutdownCh)
	c.monitorRunning = false
}
