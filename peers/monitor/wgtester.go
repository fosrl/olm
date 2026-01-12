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

	// Exponential backoff fields
	minInterval        time.Duration // Minimum interval (initial)
	maxInterval        time.Duration // Maximum interval (cap for backoff)
	backoffMultiplier  float64       // Multiplier for each stable check
	stableCountToBackoff int         // Number of stable checks before backing off
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
		serverAddr:          serverAddr,
		shutdownCh:          make(chan struct{}),
		packetInterval:      2 * time.Second,
		minInterval:         2 * time.Second,
		maxInterval:         30 * time.Second,
		backoffMultiplier:   1.5,
		stableCountToBackoff: 3, // After 3 consecutive same-state results, start backing off
		timeout:             500 * time.Millisecond, // Timeout for individual packets
		maxAttempts:         3,                      // Default max attempts
		dialer:              dialer,
	}, nil
}

// SetPacketInterval changes how frequently packets are sent in monitor mode
func (c *Client) SetPacketInterval(interval time.Duration) {
	c.packetInterval = interval
	c.minInterval = interval
}

// SetTimeout changes the timeout for waiting for responses
func (c *Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// SetMaxAttempts changes the maximum number of attempts for TestConnection
func (c *Client) SetMaxAttempts(attempts int) {
	c.maxAttempts = attempts
}

// SetMaxInterval sets the maximum backoff interval
func (c *Client) SetMaxInterval(interval time.Duration) {
	c.maxInterval = interval
}

// SetBackoffMultiplier sets the multiplier for exponential backoff
func (c *Client) SetBackoffMultiplier(multiplier float64) {
	c.backoffMultiplier = multiplier
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

	// Reusable response buffer
	responseBuffer := make([]byte, packetSize)

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

			_, err := c.conn.Write(packet)
			if err != nil {
				c.connLock.Unlock()
				logger.Info("Error sending packet: %v", err)
				continue
			}

			// Set read deadline
			c.conn.SetReadDeadline(time.Now().Add(c.timeout))

			// Wait for response
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
		stableCount := 0
		currentInterval := c.minInterval

		timer := time.NewTimer(currentInterval)
		defer timer.Stop()

		for {
			select {
			case <-c.shutdownCh:
				return
			case <-timer.C:
				ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
				connected, rtt := c.TestConnection(ctx)
				cancel()

				statusChanged := connected != lastConnected

				// Callback if status changed or it's the first check
				if statusChanged || firstRun {
					callback(ConnectionStatus{
						Connected: connected,
						RTT:       rtt,
					})
					lastConnected = connected
					firstRun = false
					// Reset backoff on status change
					stableCount = 0
					currentInterval = c.minInterval
				} else {
					// Status is stable, increment counter
					stableCount++

					// Apply exponential backoff after stable threshold
					if stableCount >= c.stableCountToBackoff {
						newInterval := time.Duration(float64(currentInterval) * c.backoffMultiplier)
						if newInterval > c.maxInterval {
							newInterval = c.maxInterval
						}
						currentInterval = newInterval
					}
				}

				// Reset timer with current interval
				timer.Reset(currentInterval)
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