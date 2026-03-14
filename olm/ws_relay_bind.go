package olm

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/gorilla/websocket"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

// WebSocketRelayBind is a WireGuard bind implementation that transports packets
// over a WebSocket tunnel.
type WebSocketRelayBind struct {
	url     string
	headers http.Header

	mu            sync.RWMutex
	conn          *websocket.Conn
	shutdown      bool
	port          uint16
	recvCh        chan []byte
	shutdownCh    chan struct{}
	retryInterval time.Duration
}

func NewWebSocketRelayBind(url string, headers http.Header) *WebSocketRelayBind {
	return &WebSocketRelayBind{
		url:        url,
		headers:    headers,
		recvCh:     make(chan []byte, 1024),
		shutdownCh: make(chan struct{}),
		// Keep retries short so WireGuard startup can recover quickly.
		retryInterval: 500 * time.Millisecond,
	}
}

func (b *WebSocketRelayBind) connect() error {
	for {
		b.mu.RLock()
		shutdown := b.shutdown
		existingConn := b.conn
		b.mu.RUnlock()

		if shutdown {
			return net.ErrClosed
		}
		if existingConn != nil {
			return nil
		}

		dialer := websocket.Dialer{}
		conn, _, err := dialer.Dial(b.url, b.headers)
		if err != nil {
			logger.Warn("WebSocket relay dial failed for %s: %v", b.url, err)
			select {
			case <-b.shutdownCh:
				return net.ErrClosed
			case <-time.After(b.retryInterval):
				continue
			}
		}

		b.mu.Lock()
		if b.shutdown {
			b.mu.Unlock()
			_ = conn.Close()
			return net.ErrClosed
		}
		// If another goroutine won the race and already connected, use it.
		if b.conn != nil {
			b.mu.Unlock()
			_ = conn.Close()
			return nil
		}
		b.conn = conn
		if conn.RemoteAddr() != nil {
			if _, port, splitErr := net.SplitHostPort(conn.RemoteAddr().String()); splitErr == nil {
				if parsed, lookupErr := net.LookupPort("tcp", port); lookupErr == nil {
					b.port = uint16(parsed)
				}
			}
		}
		b.mu.Unlock()

		go b.readLoop(conn)
		logger.Info("Connected WebSocket relay bind to %s", b.url)
		return nil
	}
}

func (b *WebSocketRelayBind) readLoop(conn *websocket.Conn) {
	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			select {
			case <-b.shutdownCh:
				return
			default:
				logger.Warn("WebSocket relay read failed: %v", err)
				b.dropConn(conn)
				return
			}
		}
		if msgType != websocket.BinaryMessage {
			continue
		}
		select {
		case b.recvCh <- payload:
		case <-b.shutdownCh:
			return
		}
	}
}

func (b *WebSocketRelayBind) dropConn(conn *websocket.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == conn {
		_ = b.conn.Close()
		b.conn = nil
	}
}

func (b *WebSocketRelayBind) WriteToRelay(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	for {
		b.mu.RLock()
		conn := b.conn
		shutdown := b.shutdown
		b.mu.RUnlock()
		if shutdown {
			return net.ErrClosed
		}
		if conn == nil {
			if err := b.connect(); err != nil {
				return err
			}
			continue
		}

		if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
			logger.Warn("WebSocket relay write failed, reconnecting: %v", err)
			b.dropConn(conn)
			select {
			case <-b.shutdownCh:
				return net.ErrClosed
			case <-time.After(b.retryInterval):
				continue
			}
		}
		return nil
	}
}

func (b *WebSocketRelayBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		_ = b.conn.Close()
		b.conn = nil
	}
	return nil
}

// Shutdown permanently closes the bind and should only be called when OLM is
// shutting down, not during routine WireGuard bind updates.
func (b *WebSocketRelayBind) Shutdown() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.shutdown {
		return nil
	}
	b.shutdown = true
	close(b.shutdownCh)
	if b.conn != nil {
		_ = b.conn.Close()
		b.conn = nil
	}
	return nil
}

func (b *WebSocketRelayBind) Open(_ uint16) ([]wgConn.ReceiveFunc, uint16, error) {
	if err := b.connect(); err != nil {
		return nil, 0, err
	}

	recvFn := func(bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (int, error) {
		for {
			select {
			case <-b.shutdownCh:
				return 0, net.ErrClosed
			case packet := <-b.recvCh:
				if len(bufs) == 0 {
					return 0, nil
				}
				n := copy(bufs[0], packet)
				sizes[0] = n
				eps[0] = &wgConn.StdNetEndpoint{
					AddrPort: netip.AddrPortFrom(netip.IPv4Unspecified(), b.port),
				}
				return 1, nil
			default:
				b.mu.RLock()
				shutdown := b.shutdown
				hasConn := b.conn != nil
				b.mu.RUnlock()
				if shutdown {
					return 0, net.ErrClosed
				}
				if !hasConn {
					if err := b.connect(); err != nil {
						return 0, err
					}
					continue
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}

	if b.port == 0 {
		b.port = 443
	}
	return []wgConn.ReceiveFunc{recvFn}, b.port, nil
}

func (b *WebSocketRelayBind) Send(bufs [][]byte, _ wgConn.Endpoint) error {
	for _, buf := range bufs {
		if err := b.connect(); err != nil {
			return fmt.Errorf("failed writing relay packet: %w", err)
		}
		if err := b.WriteToRelay(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *WebSocketRelayBind) SetMark(_ uint32) error {
	return nil
}

func (b *WebSocketRelayBind) ParseEndpoint(s string) (wgConn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &wgConn.StdNetEndpoint{AddrPort: addrPort}, nil
}

func (b *WebSocketRelayBind) BatchSize() int {
	return 1
}
