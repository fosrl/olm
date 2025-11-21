package tunfilter

import (
	"context"
	"sync"
)

// PacketInterceptor is an extensible interface for intercepting and handling packets
// before they go through the WireGuard tunnel
type PacketInterceptor interface {
	// Name returns the interceptor's name for logging/debugging
	Name() string

	// ShouldIntercept returns true if this interceptor wants to handle the packet
	// This is called for every packet, so it should be fast (just check IP/port)
	ShouldIntercept(packet []byte, direction Direction) bool

	// HandlePacket processes an intercepted packet
	// The interceptor can:
	// - Handle it completely and return nil (packet won't go through tunnel)
	// - Return an error if something went wrong
	// Context can be used for cancellation
	HandlePacket(ctx context.Context, packet []byte, direction Direction) error

	// Start initializes the interceptor (e.g., start listening sockets)
	Start(ctx context.Context) error

	// Stop cleanly shuts down the interceptor
	Stop() error
}

// InterceptorManager manages multiple packet interceptors
type InterceptorManager struct {
	interceptors []PacketInterceptor
	injector     *PacketInjector
	ctx          context.Context
	cancel       context.CancelFunc
	mutex        sync.RWMutex
}

// NewInterceptorManager creates a new interceptor manager
func NewInterceptorManager(injector *PacketInjector) *InterceptorManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &InterceptorManager{
		interceptors: make([]PacketInterceptor, 0),
		injector:     injector,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// AddInterceptor adds a new interceptor to the manager
func (m *InterceptorManager) AddInterceptor(interceptor PacketInterceptor) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.interceptors = append(m.interceptors, interceptor)

	// Start the interceptor
	if err := interceptor.Start(m.ctx); err != nil {
		return err
	}

	return nil
}

// RemoveInterceptor removes an interceptor by name
func (m *InterceptorManager) RemoveInterceptor(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, interceptor := range m.interceptors {
		if interceptor.Name() == name {
			// Stop the interceptor
			if err := interceptor.Stop(); err != nil {
				return err
			}

			// Remove from slice
			m.interceptors = append(m.interceptors[:i], m.interceptors[i+1:]...)
			return nil
		}
	}

	return nil
}

// HandlePacket is called by the filter for each packet
// It checks all interceptors in order and lets the first matching one handle it
func (m *InterceptorManager) HandlePacket(packet []byte, direction Direction) FilterAction {
	m.mutex.RLock()
	interceptors := m.interceptors
	m.mutex.RUnlock()

	// Try each interceptor in order
	for _, interceptor := range interceptors {
		if interceptor.ShouldIntercept(packet, direction) {
			// Make a copy to avoid data races
			packetCopy := make([]byte, len(packet))
			copy(packetCopy, packet)

			// Handle in background to avoid blocking packet processing
			go func(ic PacketInterceptor, pkt []byte) {
				if err := ic.HandlePacket(m.ctx, pkt, direction); err != nil {
					// Log error but don't fail
					// TODO: Add proper logging
				}
			}(interceptor, packetCopy)

			// Packet was intercepted
			return FilterActionIntercept
		}
	}

	// No interceptor wanted this packet
	return FilterActionPass
}

// Stop stops all interceptors
func (m *InterceptorManager) Stop() error {
	m.cancel()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	var lastErr error
	for _, interceptor := range m.interceptors {
		if err := interceptor.Stop(); err != nil {
			lastErr = err
		}
	}

	m.interceptors = nil
	return lastErr
}

// GetInjector returns the packet injector for interceptors to use
func (m *InterceptorManager) GetInjector() *PacketInjector {
	return m.injector
}
