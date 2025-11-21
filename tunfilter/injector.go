package tunfilter

import (
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// PacketInjector allows interceptors to inject packets back into the TUN device
// This is useful for sending response packets or injecting traffic
type PacketInjector struct {
	device tun.Device
	mutex  sync.RWMutex
}

// NewPacketInjector creates a new packet injector
func NewPacketInjector(device tun.Device) *PacketInjector {
	return &PacketInjector{
		device: device,
	}
}

// InjectInbound injects a packet as if it came from the tunnel (to the host)
// This writes the packet to the TUN device so it appears as incoming traffic
func (p *PacketInjector) InjectInbound(packet []byte) error {
	p.mutex.RLock()
	device := p.device
	p.mutex.RUnlock()

	if device == nil {
		return fmt.Errorf("device not set")
	}

	// TUN device expects packets in a specific format
	// We need to write to the device with the proper offset
	const offset = 4 // Standard TUN offset for packet info

	// Create buffer with offset
	buf := make([]byte, offset+len(packet))
	copy(buf[offset:], packet)

	// Write packet
	bufs := [][]byte{buf}
	n, err := device.Write(bufs, offset)
	if err != nil {
		return fmt.Errorf("failed to inject packet: %w", err)
	}

	if n != 1 {
		return fmt.Errorf("expected to write 1 packet, wrote %d", n)
	}

	return nil
}

// Stop cleans up the injector
func (p *PacketInjector) Stop() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.device = nil
}

// SetDevice updates the underlying TUN device
func (p *PacketInjector) SetDevice(device tun.Device) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.device = device
}
