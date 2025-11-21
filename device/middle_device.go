package device

import (
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// PacketHandler processes intercepted packets and returns true if packet should be dropped
type PacketHandler func(packet []byte) bool

// FilterRule defines a rule for packet filtering
type FilterRule struct {
	DestIP  netip.Addr
	Handler PacketHandler
}

// MiddleDevice wraps a TUN device with packet filtering capabilities
type MiddleDevice struct {
	tun.Device
	rules []FilterRule
	mutex sync.RWMutex
}

// NewMiddleDevice creates a new filtered TUN device wrapper
func NewMiddleDevice(device tun.Device) *MiddleDevice {
	return &MiddleDevice{
		Device: device,
		rules:  make([]FilterRule, 0),
	}
}

// AddRule adds a packet filtering rule
func (d *MiddleDevice) AddRule(destIP netip.Addr, handler PacketHandler) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.rules = append(d.rules, FilterRule{
		DestIP:  destIP,
		Handler: handler,
	})
}

// RemoveRule removes all rules for a given destination IP
func (d *MiddleDevice) RemoveRule(destIP netip.Addr) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	newRules := make([]FilterRule, 0, len(d.rules))
	for _, rule := range d.rules {
		if rule.DestIP != destIP {
			newRules = append(newRules, rule)
		}
	}
	d.rules = newRules
}

// extractDestIP extracts destination IP from packet (fast path)
func extractDestIP(packet []byte) (netip.Addr, bool) {
	if len(packet) < 20 {
		return netip.Addr{}, false
	}

	version := packet[0] >> 4

	switch version {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		// Destination IP is at bytes 16-19 for IPv4
		ip := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
		return ip, true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		// Destination IP is at bytes 24-39 for IPv6
		var ip16 [16]byte
		copy(ip16[:], packet[24:40])
		ip := netip.AddrFrom16(ip16)
		return ip, true
	}

	return netip.Addr{}, false
}

// Read intercepts packets going UP from the TUN device (towards WireGuard)
func (d *MiddleDevice) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	n, err = d.Device.Read(bufs, sizes, offset)
	if err != nil || n == 0 {
		return n, err
	}

	d.mutex.RLock()
	rules := d.rules
	d.mutex.RUnlock()

	if len(rules) == 0 {
		return n, err
	}

	// Process packets and filter out handled ones
	writeIdx := 0
	for readIdx := 0; readIdx < n; readIdx++ {
		packet := bufs[readIdx][offset : offset+sizes[readIdx]]

		destIP, ok := extractDestIP(packet)
		if !ok {
			// Can't parse, keep packet
			if writeIdx != readIdx {
				bufs[writeIdx] = bufs[readIdx]
				sizes[writeIdx] = sizes[readIdx]
			}
			writeIdx++
			continue
		}

		// Check if packet matches any rule
		handled := false
		for _, rule := range rules {
			if rule.DestIP == destIP {
				if rule.Handler(packet) {
					// Packet was handled and should be dropped
					handled = true
					break
				}
			}
		}

		if !handled {
			// Keep packet
			if writeIdx != readIdx {
				bufs[writeIdx] = bufs[readIdx]
				sizes[writeIdx] = sizes[readIdx]
			}
			writeIdx++
		}
	}

	return writeIdx, err
}

// Write intercepts packets going DOWN to the TUN device (from WireGuard)
func (d *MiddleDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.mutex.RLock()
	rules := d.rules
	d.mutex.RUnlock()

	if len(rules) == 0 {
		return d.Device.Write(bufs, offset)
	}

	// Filter packets going down
	filteredBufs := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		if len(buf) <= offset {
			continue
		}

		packet := buf[offset:]
		destIP, ok := extractDestIP(packet)
		if !ok {
			// Can't parse, keep packet
			filteredBufs = append(filteredBufs, buf)
			continue
		}

		// Check if packet matches any rule
		handled := false
		for _, rule := range rules {
			if rule.DestIP == destIP {
				if rule.Handler(packet) {
					// Packet was handled and should be dropped
					handled = true
					break
				}
			}
		}

		if !handled {
			filteredBufs = append(filteredBufs, buf)
		}
	}

	if len(filteredBufs) == 0 {
		return len(bufs), nil // All packets were handled
	}

	return d.Device.Write(filteredBufs, offset)
}
