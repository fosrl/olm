package olm

import (
	"encoding/binary"
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

// FilteredDevice wraps a TUN device with packet filtering capabilities
type FilteredDevice struct {
	tun.Device
	rules []FilterRule
	mutex sync.RWMutex
}

// NewFilteredDevice creates a new filtered TUN device wrapper
func NewFilteredDevice(device tun.Device) *FilteredDevice {
	return &FilteredDevice{
		Device: device,
		rules:  make([]FilterRule, 0),
	}
}

// AddRule adds a packet filtering rule
func (d *FilteredDevice) AddRule(destIP netip.Addr, handler PacketHandler) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.rules = append(d.rules, FilterRule{
		DestIP:  destIP,
		Handler: handler,
	})
}

// RemoveRule removes all rules for a given destination IP
func (d *FilteredDevice) RemoveRule(destIP netip.Addr) {
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
func (d *FilteredDevice) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
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
func (d *FilteredDevice) Write(bufs [][]byte, offset int) (int, error) {
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

// GetProtocol returns protocol number from IPv4 packet (fast path)
func GetProtocol(packet []byte) (uint8, bool) {
	if len(packet) < 20 {
		return 0, false
	}
	version := packet[0] >> 4
	if version == 4 {
		return packet[9], true
	} else if version == 6 {
		if len(packet) < 40 {
			return 0, false
		}
		return packet[6], true
	}
	return 0, false
}

// GetDestPort returns destination port from TCP/UDP packet (fast path)
func GetDestPort(packet []byte) (uint16, bool) {
	if len(packet) < 20 {
		return 0, false
	}

	version := packet[0] >> 4
	var headerLen int

	if version == 4 {
		ihl := packet[0] & 0x0F
		headerLen = int(ihl) * 4
		if len(packet) < headerLen+4 {
			return 0, false
		}
	} else if version == 6 {
		headerLen = 40
		if len(packet) < headerLen+4 {
			return 0, false
		}
	} else {
		return 0, false
	}

	// Destination port is at bytes 2-3 of TCP/UDP header
	port := binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])
	return port, true
}
