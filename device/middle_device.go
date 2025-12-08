package device

import (
	"net/netip"
	"os"
	"sync"

	"github.com/fosrl/newt/logger"
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
	rules    []FilterRule
	mutex    sync.RWMutex
	readCh   chan readResult
	injectCh chan []byte
	closed   chan struct{}
}

type readResult struct {
	bufs   [][]byte
	sizes  []int
	offset int
	n      int
	err    error
}

// NewMiddleDevice creates a new filtered TUN device wrapper
func NewMiddleDevice(device tun.Device) *MiddleDevice {
	d := &MiddleDevice{
		Device:   device,
		rules:    make([]FilterRule, 0),
		readCh:   make(chan readResult),
		injectCh: make(chan []byte, 100),
		closed:   make(chan struct{}),
	}
	go d.pump()
	return d
}

func (d *MiddleDevice) pump() {
	const defaultOffset = 16
	batchSize := d.Device.BatchSize()
	logger.Debug("MiddleDevice: pump started")

	for {
		// Check closed first with priority
		select {
		case <-d.closed:
			logger.Debug("MiddleDevice: pump exiting due to closed channel")
			return
		default:
		}

		// Allocate buffers for reading
		// We allocate new buffers for each read to avoid race conditions
		// since we pass them to the channel
		bufs := make([][]byte, batchSize)
		sizes := make([]int, batchSize)
		for i := range bufs {
			bufs[i] = make([]byte, 2048) // Standard MTU + headroom
		}

		n, err := d.Device.Read(bufs, sizes, defaultOffset)

		// Check closed again after read returns
		select {
		case <-d.closed:
			logger.Debug("MiddleDevice: pump exiting due to closed channel (after read)")
			return
		default:
		}

		// Now try to send the result
		select {
		case d.readCh <- readResult{bufs: bufs, sizes: sizes, offset: defaultOffset, n: n, err: err}:
		case <-d.closed:
			logger.Debug("MiddleDevice: pump exiting due to closed channel (during send)")
			return
		}

		if err != nil {
			logger.Debug("MiddleDevice: pump exiting due to read error: %v", err)
			return
		}
	}
}

// InjectOutbound injects a packet to be read by WireGuard (as if it came from TUN)
func (d *MiddleDevice) InjectOutbound(packet []byte) {
	select {
	case d.injectCh <- packet:
	case <-d.closed:
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

// Close stops the device
func (d *MiddleDevice) Close() error {
	select {
	case <-d.closed:
		// Already closed
		return nil
	default:
		logger.Debug("MiddleDevice: Closing, signaling closed channel")
		close(d.closed)
	}
	logger.Debug("MiddleDevice: Closing underlying TUN device")
	err := d.Device.Close()
	logger.Debug("MiddleDevice: Underlying TUN device closed, err=%v", err)
	return err
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
	// Check if already closed first (non-blocking)
	select {
	case <-d.closed:
		logger.Debug("MiddleDevice: Read returning os.ErrClosed (pre-check)")
		return 0, os.ErrClosed
	default:
	}

	// Now block waiting for data
	select {
	case res := <-d.readCh:
		if res.err != nil {
			logger.Debug("MiddleDevice: Read returning error from pump: %v", res.err)
			return 0, res.err
		}

		// Copy packets from result to provided buffers
		count := 0
		for i := 0; i < res.n && i < len(bufs); i++ {
			// Handle offset mismatch if necessary
			// We assume the pump used defaultOffset (16)
			// If caller asks for different offset, we need to shift
			src := res.bufs[i]
			srcOffset := res.offset
			srcSize := res.sizes[i]

			// Calculate where the packet data starts and ends in src
			pktData := src[srcOffset : srcOffset+srcSize]

			// Ensure dest buffer is large enough
			if len(bufs[i]) < offset+len(pktData) {
				continue // Skip if buffer too small
			}

			copy(bufs[i][offset:], pktData)
			sizes[i] = len(pktData)
			count++
		}
		n = count

	case pkt := <-d.injectCh:
		if len(bufs) == 0 {
			return 0, nil
		}
		if len(bufs[0]) < offset+len(pkt) {
			return 0, nil // Buffer too small
		}
		copy(bufs[0][offset:], pkt)
		sizes[0] = len(pkt)
		n = 1

	case <-d.closed:
		logger.Debug("MiddleDevice: Read returning os.ErrClosed")
		return 0, os.ErrClosed // Signal that device is closed
	}

	d.mutex.RLock()
	rules := d.rules
	d.mutex.RUnlock()

	if len(rules) == 0 {
		return n, nil
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
