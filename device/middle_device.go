package device

import (
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

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

// closeAwareDevice wraps a tun.Device along with a flag
// indicating whether its Close method was called.
type closeAwareDevice struct {
	isClosed     atomic.Bool
	tun.Device
	closeEventCh chan struct{}
	wg           sync.WaitGroup
	closeOnce    sync.Once
}

func newCloseAwareDevice(tunDevice tun.Device) *closeAwareDevice {
	return &closeAwareDevice{
		Device:       tunDevice,
		isClosed:     atomic.Bool{},
		closeEventCh: make(chan struct{}),
	}
}

// redirectEvents redirects the Events() method of the underlying tun.Device
// to the given channel.
func (c *closeAwareDevice) redirectEvents(out chan tun.Event) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			select {
			case ev, ok := <-c.Device.Events():
				if !ok {
					return
				}

				if ev == tun.EventDown {
					continue
				}

				select {
				case out <- ev:
				case <-c.closeEventCh:
					return
				}
			case <-c.closeEventCh:
				return
			}
		}
	}()
}

// Close calls the underlying Device's Close method
// after setting isClosed to true.
func (c *closeAwareDevice) Close() (err error) {
	c.closeOnce.Do(func() {
		c.isClosed.Store(true)
		close(c.closeEventCh)
		err = c.Device.Close()
		c.wg.Wait()
	})

	return err
}

func (c *closeAwareDevice) IsClosed() bool {
	return c.isClosed.Load()
}

type readResult struct {
	bufs   [][]byte
	sizes  []int
	offset int
	n      int
	err    error
}

// MiddleDevice wraps a TUN device with packet filtering capabilities
// and supports swapping the underlying device.
type MiddleDevice struct {
	devices    []*closeAwareDevice
	mu         sync.Mutex
	cond       *sync.Cond
	rules      []FilterRule
	rulesMutex sync.RWMutex
	readCh     chan readResult
	injectCh   chan []byte
	closed     atomic.Bool
	events     chan tun.Event
}

// NewMiddleDevice creates a new filtered TUN device wrapper
func NewMiddleDevice(device tun.Device) *MiddleDevice {
	d := &MiddleDevice{
		devices:  make([]*closeAwareDevice, 0),
		rules:    make([]FilterRule, 0),
		readCh:   make(chan readResult, 16),
		injectCh: make(chan []byte, 100),
		events:   make(chan tun.Event, 16),
	}
	d.cond = sync.NewCond(&d.mu)

	if device != nil {
		d.AddDevice(device)
	}

	return d
}

// AddDevice adds a new underlying TUN device, closing any previous one
func (d *MiddleDevice) AddDevice(device tun.Device) {
	d.mu.Lock()
	if d.closed.Load() {
		d.mu.Unlock()
		_ = device.Close()
		return
	}

	var toClose *closeAwareDevice
	if len(d.devices) > 0 {
		toClose = d.devices[len(d.devices)-1]
	}

	cad := newCloseAwareDevice(device)
	cad.redirectEvents(d.events)

	d.devices = []*closeAwareDevice{cad}

	// Start pump for the new device
	go d.pump(cad)

	d.cond.Broadcast()
	d.mu.Unlock()

	if toClose != nil {
		logger.Debug("MiddleDevice: Closing previous device")
		if err := toClose.Close(); err != nil {
			logger.Debug("MiddleDevice: Error closing previous device: %v", err)
		}
	}
}

func (d *MiddleDevice) pump(dev *closeAwareDevice) {
	const defaultOffset = 16
	batchSize := dev.BatchSize()
	logger.Debug("MiddleDevice: pump started for device")

	for {
		// Check if this device is closed
		if dev.IsClosed() {
			logger.Debug("MiddleDevice: pump exiting, device is closed")
			return
		}

		// Check if MiddleDevice itself is closed
		if d.closed.Load() {
			logger.Debug("MiddleDevice: pump exiting, MiddleDevice is closed")
			return
		}

		// Allocate buffers for reading
		bufs := make([][]byte, batchSize)
		sizes := make([]int, batchSize)
		for i := range bufs {
			bufs[i] = make([]byte, 2048) // Standard MTU + headroom
		}

		n, err := dev.Read(bufs, sizes, defaultOffset)

		// Check if device was closed during read
		if dev.IsClosed() {
			logger.Debug("MiddleDevice: pump exiting, device closed during read")
			return
		}

		// Check if MiddleDevice was closed during read
		if d.closed.Load() {
			logger.Debug("MiddleDevice: pump exiting, MiddleDevice closed during read")
			return
		}

		// Try to send the result
		select {
		case d.readCh <- readResult{bufs: bufs, sizes: sizes, offset: defaultOffset, n: n, err: err}:
		default:
			// Channel full, check if we should exit
			if dev.IsClosed() || d.closed.Load() {
				return
			}
			// Try again with blocking
			select {
			case d.readCh <- readResult{bufs: bufs, sizes: sizes, offset: defaultOffset, n: n, err: err}:
			case <-dev.closeEventCh:
				return
			}
		}

		if err != nil {
			logger.Debug("MiddleDevice: pump exiting due to read error: %v", err)
			return
		}
	}
}

// InjectOutbound injects a packet to be read by WireGuard (as if it came from TUN)
func (d *MiddleDevice) InjectOutbound(packet []byte) {
	if d.closed.Load() {
		return
	}
	select {
	case d.injectCh <- packet:
	default:
		// Channel full, drop packet
		logger.Debug("MiddleDevice: InjectOutbound dropping packet, channel full")
	}
}

// AddRule adds a packet filtering rule
func (d *MiddleDevice) AddRule(destIP netip.Addr, handler PacketHandler) {
	d.rulesMutex.Lock()
	defer d.rulesMutex.Unlock()
	d.rules = append(d.rules, FilterRule{
		DestIP:  destIP,
		Handler: handler,
	})
}

// RemoveRule removes all rules for a given destination IP
func (d *MiddleDevice) RemoveRule(destIP netip.Addr) {
	d.rulesMutex.Lock()
	defer d.rulesMutex.Unlock()
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
	if !d.closed.CompareAndSwap(false, true) {
		return nil // already closed
	}

	d.mu.Lock()
	devices := d.devices
	d.devices = nil
	d.cond.Broadcast()
	d.mu.Unlock()

	var lastErr error
	logger.Debug("MiddleDevice: Closing %d devices", len(devices))
	for _, device := range devices {
		if err := device.Close(); err != nil {
			logger.Debug("MiddleDevice: Error closing device: %v", err)
			lastErr = err
		}
	}

	close(d.events)
	return lastErr
}

// Events returns the events channel
func (d *MiddleDevice) Events() <-chan tun.Event {
	return d.events
}

// File returns the underlying file descriptor
func (d *MiddleDevice) File() *os.File {
	for {
		dev := d.peekLast()
		if dev == nil {
			if !d.waitForDevice() {
				return nil
			}
			continue
		}

		file := dev.File()

		if dev.IsClosed() {
			time.Sleep(1 * time.Millisecond)
			continue
		}

		return file
	}
}

// MTU returns the MTU of the underlying device
func (d *MiddleDevice) MTU() (int, error) {
	for {
		dev := d.peekLast()
		if dev == nil {
			if !d.waitForDevice() {
				return 0, io.EOF
			}
			continue
		}

		mtu, err := dev.MTU()
		if err == nil {
			return mtu, nil
		}

		if dev.IsClosed() {
			time.Sleep(1 * time.Millisecond)
			continue
		}

		return 0, err
	}
}

// Name returns the name of the underlying device
func (d *MiddleDevice) Name() (string, error) {
	for {
		dev := d.peekLast()
		if dev == nil {
			if !d.waitForDevice() {
				return "", io.EOF
			}
			continue
		}

		name, err := dev.Name()
		if err == nil {
			return name, nil
		}

		if dev.IsClosed() {
			time.Sleep(1 * time.Millisecond)
			continue
		}

		return "", err
	}
}

// BatchSize returns the batch size
func (d *MiddleDevice) BatchSize() int {
	dev := d.peekLast()
	if dev == nil {
		return 1
	}
	return dev.BatchSize()
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
	for {
		if d.closed.Load() {
			logger.Debug("MiddleDevice: Read returning io.EOF, device closed")
			return 0, io.EOF
		}

		// Wait for a device to be available
		dev := d.peekLast()
		if dev == nil {
			if !d.waitForDevice() {
				return 0, io.EOF
			}
			continue
		}

		// Now block waiting for data from readCh or injectCh
		select {
		case res := <-d.readCh:
			if res.err != nil {
				// Check if device was swapped
				if dev.IsClosed() {
					time.Sleep(1 * time.Millisecond)
					continue
				}
				logger.Debug("MiddleDevice: Read returning error from pump: %v", res.err)
				return 0, res.err
			}

			// Copy packets from result to provided buffers
			count := 0
			for i := 0; i < res.n && i < len(bufs); i++ {
				src := res.bufs[i]
				srcOffset := res.offset
				srcSize := res.sizes[i]

				pktData := src[srcOffset : srcOffset+srcSize]

				if len(bufs[i]) < offset+len(pktData) {
					continue
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
				return 0, nil
			}
			copy(bufs[0][offset:], pkt)
			sizes[0] = len(pkt)
			n = 1
		}

		// Apply filtering rules
		d.rulesMutex.RLock()
		rules := d.rules
		d.rulesMutex.RUnlock()

		if len(rules) == 0 {
			return n, nil
		}

		// Process packets and filter out handled ones
		writeIdx := 0
		for readIdx := 0; readIdx < n; readIdx++ {
			packet := bufs[readIdx][offset : offset+sizes[readIdx]]

			destIP, ok := extractDestIP(packet)
			if !ok {
				if writeIdx != readIdx {
					bufs[writeIdx] = bufs[readIdx]
					sizes[writeIdx] = sizes[readIdx]
				}
				writeIdx++
				continue
			}

			handled := false
			for _, rule := range rules {
				if rule.DestIP == destIP {
					if rule.Handler(packet) {
						handled = true
						break
					}
				}
			}

			if !handled {
				if writeIdx != readIdx {
					bufs[writeIdx] = bufs[readIdx]
					sizes[writeIdx] = sizes[readIdx]
				}
				writeIdx++
			}
		}

		return writeIdx, nil
	}
}

// Write intercepts packets going DOWN to the TUN device (from WireGuard)
func (d *MiddleDevice) Write(bufs [][]byte, offset int) (int, error) {
	for {
		if d.closed.Load() {
			return 0, io.EOF
		}

		dev := d.peekLast()
		if dev == nil {
			if !d.waitForDevice() {
				return 0, io.EOF
			}
			continue
		}

		d.rulesMutex.RLock()
		rules := d.rules
		d.rulesMutex.RUnlock()

		var filteredBufs [][]byte
		if len(rules) == 0 {
			filteredBufs = bufs
		} else {
			filteredBufs = make([][]byte, 0, len(bufs))
			for _, buf := range bufs {
				if len(buf) <= offset {
					continue
				}

				packet := buf[offset:]
				destIP, ok := extractDestIP(packet)
				if !ok {
					filteredBufs = append(filteredBufs, buf)
					continue
				}

				handled := false
				for _, rule := range rules {
					if rule.DestIP == destIP {
						if rule.Handler(packet) {
							handled = true
							break
						}
					}
				}

				if !handled {
					filteredBufs = append(filteredBufs, buf)
				}
			}
		}

		if len(filteredBufs) == 0 {
			return len(bufs), nil
		}

		n, err := dev.Write(filteredBufs, offset)
		if err == nil {
			return n, nil
		}

		if dev.IsClosed() {
			time.Sleep(1 * time.Millisecond)
			continue
		}

		return n, err
	}
}

func (d *MiddleDevice) waitForDevice() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	for len(d.devices) == 0 && !d.closed.Load() {
		d.cond.Wait()
	}
	return !d.closed.Load()
}

func (d *MiddleDevice) peekLast() *closeAwareDevice {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.devices) == 0 {
		return nil
	}

	return d.devices[len(d.devices)-1]
}

// WriteToTun writes packets directly to the underlying TUN device,
// bypassing WireGuard. This is useful for sending packets that should
// appear to come from the TUN interface (e.g., DNS responses from a proxy).
// Unlike Write(), this does not go through packet filtering rules.
func (d *MiddleDevice) WriteToTun(bufs [][]byte, offset int) (int, error) {
	for {
		if d.closed.Load() {
			return 0, io.EOF
		}

		dev := d.peekLast()
		if dev == nil {
			if !d.waitForDevice() {
				return 0, io.EOF
			}
			continue
		}

		n, err := dev.Write(bufs, offset)
		if err == nil {
			return n, nil
		}

		if dev.IsClosed() {
			time.Sleep(1 * time.Millisecond)
			continue
		}

		return n, err
	}
}