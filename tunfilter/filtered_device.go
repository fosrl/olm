package tunfilter

import (
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// FilteredDevice wraps a TUN device with packet filtering capabilities
// This sits between WireGuard and the TUN device, intercepting packets in both directions
type FilteredDevice struct {
	tun.Device
	filter PacketFilter
	mutex  sync.RWMutex
}

// NewFilteredDevice creates a new filtered TUN device wrapper
func NewFilteredDevice(device tun.Device, filter PacketFilter) *FilteredDevice {
	return &FilteredDevice{
		Device: device,
		filter: filter,
	}
}

// Read intercepts packets from the TUN device (outbound from tunnel)
// These are decrypted packets coming out of WireGuard going to the host
func (d *FilteredDevice) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	n, err = d.Device.Read(bufs, sizes, offset)
	if err != nil || n == 0 {
		return n, err
	}

	d.mutex.RLock()
	filter := d.filter
	d.mutex.RUnlock()

	if filter == nil {
		return n, err
	}

	// Filter packets in place to avoid allocations
	// Process from the end to avoid index issues when removing
	kept := 0
	for i := 0; i < n; i++ {
		packet := bufs[i][offset : offset+sizes[i]]

		// FilterInbound: packet coming FROM tunnel TO host
		if action := filter.FilterInbound(packet, sizes[i]); action == FilterActionPass {
			// Keep this packet - move it to the "kept" position if needed
			if kept != i {
				bufs[kept] = bufs[i]
				sizes[kept] = sizes[i]
			}
			kept++
		}
		// FilterActionDrop or FilterActionIntercept: don't increment kept
	}

	return kept, err
}

// Write intercepts packets going to the TUN device (inbound to tunnel)
// These are packets from the host going into WireGuard for encryption
func (d *FilteredDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.mutex.RLock()
	filter := d.filter
	d.mutex.RUnlock()

	if filter == nil {
		return d.Device.Write(bufs, offset)
	}

	// Pre-allocate with capacity to avoid most allocations
	filteredBufs := make([][]byte, 0, len(bufs))
	intercepted := 0

	for _, buf := range bufs {
		size := len(buf) - offset
		packet := buf[offset:]

		// FilterOutbound: packet going FROM host TO tunnel
		if action := filter.FilterOutbound(packet, size); action == FilterActionPass {
			filteredBufs = append(filteredBufs, buf)
		} else {
			// Packet was dropped or intercepted
			intercepted++
		}
	}

	if len(filteredBufs) == 0 {
		// All packets were intercepted/dropped
		return len(bufs), nil
	}

	n, err := d.Device.Write(filteredBufs, offset)
	// Add back the intercepted count so WireGuard thinks all packets were processed
	n += intercepted
	return n, err
}

// SetFilter updates the packet filter (thread-safe)
func (d *FilteredDevice) SetFilter(filter PacketFilter) {
	d.mutex.Lock()
	d.filter = filter
	d.mutex.Unlock()
}
