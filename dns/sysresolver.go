package dns

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

const defaultPollInterval = 30 * time.Second

// SystemDNSMonitor monitors the host system's DNS configuration and notifies
// callers when it changes. The reported servers are in "host:port" format
// (e.g. "8.8.8.8:53") and can be used directly as UpstreamDNS and PublicDNS.
//
// Platform behaviour:
//   - Linux: reads /run/systemd/resolve/resolv.conf when present (updated by
//     systemd-resolved on every DHCP change), then falls back to
//     /etc/resolv.conf.olm.backup (written before olm overrides DNS), and
//     finally /etc/resolv.conf.
//   - macOS: reads /etc/resolv.conf, which is never modified by olm's
//     supplemental scutil DNS override.
//   - Windows: enumerates DHCP-assigned DNS servers from every network adapter
//     in the registry.
//   - Other platforms: returns an empty list (no-op monitor).
type SystemDNSMonitor struct {
	mu         sync.RWMutex
	current    []string
	onChange   func(servers []string)
	interval   time.Duration
	stopCh     chan struct{}
	excludeMu  sync.RWMutex
	excludeIPs map[netip.Addr]bool
}

// NewSystemDNSMonitor creates a new monitor. onChange is called with the new
// server list whenever a change is detected; it is also called once from Start
// with the initial values. A zero interval uses the 30-second default.
func NewSystemDNSMonitor(interval time.Duration, onChange func(servers []string)) *SystemDNSMonitor {
	if interval <= 0 {
		interval = defaultPollInterval
	}
	return &SystemDNSMonitor{
		interval:   interval,
		onChange:   onChange,
		stopCh:     make(chan struct{}),
		excludeIPs: make(map[netip.Addr]bool),
	}
}

// SetExcludeIP registers an IP address that must never appear in the reported
// DNS server list. Call this after olm's DNS proxy is created to prevent the
// proxy's own IP from being returned as an upstream server when the OS DNS has
// been overridden to point at the proxy.
func (m *SystemDNSMonitor) SetExcludeIP(ip netip.Addr) {
	m.excludeMu.Lock()
	m.excludeIPs[ip.Unmap()] = true
	m.excludeMu.Unlock()
}

// Start reads the current system DNS immediately, fires onChange, then polls
// in the background until Stop is called or ctx is cancelled.
func (m *SystemDNSMonitor) Start(ctx context.Context) {
	servers := m.readFiltered()
	m.mu.Lock()
	m.current = servers
	m.mu.Unlock()

	if m.onChange != nil && len(servers) > 0 {
		m.onChange(servers)
	}

	go m.run(ctx)
}

// Stop halts the background polling goroutine.
func (m *SystemDNSMonitor) Stop() {
	select {
	case <-m.stopCh:
	default:
		close(m.stopCh)
	}
}

// Current returns the most recently observed system DNS servers.
func (m *SystemDNSMonitor) Current() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.current))
	copy(out, m.current)
	return out
}

// readFiltered calls the platform-specific readSystemDNS and removes any
// addresses that have been excluded via SetExcludeIP. If all addresses are
// excluded the function returns nil so the caller can retain the last
// known-good value.
func (m *SystemDNSMonitor) readFiltered() []string {
	raw := readSystemDNS()

	m.excludeMu.RLock()
	excludeIPs := m.excludeIPs
	m.excludeMu.RUnlock()

	if len(excludeIPs) == 0 {
		return raw
	}

	var filtered []string
	for _, s := range raw {
		host, _, err := net.SplitHostPort(s)
		if err != nil {
			filtered = append(filtered, s)
			continue
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || excludeIPs[addr.Unmap()] {
			continue
		}
		filtered = append(filtered, s)
	}
	return filtered
}

func (m *SystemDNSMonitor) run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			servers := m.readFiltered()
			if len(servers) == 0 {
				continue
			}

			m.mu.Lock()
			changed := !dnsSlicesEqual(m.current, servers)
			if changed {
				m.current = servers
			}
			m.mu.Unlock()

			if changed && m.onChange != nil {
				logger.Info("System DNS changed: %v", servers)
				m.onChange(servers)
			}
		}
	}
}

// dnsSlicesEqual reports whether two server lists are equal regardless of order.
func dnsSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := make([]string, len(a))
	bc := make([]string, len(b))
	copy(ac, a)
	copy(bc, b)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
