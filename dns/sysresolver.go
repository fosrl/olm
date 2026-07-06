package dns

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/miekg/dns"
)

const defaultPollInterval = 30 * time.Second

// dnsHealthCheckTimeout bounds how long we wait for a candidate DNS server to
// answer a health-check query before considering it unusable.
const dnsHealthCheckTimeout = 2 * time.Second

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
	current    []string // last health-checked, applied server list
	lastRaw    []string // last raw (exclude-filtered but unvalidated) candidate list seen
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
	m.applyCandidates(m.readFiltered())
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
	return m.filterExcluded(readSystemDNS())
}

// filterExcluded removes any addresses that have been excluded via
// SetExcludeIP from servers. Used both for the internally-polled server list
// (readFiltered) and for server lists reported externally (ReportExternal) by
// platforms - Android, iOS - where olm cannot read the OS's DNS configuration
// itself.
func (m *SystemDNSMonitor) filterExcluded(servers []string) []string {
	m.excludeMu.RLock()
	excludeIPs := m.excludeIPs
	m.excludeMu.RUnlock()

	if len(excludeIPs) == 0 {
		return servers
	}

	var filtered []string
	for _, s := range servers {
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

// ReportExternal applies an externally-observed DNS server list (e.g. from
// Android's ConnectivityManager or iOS's SCDynamicStore, where the platform
// itself - not olm - must detect the OS's real DNS configuration) through the
// same exclude-IP filtering, health-check validation, and change-detection as
// the internal poll loop, firing onChange if the result differs from the last
// known value.
func (m *SystemDNSMonitor) ReportExternal(servers []string) {
	m.applyCandidates(m.filterExcluded(servers))
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
			m.applyCandidates(m.readFiltered())
		}
	}
}

// applyCandidates takes an exclude-filtered (but not yet health-checked) list
// of candidate DNS servers - from either the internal poll loop or
// ReportExternal - and, only if it differs from the last raw list seen (to
// avoid re-running network health checks on every 30-second poll tick when
// nothing has actually changed), health-checks it via filterUnreachable and
// applies whatever passes, firing onChange if the result changed.
//
// If none of the candidates pass the health check, the previous known-good
// value is retained rather than clobbered - this is what protects against
// e.g. a carrier reporting a DNS server (such as T-Mobile's internal ULA
// DNS64 resolvers) that is technically "the system DNS" but not actually
// reachable/usable from wherever queries are sent.
func (m *SystemDNSMonitor) applyCandidates(raw []string) {
	if len(raw) == 0 {
		return
	}

	m.mu.Lock()
	if dnsSlicesEqual(m.lastRaw, raw) {
		m.mu.Unlock()
		return
	}
	m.lastRaw = raw
	m.mu.Unlock()

	validated := filterUnreachable(raw)
	if len(validated) == 0 {
		logger.Warn("None of the detected DNS servers answered a health-check query, keeping previous value: %v", raw)
		return
	}

	m.mu.Lock()
	changed := !dnsSlicesEqual(m.current, validated)
	if changed {
		m.current = validated
	}
	m.mu.Unlock()

	if changed && m.onChange != nil {
		logger.Info("System DNS changed: %v", validated)
		m.onChange(validated)
	}
}

// dnsServerReachable is a seam for tests; production code always uses probeDNSServer.
var dnsServerReachable = probeDNSServer

// filterUnreachable validates that each candidate server actually answers a
// DNS query before it's trusted, rather than statically guessing from the
// address (e.g. rejecting all private/ULA addresses, which would also reject
// a perfectly valid home router forwarding to a real resolver). Checks run
// concurrently so multiple candidates don't serialize the timeout.
func filterUnreachable(servers []string) []string {
	if len(servers) == 0 {
		return servers
	}

	reachable := make([]bool, len(servers))
	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Add(1)
		go func(i int, server string) {
			defer wg.Done()
			reachable[i] = dnsServerReachable(server)
		}(i, server)
	}
	wg.Wait()

	var result []string
	for i, server := range servers {
		if reachable[i] {
			result = append(result, server)
		} else {
			logger.Debug("Discarding DNS server %s: failed health check", server)
		}
	}
	return result
}

// probeDNSServer sends a minimal root NS query to confirm a candidate server
// actually answers, without depending on any specific external hostname being
// reachable (which could itself be blocked/filtered independently of whether
// the resolver works).
func probeDNSServer(server string) bool {
	client := &dns.Client{Timeout: dnsHealthCheckTimeout}
	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)
	_, _, err := client.Exchange(msg, server)
	return err == nil
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
