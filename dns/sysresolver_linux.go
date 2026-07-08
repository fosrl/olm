//go:build linux && !android

package dns

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"

	platform "github.com/fosrl/olm/dns/platform"
)

// readSystemDNS returns the current system DNS servers in "host:53" format.
//
// Resolution order:
//  1. /run/systemd/resolve/resolv.conf, but only when systemd-resolved is
//     actually running (checked live via D-Bus) — the file lives in /run and
//     can linger there, frozen at whatever it last contained, long after the
//     service that maintained it has stopped (e.g. it ran earlier in the
//     boot and was since disabled). Trusting its mere existence would report
//     that stale snapshot forever instead of falling through to a live
//     source. When the service is actually up the file is maintained with
//     the real per-link DNS servers, updated on every DHCP change and never
//     touched by olm's D-Bus DNS override.
//  2. NetworkManager, queried live over D-Bus — NetworkManager's own view of
//     each active connection's DNS servers, independent of what is currently
//     written to /etc/resolv.conf. This covers NetworkManager's "dnsmasq" and
//     "unbound" DNS modes, where /etc/resolv.conf only contains a loopback
//     stub address, and stays accurate even if olm's own override has
//     directly overwritten /etc/resolv.conf, without going stale the way a
//     one-time backup snapshot would if the real DNS changes mid-override
//     (e.g. the user switches WiFi networks). olm's own NetworkManager
//     override is itself a NetworkManager-level global DNS override (see
//     platform.GetNetworkManagerNameservers), so this also reads each
//     device's raw DHCP lease and applied-connection settings, which that
//     override does not touch, to recover the real servers.
//  3. /etc/resolv.conf.olm.backup — written by olm before it overrides
//     /etc/resolv.conf on non-systemd systems, for when NetworkManager isn't
//     in use at all.
//  4. /etc/resolv.conf — plain fallback.
//
// Loopback and link-local addresses (e.g. 127.0.0.53, ::1) are excluded
// because they are stub resolver addresses, not real upstream servers.
func readSystemDNS() []string {
	// Prefer systemd-resolved's resolved (non-stub) resolv.conf, but only if
	// systemd-resolved is actually alive right now - see resolution order
	// note above on why the file's existence alone isn't enough.
	if platform.IsSystemdResolvedAvailable() {
		if servers := parseResolvConf("/run/systemd/resolve/resolv.conf"); len(servers) > 0 {
			return servers
		}
	}

	if servers := readNetworkManagerDNS(); len(servers) > 0 {
		return servers
	}

	// If olm has already overridden /etc/resolv.conf the backup holds the
	// original pre-override DNS servers.
	if _, err := os.Stat("/etc/resolv.conf.olm.backup"); err == nil {
		if servers := parseResolvConf("/etc/resolv.conf.olm.backup"); len(servers) > 0 {
			return servers
		}
	}

	return parseResolvConf("/etc/resolv.conf")
}

// readNetworkManagerDNS returns the DNS servers NetworkManager reports over
// D-Bus for its active connections, in "host:53" format. Returns nil if
// NetworkManager isn't running or reports nothing usable.
func readNetworkManagerDNS() []string {
	addrs, err := platform.GetNetworkManagerNameservers()
	if err != nil || len(addrs) == 0 {
		return nil
	}

	result := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		result = append(result, addrToHostPort(addr))
	}
	return result
}

// parseResolvConf reads nameserver lines from a resolv.conf-style file,
// skipping loopback and link-local addresses.
func parseResolvConf(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var result []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		s := addrToHostPort(addr)
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// addrToHostPort converts a netip.Addr to "addr:53" format, wrapping IPv6
// addresses in brackets as required by net.JoinHostPort.
func addrToHostPort(addr netip.Addr) string {
	return net.JoinHostPort(addr.String(), "53")
}
