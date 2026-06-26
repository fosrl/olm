//go:build linux && !android

package dns

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"
)

// readSystemDNS returns the current system DNS servers in "host:53" format.
//
// Resolution order:
//  1. /run/systemd/resolve/resolv.conf — maintained by systemd-resolved with
//     the real per-link DNS servers; updated on every DHCP change and never
//     touched by olm's D-Bus DNS override.
//  2. /etc/resolv.conf.olm.backup — written by olm before it overrides
//     /etc/resolv.conf on non-systemd systems.
//  3. /etc/resolv.conf — plain fallback.
//
// Loopback and link-local addresses (e.g. 127.0.0.53, ::1) are excluded
// because they are stub resolver addresses, not real upstream servers.
func readSystemDNS() []string {
	// Prefer systemd-resolved's resolved (non-stub) resolv.conf.
	if servers := parseResolvConf("/run/systemd/resolve/resolv.conf"); len(servers) > 0 {
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
