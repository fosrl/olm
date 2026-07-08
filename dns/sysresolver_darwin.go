//go:build darwin && !ios && !nosysresolver

package dns

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// scutilPath is the well-known location of scutil on macOS.
const scutilPath = "/usr/sbin/scutil"

// readSystemDNS returns the current system DNS servers in "host:53" format.
//
// olm's own DNS override is itself a scutil supplemental resolver (see
// dns/platform/darwin.go), and macOS gives supplemental resolvers priority
// over the primary network service's resolver when generating the merged
// configuration - which is also what gets mirrored into /etc/resolv.conf.  So
// once olm's override is active, /etc/resolv.conf (and a naive read of just
// the top of "scutil --dns") reflects olm's own proxy address, not the
// physical network's real DNS.
//
// Instead this reads every resolver in the unscoped "DNS configuration"
// section of `scutil --dns` (the "(for scoped queries)" section that follows
// only duplicates per-interface resolvers and is skipped), which includes
// both the real physical-network resolver and olm's own supplemental one.
// olm's own address is expected to be filtered out by the caller via
// SystemDNSMonitor.SetExcludeIP, the same mechanism used on Windows to drop
// olm's own adapter DNS entry.
//
// /etc/resolv.conf is kept as a fallback for when scutil is unavailable.
func readSystemDNS() []string {
	if out, err := exec.Command(scutilPath, "--dns").Output(); err == nil {
		if servers := parseScutilDNS(string(out)); len(servers) > 0 {
			return servers
		}
	}
	return parseMacResolvConf("/etc/resolv.conf")
}

// parseScutilDNS extracts nameserver addresses from the unscoped "DNS
// configuration" section at the top of `scutil --dns` output, stopping at
// the "DNS configuration (for scoped queries)" section that follows it.
func parseScutilDNS(output string) []string {
	var result []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "DNS configuration (for scoped queries)") {
			break
		}
		if !strings.HasPrefix(line, "nameserver[") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		hp := net.JoinHostPort(addr.String(), "53")
		if !seen[hp] {
			seen[hp] = true
			result = append(result, hp)
		}
	}
	return result
}

func parseMacResolvConf(path string) []string {
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
		s := net.JoinHostPort(addr.String(), "53")
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
