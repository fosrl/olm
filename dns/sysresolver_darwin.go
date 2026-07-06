//go:build darwin && !ios && !nosysresolver

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
// On macOS, olm adds supplemental DNS entries via scutil without modifying
// /etc/resolv.conf or the primary network service DNS.  Reading /etc/resolv.conf
// therefore always yields the physical-network DNS supplied by DHCP or the user.
// /etc/resolv.conf on macOS is a regular file managed by mDNSResponder and is
// updated whenever the network configuration changes.
func readSystemDNS() []string {
	return parseMacResolvConf("/etc/resolv.conf")
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
