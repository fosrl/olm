//go:build windows

package dns

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/windows/registry"
)

const (
	tcpipInterfacesPath = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	dhcpNameServerKey   = "DhcpNameServer"
	staticNameServerKey = "NameServer"
)

// readSystemDNS returns the current system DNS servers in "host:53" format by
// enumerating every network adapter in the Windows registry.
//
// For each adapter olm reads the DHCP-assigned DNS servers (DhcpNameServer).
// Static DNS (NameServer) is ignored on the assumption that it belongs to the
// olm WireGuard adapter or another VPN; DHCP-assigned servers always reflect
// the physical network's DNS.  Loopback and link-local addresses are excluded.
func readSystemDNS() []string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipInterfacesPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var result []string

	for _, guid := range subkeys {
		path := fmt.Sprintf(`%s\%s`, tcpipInterfacesPath, guid)
		iKey, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		dhcp, _, err := iKey.GetStringValue(dhcpNameServerKey)
		iKey.Close()
		if err != nil || dhcp == "" {
			continue
		}

		for _, s := range splitWinDNSList(dhcp) {
			addr, err := netip.ParseAddr(s)
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
	}

	return result
}

// splitWinDNSList splits a Windows DNS server list that may be comma- or
// space-separated.
func splitWinDNSList(s string) []string {
	var out []string
	for _, part := range splitByRunes(s, []rune{',', ' '}) {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitByRunes(s string, delims []rune) []string {
	var result []string
	start := 0
	for i, r := range s {
		for _, d := range delims {
			if r == d {
				if i > start {
					result = append(result, s[start:i])
				}
				start = i + len(string(r))
				break
			}
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}
