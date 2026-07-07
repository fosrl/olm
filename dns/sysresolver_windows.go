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
// For each adapter olm reads the effective DNS servers: static (NameServer)
// if set, since a static entry overrides DHCP for that adapter and is what
// the OS resolver actually uses, otherwise falling back to the DHCP-assigned
// servers (DhcpNameServer). This also picks up olm's own WireGuard adapter,
// which olm points at its local DNS proxy via a static NameServer entry; that
// address is expected to be filtered out by the caller via
// SystemDNSMonitor.SetExcludeIP. Loopback and link-local addresses are
// excluded.
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

		servers, _, err := iKey.GetStringValue(staticNameServerKey)
		if err != nil || servers == "" {
			servers, _, err = iKey.GetStringValue(dhcpNameServerKey)
		}
		iKey.Close()
		if err != nil || servers == "" {
			continue
		}

		for _, s := range splitWinDNSList(servers) {
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
