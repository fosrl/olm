//go:build !linux && !darwin && !windows

package dns

// readSystemDNS returns nil on platforms where automatic DNS discovery is not
// implemented (android, ios, freebsd, etc.).  Callers should fall back to a
// statically configured DNS server.
func readSystemDNS() []string {
	return nil
}
