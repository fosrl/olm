//go:build darwin && !ios && nosysresolver

package dns

// readSystemDNS is disabled by the nosysresolver build tag. This is used for
// the macOS app build: unlike the CLI, the app's PacketTunnel system
// extension additionally applies NEDNSSettings (see apple/PacketTunnel),
// which can become the system's primary resolver and make /etc/resolv.conf
// reflect olm's own proxy IP instead of the real upstream DNS. Rather than
// have olm poll a value that may be self-referential, the app pushes the
// real DNS servers in via SetSystemDNS (detected in Swift via
// SCDynamicStore) exactly like Android and iOS. The CLI keeps the real
// implementation in sysresolver_darwin.go, since it has no such override
// mechanism and /etc/resolv.conf always reflects the physical network there.
func readSystemDNS() []string {
	return nil
}
