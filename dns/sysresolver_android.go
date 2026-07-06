//go:build android

package dns

// readSystemDNS returns nil on Android: olm cannot read the OS's DNS
// configuration itself here, so the app detects it (via ConnectivityManager)
// and pushes it in through Olm.SetSystemDNS instead (see SystemDnsMonitor.java).
//
// This is a dedicated file (rather than falling through the general
// sysresolver_stub.go catch-all) because wireguard-android's build passes
// "-tags linux" to share Linux netlink code with Android, and that custom tag
// makes "!linux" evaluate to false even on a real GOOS=android build, which
// would otherwise make sysresolver_stub.go stop applying and leave
// readSystemDNS undefined. An explicit "android" constraint isn't affected by
// that, since nothing passes a conflicting "-tags android".
func readSystemDNS() []string {
	return nil
}
