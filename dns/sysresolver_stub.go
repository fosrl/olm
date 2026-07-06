//go:build !linux && !darwin && !windows && !android

package dns

// readSystemDNS returns nil on platforms where automatic DNS discovery is not
// implemented (ios, freebsd, etc.).  Callers should fall back to a
// statically configured DNS server.
//
// android is excluded from this constraint (and has its own sysresolver_android.go
// with an explicit "android" tag) rather than falling through the "!linux" catch-all
// here: wireguard-android's build passes "-tags linux" to share Linux netlink code
// (a deliberate, long-standing convention, since Android's kernel is Linux), and Go's
// build constraint evaluator can't distinguish a custom "-tags linux" from the real
// GOOS=linux - so with that tag set, "!linux" is false even though GOOS is actually
// android, and this file would silently stop applying, leaving readSystemDNS undefined.
func readSystemDNS() []string {
	return nil
}
