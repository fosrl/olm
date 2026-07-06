//go:build !linux && !darwin && !windows && !android

package dns

// readSystemDNS returns nil on platforms where automatic DNS discovery is not
// implemented (freebsd, etc.).  Callers should fall back to a statically
// configured DNS server.
//
// android and ios are excluded from this constraint (and have their own
// sysresolver_android.go / sysresolver_ios.go with an explicit "android" /
// "ios" tag) rather than falling through the "!linux" / "!darwin" catch-all
// here:
//   - wireguard-android's build passes "-tags linux" to share Linux netlink code
//     (a deliberate, long-standing convention, since Android's kernel is Linux), and Go's
//     build constraint evaluator can't distinguish a custom "-tags linux" from the real
//     GOOS=linux - so with that tag set, "!linux" is false even though GOOS is actually
//     android, and this file would silently stop applying, leaving readSystemDNS undefined.
//   - Go's build constraint evaluator treats GOOS=ios as implicitly satisfying the
//     "darwin" tag as well as "ios", so "!darwin" is false on an iOS build too, which
//     would otherwise leave readSystemDNS undefined there as well.
func readSystemDNS() []string {
	return nil
}
