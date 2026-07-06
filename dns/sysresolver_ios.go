//go:build ios

package dns

// readSystemDNS returns nil on iOS: olm cannot read the OS's DNS
// configuration itself here, so the app must detect it and push it in
// through the equivalent of Olm.SetSystemDNS instead.
//
// This is a dedicated file (rather than falling through the general
// sysresolver_stub.go catch-all) because Go's build constraint evaluator
// treats GOOS=ios as implicitly satisfying the "darwin" tag as well as
// "ios". sysresolver_stub.go excludes with "!darwin", which is false for an
// iOS build, so the stub silently stops applying and would leave
// readSystemDNS undefined. An explicit "ios" constraint isn't affected by
// that ambiguity.
func readSystemDNS() []string {
	return nil
}
