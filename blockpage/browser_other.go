//go:build !(linux && !android)

package blockpage

// Elsewhere browsers use the platform trust store that installTrust adds the
// CA to, or the platform offers no way to add one.

func installBrowserTrust(*CA) error { return nil }

func removeBrowserTrust() error { return nil }
