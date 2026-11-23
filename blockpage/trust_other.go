//go:build !(linux && !android) && !windows && !(darwin && !ios)

package blockpage

import (
	"crypto/x509"
	"errors"
)

// iOS and Android (and anything else) do not let an app add a trusted root.
// The user, or MDM, has to install it; until that is supported, HTTPS block
// pages are off and blocked lookups fail instead.

var errTrustUnsupported = errors.New("adding a trusted certificate is not supported on this platform")

// DefaultDir is empty: block page certificates are off unless the host
// passes a directory.
func DefaultDir() string { return "" }

func restrictDir(string) error { return nil }

func installTrust(*CA) error { return errTrustUnsupported }

// stageForHost is a no-op: only macOS splits installing the CA between olm
// and the host app.
func stageForHost(*CA) error { return nil }

func removeTrust() error { return nil }

func systemRoots() (*x509.CertPool, error) { return nil, nil }
