//go:build linux && !android

package blockpage

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// trustFileName is the name of the CA file olm puts in a distribution's
// anchors directory, without extension.
const trustFileName = "pangolin-olm-blockpage"

// linuxStore is one way distributions manage the system trust store: drop a
// file in dir, then run update to rebuild the bundles programs read.
type linuxStore struct {
	dir    string
	ext    string
	update []string
}

// Tried in order; the first whose directory and tool both exist is used.
var linuxStores = []linuxStore{
	// Debian, Ubuntu, Alpine (needs the .crt extension)
	{dir: "/usr/local/share/ca-certificates", ext: ".crt", update: []string{"update-ca-certificates"}},
	// Fedora, RHEL, CentOS
	{dir: "/etc/pki/ca-trust/source/anchors", ext: ".pem", update: []string{"update-ca-trust", "extract"}},
	// Arch
	{dir: "/etc/ca-certificates/trust-source/anchors", ext: ".crt", update: []string{"update-ca-trust"}},
	// openSUSE
	{dir: "/etc/pki/trust/anchors", ext: ".pem", update: []string{"update-ca-certificates"}},
}

// The bundles that programs, and Go's own verifier, read. Same list and order
// as crypto/x509 uses.
var linuxBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

const updateTimeout = 2 * time.Minute

// DefaultDir is where olm keeps its block page CA when the host does not say.
// Empty, which disables HTTPS block pages, when not running as root: only
// root can add to the system trust store or keep the key out of other users'
// reach.
func DefaultDir() string {
	if os.Geteuid() != 0 {
		return ""
	}
	return "/var/lib/olm/blockpage"
}

// restrictDir is a no-op: the directory mode already keeps other users out.
func restrictDir(string) error { return nil }

func installTrust(ca *CA) error {
	store, ok := pickLinuxStore()
	if !ok {
		return errors.New("no supported trust store tool found (update-ca-certificates or update-ca-trust)")
	}
	path := filepath.Join(store.dir, trustFileName+store.ext)
	if err := writeFileAtomic(path, ca.CertPEM(), 0o644); err != nil {
		return err
	}
	return runUpdate(store)
}

// stageForHost is a no-op: only macOS splits installing the CA between olm
// and the host app.
func stageForHost(*CA) error { return nil }

func removeTrust() error {
	var errs []error
	for _, store := range linuxStores {
		path := filepath.Join(store.dir, trustFileName+store.ext)
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := exec.LookPath(store.update[0]); err == nil {
			errs = append(errs, runUpdate(store))
		}
	}
	return errors.Join(errs...)
}

func pickLinuxStore() (linuxStore, bool) {
	for _, store := range linuxStores {
		if info, err := os.Stat(store.dir); err != nil || !info.IsDir() {
			continue
		}
		if _, err := exec.LookPath(store.update[0]); err != nil {
			continue
		}
		return store, true
	}
	return linuxStore{}, false
}

func runUpdate(store linuxStore) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, store.update[0], store.update[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(store.update, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// systemRoots reads the system bundle fresh. crypto/x509 loads it once per
// process, which would miss a CA added after that.
func systemRoots() (*x509.CertPool, error) {
	files := linuxBundles
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		files = []string{f}
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(data)
		return pool, nil
	}
	return nil, errors.New("no CA bundle found")
}
