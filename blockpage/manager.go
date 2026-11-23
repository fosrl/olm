package blockpage

import (
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

// trustCheckHost is the name on the certificate minted to test whether the
// system trusts the CA. It is never served.
const trustCheckHost = "trust-check.blockpage.invalid"

var (
	// ErrDisabled means there is nowhere to keep a CA on this platform or
	// for this process, so HTTPS block pages are off.
	ErrDisabled = errors.New("block page certificates are not available on this platform")
	// ErrNotTrusted means the CA exists but the system does not trust it.
	ErrNotTrusted = errors.New("the system does not trust the block page certificate")
	// ErrAwaitingHostTrust means the CA exists but is not trusted yet, and the
	// host app, not olm, adds it to the trust store (see SetHostInstallsTrust).
	ErrAwaitingHostTrust = errors.New("waiting for the app to add the block page certificate to the trust store")
)

// Status describes the block page CA, for the local API.
type Status struct {
	// Trusted is whether the system trusts the CA, so HTTPS block pages work.
	Trusted bool `json:"trusted"`
	// CAPath is the CA certificate file, for installing it by hand. Empty
	// until the CA has been created.
	CAPath string `json:"caPath,omitempty"`
	// Error is why the CA is not trusted, if known.
	Error string `json:"error,omitempty"`
	// NeedsTrust is whether the CA exists but is not trusted, so adding it to
	// the trust store (by the host app or by hand) would turn HTTPS block
	// pages on.
	NeedsTrust bool `json:"needsTrust,omitempty"`
}

// Manager owns this device's block page CA: it creates it on first use, keeps
// it in dir and makes sure the operating system trusts it.
type Manager struct {
	dir string

	mu                sync.Mutex
	hostInstallsTrust bool
	ca                *CA
	trusted           bool
	installAttempted  bool
	// stagedFor is the CA olm last got ready for the host app to trust (see
	// stageForHost), and stageFailed whether that failed, in which case
	// trusting it would not help.
	stagedFor   *CA
	stageFailed bool
	lastErr     error
	// browsersFor is the CA last added to browser policies, so that happens
	// once per CA per process.
	browsersFor *CA
}

// NewManager returns a Manager that keeps its CA in dir. An empty dir disables
// HTTPS block pages; see DefaultDir.
func NewManager(dir string) *Manager {
	return &Manager{dir: dir}
}

// SetHostInstallsTrust makes Prepare only check whether the system trusts the
// CA, never add it itself. Use it where olm runs without a way to get the
// user's approval, as in the macOS system extension: the host app fetches the
// CA, adds it with the user's approval, and calls Prepare again.
func (m *Manager) SetHostInstallsTrust(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hostInstallsTrust = v
}

// Prepare loads the CA, creating it if there is none, and checks that the
// system trusts it. The first time it finds the CA untrusted it adds it to the
// system trust store; later calls only check again, so a failed or declined
// install is not retried until the process restarts. It returns the CA only
// when it is trusted.
//
// Installing can run external tools and take a few seconds, so call it off any
// latency sensitive path.
func (m *Manager) Prepare() (*CA, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ca, err := m.prepareLocked()
	m.trusted = err == nil
	m.lastErr = err
	return ca, err
}

func (m *Manager) prepareLocked() (*CA, error) {
	if m.dir == "" {
		return nil, ErrDisabled
	}

	if m.ca == nil {
		ca, replaced, err := loadOrCreateCA(m.dir)
		if err != nil {
			return nil, fmt.Errorf("load block page CA: %w", err)
		}
		if replaced != nil {
			logger.Info("Replaced block page CA that expires %s", replaced.NotAfter.Format(time.DateOnly))
		}
		m.ca = ca
	}

	if trustedBySystem(m.ca) {
		m.syncBrowsersLocked()
		return m.ca, nil
	}
	if m.hostInstallsTrust {
		if m.stagedFor != m.ca {
			if err := stageForHost(m.ca); err != nil {
				m.stageFailed = true
				return nil, fmt.Errorf("prepare block page CA for the app to trust: %w", err)
			}
			m.stagedFor = m.ca
			m.stageFailed = false
		}
		return nil, ErrAwaitingHostTrust
	}
	if m.installAttempted {
		return nil, ErrNotTrusted
	}
	m.installAttempted = true

	logger.Info("Adding block page CA to the system trust store")
	if err := installTrust(m.ca); err != nil {
		return nil, fmt.Errorf("add block page CA to the system trust store: %w", err)
	}
	if !trustedBySystem(m.ca) {
		return nil, ErrNotTrusted
	}
	logger.Info("Block page CA is trusted")
	m.syncBrowsersLocked()
	return m.ca, nil
}

// syncBrowsersLocked adds the CA to the policies of browsers that ignore the
// system trust store. A failure only affects those browsers, so it is logged
// and does not turn the block page off.
func (m *Manager) syncBrowsersLocked() {
	if m.browsersFor == m.ca {
		return
	}
	m.browsersFor = m.ca
	if err := installBrowserTrust(m.ca); err != nil {
		logger.Warn("Some browsers may reject block page certificates: %v", err)
	}
}

// ReleaseBrowsers takes the CA back out of browser policies while no block
// page is in use, so browsers don't stay managed for nothing. The next
// Prepare adds it again. The CA stays in the system trust store.
func (m *Manager) ReleaseBrowsers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.browsersFor = nil
	RemoveBrowserTrust()
}

// RemoveBrowserTrust takes olm's CA out of every browser policy it added it
// to, for when no Manager exists yet (say, left over from a process that did
// not shut down cleanly). Failures are logged.
func RemoveBrowserTrust() {
	if err := removeBrowserTrust(); err != nil {
		logger.Warn("Could not remove the block page CA from browser policies: %v", err)
	}
}

// Status returns the state as of the last Prepare.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{Trusted: m.trusted}
	if m.ca != nil {
		st.CAPath = filepath.Join(m.dir, caCertFile)
		st.NeedsTrust = !m.trusted && !m.stageFailed
	}
	if m.lastErr != nil {
		st.Error = m.lastErr.Error()
	}
	return st
}

// CertPEM returns the CA certificate, or nil before the CA exists.
func (m *Manager) CertPEM() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ca == nil {
		return nil
	}
	return m.ca.CertPEM()
}

// Uninstall removes every block page CA olm added to the system trust store
// and browser policies, and deletes the CA kept in dir. Call it when olm is
// uninstalled.
func Uninstall(dir string) error {
	errs := []error{removeTrust(), removeBrowserTrust()}
	if dir != "" {
		errs = append(errs, removeCAFiles(dir))
	}
	return errors.Join(errs...)
}

// trustedBySystem reports whether the system accepts certificates the CA
// signs for TLS servers.
func trustedBySystem(ca *CA) bool {
	leaf, err := ca.Leaf(trustCheckHost)
	if err != nil {
		return false
	}
	roots, err := systemRoots()
	if err != nil {
		logger.Debug("Could not read the system trust store: %v", err)
		return false
	}
	_, err = leaf.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots, // nil uses the platform verifier
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		logger.Debug("Block page CA is not trusted: %v", err)
	}
	return err == nil
}
