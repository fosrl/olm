//go:build darwin && !ios

package blockpage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	securityTool    = "/usr/bin/security"
	systemKeychain  = "/Library/Keychains/System.keychain"
	securityTimeout = 2 * time.Minute
)

// DefaultDir is where olm keeps its block page CA when the host does not say.
// Empty, which disables HTTPS block pages, when not running as root: only
// root can add to the System keychain or keep the key out of other users'
// reach.
func DefaultDir() string {
	if os.Geteuid() != 0 {
		return ""
	}
	return "/Library/Application Support/olm/blockpage"
}

// restrictDir is a no-op: the directory mode already keeps other users out.
func restrictDir(string) error { return nil }

// installTrust adds the CA to the System keychain as a trusted root. macOS asks
// for an administrator's approval to change trust settings, even for root,
// unless an MDM profile delivers the certificate. Without a logged in user to
// approve, this fails and the CA has to be installed by hand or by MDM.
func installTrust(ca *CA) error {
	if err := removeOurCAs(ca.cert.Raw); err != nil {
		return err
	}

	f, err := os.CreateTemp("", "olm-blockpage-*.pem")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(ca.CertPEM()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	_, err = runSecurity("add-trusted-cert", "-d", "-r", "trustRoot", "-k", systemKeychain, f.Name())
	return err
}

func removeTrust() error {
	return removeOurCAs(nil)
}

// removeOurCAs deletes every olm block page CA in the System keychain except
// keep, along with its trust settings.
func removeOurCAs(keep []byte) error {
	out, err := runSecurity("find-certificate", "-a", "-c", caCommonName, "-p", systemKeychain)
	if err != nil {
		// Nothing found is reported as an error too.
		return nil
	}

	var errs []error
	rest := out
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if keep != nil && bytes.Equal(block.Bytes, keep) {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !isOurCA(cert) {
			continue
		}
		if err := removeCert(cert); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func removeCert(cert *x509.Certificate) error {
	f, err := os.CreateTemp("", "olm-blockpage-*.pem")
	if err == nil {
		_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		f.Close()
		// Best effort: removing trust settings may also need approval.
		_, _ = runSecurity("remove-trusted-cert", "-d", f.Name())
		os.Remove(f.Name())
	}
	_, err = runSecurity("delete-certificate", "-Z", sha1Hex(cert), systemKeychain)
	return err
}

func sha1Hex(cert *x509.Certificate) string {
	return fmt.Sprintf("%X", sha1.Sum(cert.Raw))
}

func runSecurity(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), securityTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, securityTool, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("security %s: %w: %s", args[0], err, firstLine(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func firstLine(s string) string {
	line, _, _ := bufio.NewReader(strings.NewReader(strings.TrimSpace(s))).ReadLine()
	return string(line)
}

// systemRoots returns nil so verification uses the macOS verifier, which
// reads the keychains and trust settings on every call.
func systemRoots() (*x509.CertPool, error) {
	return nil, nil
}
