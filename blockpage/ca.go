// Package blockpage shows users a page saying a site is blocked when they open
// a domain that their organization blocks. olm answers DNS for such a domain
// with its own utility address and serves HTTP and HTTPS there, redirecting the
// browser to the block page on the Pangolin server.
//
// HTTPS needs a certificate the browser trusts for the blocked name, so each
// device gets its own certificate authority. Its private key is created on the
// device and never leaves it; the certificate is added to the operating
// system's trust store. Where that is not possible, olm does not redirect and
// blocked lookups fail instead.
package blockpage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

const (
	// caCommonName starts the subject of every CA olm creates. Trust store
	// cleanup matches on it to find CAs left behind by earlier installs.
	caCommonName   = "Pangolin Block Page CA"
	caOrganization = "Pangolin"

	caValidity = 5 * 365 * 24 * time.Hour
	// A CA closer than this to expiring is replaced.
	caRenewBefore = 30 * 24 * time.Hour

	leafValidity = 7 * 24 * time.Hour
	// A cached leaf closer than this to expiring is minted again.
	leafRenewBefore = 24 * time.Hour
	// Clock skew allowance on certificate start times.
	backdate = time.Hour

	maxCachedLeaves = 1024

	caCertFile = "ca.pem"
	caKeyFile  = "ca-key.pem"
)

// CA is this device's block page certificate authority. It mints short-lived
// certificates for blocked domains on demand.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// leafKey is shared by every leaf. It lives only in memory.
	leafKey *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// Certificate returns the CA certificate.
func (c *CA) Certificate() *x509.Certificate {
	return c.cert
}

// CertPEM returns the CA certificate in PEM form.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// LoadOrCreateCA loads the CA kept in dir, creating it when there is none. It
// does not touch the system trust store; Manager.Prepare does that.
func LoadOrCreateCA(dir string) (*CA, error) {
	ca, _, err := loadOrCreateCA(dir)
	return ca, err
}

// loadOrCreateCA reads the CA from dir, or creates and saves a new one when
// there is none or it is about to expire. replaced is the previous CA when one
// was replaced, so the caller can take it out of the trust store.
func loadOrCreateCA(dir string) (ca *CA, replaced *x509.Certificate, err error) {
	cert, key, err := readCA(dir)
	switch {
	case err == nil && time.Until(cert.NotAfter) > caRenewBefore:
		return newCA(cert, key)
	case err == nil:
		replaced = cert
	case !errors.Is(err, os.ErrNotExist):
		// Unreadable or corrupt: start over rather than stay broken. Installing
		// the new CA also clears out trust store entries of earlier ones.
		logger.Warn("Block page CA in %s is unusable, creating a new one: %v", dir, err)
	}

	cert, key, err = generateCA()
	if err != nil {
		return nil, nil, err
	}
	if err := writeCA(dir, cert, key); err != nil {
		return nil, nil, err
	}
	ca, _, err = newCA(cert, key)
	return ca, replaced, err
}

func newCA(cert *x509.Certificate, key *ecdsa.PrivateKey) (*CA, *x509.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	return &CA{
		cert:    cert,
		key:     key,
		leafKey: leafKey,
		leaves:  make(map[string]*tls.Certificate),
	}, nil, nil
}

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	name := caCommonName
	if host, err := os.Hostname(); err == nil && host != "" {
		name = fmt.Sprintf("%s (%s)", caCommonName, host)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{caOrganization},
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		// Leaves only: no intermediate can be chained under this CA.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		KeyUsage:       x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// Restricts everything it signs to TLS server certificates.
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId: keyID(&key.PublicKey),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// Leaf returns a certificate for host signed by the CA, minting one if there
// is no cached one that is still good.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, errors.New("no host name")
	}

	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	if leaf, ok := c.leaves[host]; ok && leaf.Leaf != nil && leaf.Leaf.NotAfter.Sub(now) > leafRenewBefore {
		return leaf, nil
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(leafValidity)
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: host},
		DNSNames:       []string{host},
		NotBefore:      now.Add(-backdate),
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: c.cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &c.leafKey.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("create certificate for %s: %w", host, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	leaf := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  c.leafKey,
		Leaf:        parsed,
	}
	if len(c.leaves) >= maxCachedLeaves {
		clear(c.leaves)
	}
	c.leaves[host] = leaf
	return leaf, nil
}

// readCA loads the CA certificate and key from dir. The error wraps
// os.ErrNotExist when there is no CA yet.
func readCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("CA certificate file is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("CA key file is not PEM")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	key, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, errors.New("CA key does not match its certificate")
	}
	return cert, key, nil
}

func writeCA(dir string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	// MkdirAll leaves an existing directory's mode alone.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("restrict %s: %w", dir, err)
	}
	if err := restrictDir(dir); err != nil {
		return fmt.Errorf("restrict %s: %w", dir, err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, caKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, caCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// removeCAFiles deletes the CA certificate and key from dir.
func removeCAFiles(dir string) error {
	var errs []error
	for _, name := range []string{caKeyFile, caCertFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// isOurCA reports whether cert is a block page CA created by olm, on this or
// an earlier install.
func isOurCA(cert *x509.Certificate) bool {
	return cert.IsCA &&
		strings.HasPrefix(cert.Subject.CommonName, caCommonName) &&
		len(cert.Subject.Organization) == 1 &&
		cert.Subject.Organization[0] == caOrganization
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func keyID(pub *ecdsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha1.Sum(der)
	return sum[:]
}

// normalizeHost lowercases a host name and drops a port and trailing dot.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
