//go:build windows

package blockpage

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Full control for SYSTEM and Administrators only, not inherited from the
// parent, inherited by files created inside. ProgramData otherwise lets every
// local user read new files.
const blockPageDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// DefaultDir is where olm keeps its block page CA when the host does not say.
func DefaultDir() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return ""
	}
	return filepath.Join(programData, "olm", "blockpage")
}

func restrictDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(blockPageDirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

// openRootStore opens the machine-wide Trusted Root Certification
// Authorities store. Writing to it needs SYSTEM or an elevated administrator.
func openRootStore() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		return 0, err
	}
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(name)),
	)
	if err != nil {
		return 0, fmt.Errorf("open LocalMachine\\Root: %w", err)
	}
	return store, nil
}

func installTrust(ca *CA) error {
	store, err := openRootStore()
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)

	// Earlier CAs (from a reinstall or a replaced CA) have no key anymore and
	// only clutter the store.
	if err := removeOurCAs(store, ca.cert.Raw); err != nil {
		return err
	}

	raw := ca.cert.Raw
	ctx, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		&raw[0],
		uint32(len(raw)),
	)
	if err != nil {
		return fmt.Errorf("create certificate context: %w", err)
	}
	defer windows.CertFreeCertificateContext(ctx)

	if err := windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil); err != nil {
		return fmt.Errorf("add to LocalMachine\\Root: %w", err)
	}
	return nil
}

// stageForHost is a no-op: only macOS splits installing the CA between olm
// and the host app.
func stageForHost(*CA) error { return nil }

func removeTrust() error {
	store, err := openRootStore()
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	return removeOurCAs(store, nil)
}

// removeOurCAs deletes every olm block page CA in store except keep.
func removeOurCAs(store windows.Handle, keep []byte) error {
	var stale []*windows.CertContext
	var prev *windows.CertContext
	for {
		// Frees prev; returns an error once there are no more.
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil || ctx == nil {
			break
		}
		prev = ctx

		der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		if keep != nil && bytes.Equal(der, keep) {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil || !isOurCA(cert) {
			continue
		}
		stale = append(stale, windows.CertDuplicateCertificateContext(ctx))
	}

	var errs []error
	for _, ctx := range stale {
		// Frees ctx, even when it fails.
		if err := windows.CertDeleteCertificateFromStore(ctx); err != nil {
			errs = append(errs, fmt.Errorf("remove old block page CA: %w", err))
		}
	}
	return errors.Join(errs...)
}

// systemRoots returns nil so verification uses the Windows verifier, which
// reads the certificate stores on every call.
func systemRoots() (*x509.CertPool, error) {
	return nil, nil
}
