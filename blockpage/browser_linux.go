//go:build linux && !android

package blockpage

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fosrl/newt/logger"
)

// Browsers on Linux do not all honor the system trust store. Chromium based
// browsers ignore CAs that reach NSS through its built-in roots module, which
// is how distributions using p11-kit (Arch, Fedora) expose the system store,
// and Firefox builds that ship their own roots ignore it too. Both read
// machine-wide policy files, so olm also lists its CA there.

// chromiumBrowser is a Chromium based browser that reads JSON policy files
// from policyDir.
type chromiumBrowser struct {
	name      string
	policyDir string
	// present lists paths of which any existing means the browser is
	// installed. Policy files are only written for installed browsers.
	present []string
}

var chromiumBrowsers = []chromiumBrowser{
	{"Google Chrome", "/etc/opt/chrome/policies/managed", []string{"/opt/google/chrome"}},
	{"Chromium", "/etc/chromium/policies/managed", []string{"/usr/lib/chromium", "/usr/lib64/chromium", "/usr/lib/chromium-browser", "/usr/lib64/chromium-browser"}},
	// Ubuntu's snap reads its own directory.
	{"Chromium (snap)", "/etc/chromium-browser/policies/managed", []string{"/snap/bin/chromium"}},
	{"Microsoft Edge", "/etc/opt/edge/policies/managed", []string{"/opt/microsoft/msedge"}},
	{"Brave", "/etc/brave/policies/managed", []string{"/opt/brave.com/brave"}},
}

// firefoxInstall is a Firefox build. It reads policies.json from etcDir when
// that file exists, and otherwise from the distribution directory of the
// install.
type firefoxInstall struct {
	name   string
	etcDir string
	// installDirs are writable install locations; Firefox reads
	// <dir>/distribution/policies.json.
	installDirs []string
	present     []string
}

var firefoxInstalls = []firefoxInstall{
	{
		name:        "Firefox",
		etcDir:      "/etc/firefox/policies",
		installDirs: []string{"/usr/lib/firefox", "/usr/lib64/firefox", "/opt/firefox"},
		// The snap reads /etc/firefox/policies.
		present: []string{"/usr/lib/firefox", "/usr/lib64/firefox", "/opt/firefox", "/snap/bin/firefox"},
	},
	{
		name:        "Firefox ESR",
		etcDir:      "/etc/firefox-esr/policies",
		installDirs: []string{"/usr/lib/firefox-esr", "/usr/lib64/firefox-esr"},
		present:     []string{"/usr/lib/firefox-esr", "/usr/lib64/firefox-esr"},
	},
}

// installBrowserTrust adds ca to the policies of the installed browsers that
// need it. Files already in the right state are left alone, so calling it
// again is cheap.
func installBrowserTrust(ca *CA) error {
	var errs []error

	policy := chromiumPolicy(ca)
	for _, b := range chromiumBrowsers {
		if !anyExists(b.present) {
			continue
		}
		path := filepath.Join(b.policyDir, trustFileName+".json")
		changed, err := writeIfChanged(path, policy)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s policy: %w", b.name, err))
			continue
		}
		if changed {
			logger.Info("Added block page CA to the %s policy in %s", b.name, path)
		}
	}

	for _, f := range firefoxInstalls {
		if !anyExists(f.present) {
			continue
		}
		policyFile := f.policyFile()
		certPath := firefoxCertPath(policyFile)
		changed, err := writeIfChanged(certPath, ca.CertPEM())
		if err == nil {
			var added bool
			added, err = addFirefoxCert(policyFile, certPath)
			changed = changed || added
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s policy: %w", f.name, err))
			continue
		}
		if changed {
			logger.Info("Added block page CA to the %s policy in %s; Firefox loads it on its next start", f.name, policyFile)
		}
	}

	return errors.Join(errs...)
}

// removeBrowserTrust undoes installBrowserTrust for every browser, installed
// or not. Firefox keeps a CA it imported in each profile it was imported
// into; this only stops it importing the CA again.
func removeBrowserTrust() error {
	var errs []error
	for _, b := range chromiumBrowsers {
		path := filepath.Join(b.policyDir, trustFileName+".json")
		if !fileExists(path) {
			continue
		}
		if err := removeIfExists(path); err != nil {
			errs = append(errs, err)
			continue
		}
		logger.Info("Removed block page CA from the %s policy", b.name)
	}
	for _, f := range firefoxInstalls {
		for _, policyFile := range f.policyFiles() {
			certPath := firefoxCertPath(policyFile)
			removed, err := removeFirefoxCert(policyFile, certPath)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if err := removeIfExists(certPath); err != nil {
				errs = append(errs, err)
				continue
			}
			if removed {
				logger.Info("Removed block page CA from the %s policy in %s", f.name, policyFile)
			}
		}
	}
	return errors.Join(errs...)
}

// chromiumPolicy is the policy file that makes Chromium based browsers trust
// ca for TLS servers. CACertificates takes base64 DER certificates (Chrome
// 132 and later) and is reloaded while the browser runs. If another policy
// file in the same directory also sets CACertificates, only one of them
// applies.
func chromiumPolicy(ca *CA) []byte {
	data, _ := json.MarshalIndent(map[string][]string{
		"CACertificates": {base64.StdEncoding.EncodeToString(ca.Certificate().Raw)},
	}, "", "  ")
	return append(data, '\n')
}

// policyFile is the policies.json this Firefox reads: the one in etcDir when
// it exists, else an existing one in a distribution directory, else a new one
// in etcDir. Creating the etcDir file while a distribution one exists would
// hide the distribution one from Firefox.
func (f firefoxInstall) policyFile() string {
	files := f.policyFiles()
	for _, p := range files {
		if fileExists(p) {
			return p
		}
	}
	return files[0]
}

// policyFiles lists every policies.json this Firefox might read, in the order
// Firefox looks for them.
func (f firefoxInstall) policyFiles() []string {
	files := []string{filepath.Join(f.etcDir, "policies.json")}
	for _, dir := range f.installDirs {
		files = append(files, filepath.Join(dir, "distribution", "policies.json"))
	}
	return files
}

// firefoxCertPath is where the CA goes for the policy file: next to it, where
// Firefox (the snap included) can read it, unlike olm's own key directory.
func firefoxCertPath(policyFile string) string {
	return filepath.Join(filepath.Dir(policyFile), trustFileName+".pem")
}

// addFirefoxCert adds certPath to Certificates.Install in policyFile,
// creating the file if needed and keeping every other policy in it. It
// reports whether the file changed.
func addFirefoxCert(policyFile, certPath string) (bool, error) {
	doc, err := readPolicyJSON(policyFile)
	if err != nil {
		return false, err
	}
	policies, err := childObject(doc, "policies")
	if err != nil {
		return false, err
	}
	certs, err := childObject(policies, "Certificates")
	if err != nil {
		return false, err
	}
	install, err := installList(certs)
	if err != nil {
		return false, err
	}
	for _, v := range install {
		if v == certPath {
			return false, nil
		}
	}
	certs["Install"] = append(install, certPath)
	return true, writePolicyJSON(policyFile, doc)
}

// removeFirefoxCert removes certPath from Certificates.Install in policyFile.
// It deletes the file when nothing else is left in it, and reports whether
// it found the entry.
func removeFirefoxCert(policyFile, certPath string) (bool, error) {
	raw, err := os.ReadFile(policyFile)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Contains(raw, []byte(certPath)) {
		// Not ours to touch, even if it is not valid JSON.
		return false, nil
	}
	doc, err := readPolicyJSON(policyFile)
	if err != nil {
		return false, err
	}
	policies, _ := doc["policies"].(map[string]any)
	certs, _ := policies["Certificates"].(map[string]any)
	install, _ := certs["Install"].([]any)

	kept := install[:0:0]
	for _, v := range install {
		if v != certPath {
			kept = append(kept, v)
		}
	}
	if len(kept) == len(install) {
		return false, nil
	}

	if len(kept) > 0 {
		certs["Install"] = kept
	} else {
		delete(certs, "Install")
		if len(certs) == 0 {
			delete(policies, "Certificates")
		}
		if len(policies) == 0 {
			delete(doc, "policies")
		}
	}
	if len(doc) == 0 {
		return true, removeIfExists(policyFile)
	}
	return true, writePolicyJSON(policyFile, doc)
}

func readPolicyJSON(path string) (map[string]any, error) {
	doc := map[string]any{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return doc, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // keep numbers exactly as written
	if err := dec.Decode(&doc); err != nil {
		// Never rewrite a file olm cannot read; that would lose its policies.
		return nil, fmt.Errorf("%s is not valid JSON, leaving it alone: %w", path, err)
	}
	return doc, nil
}

func writePolicyJSON(path string, doc map[string]any) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0o644)
}

// childObject returns parent[key] as an object, adding an empty one if it is
// missing.
func childObject(parent map[string]any, key string) (map[string]any, error) {
	v, ok := parent[key]
	if !ok {
		child := map[string]any{}
		parent[key] = child
		return child, nil
	}
	child, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%q is not an object", key)
	}
	return child, nil
}

func installList(certs map[string]any) ([]any, error) {
	v, ok := certs["Install"]
	if !ok {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, errors.New(`"Certificates.Install" is not a list`)
	}
	return list, nil
}

// writeIfChanged writes data to path, creating its directory, unless the file
// already holds exactly data. It reports whether it wrote.
func writeIfChanged(path string, data []byte) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func anyExists(paths []string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
