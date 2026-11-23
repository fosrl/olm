//go:build linux && !android

package blockpage

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fakeBrowsers points the browser tables at a temporary directory: one
// installed Chromium browser, one that is not installed, and one Firefox.
func fakeBrowsers(t *testing.T) (root string, chrome, absent chromiumBrowser, ff firefoxInstall) {
	t.Helper()
	root = t.TempDir()
	chrome = chromiumBrowser{"Chrome", filepath.Join(root, "etc/opt/chrome/policies/managed"), []string{filepath.Join(root, "opt/google/chrome")}}
	absent = chromiumBrowser{"Edge", filepath.Join(root, "etc/opt/edge/policies/managed"), []string{filepath.Join(root, "opt/microsoft/msedge")}}
	ff = firefoxInstall{
		name:        "Firefox",
		etcDir:      filepath.Join(root, "etc/firefox/policies"),
		installDirs: []string{filepath.Join(root, "usr/lib/firefox")},
		present:     []string{filepath.Join(root, "usr/lib/firefox")},
	}
	mustMkdir(t, chrome.present[0])
	mustMkdir(t, ff.installDirs[0])

	oldChromium, oldFirefox := chromiumBrowsers, firefoxInstalls
	chromiumBrowsers = []chromiumBrowser{chrome, absent}
	firefoxInstalls = []firefoxInstall{ff}
	t.Cleanup(func() { chromiumBrowsers, firefoxInstalls = oldChromium, oldFirefox })
	return root, chrome, absent, ff
}

func TestChromiumPolicy(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var policy struct{ CACertificates []string }
	if err := json.Unmarshal(chromiumPolicy(ca), &policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.CACertificates) != 1 {
		t.Fatalf("CACertificates = %v, want one certificate", policy.CACertificates)
	}
	der, err := base64.StdEncoding.DecodeString(policy.CACertificates[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, ca.Certificate().Raw) {
		t.Error("CACertificates must hold the CA as base64 DER")
	}
}

func TestBrowserTrustNewFirefoxPolicy(t *testing.T) {
	_, chrome, absent, ff := fakeBrowsers(t)
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if err := installBrowserTrust(ca); err != nil {
		t.Fatal(err)
	}

	chromeFile := filepath.Join(chrome.policyDir, trustFileName+".json")
	if data, err := os.ReadFile(chromeFile); err != nil || !bytes.Equal(data, chromiumPolicy(ca)) {
		t.Errorf("Chrome policy not written (err %v)", err)
	}
	if _, err := os.Stat(absent.policyDir); err == nil {
		t.Error("no policy should be written for a browser that is not installed")
	}

	// No policies.json existed, so the system-wide one is created.
	policyFile := filepath.Join(ff.etcDir, "policies.json")
	certPath := filepath.Join(ff.etcDir, trustFileName+".pem")
	if got := firefoxInstallList(t, policyFile); len(got) != 1 || got[0] != certPath {
		t.Errorf("Install = %v, want [%s]", got, certPath)
	}
	if data, err := os.ReadFile(certPath); err != nil || !bytes.Equal(data, ca.CertPEM()) {
		t.Errorf("Firefox certificate not written (err %v)", err)
	}

	// Installing again changes nothing.
	before := readAll(t, policyFile)
	if err := installBrowserTrust(ca); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readAll(t, policyFile)) {
		t.Error("installing twice rewrote the Firefox policy")
	}
	if got := firefoxInstallList(t, policyFile); len(got) != 1 {
		t.Errorf("Install = %v after a second install, want one entry", got)
	}

	if err := removeBrowserTrust(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{chromeFile, policyFile, certPath} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s left behind after removal", p)
		}
	}
}

func TestBrowserTrustKeepsExistingFirefoxPolicies(t *testing.T) {
	_, _, _, ff := fakeBrowsers(t)
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// An admin's policies.json in the distribution directory: olm must merge
	// into it, not create one in etcDir that would hide it.
	distFile := filepath.Join(ff.installDirs[0], "distribution", "policies.json")
	mustMkdir(t, filepath.Dir(distFile))
	const existing = `{"policies": {"DisableTelemetry": true, "Proxy": {"Port": 12345678901234567890}, "Certificates": {"Install": ["/admin/root.pem"]}}}`
	if err := os.WriteFile(distFile, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := installBrowserTrust(ca); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ff.etcDir, "policies.json")); err == nil {
		t.Error("created a policies.json in etcDir while a distribution one exists")
	}
	certPath := filepath.Join(filepath.Dir(distFile), trustFileName+".pem")
	got := firefoxInstallList(t, distFile)
	if len(got) != 2 || got[0] != "/admin/root.pem" || got[1] != certPath {
		t.Errorf("Install = %v, want the admin's entry then ours", got)
	}
	if !bytes.Contains(readAll(t, distFile), []byte("12345678901234567890")) {
		t.Error("a large number in the admin's policies was changed")
	}

	if err := removeBrowserTrust(); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Policies map[string]json.RawMessage `json:"policies"`
	}
	if err := json.Unmarshal(readAll(t, distFile), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Policies["DisableTelemetry"]; !ok {
		t.Error("removal dropped the admin's other policies")
	}
	if got := firefoxInstallList(t, distFile); len(got) != 1 || got[0] != "/admin/root.pem" {
		t.Errorf("Install = %v after removal, want only the admin's entry", got)
	}
	if _, err := os.Stat(certPath); err == nil {
		t.Error("certificate file left behind after removal")
	}
}

func TestBrowserTrustLeavesInvalidFirefoxPolicy(t *testing.T) {
	_, _, _, ff := fakeBrowsers(t)
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(ff.etcDir, "policies.json")
	mustMkdir(t, ff.etcDir)
	const broken = `{"policies": {`
	if err := os.WriteFile(policyFile, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installBrowserTrust(ca); err == nil {
		t.Error("expected an error for an unreadable policies.json")
	}
	if got := string(readAll(t, policyFile)); got != broken {
		t.Errorf("policies.json was rewritten to %q", got)
	}
}

func firefoxInstallList(t *testing.T, path string) []string {
	t.Helper()
	var doc struct {
		Policies struct {
			Certificates struct {
				Install []string
			}
		} `json:"policies"`
	}
	if err := json.Unmarshal(readAll(t, path), &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc.Policies.Certificates.Install
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}
