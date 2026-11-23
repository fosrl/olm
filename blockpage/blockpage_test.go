package blockpage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCAPersistsAndReloads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "blockpage")

	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !isOurCA(ca.Certificate()) {
		t.Fatal("new CA is not recognized as ours")
	}
	if !ca.Certificate().MaxPathLenZero || ca.Certificate().MaxPathLen != 0 {
		t.Error("CA must not allow intermediates")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, caKeyFile))
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("key file mode = %o, want 600", mode)
		}
		info, err = os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o700 {
			t.Errorf("dir mode = %o, want 700", mode)
		}
	}

	again, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !again.Certificate().Equal(ca.Certificate()) {
		t.Error("reloading created a new CA instead of reusing the saved one")
	}
}

func TestCorruptCAIsReplaced(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, caCertFile), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err != nil {
		t.Fatalf("a corrupt CA should be replaced, got %v", err)
	}
}

func TestLeafVerifiesAgainstCA(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("WWW.Blocked.Example.")
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	_, err = leaf.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "www.blocked.example",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example"}); err == nil {
		t.Error("leaf must not be valid for other names")
	}
	if d := time.Until(leaf.Leaf.NotAfter); d > leafValidity || d < leafValidity-time.Minute {
		t.Errorf("leaf validity = %v, want about %v", d, leafValidity)
	}

	cached, err := ca.Leaf("www.blocked.example")
	if err != nil {
		t.Fatal(err)
	}
	if cached != leaf {
		t.Error("expected the cached leaf for the same normalized name")
	}
}

func testServer(t *testing.T, pageURL string) (*Server, *CA) {
	t.Helper()
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	allow := func(host string) bool {
		return host == "blocked.example" || strings.HasSuffix(host, ".blocked.example")
	}
	return NewServer(ca, allow, func() string { return pageURL }), ca
}

func TestServeHTTPRedirects(t *testing.T) {
	srv, _ := testServer(t, "https://pangolin.example.com/blocked/org_1")

	req := httptest.NewRequest(http.MethodGet, "http://www.blocked.example:80/path?x=1", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	want := "https://pangolin.example.com/blocked/org_1?domain=www.blocked.example"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("redirect must not be cached")
	}
}

func TestServeHTTPUnknownHost(t *testing.T) {
	srv, _ := testServer(t, "https://pangolin.example.com/blocked/org_1")
	req := httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a host that is not blocked", rec.Code)
	}
}

func TestServeHTTPFallbackPage(t *testing.T) {
	for name, pageURL := range map[string]string{
		"no page":      "",
		"page on host": "https://blocked.example/blocked/org_1",
		"not http":     "javascript:alert(1)",
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := testServer(t, pageURL)
			req := httptest.NewRequest(http.MethodGet, "http://blocked.example/", nil)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "<code>blocked.example</code>") {
				t.Errorf("fallback page should name the domain, got %q", rec.Body.String())
			}
		})
	}
}

func TestServeTLS(t *testing.T) {
	srv, ca := testServer(t, "https://pangolin.example.com/blocked/org_1")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Serve(nil, ln)
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	addr := ln.Addr().String()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Get("https://blocked.example/")
	if err != nil {
		t.Fatalf("GET blocked host over TLS: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}

	if _, err := client.Get("https://allowed.example/"); err == nil {
		t.Error("TLS handshake for a host that is not blocked must fail")
	}
}
