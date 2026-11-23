package blockpage

import (
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Server answers browsers that opened a blocked domain. Both the plain HTTP
// and the TLS listener redirect to the block page with the domain in the query
// string. Requests for names that are not blocked get a 404, and TLS
// handshakes for them fail, so the server never vouches for other names.
type Server struct {
	ca      *CA
	allow   func(host string) bool
	pageURL func() string

	mu      sync.Mutex
	servers []*http.Server
}

// NewServer returns a Server that mints certificates with ca. allow reports
// whether a host name gets the block page; pageURL returns the page to
// redirect to, without the domain parameter.
func NewServer(ca *CA, allow func(host string) bool, pageURL func() string) *Server {
	return &Server{ca: ca, allow: allow, pageURL: pageURL}
}

// Serve starts serving plain HTTP on httpLn and HTTPS on httpsLn in the
// background. Either may be nil. Close stops both.
func (s *Server) Serve(httpLn, httpsLn net.Listener) {
	if httpLn != nil {
		s.start(httpLn)
	}
	if httpsLn != nil {
		s.start(tls.NewListener(httpsLn, s.tlsConfig()))
	}
}

func (s *Server) start(ln net.Listener) {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		// Apps that pin certificates fail every handshake; don't log each one.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	s.mu.Lock()
	s.servers = append(s.servers, srv)
	s.mu.Unlock()
	go func() {
		// Serve returns without closing ln when the server was closed before
		// it started, so close it here either way.
		_ = srv.Serve(ln)
		_ = ln.Close()
	}()
}

// Close stops the server and closes its listeners.
func (s *Server) Close() {
	s.mu.Lock()
	servers := s.servers
	s.servers = nil
	s.mu.Unlock()
	for _, srv := range servers {
		_ = srv.Close()
	}
}

func (s *Server) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := normalizeHost(hello.ServerName)
			if host == "" || !s.allow(host) {
				return nil, fmt.Errorf("no certificate for %q", hello.ServerName)
			}
			return s.ca.Leaf(host)
		},
	}
}

// ServeHTTP redirects a request for a blocked host to the block page.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.Host)
	if host == "" || !s.allow(host) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	if target := s.redirectURL(host); target != "" {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	// No page to send the browser to: say so here instead.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprintf(w, fallbackPage, html.EscapeString(host))
}

// redirectURL is the block page for host, or "" when there is none or it is
// on host itself, which would loop.
func (s *Server) redirectURL(host string) string {
	page := s.pageURL()
	if page == "" {
		return ""
	}
	u, err := url.Parse(page)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	if normalizeHost(u.Host) == host {
		return ""
	}
	q := u.Query()
	q.Set("domain", host)
	u.RawQuery = q.Encode()
	return u.String()
}

const fallbackPage = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blocked</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 15vh auto; padding: 0 1rem">
<h1 style="font-size: 1.4rem">This site is blocked</h1>
<p><code>%s</code> is blocked by your organization. Contact your administrator if you need access.</p>
</body></html>
`
