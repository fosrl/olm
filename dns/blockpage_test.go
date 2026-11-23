package dns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/fosrl/olm/blockpage"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestBlockDecisionWithPageList(t *testing.T) {
	proxy := &DNSProxy{recordStore: NewDNSRecordStore()}
	proxy.SetBlocklist(NewBlocklist([]string{"ads.example.com"}))
	proxy.SetPageBlocklist(NewBlocklist([]string{"social.example"}))

	// Until the block page server is up, page domains fail like the rest.
	if got := proxy.blockDecision("www.social.example."); got != blockFail {
		t.Errorf("inactive page: decision = %v, want blockFail", got)
	}
	if proxy.PageBlocked("www.social.example") {
		t.Error("PageBlocked must be false while the block page is inactive")
	}

	proxy.SetBlockPageActive(true)
	if got := proxy.blockDecision("www.social.example."); got != blockWithPage {
		t.Errorf("active page: decision = %v, want blockWithPage", got)
	}
	if !proxy.PageBlocked("www.social.example") {
		t.Error("PageBlocked must be true for a page domain while active")
	}
	if got := proxy.blockDecision("ads.example.com."); got != blockFail {
		t.Errorf("plain blocked domain: decision = %v, want blockFail", got)
	}
	if got := proxy.blockDecision("ok.example."); got != notBlocked {
		t.Errorf("unlisted domain: decision = %v, want notBlocked", got)
	}

	// A Pangolin alias wins over the page list too.
	if err := proxy.recordStore.AddRecord("intranet.social.example", net.ParseIP("10.0.0.1"), 1); err != nil {
		t.Fatal(err)
	}
	if got := proxy.blockDecision("intranet.social.example."); got != notBlocked {
		t.Errorf("aliased domain: decision = %v, want notBlocked", got)
	}
}

func TestBlockPageResponse(t *testing.T) {
	proxy := &DNSProxy{proxyIP: netip.MustParseAddr("100.96.128.1")}

	query := new(dns.Msg)
	query.SetQuestion("social.example.", dns.TypeA)
	resp := proxy.blockPageResponse(query, query.Question[0])
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("A query: rcode %d, %d answers; want NOERROR with one answer", resp.Rcode, len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "100.96.128.1" {
		t.Errorf("A answer = %v, want the proxy address", resp.Answer[0])
	}
	if a.Hdr.Ttl != blockPageTTL {
		t.Errorf("TTL = %d, want %d", a.Hdr.Ttl, blockPageTTL)
	}

	for _, qtype := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeMX} {
		query := new(dns.Msg)
		query.SetQuestion("social.example.", qtype)
		resp := proxy.blockPageResponse(query, query.Question[0])
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
			t.Errorf("%s query: rcode %d, %d answers; want NOERROR with none", dns.TypeToString[qtype], resp.Rcode, len(resp.Answer))
		}
	}
}

// TestBlockPageOverNetstack connects a client netstack to the proxy the way
// the TUN does and fetches a blocked site over HTTP and HTTPS.
func TestBlockPageOverNetstack(t *testing.T) {
	proxy, err := NewDNSProxy(nil, 1280, "100.96.128.0/24", []string{"127.0.0.1:53"}, false, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.Stop)

	client := newClientStack(t, proxy)

	ca, err := blockpage.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proxy.SetPageBlocklist(NewBlocklist([]string{"blocked.example"}))

	httpLn, err := proxy.ListenTCP(80)
	if err != nil {
		t.Fatal(err)
	}
	httpsLn, err := proxy.ListenTCP(443)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proxy.ListenTCP(80); err == nil {
		t.Error("listening twice on a port must fail")
	}

	srv := blockpage.NewServer(ca, proxy.PageBlocked, func() string {
		return "https://pangolin.example.com/blocked/org_1"
	})
	srv.Serve(httpLn, httpsLn)
	proxy.SetBlockPageActive(true)

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	proxyAddr := proxy.GetProxyIP().As4()
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots},
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				_, portStr, _ := net.SplitHostPort(addr)
				port := uint16(80)
				if portStr == "443" {
					port = 443
				}
				return gonet.DialContextTCP(ctx, client, tcpip.FullAddress{
					NIC:  1,
					Addr: tcpip.AddrFrom4(proxyAddr),
					Port: port,
				}, ipv4.ProtocolNumber)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	for _, url := range []string{"http://blocked.example/a/b", "https://www.blocked.example/"} {
		resp, err := httpClient.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("GET %s: status %d, want 302", url, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc == "" {
			t.Errorf("GET %s: no Location", url)
		}
	}

	if _, err := httpClient.Get("https://notblocked.example/"); err == nil {
		t.Error("TLS to a name that is not on the page list must fail")
	}

	// Once the server is gone, connecting is refused right away rather than
	// timing out, and the ports can be listened on again.
	srv.Close()
	start := time.Now()
	if _, err := httpClient.Get("http://blocked.example/"); err == nil {
		t.Error("expected the connection to be refused after the server closed")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("refusing took %v, want a prompt reset", time.Since(start))
	}
	ln, err := proxy.ListenTCP(80)
	if err != nil {
		t.Fatalf("port 80 not released: %v", err)
	}
	ln.Close()
}

// newClientStack returns a netstack that exchanges packets with proxy like
// the host does through the TUN.
func newClientStack(t *testing.T, proxy *DNSProxy) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	ep := channel.New(256, 1280, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{100, 90, 0, 2}).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ep.Close()
		s.Close()
	})

	// client -> proxy, through the same filter the TUN path uses
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			data := flatten(pkt)
			pkt.DecRef()
			if !proxy.handlePacket(data) {
				t.Errorf("proxy did not take a packet addressed to it")
			}
		}
	}()
	// proxy -> client
	go func() {
		for {
			pkt := proxy.ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			data := flatten(pkt)
			pkt.DecRef()
			in := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
			ep.InjectInbound(ipv4.ProtocolNumber, in)
			in.DecRef()
		}
	}()
	return s
}

func flatten(pkt *stack.PacketBuffer) []byte {
	var out []byte
	for _, s := range pkt.AsSlices() {
		out = append(out, s...)
	}
	return out
}
