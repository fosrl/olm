package device

import (
	"net/netip"
	"testing"

	"github.com/fosrl/newt/bind"
	"github.com/fosrl/newt/util"
)

// buildIPv4UDPPacket builds a minimal IPv4/UDP packet (no options) carrying payload.
func buildIPv4UDPPacket(payload []byte) []byte {
	const ipHeaderLen = 20
	const udpHeaderLen = 8

	packet := make([]byte, ipHeaderLen+udpHeaderLen+len(payload))
	packet[0] = 0x45 // version 4, IHL 5
	packet[9] = 17    // protocol: UDP
	copy(packet[ipHeaderLen+udpHeaderLen:], payload)
	return packet
}

func TestExtractDestIP(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		wantIP string
		wantOk bool
	}{
		{
			name: "IPv4 packet",
			packet: []byte{
				0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
				0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
				0x0a, 0x1e, 0x1e, 0x1e, // Dest IP: 10.30.30.30
			},
			wantIP: "10.30.30.30",
			wantOk: true,
		},
		{
			name:   "Too short packet",
			packet: []byte{0x45, 0x00},
			wantIP: "",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, gotOk := extractDestIP(tt.packet)
			if gotOk != tt.wantOk {
				t.Errorf("extractDestIP() ok = %v, want %v", gotOk, tt.wantOk)
				return
			}
			if tt.wantOk {
				wantAddr := netip.MustParseAddr(tt.wantIP)
				if gotIP != wantAddr {
					t.Errorf("extractDestIP() ip = %v, want %v", gotIP, wantAddr)
				}
			}
		})
	}
}

func TestGetProtocol(t *testing.T) {
	tests := []struct {
		name      string
		packet    []byte
		wantProto uint8
		wantOk    bool
	}{
		{
			name: "UDP packet",
			packet: []byte{
				0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
				0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, // Protocol: UDP (17) at byte 9
				0x0a, 0x1e, 0x1e, 0x1e,
			},
			wantProto: 17,
			wantOk:    true,
		},
		{
			name:      "Too short",
			packet:    []byte{0x45, 0x00},
			wantProto: 0,
			wantOk:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProto, gotOk := util.GetProtocol(tt.packet)
			if gotOk != tt.wantOk {
				t.Errorf("GetProtocol() ok = %v, want %v", gotOk, tt.wantOk)
				return
			}
			if gotProto != tt.wantProto {
				t.Errorf("GetProtocol() proto = %v, want %v", gotProto, tt.wantProto)
			}
		})
	}
}

func TestIsLeakedMagicPacket(t *testing.T) {
	request := make([]byte, bind.MagicTestRequestLen)
	copy(request, bind.MagicTestRequest)

	response := make([]byte, bind.MagicTestResponseLen)
	copy(response, bind.MagicTestResponse)

	tests := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{
			name:   "magic test request leaked into tunnel",
			packet: buildIPv4UDPPacket(request),
			want:   true,
		},
		{
			name:   "magic test response leaked into tunnel",
			packet: buildIPv4UDPPacket(response),
			want:   true,
		},
		{
			name:   "ordinary UDP payload",
			packet: buildIPv4UDPPacket([]byte("just some ordinary application data")),
			want:   false,
		},
		{
			name:   "too short to be a packet",
			packet: []byte{0x45, 0x00},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLeakedMagicPacket(tt.packet); got != tt.want {
				t.Errorf("isLeakedMagicPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkExtractDestIP(b *testing.B) {
	packet := []byte{
		0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
		0x0a, 0x1e, 0x1e, 0x1e,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractDestIP(packet)
	}
}

func TestFilterDownstreamBufsNoDropIsAllocFree(t *testing.T) {
	bufs := make([][]byte, 128)
	for i := range bufs {
		bufs[i] = buildIPv4UDPPacket(make([]byte, 1372))
	}

	allocs := testing.AllocsPerRun(1000, func() {
		out := filterDownstreamBufs(bufs, nil, 0)
		if len(out) != len(bufs) {
			t.Fatalf("expected no packets dropped, got %d/%d", len(out), len(bufs))
		}
	})

	if allocs != 0 {
		t.Errorf("filterDownstreamBufs() with nothing to drop allocated %v times per call, want 0", allocs)
	}
}

func TestFilterDownstreamBufsDropsMagicPacket(t *testing.T) {
	request := make([]byte, bind.MagicTestRequestLen)
	copy(request, bind.MagicTestRequest)

	bufs := [][]byte{
		buildIPv4UDPPacket([]byte("ordinary payload one")),
		buildIPv4UDPPacket(request),
		buildIPv4UDPPacket([]byte("ordinary payload two")),
	}

	out := filterDownstreamBufs(bufs, nil, 0)
	if len(out) != 2 {
		t.Fatalf("expected 1 packet dropped, got %d remaining", len(out))
	}
}

func BenchmarkFilterDownstreamBufsNoDrop(b *testing.B) {
	bufs := make([][]byte, 128)
	for i := range bufs {
		bufs[i] = buildIPv4UDPPacket(make([]byte, 1372))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		filterDownstreamBufs(bufs, nil, 0)
	}
}

func BenchmarkIsLeakedMagicPacket(b *testing.B) {
	// A typical ~1400 byte ordinary application payload (the common case on the
	// hot path - almost every real packet should look like this).
	ordinary := buildIPv4UDPPacket(make([]byte, 1372))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isLeakedMagicPacket(ordinary)
	}
}
