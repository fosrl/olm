package olm

import (
	"net/netip"
	"testing"
)

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
			gotProto, gotOk := GetProtocol(tt.packet)
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
