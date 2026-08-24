package peers

import "testing"

func TestNormalizeServerRouteDestination(t *testing.T) {
	tests := []struct {
		name     string
		serverIP string
		want     string
	}{
		{
			name:     "bare IPv4 address",
			serverIP: "100.90.128.4",
			want:     "100.90.128.4/32",
		},
		{
			name:     "IPv4 host CIDR",
			serverIP: "100.90.128.4/32",
			want:     "100.90.128.4/32",
		},
		{
			name:     "other IPv4 CIDR",
			serverIP: "192.0.2.1/24",
			want:     "192.0.2.1/24",
		},
		{
			name:     "IPv6 address is preserved",
			serverIP: "2001:db8::4",
			want:     "2001:db8::4",
		},
		{
			name:     "invalid address is preserved",
			serverIP: "not-an-ip",
			want:     "not-an-ip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeServerRouteDestination(tt.serverIP); got != tt.want {
				t.Fatalf("normalizeServerRouteDestination(%q) = %q, want %q", tt.serverIP, got, tt.want)
			}
		})
	}
}
