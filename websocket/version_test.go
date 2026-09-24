package websocket

import "testing"

func TestSupportsBatchedSiteMessages(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"", false},
		{"1.23.0", false},
		{"1.23.9", false},
		{"1.24.0", true},
		{"1.24.1", true},
		{"1.25.0", true},
		{"2.0.0", true},
		{"1.24.0-s.5", true},   // cloud build of a supported base version
		{"1.23.0-s.99", false}, // cloud build of an unsupported base version
		{"not-a-version", false},
	}

	for _, c := range cases {
		if got := supportsBatchedSiteMessages(c.version); got != c.want {
			t.Errorf("supportsBatchedSiteMessages(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.24.0", "1.24.0", 0},
		{"1.23.0", "1.24.0", -1},
		{"1.24.0", "1.23.0", 1},
		{"1.24", "1.24.0", 0},
		{"1.24.1", "1.24", 1},
		{"2.0.0", "1.99.99", 1},
	}

	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
