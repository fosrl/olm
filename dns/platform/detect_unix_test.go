//go:build (linux && !android) || freebsd

package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNsswitchPrefersResolved(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "arch default with short-circuit",
			content: "hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n",
			want:    true,
		},
		{
			name:    "resolve before dns without action clause",
			content: "hosts: files resolve dns\n",
			want:    true,
		},
		{
			name:    "resolve only, no dns",
			content: "hosts: files resolve\n",
			want:    true,
		},
		{
			name:    "classic debian-style, dns only",
			content: "hosts: files dns\n",
			want:    false,
		},
		{
			name:    "dns before resolve",
			content: "hosts: files dns resolve\n",
			want:    false,
		},
		{
			name:    "neither resolve nor dns",
			content: "hosts: files myhostname\n",
			want:    false,
		},
		{
			name:    "commented hosts line is ignored, real line wins",
			content: "# hosts: files resolve dns\nhosts: files dns\n",
			want:    false,
		},
		{
			name:    "whitespace-indented hosts line",
			content: "   hosts:   mymachines   resolve   [!UNAVAIL=return]   files   dns\n",
			want:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "nsswitch.conf")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("write temp nsswitch: %v", err)
			}

			orig := nsswitchPath
			nsswitchPath = path
			defer func() { nsswitchPath = orig }()

			if got := nsswitchPrefersResolved(); got != tc.want {
				t.Errorf("nsswitchPrefersResolved() = %v, want %v\ncontent:\n%s", got, tc.want, tc.content)
			}
		})
	}
}

func TestNsswitchPrefersResolved_MissingFile(t *testing.T) {
	orig := nsswitchPath
	nsswitchPath = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { nsswitchPath = orig }()

	if got := nsswitchPrefersResolved(); got != false {
		t.Errorf("nsswitchPrefersResolved() on missing file = %v, want false", got)
	}
}
