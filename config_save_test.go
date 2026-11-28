package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestSaveConfigCreatesOwnerOnlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes do not apply on Windows")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("CONFIG_FILE", path)

	if err := SaveConfig(&OlmConfig{ID: "id", Secret: "secret"}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("config file mode = %o, want 600", got)
	}
}

func TestSaveConfigRestrictsExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes do not apply on Windows")
	}
	for _, mode := range []os.FileMode{0644, 0660} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(strings.Repeat("x", 10000)), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CONFIG_FILE", path)
			if err := SaveConfig(&OlmConfig{ID: "id", Secret: "secret"}); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0600 {
				t.Fatalf("existing config file mode = %o, want 600", got)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var saved OlmConfig
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatalf("saved config has invalid JSON or stale trailing bytes: %v", err)
			}
			if saved.ID != "id" || saved.Secret != "secret" {
				t.Fatal("saved config does not contain the requested values")
			}
		})
	}
}

func TestSaveConfigReadOnlyFileIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_FILE", path)

	err := SaveConfig(&OlmConfig{ID: "id"})
	if err == nil {
		t.Fatal("SaveConfig on a read-only file succeeded, want an error")
	}
	if !isReadOnlyConfigError(err) {
		t.Fatalf("isReadOnlyConfigError(%v) = false, want true", err)
	}
}

func TestIsReadOnlyConfigError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"read-only file system", &fs.PathError{Op: "open", Path: "/run/credentials/olm.json", Err: syscall.EROFS}, true},
		{"permission denied", &fs.PathError{Op: "open", Path: "/etc/olm.json", Err: fs.ErrPermission}, true},
		{"missing directory", &fs.PathError{Op: "open", Path: "/nope/olm.json", Err: fs.ErrNotExist}, false},
		{"other error", errors.New("disk full"), false},
	}
	for _, tc := range cases {
		if got := isReadOnlyConfigError(tc.err); got != tc.want {
			t.Errorf("%s: isReadOnlyConfigError = %v, want %v", tc.name, got, tc.want)
		}
	}
}
