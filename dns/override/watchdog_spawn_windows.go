//go:build windows

package olm

import (
	"os/exec"
)

// SpawnWatchdogConfig is provided on Windows for API symmetry but the
// watchdog itself is effectively a no-op there (see watchdog_windows.go).
type SpawnWatchdogConfig struct {
	Executable    string
	Subcommand    []string
	InterfaceName string
	SocketPath    string
	LogFile       string
}

// SpawnWatchdog is a no-op on Windows; DNS overrides are interface-GUID
// scoped and reclaimed when the interface is removed.
func SpawnWatchdog(cfg SpawnWatchdogConfig) (*exec.Cmd, error) {
	_ = cfg
	return nil, nil
}

// StopWatchdog is a no-op on Windows.
func StopWatchdog(cmd *exec.Cmd) {
	_ = cmd
}
