//go:build !windows

package olm

import (
	"os"
	"syscall"
)

// pidAlive returns true if the process with the given PID is still alive.
// On Unix-like systems we use signal 0, which performs error checking but
// does not deliver an actual signal.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	return true
}
