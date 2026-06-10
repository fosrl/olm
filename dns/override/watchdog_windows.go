//go:build windows

package olm

// pidAlive on Windows. Reliable PID probing on Windows requires syscall
// OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION followed by
// GetExitCodeProcess, which is non-trivial. Since DNS override on Windows
// is interface-GUID-scoped and is naturally cleaned up when the WireGuard
// interface goes away, the watchdog is effectively a no-op on Windows.
// We always report the parent as alive so the watchdog never tears down
// DNS based on PID checks.
func pidAlive(pid int) bool {
	_ = pid
	return true
}
