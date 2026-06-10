//go:build !windows

package olm

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/fosrl/newt/logger"
)

// SpawnWatchdogConfig captures the inputs needed to launch the external
// watchdog subprocess that monitors the calling olm process and forces a
// DNS reset if the parent dies before restoring DNS.
type SpawnWatchdogConfig struct {
	// Executable is the path to the binary that will host the watchdog
	// (typically os.Executable()). The binary must understand the
	// watchdog subcommand layout described below.
	Executable string

	// Subcommand is the argv prefix the binary uses to enter watchdog
	// mode (e.g., []string{"watchdog"} or []string{"dns", "watchdog"}).
	Subcommand []string

	// InterfaceName is the WireGuard interface whose DNS override should
	// be reset if the parent dies.
	InterfaceName string

	// SocketPath is the parent's olm API socket path (may be empty).
	SocketPath string

	// LogFile, if non-empty, is the path the watchdog writes its stdout
	// and stderr to. If empty, /dev/null is used.
	LogFile string
}

// SpawnWatchdog launches the watchdog subprocess in a detached process group
// so that it survives the death of the parent. The returned *exec.Cmd is the
// handle the parent should call StopWatchdog on during clean shutdown.
//
// The spawned process is invoked as:
//
//	<Executable> <Subcommand...> --parent-pid=<ppid> \
//	    --interface=<InterfaceName> [--socket=<SocketPath>]
//
// Both pangolin (cli) and olm should map their watchdog subcommand to
// RunWatchdog.
func SpawnWatchdog(cfg SpawnWatchdogConfig) (*exec.Cmd, error) {
	if cfg.Executable == "" {
		return nil, fmt.Errorf("watchdog: executable is required")
	}
	if len(cfg.Subcommand) == 0 {
		return nil, fmt.Errorf("watchdog: subcommand is required")
	}

	args := append([]string{}, cfg.Subcommand...)
	args = append(args,
		"--parent-pid="+strconv.Itoa(os.Getpid()),
		"--interface="+cfg.InterfaceName,
	)
	if cfg.SocketPath != "" {
		args = append(args, "--socket="+cfg.SocketPath)
	}

	cmd := exec.Command(cfg.Executable, args...)

	// Detach: new session so the watchdog is not killed by a signal
	// delivered to the parent's process group.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	// Direct watchdog output to a log file or /dev/null so it doesn't
	// share file descriptors with the parent's TTY.
	logTarget := cfg.LogFile
	if logTarget == "" {
		logTarget = os.DevNull
	}
	logFile, err := os.OpenFile(logTarget, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("watchdog: open log file: %w", err)
	}
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("watchdog: start: %w", err)
	}

	// We don't need our handle on the log file after the subprocess
	// inherits it.
	_ = logFile.Close()

	logger.Info("DNS watchdog spawned (pid=%d, exe=%s)", cmd.Process.Pid, cfg.Executable)
	return cmd, nil
}

// StopWatchdog asks the watchdog to exit cleanly via SIGTERM and reaps it.
// Safe to call with a nil cmd.
func StopWatchdog(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		logger.Debug("DNS watchdog stop signal failed (pid=%d): %v", pid, err)
	}
	// Reap in the background; we don't want to block shutdown if the
	// watchdog is wedged.
	go func() {
		_ = cmd.Wait()
		logger.Debug("DNS watchdog (pid=%d) reaped", pid)
	}()
}
