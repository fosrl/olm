package olm

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/fosrl/newt/logger"
)

// WatchdogConfig configures the DNS override watchdog. The watchdog runs as
// an external process (spawned via SpawnWatchdog) and monitors a parent olm
// process. When the parent appears to have died without restoring DNS, the
// watchdog forcibly resets the system DNS configuration.
type WatchdogConfig struct {
	// ParentPID is the PID of the olm process that installed the DNS
	// override. The watchdog exits when this PID is no longer alive.
	ParentPID int

	// SocketPath is the path to the olm Unix domain socket (or named pipe
	// on Windows). The watchdog uses it as a secondary liveness signal.
	// May be empty if no socket-based API is enabled.
	SocketPath string

	// InterfaceName is the name of the WireGuard interface whose DNS
	// override should be reset on parent death.
	InterfaceName string

	// CheckInterval is how often to poll the parent's liveness.
	// Defaults to 5 seconds when zero.
	CheckInterval time.Duration

	// FailureThreshold is the number of consecutive failed liveness checks
	// before the watchdog declares the parent dead and resets DNS.
	// Defaults to 3 when zero.
	FailureThreshold int
}

// RunWatchdog runs the watchdog loop in the current process until either
// (a) the parent dies and DNS is reset, or (b) ctx is cancelled.
func RunWatchdog(ctx context.Context, cfg WatchdogConfig) error {
	if cfg.ParentPID <= 0 {
		return fmt.Errorf("watchdog: invalid parent PID %d", cfg.ParentPID)
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 5 * time.Second
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}

	logger.Info("DNS watchdog started: parent=%d interval=%s threshold=%d socket=%q interface=%q",
		cfg.ParentPID, cfg.CheckInterval, cfg.FailureThreshold, cfg.SocketPath, cfg.InterfaceName)

	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()

	consecutiveFailures := 0

	for {
		select {
		case <-ctx.Done():
			logger.Info("DNS watchdog context cancelled, exiting cleanly")
			return ctx.Err()
		case <-ticker.C:
		}

		alive := isParentAlive(cfg.ParentPID, cfg.SocketPath)
		if alive {
			if consecutiveFailures > 0 {
				logger.Debug("DNS watchdog: parent recovered after %d failures", consecutiveFailures)
			}
			consecutiveFailures = 0
			continue
		}

		consecutiveFailures++
		logger.Warn("DNS watchdog: parent liveness check failed (%d/%d)",
			consecutiveFailures, cfg.FailureThreshold)

		if consecutiveFailures >= cfg.FailureThreshold {
			logger.Warn("DNS watchdog: parent declared dead, forcing DNS reset")
			if err := ForceResetDNS(cfg.InterfaceName); err != nil {
				logger.Error("DNS watchdog: ForceResetDNS failed: %v", err)
				return err
			}
			logger.Info("DNS watchdog: DNS reset complete, exiting")
			return nil
		}
	}
}

// isParentAlive returns true if the parent process appears to be alive. It
// considers the parent alive if EITHER the PID is still running OR the
// socket-based health endpoint responds. This dual check avoids false
// positives where one signal is flaky (e.g., socket blocked but process
// still recovering).
func isParentAlive(pid int, socketPath string) bool {
	if pidAlive(pid) {
		return true
	}
	// Process is gone; double-check via socket to avoid races where PID
	// recycling or signal-0 quirks lie to us. Socket should already be
	// gone too.
	if socketPath != "" && socketHealthy(socketPath) {
		return true
	}
	return false
}

// socketHealthy attempts a fast /health request over the unix socket.
func socketHealthy(socketPath string) bool {
	if _, err := os.Stat(socketPath); err != nil {
		return false
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}

	resp, err := client.Get("http://localhost/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
