//go:build (linux && !android) || freebsd

package dns

import (
	"bufio"
	"io"
	"os"
	"strings"

	"github.com/fosrl/newt/logger"
)

const (
	defaultResolvConfPath = "/etc/resolv.conf"
	defaultNsswitchPath   = "/etc/nsswitch.conf"
)

// nsswitchPath is the file consulted by nsswitchPrefersResolved. Overridable for tests.
var nsswitchPath = defaultNsswitchPath

// DNSManagerType represents the type of DNS manager detected
type DNSManagerType int

const (
	// UnknownManager indicates we couldn't determine the DNS manager
	UnknownManager DNSManagerType = iota
	// SystemdResolvedManager indicates systemd-resolved is managing DNS
	SystemdResolvedManager
	// NetworkManagerManager indicates NetworkManager is managing DNS
	NetworkManagerManager
	// ResolvconfManager indicates resolvconf is managing DNS
	ResolvconfManager
	// FileManager indicates direct file management (no DNS manager)
	FileManager
)

// DetectDNSManagerFromFile reads /etc/resolv.conf to determine which DNS manager is in use
// This provides a hint based on comments in the file, similar to Netbird's approach
func DetectDNSManagerFromFile() DNSManagerType {
	file, err := os.Open(defaultResolvConfPath)
	if err != nil {
		return UnknownManager
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) == 0 {
			continue
		}

		// If we hit a non-comment line, default to file-based
		if text[0] != '#' {
			return FileManager
		}

		// Check for DNS manager signatures in comments
		if strings.Contains(text, "NetworkManager") {
			return NetworkManagerManager
		}

		if strings.Contains(text, "systemd-resolved") {
			return SystemdResolvedManager
		}

		if strings.Contains(text, "resolvconf") {
			return ResolvconfManager
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return UnknownManager
	}

	// No indicators found, assume file-based management
	return FileManager
}

// String returns a human-readable name for the DNS manager type
func (d DNSManagerType) String() string {
	switch d {
	case SystemdResolvedManager:
		return "systemd-resolved"
	case NetworkManagerManager:
		return "NetworkManager"
	case ResolvconfManager:
		return "resolvconf"
	case FileManager:
		return "file"
	default:
		return "unknown"
	}
}

// nsswitchPrefersResolved reports whether /etc/nsswitch.conf routes hostname
// lookups through systemd-resolved's NSS module (libnss_resolve) ahead of, or
// to the exclusion of, the classic "dns" service that consults /etc/resolv.conf.
//
// This matters because on distributions whose default hosts line is
//
//	hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns
//
// (common on Arch Linux and other systemd-forward distros), writing nameservers
// to /etc/resolv.conf has no effect on resolution: NSS consults resolved first,
// resolved returns NOTFOUND for an interface it knows nothing about, and the
// [!UNAVAIL=return] action halts fallthrough to the dns service. In that case
// we must register the DNS server with systemd-resolved via D-Bus for the
// tunnel interface instead.
func nsswitchPrefersResolved() bool {
	data, err := os.ReadFile(nsswitchPath)
	if err != nil {
		return false
	}

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "hosts:") {
			continue
		}

		fields := strings.Fields(strings.TrimPrefix(trimmed, "hosts:"))

		resolveIdx, dnsIdx := -1, -1
		for i, f := range fields {
			// Ignore action clauses like [!UNAVAIL=return] when locating services.
			if strings.HasPrefix(f, "[") {
				continue
			}
			switch f {
			case "resolve":
				if resolveIdx == -1 {
					resolveIdx = i
				}
			case "dns":
				if dnsIdx == -1 {
					dnsIdx = i
				}
			}
		}

		if resolveIdx == -1 {
			return false
		}
		// resolve is the sole DNS-facing service: it dominates.
		if dnsIdx == -1 {
			return true
		}
		// resolve consulted before dns: it answers first, and any halting action
		// between them (e.g. [!UNAVAIL=return], [NOTFOUND=return]) prevents
		// fallthrough on failure.
		return resolveIdx < dnsIdx
	}

	return false
}

// DetectDNSManager combines file detection with runtime availability checks
// to determine the best DNS configurator to use
func DetectDNSManager(interfaceName string) DNSManagerType {
	// First check what the file suggests
	fileHint := DetectDNSManagerFromFile()

	// Verify the hint with runtime checks
	switch fileHint {
	case SystemdResolvedManager:
		// Verify systemd-resolved is actually running
		if IsSystemdResolvedAvailable() {
			return SystemdResolvedManager
		}
		logger.Warn("dns platform: Found systemd-resolved but it is not running. Falling back to file...")
		os.Exit(0)
		return FileManager

	case NetworkManagerManager:
		// Verify NetworkManager is actually running
		if IsNetworkManagerAvailable() {
			// If systemd-resolved is running and NSS is wired to consult it first,
			// NetworkManager writing /etc/resolv.conf has no effect on resolution:
			// NSS asks resolved first, resolved has no DNS configured for the tunnel
			// interface and returns NOTFOUND, and [!UNAVAIL=return]-style actions
			// halt fallthrough to the dns service. Register with resolved via D-Bus.
			if IsSystemdResolvedAvailable() && nsswitchPrefersResolved() {
				logger.Info("NetworkManager is running but NSS routes through systemd-resolved, using systemd-resolved configurator")
				return SystemdResolvedManager
			}
			// Check if NetworkManager is delegating to systemd-resolved
			if !IsNetworkManagerDNSModeSupported() {
				logger.Info("NetworkManager is delegating DNS to systemd-resolved, using systemd-resolved configurator")
				if IsSystemdResolvedAvailable() {
					return SystemdResolvedManager
				}
			}
			return NetworkManagerManager
		}
		logger.Warn("dns platform: Found network manager but it is not running. Falling back to file...")
		return FileManager

	case ResolvconfManager:
		// If NSS routes through systemd-resolved, writing /etc/resolv.conf via
		// resolvconf will not affect hostname resolution — register DNS directly
		// with resolved instead. See nsswitchPrefersResolved for rationale.
		if IsSystemdResolvedAvailable() && nsswitchPrefersResolved() {
			logger.Info("resolvconf is in use but NSS routes through systemd-resolved, using systemd-resolved configurator")
			return SystemdResolvedManager
		}
		// Verify resolvconf is available
		if IsResolvconfAvailable() {
			return ResolvconfManager
		}
		// If resolvconf is mentioned but not available, fall back to file
		return FileManager

	case FileManager:
		// File suggests direct file management
		// But we should still check if a manager is available that wasn't mentioned
		if IsSystemdResolvedAvailable() && interfaceName != "" {
			return SystemdResolvedManager
		}
		if IsNetworkManagerAvailable() && interfaceName != "" {
			return NetworkManagerManager
		}
		if IsResolvconfAvailable() && interfaceName != "" {
			return ResolvconfManager
		}
		return FileManager

	default:
		// Unknown - do runtime detection
		if IsSystemdResolvedAvailable() && interfaceName != "" {
			return SystemdResolvedManager
		}
		if IsNetworkManagerAvailable() && interfaceName != "" {
			return NetworkManagerManager
		}
		if IsResolvconfAvailable() && interfaceName != "" {
			return ResolvconfManager
		}
		return FileManager
	}
}
