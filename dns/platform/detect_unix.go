//go:build (linux && !android) || freebsd

package dns

import (
	"bufio"
	"io"
	"os"
	"strings"

	"github.com/fosrl/newt/logger"
)

const defaultResolvConfPath = "/etc/resolv.conf"

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
