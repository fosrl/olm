# DNS Platform Module

A standalone Go module for managing system DNS settings across different platforms and DNS management systems.

## Overview

This module provides a unified interface for overriding system DNS servers on:
- **macOS**: Using `scutil`
- **Windows**: Using Windows Registry
- **Linux/FreeBSD**: Supporting multiple backends:
  - systemd-resolved (D-Bus)
  - NetworkManager (D-Bus)
  - resolvconf utility
  - Direct `/etc/resolv.conf` manipulation

## Features

- ✅ Cross-platform DNS override
- ✅ Automatic detection of best DNS management method
- ✅ Backup and restore original DNS settings
- ✅ Platform-specific optimizations
- ✅ No external dependencies for basic functionality

## Architecture

### Interface

All configurators implement the `DNSConfigurator` interface:

```go
type DNSConfigurator interface {
    SetDNS(servers []netip.Addr) ([]netip.Addr, error)
    RestoreDNS() error
    GetCurrentDNS() ([]netip.Addr, error)
    Name() string
}
```

### Platform-Specific Implementations

Each platform has dedicated structs instead of using build tags at the file level:

- `DarwinDNSConfigurator` - macOS using scutil
- `WindowsDNSConfigurator` - Windows using registry
- `FileDNSConfigurator` - Unix using /etc/resolv.conf
- `SystemdResolvedDNSConfigurator` - Linux using systemd-resolved
- `NetworkManagerDNSConfigurator` - Linux using NetworkManager
- `ResolvconfDNSConfigurator` - Linux using resolvconf utility

## Usage

### Automatic Detection

```go
import "github.com/your-org/olm/dns/platform"

// On Linux/Unix - provide interface name for best results
configurator, err := platform.DetectBestConfigurator("eth0")
if err != nil {
    log.Fatal(err)
}

// Set DNS servers
originalServers, err := configurator.SetDNS([]netip.Addr{
    netip.MustParseAddr("8.8.8.8"),
    netip.MustParseAddr("8.8.4.4"),
})
if err != nil {
    log.Fatal(err)
}

// Restore original DNS
defer configurator.RestoreDNS()
```

### Manual Selection

```go
// Linux - Direct file manipulation
configurator, err := platform.NewFileDNSConfigurator()

// Linux - systemd-resolved
configurator, err := platform.NewSystemdResolvedDNSConfigurator("eth0")

// Linux - NetworkManager
configurator, err := platform.NewNetworkManagerDNSConfigurator("eth0")

// Linux - resolvconf
configurator, err := platform.NewResolvconfDNSConfigurator("eth0")

// macOS
configurator, err := platform.NewDarwinDNSConfigurator()

// Windows (requires interface GUID)
configurator, err := platform.NewWindowsDNSConfigurator("{GUID-HERE}")
```

### Platform Detection Utilities

```go
// Check if systemd-resolved is available
if platform.IsSystemdResolvedAvailable() {
    // Use systemd-resolved
}

// Check if NetworkManager is available
if platform.IsNetworkManagerAvailable() {
    // Use NetworkManager
}

// Check if resolvconf is available
if platform.IsResolvconfAvailable() {
    // Use resolvconf
}

// Get system DNS servers
servers, err := platform.GetSystemDNS()
```

## Implementation Details

### macOS (Darwin)

Uses `scutil` to create DNS configuration states in the system configuration database. DNS settings are applied via the Network Service state hierarchy.

**Pros:**
- Native macOS API
- Proper integration with system preferences
- Supports DNS flushing

**Cons:**
- Requires elevated privileges

### Windows

Modifies registry keys under `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`.

**Pros:**
- Direct registry manipulation
- Immediate effect after cache flush

**Cons:**
- Requires interface GUID
- Requires administrator privileges
- May require restart of DNS client service

### Linux: systemd-resolved

Uses D-Bus API to communicate with systemd-resolved service.

**Pros:**
- Modern standard on many distributions
- Proper per-interface configuration
- No file manipulation needed

**Cons:**
- Requires D-Bus access
- Only available on systemd systems
- Interface-specific

### Linux: NetworkManager

Uses D-Bus API to modify NetworkManager connection settings.

**Pros:**
- Common on desktop Linux
- Integrates with NetworkManager GUI
- Per-interface configuration

**Cons:**
- Requires NetworkManager to be running
- D-Bus access required
- Interface-specific

### Linux: resolvconf

Uses the `resolvconf` utility to update DNS configuration.

**Pros:**
- Works on many different systems
- Handles merging of multiple DNS sources
- Supports both openresolv and Debian resolvconf

**Cons:**
- Requires resolvconf to be installed
- Interface-specific

### Linux: Direct File

Directly modifies `/etc/resolv.conf` with backup.

**Pros:**
- Works everywhere
- No dependencies
- Simple and reliable

**Cons:**
- May be overwritten by DHCP or other services
- No per-interface configuration
- Doesn't integrate with system tools

## Build Tags

The module uses build tags to compile platform-specific code:

- `//go:build darwin && !ios` - macOS (non-iOS)
- `//go:build windows` - Windows
- `//go:build (linux && !android) || freebsd` - Linux and FreeBSD
- `//go:build linux && !android` - Linux only (for systemd)

## Dependencies

- `github.com/godbus/dbus/v5` - D-Bus communication (Linux only)
- `golang.org/x/sys` - System calls and registry access
- Standard library

## Security Considerations

- **Elevated Privileges**: Most DNS modification operations require root/administrator privileges
- **Backup Files**: Backup files contain original DNS configuration and should be protected
- **State Persistence**: DNS state is stored in memory; unexpected termination may require manual cleanup

## Cleanup

The module properly cleans up after itself:

1. Backup files are created before modification
2. Original DNS servers are stored in memory
3. `RestoreDNS()` should be called to restore original settings
4. On Linux file-based systems, backup files are removed after restoration

## Testing

Each configurator can be tested independently:

```go
func TestDNSOverride(t *testing.T) {
    configurator, err := platform.NewFileDNSConfigurator()
    require.NoError(t, err)
    
    servers := []netip.Addr{
        netip.MustParseAddr("1.1.1.1"),
    }
    
    original, err := configurator.SetDNS(servers)
    require.NoError(t, err)
    
    defer configurator.RestoreDNS()
    
    current, err := configurator.GetCurrentDNS()
    require.NoError(t, err)
    require.Equal(t, servers, current)
}
```

## Future Enhancements

- [ ] Support for search domains configuration
- [ ] Support for DNS options (timeout, attempts, etc.)
- [ ] Monitoring for external DNS changes
- [ ] Automatic restoration on process exit
- [ ] Windows NRPT (Name Resolution Policy Table) support
- [ ] IPv6 DNS server support on all platforms
