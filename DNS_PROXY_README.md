# Virtual DNS Proxy Implementation

## Overview

This implementation adds a high-performance virtual DNS proxy that intercepts DNS queries destined for `10.30.30.30:53` before they reach the WireGuard tunnel. The proxy processes DNS queries using a gvisor netstack and forwards them to upstream DNS servers, bypassing the VPN tunnel entirely.

## Architecture

### Components

1. **FilteredDevice** (`olm/device_filter.go`)
   - Wraps the TUN device with packet filtering capabilities
   - Provides fast packet inspection without deep packet processing
   - Supports multiple filtering rules that can be added/removed dynamically
   - Optimized for performance - only extracts destination IP on fast path

2. **DNSProxy** (`olm/dns_proxy.go`)
   - Uses gvisor netstack to handle DNS protocol processing
   - Listens on `10.30.30.30:53` within its own network stack
   - Forwards queries to Google DNS (8.8.8.8, 8.8.4.4)
   - Writes responses directly back to the TUN device, bypassing WireGuard

### Packet Flow

```
┌─────────────────────────────────────────────────────────────┐
│                        Application                          │
└──────────────────────┬──────────────────────────────────────┘
                       │ DNS Query to 10.30.30.30:53
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                      TUN Interface                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   FilteredDevice (Read)                     │
│  - Fast IP extraction                                       │
│  - Rule matching (10.30.30.30)                              │
└──────────────┬──────────────────────────────────────────────┘
               │                                   
    ┌──────────┴──────────┐
    │                     │
    ▼                     ▼
┌─────────┐         ┌─────────────────────────┐
│DNS Proxy│         │   WireGuard Device      │
│Netstack │         │   (other traffic)       │
└────┬────┘         └─────────────────────────┘
     │
     │ Forward to 8.8.8.8
     ▼
┌─────────────┐
│   Internet  │
│ (Direct)    │
└──────┬──────┘
       │ DNS Response
       ▼
┌─────────────────────────────────────────────────────────────┐
│            DNSProxy writes directly to TUN                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                      Application                            │
└─────────────────────────────────────────────────────────────┘
```

## Performance Considerations

### Fast Path Optimization

1. **Minimal Packet Inspection**
   - Only extracts destination IP (bytes 16-19 for IPv4, 24-39 for IPv6)
   - No deep packet inspection unless packet matches a rule
   - Zero-copy operations where possible

2. **Rule Matching**
   - Simple IP comparison (not prefix matching for rules)
   - Linear scan of rules (fast for small number of rules)
   - Read-lock only for rule access

3. **Packet Processing**
   - Filtered packets are removed from the slice in-place
   - Non-matching packets passed through with minimal overhead
   - No memory allocation for packets that don't match rules

### Memory Efficiency

- Packet copies are only made when absolutely necessary
- gvisor netstack uses buffer pooling internally
- DNS proxy uses a separate goroutine for response handling

## Usage

### Configuration

The DNS proxy is automatically started when the tunnel is created. By default:
- DNS proxy IP: `10.30.30.30`
- DNS port: `53`
- Upstream DNS: `8.8.8.8` (primary), `8.8.4.4` (fallback)

### Testing

To test the DNS proxy, configure your DNS settings to use `10.30.30.30`:

```bash
# Using dig
dig @10.30.30.30 google.com

# Using nslookup
nslookup google.com 10.30.30.30
```

## Extensibility

The `FilteredDevice` architecture is designed to be extensible:

### Adding New Services

To add a new service (e.g., HTTP proxy on 10.30.30.31):

1. Create a new service similar to `DNSProxy`
2. Register a filter rule with `filteredDev.AddRule()`
3. Process packets in your handler
4. Write responses back to the TUN device

Example:

```go
// In your service
func (s *MyService) handlePacket(packet []byte) bool {
    // Parse packet
    // Process request
    // Write response to TUN device
    s.tunDevice.Write([][]byte{response}, 0)
    return true // Drop from normal path
}

// During initialization
filteredDev.AddRule(myServiceIP, myService.handlePacket)
```

### Adding Filtering Rules

Rules can be added/removed dynamically:

```go
// Add a rule
filteredDev.AddRule(netip.MustParseAddr("10.30.30.40"), handleSpecialIP)

// Remove a rule
filteredDev.RemoveRule(netip.MustParseAddr("10.30.30.40"))
```

## Implementation Details

### Why Direct TUN Write?

The DNS proxy writes responses directly back to the TUN device instead of going through the filter because:
1. Responses should go to the host, not through WireGuard
2. Avoids infinite loops (response → filter → DNS proxy → ...)
3. Better performance (one less layer)

### Thread Safety

- `FilteredDevice` uses RWMutex for rule access (read-heavy workload)
- `DNSProxy` goroutines are properly synchronized
- TUN device write operations are thread-safe

### Error Handling

- Failed DNS queries fall back to secondary DNS server
- Malformed packets are logged but don't crash the proxy
- Context cancellation ensures clean shutdown

## Future Enhancements

Potential improvements:
1. DNS caching to reduce upstream queries
2. DNS-over-HTTPS (DoH) support
3. Custom DNS filtering/blocking
4. Metrics and monitoring
5. IPv6 support for DNS proxy
6. Multiple upstream DNS servers with health checking
7. HTTP/HTTPS proxy on different IPs
8. SOCKS5 proxy support
