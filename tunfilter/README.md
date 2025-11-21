# TUN Filter Interceptor System

An extensible packet filtering and interception framework for the olm TUN device.

## Architecture

The system consists of several components that work together:

```
┌─────────────────┐
│   WireGuard     │
└────────┬────────┘
         │
┌────────▼────────┐
│ FilteredDevice  │  (Wraps TUN device)
└────────┬────────┘
         │
┌────────▼──────────────┐
│ InterceptorFilter     │
└────────┬──────────────┘
         │
┌────────▼──────────────┐
│ InterceptorManager    │
│  ┌─────────────────┐  │
│  │ DNS Proxy       │  │
│  ├─────────────────┤  │
│  │ Future...       │  │
│  └─────────────────┘  │
└────────┬──────────────┘
         │
┌────────▼────────┐
│  TUN Device     │
└─────────────────┘
```

## Components

### FilteredDevice
- Wraps the TUN device
- Calls packet filters for every packet in both directions
- Located between WireGuard and the TUN device

### PacketInterceptor Interface
Extensible interface for creating custom packet interceptors:
```go
type PacketInterceptor interface {
    Name() string
    ShouldIntercept(packet []byte, direction Direction) bool
    HandlePacket(ctx context.Context, packet []byte, direction Direction) error
    Start(ctx context.Context) error
    Stop() error
}
```

### InterceptorManager
- Manages multiple interceptors
- Routes packets to the first matching interceptor
- Handles lifecycle (start/stop) for all interceptors

### PacketInjector
- Allows interceptors to inject response packets
- Writes packets back into the TUN device as if they came from the tunnel

### DNS Proxy Interceptor
Example implementation that:
- Intercepts DNS queries to `10.30.30.30`
- Forwards them to `8.8.8.8`
- Injects responses back as if they came from `10.30.30.30`

## Usage

The system is automatically initialized in `olm.go` when a tunnel is created:

```go
// Create packet injector for the TUN device
packetInjector = tunfilter.NewPacketInjector(tdev)

// Create interceptor manager
interceptorManager = tunfilter.NewInterceptorManager(packetInjector)

// Add DNS proxy interceptor for 10.30.30.30
dnsProxy := tunfilter.NewDNSProxyInterceptor(
    tunfilter.DNSProxyConfig{
        Name:        "dns-proxy",
        InterceptIP: netip.MustParseAddr("10.30.30.30"),
        UpstreamDNS: "8.8.8.8:53",
        LocalIP:     tunnelIP,
    },
    packetInjector,
)

interceptorManager.AddInterceptor(dnsProxy)

// Create filter and wrap TUN device
interceptorFilter := tunfilter.NewInterceptorFilter(interceptorManager)
filteredDev = tunfilter.NewFilteredDevice(tdev, interceptorFilter)
```

## Adding New Interceptors

To create a new interceptor:

1. **Implement the PacketInterceptor interface:**

```go
type MyInterceptor struct {
    name     string
    injector *tunfilter.PacketInjector
    // your fields...
}

func (i *MyInterceptor) Name() string {
    return i.name
}

func (i *MyInterceptor) ShouldIntercept(packet []byte, direction tunfilter.Direction) bool {
    // Quick check: parse packet and decide if you want to handle it
    // This is called for EVERY packet, so make it fast!
    info, ok := tunfilter.ParsePacket(packet)
    if !ok {
        return false
    }
    
    // Example: intercept UDP packets to a specific IP and port
    return info.IsUDP && info.DstIP == myTargetIP && info.DstPort == myPort
}

func (i *MyInterceptor) HandlePacket(ctx context.Context, packet []byte, direction tunfilter.Direction) error {
    // Process the packet
    // You can:
    // 1. Extract data from it
    // 2. Make external requests
    // 3. Inject response packets using i.injector.InjectInbound(responsePacket)
    
    return nil
}

func (i *MyInterceptor) Start(ctx context.Context) error {
    // Initialize resources (e.g., start listeners, connect to services)
    return nil
}

func (i *MyInterceptor) Stop() error {
    // Clean up resources
    return nil
}
```

2. **Register it with the manager:**

```go
myInterceptor := NewMyInterceptor(...)
if err := interceptorManager.AddInterceptor(myInterceptor); err != nil {
    logger.Error("Failed to add interceptor: %v", err)
}
```

## Packet Flow

### Outbound (Host → Tunnel)
1. Packet written by application
2. TUN device receives it
3. FilteredDevice.Write intercepts it
4. InterceptorFilter checks all interceptors
5. If intercepted: Handler processes it, returns FilterActionIntercept
6. If passed: Packet continues to WireGuard for encryption

### Inbound (Tunnel → Host)
1. WireGuard decrypts packet
2. FilteredDevice.Read intercepts it
3. InterceptorFilter checks all interceptors
4. If intercepted: Handler processes it, returns FilterActionIntercept
5. If passed: Packet written to TUN device for delivery to host

## Example: DNS Proxy

DNS queries to `10.30.30.30:53` are intercepted:

```
Application → 10.30.30.30:53
           ↓
    DNSProxyInterceptor
           ↓
    Forward to 8.8.8.8:53
           ↓
    Get response
           ↓
    Build response packet (src: 10.30.30.30)
           ↓
    Inject into TUN device
           ↓
    Application receives response
```

All other traffic flows normally through the WireGuard tunnel.

## Future Ideas

The interceptor system can be extended for:

- **HTTP Proxy**: Intercept HTTP traffic and route through a proxy
- **Protocol Translation**: Convert one protocol to another
- **Traffic Shaping**: Add delays, simulate packet loss
- **Logging/Monitoring**: Record specific traffic patterns
- **Custom DNS Rules**: Different upstream servers based on domain
- **Local Service Integration**: Route certain IPs to local services
- **mDNS Support**: Handle multicast DNS queries locally

## Performance Notes

- `ShouldIntercept()` is called for every packet - keep it fast!
- Use simple checks (IP/port comparisons)
- Avoid allocations in the hot path
- Packet handling runs in a goroutine to avoid blocking
- The filtered device uses zero-copy techniques where possible
