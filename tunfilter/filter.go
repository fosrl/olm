package tunfilter

// FilterAction defines what to do with a packet
type FilterAction int

const (
	// FilterActionPass allows the packet to continue normally
	FilterActionPass FilterAction = iota
	// FilterActionDrop silently drops the packet
	FilterActionDrop
	// FilterActionIntercept captures the packet for custom handling
	FilterActionIntercept
)

// PacketFilter interface for filtering and intercepting packets
type PacketFilter interface {
	// FilterOutbound filters packets going FROM host TO tunnel (before encryption)
	// Return FilterActionPass to allow, FilterActionDrop to drop, FilterActionIntercept to handle
	FilterOutbound(packet []byte, size int) FilterAction

	// FilterInbound filters packets coming FROM tunnel TO host (after decryption)
	// Return FilterActionPass to allow, FilterActionDrop to drop, FilterActionIntercept to handle
	FilterInbound(packet []byte, size int) FilterAction
}

// HandlerFunc is called when a packet is intercepted
type HandlerFunc func(packet []byte, direction Direction) error

// Direction indicates packet flow direction
type Direction int

const (
	DirectionOutbound Direction = iota // Host -> Tunnel
	DirectionInbound                   // Tunnel -> Host
)
