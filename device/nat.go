package device

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

const (
	ipv4SrcOffset = 12
	ipv4DstOffset = 16
)

// FixIPv4Source rewrites an IPv4 packet's source address to correctSrc if it
// doesn't already match. It returns whether a rewrite happened.
func FixIPv4Source(packet []byte, correctSrc [4]byte) bool {
	return fixIPv4Address(packet, ipv4SrcOffset, correctSrc)
}

// FixIPv4Dest rewrites an IPv4 packet's destination address to correctDst if
// it doesn't already match. It returns whether a rewrite happened.
func FixIPv4Dest(packet []byte, correctDst [4]byte) bool {
	return fixIPv4Address(packet, ipv4DstOffset, correctDst)
}

// fixIPv4Address rewrites the IPv4 address at the given header offset (source
// or destination) to newAddr if it doesn't already match, incrementally
// fixing up the IPv4 header checksum and (for TCP/UDP) the transport
// checksum so the packet stays valid.
//
// The common case - address already correct - is a single 4-byte comparison
// and nothing else, so this is safe to call unconditionally on every packet
// matched by a MiddleDevice rule. When a rewrite is needed, checksums are
// updated via the RFC 1624 incremental method (add the delta of the changed
// 16-bit words) rather than a full recompute over the packet, since only the
// address field changed. The formula is agnostic to which field (source or
// destination) changed - both are covered by the IPv4 header checksum and
// the TCP/UDP pseudo-header checksum identically. ICMP has no pseudo-header
// dependency on the IP addresses, so its checksum is left untouched.
// Non-IPv4 or malformed packets are left untouched.
func fixIPv4Address(packet []byte, offset int, newAddr [4]byte) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}

	if packet[offset] == newAddr[0] && packet[offset+1] == newAddr[1] &&
		packet[offset+2] == newAddr[2] && packet[offset+3] == newAddr[3] {
		return false
	}

	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return false
	}

	old := [4]byte{packet[offset], packet[offset+1], packet[offset+2], packet[offset+3]}

	ipChecksum := binary.BigEndian.Uint16(packet[10:12])
	binary.BigEndian.PutUint16(packet[10:12], checksumAdjust(ipChecksum, old[:], newAddr[:]))

	switch packet[9] {
	case 6: // TCP
		if len(packet) >= ihl+20 {
			off := ihl + 16
			c := binary.BigEndian.Uint16(packet[off : off+2])
			binary.BigEndian.PutUint16(packet[off:off+2], checksumAdjust(c, old[:], newAddr[:]))
		}
	case 17: // UDP
		if len(packet) >= ihl+8 {
			off := ihl + 6
			c := binary.BigEndian.Uint16(packet[off : off+2])
			if c != 0 { // zero means checksum not used - must stay zero
				binary.BigEndian.PutUint16(packet[off:off+2], checksumAdjust(c, old[:], newAddr[:]))
			}
		}
	}

	copy(packet[offset:offset+4], newAddr[:])
	return true
}

// checksumAdjust incrementally updates a ones-complement checksum after some
// of the bytes it covers changed from old to new (RFC 1624), avoiding a full
// recompute over the packet. old and new must be the same (even) length.
func checksumAdjust(checksum uint16, old, new []byte) uint16 {
	sum := uint32(^checksum)

	for i := 0; i+1 < len(old); i += 2 {
		sum += uint32(^binary.BigEndian.Uint16(old[i:i+2])) & 0xffff
	}
	for i := 0; i+1 < len(new); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(new[i : i+2]))
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// ipv4L4Ports extracts the TCP/UDP source and destination ports from an IPv4
// packet. ok is false for anything else (non-IPv4, non-TCP/UDP, malformed).
func ipv4L4Ports(packet []byte) (proto uint8, srcPort, dstPort uint16, ok bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, 0, 0, false
	}
	proto = packet[9]
	if proto != 6 && proto != 17 {
		return 0, 0, 0, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+4 {
		return 0, 0, 0, false
	}
	srcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
	dstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	return proto, srcPort, dstPort, true
}

// IPv4SourceEquals reports whether packet's IPv4 source address equals addr.
func IPv4SourceEquals(packet []byte, addr [4]byte) bool {
	return len(packet) >= 16 && packet[0]>>4 == 4 &&
		packet[12] == addr[0] && packet[13] == addr[1] && packet[14] == addr[2] && packet[15] == addr[3]
}

// natEntryTTL bounds how long an ExitNodeNAT entry is honored without being
// refreshed by further traffic on the same port. It's a var rather than a
// const so tests can shrink it. Chosen generously relative to typical
// request/response traffic - the only cost of expiring too early is the
// original bug reappearing for that one flow, not corruption of anything
// else, so this errs on the long side.
var natEntryTTL = 5 * time.Minute

// natRefreshInterval bounds how often a busy flow's entry timestamp actually
// gets rewritten. A saturating connection (e.g. iperf) calls FixOutboundSource
// or FixInboundDest on every single packet - refreshing on every one of them
// would mean a map write (and, for new entries, a full-table prune) at line
// rate instead of at most once per interval. natEntryTTL is minutes, so
// resolution at this granularity costs nothing.
const natRefreshInterval = time.Second

type natKey struct {
	proto uint8
	port  uint16
}

// ExitNodeNAT tracks which local (protocol, port) pairs had their outbound
// source address corrected by FixOutboundSource, so FixInboundDest can
// translate the destination of the matching inbound reply back to the
// address the local OS socket actually expects.
//
// This statefulness exists because rewriting the outbound packet's source
// only changes what goes out on the wire - it does not change the local
// kernel's own record of the connection's local address, which was already
// selected and cached (in the socket's own connection state) at connect()/
// send() time, before this packet ever reached this interception point.
// Without also translating the reply's destination back, the OS can't match
// the exit node's response to the socket waiting for it, and the request
// hangs even though the corrected outbound packet reached the server fine.
//
// Entries are keyed by local port only (not the full flow), refreshed on
// every match, and expire after natEntryTTL of inactivity - both so a later,
// unrelated connection that happens to reuse the same ephemeral port isn't
// wrongly treated as needing translation (e.g. one that was never affected
// because it bound explicitly to the correct address), and so the table
// doesn't grow unbounded over a long-lived tunnel.
type ExitNodeNAT struct {
	mu   sync.Mutex
	seen map[natKey]time.Time
}

func NewExitNodeNAT() *ExitNodeNAT {
	return &ExitNodeNAT{seen: make(map[natKey]time.Time)}
}

// FixOutboundSource rewrites packet's source to correctSrc (see
// FixIPv4Source) and, if a rewrite was needed, remembers the packet's source
// port so FixInboundDest knows to translate the reply back.
func (n *ExitNodeNAT) FixOutboundSource(packet []byte, correctSrc [4]byte) {
	if !FixIPv4Source(packet, correctSrc) {
		return
	}

	proto, srcPort, _, ok := ipv4L4Ports(packet)
	if !ok {
		return
	}

	key := natKey{proto, srcPort}
	now := time.Now()

	n.mu.Lock()
	t, existed := n.seen[key]
	if existed && now.Sub(t) < natRefreshInterval {
		// Already recorded recently enough - skip the write entirely. This is
		// the common case for a busy flow: every packet gets here, but only
		// one per interval needs to touch the map.
		n.mu.Unlock()
		return
	}
	n.seen[key] = now
	if !existed {
		// Only prune when the table is actually growing (a new connection),
		// not on every packet - this is an O(map size) scan and the map only
		// ever gains entries here.
		n.prune()
	}
	n.mu.Unlock()

	if !existed {
		logger.Debug("ExitNodeNAT: corrected outbound source for proto=%d port=%d", proto, srcPort)
	}
}

// FixInboundDest rewrites packet's destination to wrongDst, but only if its
// destination port matches an outbound flow FixOutboundSource actually
// corrected - otherwise this connection was never affected by the bug (e.g.
// a socket explicitly bound to the correct address already) and must be
// left alone.
func (n *ExitNodeNAT) FixInboundDest(packet []byte, wrongDst [4]byte) {
	proto, _, dstPort, ok := ipv4L4Ports(packet)
	if !ok {
		return
	}

	key := natKey{proto, dstPort}
	now := time.Now()

	n.mu.Lock()
	t, tracked := n.seen[key]
	expired := tracked && now.Sub(t) > natEntryTTL
	if tracked {
		if expired {
			delete(n.seen, key)
			tracked = false
		} else if now.Sub(t) >= natRefreshInterval {
			n.seen[key] = now
		}
	}
	n.mu.Unlock()

	if expired {
		logger.Warn("ExitNodeNAT: entry for proto=%d port=%d expired before a reply arrived on it - that flow's replies will be dropped by the OS from here on", proto, dstPort)
	}

	if !tracked {
		return
	}

	FixIPv4Dest(packet, wrongDst)
}

// prune removes expired entries. Called with n.mu held, only from
// FixOutboundSource so the cost is amortized over new outbound connections
// rather than paid on every packet.
func (n *ExitNodeNAT) prune() {
	now := time.Now()
	for k, t := range n.seen {
		if now.Sub(t) > natEntryTTL {
			delete(n.seen, k)
		}
	}
}
