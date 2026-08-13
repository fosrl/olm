package device

import "encoding/binary"

// FixIPv4Source rewrites an IPv4 packet's source address to correctSrc if it
// doesn't already match, incrementally fixing up the IPv4 header checksum
// and (for TCP/UDP) the transport checksum so the packet stays valid.
//
// The common case - source already correct - is a single 4-byte comparison
// and nothing else, so this is safe to call unconditionally on every packet
// matched by a MiddleDevice rule. When a rewrite is needed, checksums are
// updated via the RFC 1624 incremental method (add the delta of the changed
// 16-bit words) rather than a full recompute over the packet, since only the
// address field changed. ICMP has no pseudo-header dependency on the IP
// addresses, so its checksum is left untouched. Non-IPv4 or malformed
// packets are left untouched.
func FixIPv4Source(packet []byte, correctSrc [4]byte) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return
	}

	if packet[12] == correctSrc[0] && packet[13] == correctSrc[1] &&
		packet[14] == correctSrc[2] && packet[15] == correctSrc[3] {
		return
	}

	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return
	}

	oldSrc := [4]byte{packet[12], packet[13], packet[14], packet[15]}

	ipChecksum := binary.BigEndian.Uint16(packet[10:12])
	binary.BigEndian.PutUint16(packet[10:12], checksumAdjust(ipChecksum, oldSrc[:], correctSrc[:]))

	switch packet[9] {
	case 6: // TCP
		if len(packet) >= ihl+20 {
			off := ihl + 16
			old := binary.BigEndian.Uint16(packet[off : off+2])
			binary.BigEndian.PutUint16(packet[off:off+2], checksumAdjust(old, oldSrc[:], correctSrc[:]))
		}
	case 17: // UDP
		if len(packet) >= ihl+8 {
			off := ihl + 6
			old := binary.BigEndian.Uint16(packet[off : off+2])
			if old != 0 { // zero means checksum not used - must stay zero
				binary.BigEndian.PutUint16(packet[off:off+2], checksumAdjust(old, oldSrc[:], correctSrc[:]))
			}
		}
	}

	copy(packet[12:16], correctSrc[:])
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
