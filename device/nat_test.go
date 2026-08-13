package device

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// onesComplementSum computes an RFC 1071 ones-complement checksum from
// scratch, independent of checksumAdjust, so it can be used to verify
// FixIPv4Source's incremental updates rather than tautologically re-deriving
// them with the same formula.
func onesComplementSum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if n%2 == 1 {
		sum += uint32(data[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildIPv4Header(src, dst [4]byte, proto byte, payloadLen int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(20+payloadLen))
	h[6] = 0x40 // DF
	h[8] = 64   // TTL
	h[9] = proto
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])
	binary.BigEndian.PutUint16(h[10:12], onesComplementSum(h))
	return h
}

func buildUDPSegment(src, dst [4]byte, payload []byte) []byte {
	udpLen := 8 + len(payload)
	seg := make([]byte, udpLen)
	binary.BigEndian.PutUint16(seg[0:2], 12345)
	binary.BigEndian.PutUint16(seg[2:4], 53)
	binary.BigEndian.PutUint16(seg[4:6], uint16(udpLen))
	copy(seg[8:], payload)

	pseudo := make([]byte, 12+udpLen)
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpLen))
	copy(pseudo[12:], seg)
	csum := onesComplementSum(pseudo)
	if csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(seg[6:8], csum)
	return seg
}

func buildTCPSegment(src, dst [4]byte, payload []byte) []byte {
	tcpLen := 20 + len(payload)
	seg := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(seg[0:2], 54321)
	binary.BigEndian.PutUint16(seg[2:4], 443)
	seg[12] = 0x50 // data offset 5
	copy(seg[20:], payload)

	pseudo := make([]byte, 12+tcpLen)
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	copy(pseudo[12:], seg)
	binary.BigEndian.PutUint16(seg[16:18], onesComplementSum(pseudo))
	return seg
}

func verifyIPv4HeaderChecksum(t *testing.T, packet []byte) {
	t.Helper()
	header := append([]byte(nil), packet[:20]...)
	binary.BigEndian.PutUint16(header[10:12], 0)
	want := onesComplementSum(header)
	got := binary.BigEndian.Uint16(packet[10:12])
	if got != want {
		t.Errorf("IPv4 header checksum = %#04x, want %#04x", got, want)
	}
}

func verifyUDPChecksum(t *testing.T, packet []byte, src, dst [4]byte) {
	t.Helper()
	seg := append([]byte(nil), packet[20:]...)
	binary.BigEndian.PutUint16(seg[6:8], 0)
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	want := onesComplementSum(pseudo)
	if want == 0 {
		want = 0xffff
	}
	got := binary.BigEndian.Uint16(packet[26:28])
	if got != want {
		t.Errorf("UDP checksum = %#04x, want %#04x", got, want)
	}
}

func verifyTCPChecksum(t *testing.T, packet []byte, src, dst [4]byte) {
	t.Helper()
	seg := append([]byte(nil), packet[20:]...)
	binary.BigEndian.PutUint16(seg[16:18], 0)
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	want := onesComplementSum(pseudo)
	got := binary.BigEndian.Uint16(packet[36:38])
	if got != want {
		t.Errorf("TCP checksum = %#04x, want %#04x", got, want)
	}
}

func TestFixIPv4SourceUDP(t *testing.T) {
	wrongSrc := [4]byte{10, 0, 0, 1}
	correctSrc := [4]byte{10, 0, 0, 2}
	dst := [4]byte{192, 168, 1, 1}
	payload := []byte("hello world")

	udp := buildUDPSegment(wrongSrc, dst, payload)
	ip := buildIPv4Header(wrongSrc, dst, 17, len(udp))
	packet := append(ip, udp...)

	FixIPv4Source(packet, correctSrc)

	if got := [4]byte{packet[12], packet[13], packet[14], packet[15]}; got != correctSrc {
		t.Fatalf("source = %v, want %v", got, correctSrc)
	}
	verifyIPv4HeaderChecksum(t, packet)
	verifyUDPChecksum(t, packet, correctSrc, dst)
	if !bytes.Equal(packet[28:], payload) {
		t.Errorf("UDP payload was mutated: got %q, want %q", packet[28:], payload)
	}
}

func TestFixIPv4SourceTCP(t *testing.T) {
	wrongSrc := [4]byte{172, 16, 0, 5}
	correctSrc := [4]byte{172, 16, 0, 9}
	dst := [4]byte{8, 8, 8, 8}
	payload := []byte("GET / HTTP/1.1")

	tcp := buildTCPSegment(wrongSrc, dst, payload)
	ip := buildIPv4Header(wrongSrc, dst, 6, len(tcp))
	packet := append(ip, tcp...)

	FixIPv4Source(packet, correctSrc)

	if got := [4]byte{packet[12], packet[13], packet[14], packet[15]}; got != correctSrc {
		t.Fatalf("source = %v, want %v", got, correctSrc)
	}
	verifyIPv4HeaderChecksum(t, packet)
	verifyTCPChecksum(t, packet, correctSrc, dst)
}

func TestFixIPv4SourceAlreadyCorrect(t *testing.T) {
	correctSrc := [4]byte{10, 0, 0, 2}
	dst := [4]byte{192, 168, 1, 1}
	udp := buildUDPSegment(correctSrc, dst, []byte("payload"))
	ip := buildIPv4Header(correctSrc, dst, 17, len(udp))
	packet := append(ip, udp...)

	original := append([]byte(nil), packet...)
	FixIPv4Source(packet, correctSrc)

	if !bytes.Equal(packet, original) {
		t.Errorf("fast path mutated an already-correct packet: got %x, want %x", packet, original)
	}
}

func TestFixIPv4SourceICMPChecksumUntouched(t *testing.T) {
	wrongSrc := [4]byte{10, 0, 0, 1}
	correctSrc := [4]byte{10, 0, 0, 2}
	dst := [4]byte{192, 168, 1, 1}

	// Minimal ICMP echo request: type=8, code=0, checksum, id, seq.
	icmp := []byte{8, 0, 0xf7, 0xfd, 0x00, 0x01, 0x00, 0x01}
	originalICMP := append([]byte(nil), icmp...)
	ip := buildIPv4Header(wrongSrc, dst, 1, len(icmp))
	packet := append(ip, icmp...)

	FixIPv4Source(packet, correctSrc)

	if got := [4]byte{packet[12], packet[13], packet[14], packet[15]}; got != correctSrc {
		t.Fatalf("source = %v, want %v", got, correctSrc)
	}
	verifyIPv4HeaderChecksum(t, packet)
	if !bytes.Equal(packet[20:], originalICMP) {
		t.Errorf("ICMP body was mutated: got %x, want %x", packet[20:], originalICMP)
	}
}

func TestFixIPv4SourceMalformedPacketNoPanic(t *testing.T) {
	correctSrc := [4]byte{10, 0, 0, 2}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FixIPv4Source panicked: %v", r)
		}
	}()

	FixIPv4Source(nil, correctSrc)
	FixIPv4Source([]byte{}, correctSrc)
	FixIPv4Source([]byte{0x45, 0x00, 0x00}, correctSrc)
	FixIPv4Source([]byte{0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, correctSrc) // IPv6 version nibble
}

func TestFixIPv4DestUDP(t *testing.T) {
	src := [4]byte{192, 168, 1, 1}
	wrongDst := [4]byte{10, 0, 0, 1}
	correctDst := [4]byte{10, 0, 0, 2}
	payload := []byte("reply")

	udp := buildUDPSegment(src, wrongDst, payload)
	ip := buildIPv4Header(src, wrongDst, 17, len(udp))
	packet := append(ip, udp...)

	if !FixIPv4Dest(packet, correctDst) {
		t.Fatal("expected FixIPv4Dest to report a rewrite")
	}
	if got := [4]byte{packet[16], packet[17], packet[18], packet[19]}; got != correctDst {
		t.Fatalf("dest = %v, want %v", got, correctDst)
	}
	verifyIPv4HeaderChecksum(t, packet)
	verifyUDPChecksum(t, packet, src, correctDst)
}

// exitNodeNATTestPacket builds a minimal IPv4/UDP packet with the given
// addresses and ports, for exercising ExitNodeNAT's port-based tracking.
func exitNodeNATTestPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	seg := make([]byte, 8)
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))

	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	csum := onesComplementSum(pseudo)
	if csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(seg[6:8], csum)

	ip := buildIPv4Header(src, dst, 17, len(seg))
	return append(ip, seg...)
}

func TestExitNodeNATRoundTrip(t *testing.T) {
	wrongSrc := [4]byte{100, 89, 128, 9}  // primary/site tunnel IP (the bug's default pick)
	correctSrc := [4]byte{100, 89, 128, 4} // exit node's secondary tunnel IP
	serverIP := [4]byte{100, 89, 128, 1}
	const localPort = 52746

	nat := NewExitNodeNAT()

	// Outbound: kernel picked the wrong source; our fix rewrites it and should
	// remember the local port so the reply gets translated.
	outbound := exitNodeNATTestPacket(wrongSrc, serverIP, localPort, 80)
	nat.FixOutboundSource(outbound, correctSrc)
	if got := [4]byte{outbound[12], outbound[13], outbound[14], outbound[15]}; got != correctSrc {
		t.Fatalf("outbound source = %v, want %v", got, correctSrc)
	}

	// Inbound reply: correctly addressed to correctSrc (the exit node saw the
	// fixed source), but the OS's own connection state still expects wrongSrc.
	reply := exitNodeNATTestPacket(serverIP, correctSrc, 80, localPort)
	nat.FixInboundDest(reply, wrongSrc)
	if got := [4]byte{reply[16], reply[17], reply[18], reply[19]}; got != wrongSrc {
		t.Fatalf("reply dest = %v, want %v (translated back for the OS to match the socket)", got, wrongSrc)
	}
	verifyIPv4HeaderChecksum(t, reply)
}

func TestExitNodeNATUntrackedPortPassesThrough(t *testing.T) {
	wrongSrc := [4]byte{100, 89, 128, 9}
	correctSrc := [4]byte{100, 89, 128, 4}
	serverIP := [4]byte{100, 89, 128, 1}
	const localPort = 55555 // never seen by FixOutboundSource

	nat := NewExitNodeNAT()

	// A socket that was already, legitimately bound to correctSrc: its reply
	// must not be touched, since translating it would misroute it away from
	// the socket that's actually expecting it.
	reply := exitNodeNATTestPacket(serverIP, correctSrc, 80, localPort)
	original := append([]byte(nil), reply...)
	nat.FixInboundDest(reply, wrongSrc)

	if !bytes.Equal(reply, original) {
		t.Errorf("untracked port was translated: got %x, want unchanged %x", reply, original)
	}
}

func TestExitNodeNATEntryExpires(t *testing.T) {
	origTTL := natEntryTTL
	natEntryTTL = 10 * time.Millisecond
	defer func() { natEntryTTL = origTTL }()

	wrongSrc := [4]byte{100, 89, 128, 9}
	correctSrc := [4]byte{100, 89, 128, 4}
	serverIP := [4]byte{100, 89, 128, 1}
	const localPort = 52746

	nat := NewExitNodeNAT()

	outbound := exitNodeNATTestPacket(wrongSrc, serverIP, localPort, 80)
	nat.FixOutboundSource(outbound, correctSrc)

	time.Sleep(50 * time.Millisecond)

	reply := exitNodeNATTestPacket(serverIP, correctSrc, 80, localPort)
	original := append([]byte(nil), reply...)
	nat.FixInboundDest(reply, wrongSrc)

	if !bytes.Equal(reply, original) {
		t.Errorf("expired entry was still translated: got %x, want unchanged %x", reply, original)
	}
}
