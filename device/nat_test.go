package device

import (
	"bytes"
	"encoding/binary"
	"testing"
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
