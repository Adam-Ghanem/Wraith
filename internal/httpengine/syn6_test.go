package httpengine

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildTCPSYN6HasValidChecksum(t *testing.T) {
	source := net.ParseIP("2001:db8::10")
	destination := net.ParseIP("2001:db8::20")
	segment := buildTCPSYN6(source, destination, 45000, 443, 12345)
	if len(segment) != 40 {
		t.Fatalf("segment length=%d, want 40", len(segment))
	}
	if segment[13] != 0x02 {
		t.Fatalf("flags=%#x, want SYN", segment[13])
	}
	if got := tcpChecksumIPv6(source, destination, segment); got != 0 {
		t.Fatalf("checksum verification=%#x, want 0", got)
	}
}

func TestParseSYN6ReplyExtractsFingerprint(t *testing.T) {
	packet := make([]byte, 72)
	packet[0] = 0x60
	packet[6] = 6
	packet[7] = 53
	tcp := packet[40:]
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 45000)
	binary.BigEndian.PutUint32(tcp[4:8], 9000)
	binary.BigEndian.PutUint32(tcp[8:12], 12346)
	tcp[12] = 8 << 4
	tcp[13] = 0x12
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	copy(tcp[20:32], []byte{2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 7, 0, 0})

	reply, sourcePort, destinationPort, ok := parseSYN6Reply(packet, 0)
	if !ok {
		t.Fatal("expected IPv6 SYN reply to parse")
	}
	if sourcePort != 443 || destinationPort != 45000 {
		t.Fatalf("ports=%d->%d, want 443->45000", sourcePort, destinationPort)
	}
	if reply.flags != 0x12 || reply.ttl != 53 || reply.window != 64240 {
		t.Fatalf("unexpected reply: %#v", reply)
	}
	if reply.mss != 1460 || !reply.sackPermitted || !reply.windowScaleSet || reply.windowScale != 7 {
		t.Fatalf("unexpected options: %#v", reply)
	}
}

func TestTCPChecksumIPv6RejectsIPv4Inputs(t *testing.T) {
	if got := tcpChecksumIPv6(net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1"), make([]byte, 20)); got != 0 {
		t.Fatalf("checksum=%#x, want 0 for mixed address families", got)
	}
}
