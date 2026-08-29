package httpengine

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func TestValidateSYNRequestSortsPorts(t *testing.T) {
	ports, err := validateSYNRequest(SYNScanRequest{
		ProjectID: "test",
		Target:    policy.Target{IP: netip.MustParseAddr("192.0.2.10")},
		Ports:     []uint16{443, 22, 80},
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{22, 80, 443}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports[%d]=%d, want %d", i, ports[i], want[i])
		}
	}
}

func TestValidateSYNRequestRejectsDuplicatePorts(t *testing.T) {
	_, err := validateSYNRequest(SYNScanRequest{
		ProjectID: "test",
		Target:    policy.Target{IP: netip.MustParseAddr("192.0.2.10")},
		Ports:     []uint16{80, 80},
		Timeout:   time.Second,
	})
	if err == nil {
		t.Fatal("expected duplicate ports to be rejected")
	}
}

func TestBuildTCPSYNHasValidChecksum(t *testing.T) {
	source := net.IPv4(192, 0, 2, 10)
	destination := net.IPv4(198, 51, 100, 20)
	segment := buildTCPSYN(source, destination, 45000, 443, 12345)
	if len(segment) != 40 {
		t.Fatalf("segment length=%d, want 40", len(segment))
	}
	if segment[13] != 0x02 {
		t.Fatalf("flags=%#x, want SYN", segment[13])
	}
	if got := tcpChecksum(source, destination, segment); got != 0 {
		t.Fatalf("checksum verification=%#x, want 0", got)
	}
}

func TestParseSYNReplyExtractsFingerprint(t *testing.T) {
	packet := make([]byte, 52)
	packet[0] = 0x45
	packet[8] = 57
	packet[9] = 6
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 45000)
	binary.BigEndian.PutUint32(tcp[4:8], 9000)
	binary.BigEndian.PutUint32(tcp[8:12], 12346)
	tcp[12] = 8 << 4
	tcp[13] = 0x12
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	copy(tcp[20:32], []byte{2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 7, 0, 0})

	reply, sourcePort, destinationPort, ok := parseSYNReply(packet, 0)
	if !ok {
		t.Fatal("expected SYN reply to parse")
	}
	if sourcePort != 443 || destinationPort != 45000 {
		t.Fatalf("ports=%d->%d, want 443->45000", sourcePort, destinationPort)
	}
	if reply.flags != 0x12 || reply.ttl != 57 || reply.window != 64240 {
		t.Fatalf("unexpected reply: %#v", reply)
	}
	if reply.mss != 1460 || !reply.sackPermitted || !reply.windowScaleSet || reply.windowScale != 7 {
		t.Fatalf("unexpected options: %#v", reply)
	}
}
