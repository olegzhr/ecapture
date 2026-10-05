package openssl

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/sys/unix"
	"net/netip"
	"testing"
)

func tlsFixture(t *testing.T, endpoint *tlsEndpoint) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	var data [MaxDataSize]byte
	copy(data[:], "GET / HTTP/1.1\r\n\r\n")
	var comm [TaskCommLen]byte
	copy(comm[:], "curl")
	for _, field := range []any{int64(DataTypeWrite), uint64(42), uint32(12), uint32(13), data, int32(18), comm, uint32(7), int32(771), uint32(0)} {
		if err := binary.Write(buf, binary.LittleEndian, field); err != nil {
			t.Fatal(err)
		}
	}
	if endpoint != nil {
		if err := binary.Write(buf, binary.LittleEndian, endpoint); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestEndpointSnapshotABIAndReusedDescriptor(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		ep := tlsEndpoint{Sock: 123, Family: unix.AF_INET, Sport: 12345, Dport: 443}
		src, dst := "127.0.0.1", "192.0.2.20"
		if ipv6 {
			ep.Family = unix.AF_INET6
			src = "2001:db8::7"
			dst = "2001:db8::20"
		}
		if ipv6 {
			ep.Saddr = netip.MustParseAddr(src).As16()
			ep.Daddr = netip.MustParseAddr(dst).As16()
		} else {
			a, b := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
			copy(ep.Saddr[:], a[:])
			copy(ep.Daddr[:], b[:])
		}
		event := new(Event)
		if err := event.DecodeFromBytes(tlsFixture(t, &ep)); err != nil {
			t.Fatal(err)
		}
		wire := event.ToProtobufEvent()
		if wire.SrcIp != src || wire.DstIp != dst || wire.SrcPort != 12345 || wire.DstPort != 443 || event.Sock != 123 {
			t.Fatal(wire)
		}
		ep.Sock = 124
		ep.Sport = 23456 // same PID/FD, a new socket
		if err := event.DecodeFromBytes(tlsFixture(t, &ep)); err != nil {
			t.Fatal(err)
		}
		if wire := event.ToProtobufEvent(); wire.SrcPort != 23456 || event.Sock != 124 {
			t.Fatal("stale snapshot", wire)
		}
		// Legacy ABI is still readable, but never retains an earlier endpoint.
		if err := event.DecodeFromBytes(tlsFixture(t, nil)); err != nil {
			t.Fatal(err)
		}
		if wire := event.ToProtobufEvent(); wire.SrcIp != "" || wire.SrcPort != 0 || event.Sock != 0 {
			t.Fatal("legacy payload retained stale endpoint", wire)
		}
	}
}

func TestTruncatedEndpointExtensionRejected(t *testing.T) {
	data := tlsFixture(t, &tlsEndpoint{Sock: 1})
	if err := new(Event).DecodeFromBytes(data[:len(data)-1]); err == nil {
		t.Fatal("partial endpoint accepted")
	}
}
