package packet

import (
	"bytes"
	"testing"
)

func TestIP4GREDecoder(t *testing.T) {
	mockPayload := []byte{
		0x01, 0x02, 0x03, 0x04,
	}

	raw := append(ip4TestHeader, greTestHeader...)
	raw = append(raw, mockPayload...)

	decoder := NewIP4GREDecoder()
	consumedBytes, ok := decoder.Decode(raw)
	if !ok {
		t.Fatal("ip4 gre decode: should work")
	}

	// IP4: 20 bytes
	// GRE: 8 bytes
	if consumedBytes != 20+8 {
		t.Fatal("ip4 gre decode: consumed bytes mismatch")
	}

	var (
		lastIP4 = decoder.LastIP4Header()
		lastGRE = decoder.LastGREHeader()
	)

	if lastIP4.SrcIP.String() != "100.120.0.1" {
		t.Fatal("ip4 gre decode: src ip mismatch")
	}

	if lastIP4.DstIP.String() != "100.100.0.0" {
		t.Fatal("ip4 gre decode: dst ip mismatch")
	}

	if lastIP4.Protocol != IP4ProtocolGRE {
		t.Fatal("ip4 gre decode: ip4 protocol mismatch")
	}

	if lastGRE.Protocol != GREProtocolIP4 {
		t.Fatal("ip4 gre decode: gre protocol mismatch")
	}

	payload := raw[consumedBytes:]
	if !bytes.Equal(payload, mockPayload) {
		t.Fatal("ip4 gre decode: payload mismatch")
	}
}
