package packet

import (
	"bytes"
	"testing"
)

var (
	ip4TestHeader = []byte{
		0x45,
		0x00,
		0x00, 0x70,
		0x18, 0xd7,
		0x40, 0x00,
		0x3e,
		0x2f,
		0x5a, 0xab,
		0x64, 0x78, 0x00, 0x01,
		0x64, 0x64, 0x00, 0x00,
	}

	greTestHeader = []byte{
		0x20, 0x00,
		0x08, 0x00,
		0x00, 0x00, 0x04, 0xd2,
	}
)

func TestIP4Header(t *testing.T) {
	raw := ip4TestHeader

	var header IP4Header
	if _, err := FillIP4Header(raw, &header); err != nil {
		t.Fatalf("fill error: %v", err)
	}

	for _, testCase := range []struct {
		condition bool
		field     string
	}{
		{header.Version != 4, "version"},
		{header.IHL != 5, "ihl"},
		{header.DSCP != 0, "dscp"},
		{header.ECN != 0, "ecn"},
		{header.TotalLength != 112, "total length"},
		{header.ID != 6359, "id"},
		{header.Flags != 2, "flags"},
		{header.FragmentOffset != 0, "fragment offset"},
		{header.TTL != 62, "ttl"},
		{header.Protocol != IP4ProtocolGRE, "protocol"},
		{header.Checksum != 23211, "checksum"},
		{header.SrcIP.String() != "100.120.0.1", "src ip"},
		{header.DstIP.String() != "100.100.0.0", "dst ip"},
	} {
		if testCase.condition {
			t.Fatalf("incorrect %s, mismatch", testCase.field)
		}
	}

	if !bytes.Equal(header.ToBytes(), raw) {
		t.Fatal("incorrect header bytes, mismatch")
	}

	t.Logf("header: %+v", header)
}

func TestIP4Header_DataTooShort(t *testing.T) {
	raw := []byte{
		0x45,
		0x00,
	}

	var header IP4Header
	if _, err := FillIP4Header(raw, &header); err != nil {
		if derr, ok := err.(*DataTooShortError); ok {
			t.Logf("data too short, expected %d, actual %d", derr.Expected, derr.Actual)
		} else {
			t.Fatalf("fill error: %v", err)
		}
	}
}

func TestGREHeader(t *testing.T) {
	raw := greTestHeader

	var header GREHeader
	consumedBytes, err := FillGREHeader(raw, &header)
	if err != nil {
		t.Fatalf("fill error: %v", err)
	}

	if consumedBytes != 8 {
		t.Fatal("incorrect consumed bytes, mismatch")
	}

	if header.Protocol != GREProtocolIP4 {
		t.Fatal("incorrect protocol, mismatch")
	}

	if header.Key != 1234 {
		t.Fatal("incorrect key, mismatch")
	}

	if !bytes.Equal(header.ToBytes(), raw) {
		t.Fatal("incorrect header bytes, mismatch")
	}

	t.Logf("header: %+v", header)
}

func TestGREHeader_DataTooShort(t *testing.T) {
	raw := []byte{
		0x00, 0x00,
	}

	var header GREHeader
	if _, err := FillGREHeader(raw, &header); err != nil {
		if derr, ok := err.(*DataTooShortError); ok {
			t.Logf("data too short, expected %d, actual %d", derr.Expected, derr.Actual)
		} else {
			t.Fatalf("fill error: %v", err)
		}
	}
}
