package gre

import (
	"testing"
)

func TestGREHeader_ChecksumPresent(t *testing.T) {
	header := NewEmptyRFC2784GREHeader().WithChecksumPresent()
	t.Logf("reserved: 0x%X", header[checksumPresentOffset:])

	if !header.ChecksumPresent() {
		t.Fatalf("expected checksum present")
	}
}

func TestGREHeader_HeaderComponents(t *testing.T) {
	header := NewEmptyRFC2784GREHeader().
		WithIPv4ProtocolType().
		WithChecksumPresent().
		WithChecksum(0xa3bb)
	t.Logf("header: 0x%X", header[:])

	var expectedChecksum uint16 = 0xa3bb
	if actualChecksum := header.Checksum(); actualChecksum != expectedChecksum {
		t.Fatalf("did not match expected checksum, got: 0x%X, expected: 0x%X", actualChecksum, expectedChecksum)
	}

	var expectedProtocolType uint16 = ipv4EtherType
	if actualProtocolType := header.ProtocolType(); actualProtocolType != expectedProtocolType {
		t.Fatalf("did not match expected protocol type, got: 0x%X, expected: 0x%X", actualProtocolType, expectedProtocolType)
	}
}

func TestGREHeader_WithChecksumPresent(t *testing.T) {
	header := NewEmptyBaseGREHeader().WithChecksumPresent()
	t.Logf("header: 0x%X", header[:])

	if !header.ChecksumPresent() {
		t.Fatalf("expected checksum present")
	}

	header = header.WithoutChecksumPresent()
	t.Logf("header: 0x%X", header[:])

	if header.ChecksumPresent() {
		t.Fatalf("expected checksum not present")
	}
}

func TestGREHeader_WithIPv6ProtocolType(t *testing.T) {
	header := NewEmptyRFC2784GREHeader().WithIPv6ProtocolType()
	t.Logf("header: 0x%X", header[:])

	var expectedProtocolType uint16 = ipv6EtherType
	if actualProtocolType := header.ProtocolType(); actualProtocolType != expectedProtocolType {
		t.Fatalf("did not match expected protocol type, got: 0x%X, expected: 0x%X", actualProtocolType, expectedProtocolType)
	}
}

func TestGREHeader_KeyPresent(t *testing.T) {
	header := NewEmptyRFC2784GREHeader().WithKeyPresent()
	t.Logf("header: 0x%X", header[:])

	if !header.KeyPresent() {
		t.Fatalf("expected key present")
	}

	header = header.WithoutKeyPresent()
	t.Logf("header: 0x%X", header[:])

	if header.KeyPresent() {
		t.Fatalf("expected key not present")
	}
}

func TestGREHeader_SequenceNumberPresent(t *testing.T) {
	header := NewEmptyRFC2784GREHeader().WithSequenceNumberPresent()
	t.Logf("header: 0x%X", header[:])

	if !header.SequenceNumberPresent() {
		t.Fatalf("expected sequence number present")
	}

	header = header.WithoutSequenceNumberPresent()
	t.Logf("header: 0x%X", header[:])

	if header.SequenceNumberPresent() {
		t.Fatalf("expected sequence number not present")
	}
}

func TestGREHeader_DoNotOverride(t *testing.T) {
	header := NewEmptyRFC2890GREHeader().
		WithChecksumPresent().
		WithKeyPresent()
	t.Logf("header: 0x%X", header[:])

	if !header.ChecksumPresent() {
		t.Fatal("expected checksum present")
	}

	header = header.WithSequenceNumberPresent()
	t.Logf("header: 0x%X", header[:])

	if !header.KeyPresent() {
		t.Fatal("expected key present")
	}
}

func TestGREHeader_HeaderLength(t *testing.T) {
	header := NewEmptyRFC2890GREHeader().WithChecksumPresent().WithKeyPresent().WithSequenceNumberPresent()
	t.Logf("header: 0x%X", header[:])

	t.Log(header.KeyPresent(), header.SequenceNumberPresent(), header.ChecksumPresent())

	var expectedHeaderLength int = 16
	if actualHeaderLength := header.HeaderLength(); actualHeaderLength != expectedHeaderLength {
		t.Fatalf("did not match expected header length, got: %d, expected: %d", actualHeaderLength, expectedHeaderLength)
	}
}

func TestGREHeader_Reserved1(t *testing.T) {
	if NewEmptyRFC2890GREHeader().Reserved1() != 0 {
		t.Fatal("expected empty reserved1")
	}
}
