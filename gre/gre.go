package gre

import (
	"encoding/binary"
)

const (
	greBaseLength                 = 4
	rfc2784Length                 = 8
	rfc2890Length                 = 16
	ipv4EtherType                 = 0x0800
	ipv6EtherType                 = 0x86dd
	checksumPresentOffset         = 0
	checksumPresentPosition       = 0
	keyPresentOffset              = 0
	keyPresentPosition            = 2
	sequenceNumberPresentOffset   = 0
	sequenceNumberPresentPosition = 3
	reserved0Offset               = 0
	versionNumberOffset           = 0
	versionNumberPosition         = 13
	protocolTypeOffset            = 2
	checksumOffset                = 4
	reserved1Offset               = 6
)

type GREHeader []byte

func NewEmptyBaseGREHeader() GREHeader {
	return make(GREHeader, greBaseLength)
}

func NewEmptyRFC2784GREHeader() GREHeader {
	return make(GREHeader, rfc2784Length)
}

func NewEmptyRFC2890GREHeader() GREHeader {
	return make(GREHeader, rfc2890Length)
}

func (g GREHeader) ChecksumPresent() bool {
	return HasUint16Bit(binary.BigEndian.Uint16(g[checksumPresentOffset:]), checksumPresentPosition)
}

func (g GREHeader) WithChecksumPresent() GREHeader {
	value := binary.BigEndian.Uint16(g[checksumPresentOffset:])
	value = SetUint16Bit(value, checksumPresentPosition)
	binary.BigEndian.PutUint16(g[checksumPresentOffset:], value)
	return g
}

func (g GREHeader) WithoutChecksumPresent() GREHeader {
	value := binary.BigEndian.Uint16(g[checksumPresentOffset:])
	value = ClearUint16Bit(value, checksumPresentPosition)
	binary.BigEndian.PutUint16(g[checksumPresentOffset:], value)
	return g

}

func (g GREHeader) Checksum() uint16 {
	return binary.BigEndian.Uint16(g[checksumOffset:])
}

func (g GREHeader) KeyPresent() bool {
	return HasUint16Bit(binary.BigEndian.Uint16(g[keyPresentOffset:]), keyPresentPosition)
}

func (g GREHeader) WithKeyPresent() GREHeader {
	value := binary.BigEndian.Uint16(g[keyPresentOffset:])
	value = SetUint16Bit(value, keyPresentPosition)
	binary.BigEndian.PutUint16(g[keyPresentOffset:], value)
	return g
}

func (g GREHeader) WithoutKeyPresent() GREHeader {
	value := binary.BigEndian.Uint16(g[keyPresentOffset:])
	value = ClearUint16Bit(value, keyPresentPosition)
	binary.BigEndian.PutUint16(g[keyPresentOffset:], value)
	return g
}

func (g GREHeader) SequenceNumberPresent() bool {
	return HasUint16Bit(binary.BigEndian.Uint16(g[sequenceNumberPresentOffset:]), sequenceNumberPresentPosition)
}

func (g GREHeader) WithSequenceNumberPresent() GREHeader {
	value := binary.BigEndian.Uint16(g[sequenceNumberPresentOffset:])
	value = SetUint16Bit(value, sequenceNumberPresentPosition)
	binary.BigEndian.PutUint16(g[sequenceNumberPresentOffset:], value)
	return g
}

func (g GREHeader) WithoutSequenceNumberPresent() GREHeader {
	value := binary.BigEndian.Uint16(g[sequenceNumberPresentOffset:])
	value = ClearUint16Bit(value, sequenceNumberPresentPosition)
	binary.BigEndian.PutUint16(g[sequenceNumberPresentOffset:], value)
	return g
}

func (g GREHeader) WithChecksum(checksum uint16) GREHeader {
	binary.BigEndian.PutUint16(g[checksumOffset:], checksum)
	return g
}

func (g GREHeader) ProtocolType() uint16 {
	return binary.BigEndian.Uint16(g[protocolTypeOffset:])
}

func (g GREHeader) WithIPv4ProtocolType() GREHeader {
	binary.BigEndian.PutUint16(g[protocolTypeOffset:], ipv4EtherType)
	return g
}

func (g GREHeader) WithIPv6ProtocolType() GREHeader {
	binary.BigEndian.PutUint16(g[protocolTypeOffset:], ipv6EtherType)
	return g
}

func (g GREHeader) Reserved1() uint16 {
	return binary.BigEndian.Uint16(g[reserved1Offset:])
}

func (g GREHeader) HeaderLength() int {
	headerLength := greBaseLength

	if g.ChecksumPresent() {
		headerLength += 2 // Checksum
		headerLength += 2 // Reserved1
	}

	if g.KeyPresent() {
		headerLength += 4 // Key
	}

	if g.SequenceNumberPresent() {
		headerLength += 4 // Sequence Number
	}

	return headerLength
}
