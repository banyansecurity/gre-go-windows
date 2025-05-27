package packet

import (
	"encoding/binary"
	"net"
)

// IP4Header represents a standard IPv4 header over the wire as would be
// present in a standard packet trace.
//
// See: https://en.wikipedia.org/wiki/IPv4#Header
type IP4Header struct {
	Version, IHL, DSCP, ECN uint8
	TotalLength, ID         uint16
	Flags                   uint8
	FragmentOffset          uint16
	TTL, Protocol           uint8
	Checksum                uint16
	SrcIP, DstIP            net.IP
	Options                 []byte
}

const (
	minIP4HeaderLength = 20
	minGREHeaderLength = 4
)

const (
	IP4ProtocolGRE  = 0x2F
	GREProtocolIP4  = 0x0800
	GREConnectorKey = 0x000004D2
)

// FillIP4Header takes an existing IP4Header variable, resets it, and fills it
// with values from the provided raw packet bytes.
//
// Returns the number of bytes consumed to populate the given target as the
// first return value.
func FillIP4Header(raw []byte, target *IP4Header) (int, error) {
	resetIP4Header(target)

	actualHeaderLength := len(raw)
	if actualHeaderLength < minIP4HeaderLength {
		return 0, &DataTooShortError{
			Expected: minIP4HeaderLength,
			Actual:   actualHeaderLength,
		}
	}

	target.Version = raw[0] >> 4
	target.IHL = raw[0] & 0x0F

	ip4HeaderLength := int(target.IHL) * 4
	if actualHeaderLength < ip4HeaderLength {
		return 0, &DataTooShortError{
			Expected: ip4HeaderLength,
			Actual:   actualHeaderLength,
		}
	}

	target.DSCP = raw[1] >> 2
	target.ECN = raw[1] & 0x03
	target.TotalLength = binary.BigEndian.Uint16(raw[2:4])
	target.ID = binary.BigEndian.Uint16(raw[4:6])

	flagsAndOffset := binary.BigEndian.Uint16(raw[6:8])
	target.Flags = uint8(flagsAndOffset >> 13)
	target.FragmentOffset = flagsAndOffset & 0x1FFF

	target.TTL = raw[8]
	target.Protocol = raw[9]
	target.Checksum = binary.BigEndian.Uint16(raw[10:12])
	target.SrcIP = net.IPv4(raw[12], raw[13], raw[14], raw[15])
	target.DstIP = net.IPv4(raw[16], raw[17], raw[18], raw[19])

	if ip4HeaderLength > minIP4HeaderLength {
		target.Options = raw[minIP4HeaderLength:ip4HeaderLength]
	}

	return int(target.IHL) * 4, nil
}

func (h *IP4Header) ToBytes() []byte {
	headerLengthBytes := int(h.IHL) * 4
	buf := make([]byte, headerLengthBytes)
	buf[0] = (h.Version << 4) | (h.IHL & 0x0F)
	buf[1] = (h.DSCP << 2) | (h.ECN & 0x03)
	binary.BigEndian.PutUint16(buf[2:4], h.TotalLength)
	binary.BigEndian.PutUint16(buf[4:6], h.ID)

	flagsAndOffset := (uint16(h.Flags&0x07) << 13) | (h.FragmentOffset & 0x1FFF)
	binary.BigEndian.PutUint16(buf[6:8], flagsAndOffset)

	buf[8] = h.TTL
	buf[9] = h.Protocol
	binary.BigEndian.PutUint16(buf[10:12], h.Checksum)

	copy(buf[12:16], h.SrcIP.To4())
	copy(buf[16:20], h.DstIP.To4())
	copy(buf[minIP4HeaderLength:headerLengthBytes], h.Options)

	return buf
}

func resetIP4Header(target *IP4Header) {
	target.Version = 0
	target.IHL = 0
	target.DSCP = 0
	target.ECN = 0
	target.TotalLength = 0
	target.ID = 0
	target.Flags = 0
	target.FragmentOffset = 0
	target.TTL = 0
	target.Protocol = 0
	target.Checksum = 0
	target.SrcIP = nil
	target.DstIP = nil
	target.Options = nil
}

// GREHeader represents a GRE header (RFC 1701) over the wire.
//
// See: https://en.wikipedia.org/wiki/Generic_routing_encapsulation#Original_GRE_packet_header_(RFC_1701)
type GREHeader struct {
	ChecksumBit, RoutingBit, KeyBit, SequenceNumberBit, StrictSourceRouteBit bool
	RecursionControl, Flags, Version                                         uint8
	Protocol, Checksum, Offset                                               uint16
	Key, SequenceNumber                                                      uint32
}

func FillGREHeader(raw []byte, target *GREHeader) (int, error) {
	resetGREHeader(target)

	actualHeaderLength := len(raw)
	if actualHeaderLength < minGREHeaderLength {
		return 0, &DataTooShortError{
			Expected: minGREHeaderLength,
			Actual:   actualHeaderLength,
		}
	}

	var (
		flagsLo       = raw[0]
		flagsHi       = raw[1]
		consumedBytes int
	)
	target.ChecksumBit = (flagsLo & 0x80) != 0          // 1 Bit
	target.RoutingBit = (flagsLo & 0x40) != 0           // 1 Bit
	target.KeyBit = (flagsLo & 0x20) != 0               // 1 Bit
	target.SequenceNumberBit = (flagsLo & 0x10) != 0    // 1 Bit
	target.StrictSourceRouteBit = (flagsLo & 0x08) != 0 // 1 Bit
	target.RecursionControl = (flagsLo & 0x07)          // 3 Bits
	target.Flags = (flagsHi & 0x1F)                     // 5 Bits
	target.Version = (flagsHi >> 5) & 0x07              // 3 Bits

	// FIXME: I'm not sure if the routing bit is required for connector, so fail
	//        fast here if it is required so that we implement it correctly. From
	//        what I can tell, this is not used at all for connector currently.
	if target.RoutingBit {
		panic("gre: routing bit is not implemented")
	}

	target.Protocol = binary.BigEndian.Uint16(raw[2:4])
	consumedBytes += 4

	if target.ChecksumBit {
		if consumedBytes+2 > actualHeaderLength {
			return 0, &DataTooShortError{
				Expected: consumedBytes + 2,
				Actual:   actualHeaderLength,
			}
		}

		target.Checksum = binary.BigEndian.Uint16(raw[consumedBytes : consumedBytes+2])
		consumedBytes += 2
	}

	if target.ChecksumBit || target.RoutingBit {
		if consumedBytes+2 > actualHeaderLength {
			return 0, &DataTooShortError{
				Expected: consumedBytes + 2,
				Actual:   actualHeaderLength,
			}
		}

		target.Offset = binary.BigEndian.Uint16(raw[consumedBytes : consumedBytes+2])
		consumedBytes += 2
	}

	if target.KeyBit {
		if consumedBytes+4 > actualHeaderLength {
			return 0, &DataTooShortError{
				Expected: consumedBytes + 4,
				Actual:   actualHeaderLength,
			}
		}

		target.Key = binary.BigEndian.Uint32(raw[consumedBytes : consumedBytes+4])
		consumedBytes += 4
	}

	if target.SequenceNumberBit {
		if consumedBytes+4 > actualHeaderLength {
			return 0, &DataTooShortError{
				Expected: consumedBytes + 4,
				Actual:   actualHeaderLength,
			}
		}

		target.SequenceNumber = binary.BigEndian.Uint32(raw[consumedBytes : consumedBytes+4])
		consumedBytes += 4
	}

	return consumedBytes, nil
}

func (h *GREHeader) ToBytes() []byte {
	headerLengthBytes := minGREHeaderLength

	if h.ChecksumBit || h.RoutingBit {
		headerLengthBytes += 4
	}

	if h.KeyBit {
		headerLengthBytes += 4
	}

	if h.SequenceNumberBit {
		headerLengthBytes += 4
	}

	buf := make([]byte, headerLengthBytes)

	var firstByte uint8
	if h.ChecksumBit {
		firstByte |= 0x80
	}

	if h.RoutingBit {
		firstByte |= 0x40
	}

	if h.KeyBit {
		firstByte |= 0x20
	}

	if h.SequenceNumberBit {
		firstByte |= 0x10
	}

	if h.StrictSourceRouteBit {
		firstByte |= 0x08
	}

	firstByte |= (h.RecursionControl & 0x07)

	buf[0] = firstByte

	var secondByte uint8
	secondByte |= (h.Version & 0x07) << 5
	secondByte |= (h.Flags & 0x1F)
	buf[1] = secondByte

	binary.BigEndian.PutUint16(buf[2:4], h.Protocol)

	if h.KeyBit {
		binary.BigEndian.PutUint32(buf[4:8], h.Key)
	}

	return buf
}

func resetGREHeader(target *GREHeader) {
	target.ChecksumBit = false
	target.RoutingBit = false
	target.KeyBit = false
	target.SequenceNumberBit = false
	target.StrictSourceRouteBit = false
	target.RecursionControl = 0
	target.Flags = 0
	target.Version = 0
	target.Protocol = 0
	target.Checksum = 0
	target.Offset = 0
	target.Key = 0
	target.SequenceNumber = 0
}
