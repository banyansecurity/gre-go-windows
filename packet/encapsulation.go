package packet

import (
	"encoding/binary"
	"math"
	"math/rand"
	"net"
)

type IP4GREDecoder struct {
	deliveryHeader IP4Header
	greHeader      GREHeader
}

func NewIP4GREDecoder() *IP4GREDecoder {
	return &IP4GREDecoder{}
}

// Decode searches the given packet data for the encapsulated payload and
// returns the offset for that payload.
//
// The second return value indicates whether we're even dealing with a GRE
// payload. If we're not, a false value would indicate that the given packet is
// not encapsulated at all.
func (gd *IP4GREDecoder) Decode(raw []byte) (int, bool) {
	var totalConsumedBytes int
	ip4ConsumedBytes, err := FillIP4Header(raw, &gd.deliveryHeader)
	if err != nil {
		return 0, false
	}

	if gd.deliveryHeader.Protocol != IP4ProtocolGRE {
		return 0, false
	}
	totalConsumedBytes += ip4ConsumedBytes

	greConsumedBytes, err := FillGREHeader(raw[totalConsumedBytes:], &gd.greHeader)
	if err != nil {
		return 0, false
	}
	totalConsumedBytes += greConsumedBytes

	return totalConsumedBytes, true
}

func (gd *IP4GREDecoder) LastIP4Header() *IP4Header {
	return &gd.deliveryHeader
}

func (gd *IP4GREDecoder) LastGREHeader() *GREHeader {
	return &gd.greHeader
}

type IP4GREEncoder struct {
	deliveryHeader IP4Header
	greHeader      GREHeader
	counter        uint16
}

func NewIP4GREEncoder() *IP4GREEncoder {
	return &IP4GREEncoder{
		counter: uint16(rand.Intn(math.MaxUint16 + 1)),
	}
}

// Encode takes a given payload and wrap
func (gd *IP4GREEncoder) Encode(raw []byte, source, destination net.IP) ([]byte, error) {
	defer func() { gd.counter++ }()

	var greHeader GREHeader
	greHeader.KeyBit = true
	greHeader.Protocol = GREProtocolIP4
	greHeader.Key = GREConnectorKey
	greBytes := greHeader.ToBytes()

	var deliveryHeader IP4Header
	deliveryHeader.Version = 4
	deliveryHeader.IHL = 5
	deliveryHeader.TotalLength = uint16(int(deliveryHeader.IHL*4) + len(greBytes) + len(raw))
	deliveryHeader.ID = gd.counter
	deliveryHeader.Flags = 2
	deliveryHeader.TTL = 64
	deliveryHeader.Protocol = IP4ProtocolGRE
	deliveryHeader.Checksum = 0 // Compute later
	deliveryHeader.SrcIP = source
	deliveryHeader.DstIP = destination
	deliveryBytes := deliveryHeader.ToBytes()
	binary.BigEndian.PutUint16(deliveryBytes[10:12], gd.ComputeChecksum(deliveryBytes))

	finalBytes := append(deliveryBytes, greBytes...)
	finalBytes = append(finalBytes, raw...)

	return finalBytes, nil
}

func (gd *IP4GREEncoder) ComputeChecksum(bytes []byte) uint16 {
	// Clear checksum bytes
	bytes[10] = 0
	bytes[11] = 0

	// Compute checksum
	var csum uint32
	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}
	for {
		// Break when sum is less or equals to 0xFFFF
		if csum <= 65535 {
			break
		}
		// Add carry to the sum
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	// Flip all the bits
	return ^uint16(csum)
}
