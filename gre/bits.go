package gre

func SetUint16Bit(value uint16, pos uint) uint16 {
	return value | (1 << pos)
}

func ClearUint16Bit(value uint16, pos uint) uint16 {
	var mask uint16 = ^(1 << pos)
	return value & mask
}

func HasUint16Bit(value uint16, pos uint) bool {
	val := value & (1 << pos)
	return (val > 0)
}
