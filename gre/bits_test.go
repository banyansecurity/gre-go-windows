package gre

import "testing"

func TestSetUint16Bit(t *testing.T) {
	value := uint16(0)
	value = SetUint16Bit(value, 0)
	if value != 1 {
		t.Errorf("expected 1, got %d", value)
	}
}

func TestClearUint16Bit(t *testing.T) {
	value := uint16(1)
	value = ClearUint16Bit(value, 0)
	if value != 0 {
		t.Errorf("expected 0, got %d", value)
	}
}

func TestHasUint16Bit(t *testing.T) {
	value := uint16(1)
	if !HasUint16Bit(value, 0) {
		t.Errorf("expected true, got false")
	}
}
