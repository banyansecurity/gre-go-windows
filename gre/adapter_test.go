package gre

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/elevate"
)

func TestNewDefaultGREAdapter(t *testing.T) {
	if err := elevate.DoAsSystem(func() error {
		adapter, err := NewDefaultGREAdapter()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if adapter == nil {
			t.Fatal("expected adapter, got nil")
		}

		if adapter.LUID() == 0 {
			t.Fatalf("expected luid, got 0")
		}

		if adapter.Adapter() == nil {
			t.Fatalf("expected adapter, got nil")
		}

		adapter.Start()
		time.Sleep(5 * time.Second)

		if err := adapter.Close(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		return nil
	}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestNewGREAdapter(t *testing.T) {
	adapterName := "test0"
	if err := elevate.DoAsSystem(func() error {
		adapter, err := NewGREAdapter(adapterName, net.ParseIP("100.100.0.0"), net.ParseIP("100.120.0.0"))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if adapter == nil {
			t.Fatal("expected adapter, got nil")
		}

		if adapter.LUID() == 0 {
			t.Fatalf("expected luid, got 0")
		}

		if adapter.Adapter() == nil {
			t.Fatalf("expected adapter, got nil")
		}

		adapter.Start()
		time.Sleep(5 * time.Minute)

		if err := adapter.Close(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		return nil
	}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
