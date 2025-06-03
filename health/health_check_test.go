package health

import (
	"net"
	"testing"
	"time"
)

func TestHealthCheckBadStatus(t *testing.T) {
	var (
		hc    = NewHealthCheck()
		peers []string
		ok    bool
	)
	hc.SetNumExpected(3)
	hc.AddReachable(net.ParseIP("192.168.1.1"))

	peers, ok = hc.Status()
	if ok {
		t.Fatal("expected ok to be false")
	}

	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}

	time.Sleep(timeout + 1*time.Second)
	peers, ok = hc.Status()
	if ok {
		t.Fatal("expected ok to be false")
	}

	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
}

func TestHealthCheckGoodStatus(t *testing.T) {
	var (
		hc    = NewHealthCheck()
		peers []string
		ok    bool
	)
	hc.SetNumExpected(3)
	hc.AddReachable(net.ParseIP("192.168.1.1"))
	hc.AddReachable(net.ParseIP("192.168.1.2"))

	peers, ok = hc.Status()
	if ok {
		t.Fatal("expected ok to be false")
	}

	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}

	time.Sleep(1 * time.Second)
	hc.AddReachable(net.ParseIP("192.168.1.3"))
	time.Sleep(pollInterval + 1*time.Second)

	peers, ok = hc.Status()
	if !ok {
		t.Fatal("expected ok to be true")
	}

	if len(peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(peers))
	}
}
