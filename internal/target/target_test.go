package target

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSingleAddress(t *testing.T) {
	hosts, err := Parse(context.Background(), []string{"192.168.1.1"}, Options{})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if hosts[0].V4.String() != "192.168.1.1" {
		t.Errorf("address = %s", hosts[0].V4)
	}
}

func TestParseCIDR(t *testing.T) {
	hosts, err := Parse(context.Background(), []string{"10.0.0.0/29"}, Options{})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	// A /29 has eight addresses; the network and broadcast addresses are
	// dropped by default.
	if len(hosts) != 6 {
		t.Fatalf("got %d hosts, want 6", len(hosts))
	}
	if hosts[0].V4.String() != "10.0.0.1" {
		t.Errorf("first host = %s, want 10.0.0.1", hosts[0].V4)
	}
	if hosts[len(hosts)-1].V4.String() != "10.0.0.6" {
		t.Errorf("last host = %s, want 10.0.0.6", hosts[len(hosts)-1].V4)
	}
}

func TestParseCIDRKeepsEdges(t *testing.T) {
	hosts, err := Parse(context.Background(), []string{"10.0.0.0/29"}, Options{
		IncludeNetworkAndBroadcast: true,
	})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if len(hosts) != 8 {
		t.Fatalf("got %d hosts, want 8", len(hosts))
	}
}

func TestParseWildcard(t *testing.T) {
	hosts, err := Parse(context.Background(), []string{"192.168.1.*"}, Options{})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if len(hosts) != 254 {
		t.Fatalf("got %d hosts, want 254", len(hosts))
	}
}

func TestParseRange(t *testing.T) {
	hosts, err := Parse(context.Background(), []string{"192.168.1.10-192.168.1.13"}, Options{})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if len(hosts) != 4 {
		t.Fatalf("got %d hosts, want 4", len(hosts))
	}
}

func TestParseShorthandRange(t *testing.T) {
	hosts, err := Parse(context.Background(), []string{"192.168.1.10-13"}, Options{})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if len(hosts) != 4 {
		t.Fatalf("got %d hosts, want 4", len(hosts))
	}
	if hosts[3].V4.String() != "192.168.1.13" {
		t.Errorf("last host = %s", hosts[3].V4)
	}
}

func TestParseCommaList(t *testing.T) {
	hosts, err := Parse(context.Background(), []string{"10.0.0.1,10.0.0.2,10.0.0.3"}, Options{})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("got %d hosts, want 3", len(hosts))
	}
}

func TestParseDeduplicates(t *testing.T) {
	hosts, err := Parse(context.Background(), []string{"10.0.0.1", "10.0.0.1", "10.0.0.2"}, Options{})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(hosts))
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	if err := os.WriteFile(path, []byte("# comment\n10.0.0.1\n\n10.0.0.2-10.0.0.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := Parse(context.Background(), []string{"@" + path}, Options{})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("got %d hosts, want 3", len(hosts))
	}
}

func TestParseExclusions(t *testing.T) {
	excl, err := ParseExclusions([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatalf("ParseExclusions returned an error: %v", err)
	}
	hosts, err := Parse(context.Background(), []string{"10.0.0.0/28"}, Options{ExcludeCIDRs: excl})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("got %d hosts, want 0", len(hosts))
	}
}

func TestParseMaxHosts(t *testing.T) {
	_, err := Parse(context.Background(), []string{"10.0.0.0/16"}, Options{MaxHosts: 100})
	if err == nil {
		t.Fatal("Parse succeeded, want an error")
	}
}

func TestParseRejectsHostname(t *testing.T) {
	if _, err := Parse(context.Background(), []string{"example.com"}, Options{}); err == nil {
		t.Fatal("Parse accepted a hostname without --resolve")
	}
}

func TestHostAddrs(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.1")
	v6 := netip.MustParseAddr("::1")

	h := Host{V4: v4}
	if got := h.Addrs(); len(got) != 1 || got[0] != v4 {
		t.Errorf("Addrs = %v", got)
	}
	if h.Any() != v4 {
		t.Errorf("Any = %s, want %s", h.Any(), v4)
	}

	dual := Host{V4: v4, V6: v6}
	got := dual.Addrs()
	if len(got) != 2 {
		t.Fatalf("Addrs = %v, want two entries", got)
	}
	if got[0] != v6 {
		t.Errorf("the IPv6 address should be preferred, got %s", got[0])
	}

	var empty Host
	if len(empty.Addrs()) != 0 {
		t.Error("an empty host should have no addresses")
	}
}

func BenchmarkParseCIDR24(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Parse(context.Background(), []string{"192.168.0.0/24"}, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}
