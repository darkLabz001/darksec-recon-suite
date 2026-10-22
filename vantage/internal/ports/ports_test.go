package ports

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		spec string
		tcp  []uint16
		udp  []uint16
	}{
		{"single port", "80", []uint16{80}, nil},
		{"range", "1-3", []uint16{1, 2, 3}, nil},
		{"range with spaces", " 10 - 12 ", []uint16{10, 11, 12}, nil},
		{"list", "22,80,443", []uint16{22, 80, 443}, nil},
		{"mixed list", "22 80,443", []uint16{22, 80, 443}, nil},
		{"tcp prefix", "T:80,443", []uint16{80, 443}, nil},
		{"udp prefix", "U:53,67", nil, []uint16{53, 67}},
		{"both prefixes", "T:80,U:53", []uint16{80}, []uint16{53}},
		{"duplicates are removed", "80,80,80", []uint16{80}, nil},
		{"sorted output", "443,22,80", []uint16{22, 80, 443}, nil},
		{"empty", "", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, err := Parse(tt.spec)
			if err != nil {
				t.Fatalf("Parse(%q) returned an error: %v", tt.spec, err)
			}
			if !reflect.DeepEqual(set.TCP, tt.tcp) {
				t.Errorf("TCP = %v, want %v", set.TCP, tt.tcp)
			}
			if !reflect.DeepEqual(set.UDP, tt.udp) {
				t.Errorf("UDP = %v, want %v", set.UDP, tt.udp)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	for _, spec := range []string{"0", "65536", "abc", "1-", "-5", "80-70", "X:80", "1-2-3"} {
		if _, err := Parse(spec); err == nil {
			t.Errorf("Parse(%q) succeeded, want an error", spec)
		}
	}
}

func TestParseFullRange(t *testing.T) {
	set, err := Parse("-")
	if err != nil {
		t.Fatalf("Parse(\"-\") returned an error: %v", err)
	}
	if len(set.TCP) != 65535 {
		t.Fatalf("full range has %d ports, want 65535", len(set.TCP))
	}
	if set.TCP[0] != 1 || set.TCP[len(set.TCP)-1] != 65535 {
		t.Errorf("full range bounds = %d..%d", set.TCP[0], set.TCP[len(set.TCP)-1])
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports.txt")
	content := "# a comment\n\n80\n443,8080\nU:53\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	set, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned an error: %v", err)
	}
	if !reflect.DeepEqual(set.TCP, []uint16{80, 443, 8080}) {
		t.Errorf("TCP = %v", set.TCP)
	}
	if !reflect.DeepEqual(set.UDP, []uint16{53}) {
		t.Errorf("UDP = %v", set.UDP)
	}
}

func TestTop(t *testing.T) {
	top := Top(10)
	if len(top) != 10 {
		t.Fatalf("Top(10) has %d entries, want 10", len(top))
	}
	for i := 1; i < len(top); i++ {
		if top[i] == top[i-1] {
			t.Errorf("Top(10) contains the duplicate port %d", top[i])
		}
	}
	if len(Top(TopLen()+100)) != TopLen() {
		t.Error("Top does not clamp to the length of the list")
	}
	if Top(0) != nil {
		t.Error("Top(0) should be empty")
	}
}

func TestTopUDP(t *testing.T) {
	top := TopUDP(10)
	if len(top) != 10 {
		t.Fatalf("TopUDP(10) has %d entries, want 10", len(top))
	}
	for i := 1; i < len(top); i++ {
		if top[i] == top[i-1] {
			t.Errorf("TopUDP(10) contains the duplicate port %d", top[i])
		}
	}
}

func TestExclude(t *testing.T) {
	list := []uint16{20, 22, 25, 80}
	got := Exclude(list, []uint16{22, 80})
	if !reflect.DeepEqual(got, []uint16{20, 25}) {
		t.Errorf("Exclude = %v, want [20 25]", got)
	}
	if got := Exclude(list, nil); !reflect.DeepEqual(got, list) {
		t.Errorf("Exclude with no exclusions changed the list: %v", got)
	}
}

func TestMerge(t *testing.T) {
	a := Set{TCP: []uint16{80, 443}}
	b := Set{TCP: []uint16{22, 80}, UDP: []uint16{53}}
	got := Merge(a, b)
	if !reflect.DeepEqual(got.TCP, []uint16{22, 80, 443}) {
		t.Errorf("merged TCP = %v", got.TCP)
	}
	if !reflect.DeepEqual(got.UDP, []uint16{53}) {
		t.Errorf("merged UDP = %v", got.UDP)
	}
}

func TestSetHelpers(t *testing.T) {
	var empty Set
	if !empty.Empty() {
		t.Error("the zero set should be empty")
	}
	s := Set{TCP: []uint16{80}, UDP: []uint16{53}}
	if s.Empty() {
		t.Error("a populated set should not be empty")
	}
	if s.Count() != 2 {
		t.Errorf("Count = %d, want 2", s.Count())
	}
	if !reflect.DeepEqual(s.For(UDP), []uint16{53}) {
		t.Errorf("For(UDP) = %v", s.For(UDP))
	}
}

func BenchmarkParseFullRange(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Parse("1-65535"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseTopList(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Parse("80,443,22,21,25,53,23,3389,8080,8443"); err != nil {
			b.Fatal(err)
		}
	}
}
