package detect

import (
	"encoding/base64"
	"testing"
)

func TestMurmur3Vectors(t *testing.T) {
	// Reference values produced by the canonical MurmurHash3 x86 32 bit
	// implementation with a zero seed.
	vectors := []struct {
		in   string
		want uint32
	}{
		{"", 0},
		{"hello", 613153351},
		{"a", 0x3c2569b2},
		{"abc", 0xb3dd93fa},
		{"The quick brown fox jumps over the lazy dog", 0x2e4ff723},
	}

	for _, v := range vectors {
		if got := murmur3([]byte(v.in), 0); got != v.want {
			t.Errorf("murmur3(%q) = %d, want %d", v.in, got, v.want)
		}
	}
}

func TestMurmur3SeedChangesResult(t *testing.T) {
	a := murmur3([]byte("vantage"), 0)
	b := murmur3([]byte("vantage"), 1)
	if a == b {
		t.Error("different seeds produced the same hash")
	}
}

func TestMurmur3LengthBlocks(t *testing.T) {
	// Exercise the tail handling for every possible remainder.
	base := murmur3([]byte("0123456789abcdef"), 0)
	for i := 0; i < 4; i++ {
		got := murmur3([]byte("0123456789abcdef")[:4+i], 0)
		if got == base {
			t.Errorf("hash of a %d byte prefix collided with the full block", 4+i)
		}
	}
}

func TestFaviconHash(t *testing.T) {
	// The favicon fingerprint is the base64 encoding of the signed
	// decimal rendering of the MurmurHash3 of the base64 encoded icon.
	icon := []byte("favicon bytes")
	encoded := base64.StdEncoding.EncodeToString(icon)
	sum := int32(murmur3([]byte(encoded), 0))

	want := base64.StdEncoding.EncodeToString([]byte(itoa(int64(sum))))
	if got := FaviconHash(icon); got != want {
		t.Errorf("FaviconHash = %q, want %q", got, want)
	}
}

func TestFaviconHashIsStable(t *testing.T) {
	icon := []byte{0x00, 0x01, 0x02, 0x03, 0xff}
	if FaviconHash(icon) != FaviconHash(icon) {
		t.Error("FaviconHash is not deterministic")
	}
	if FaviconHash(icon) == FaviconHash([]byte{0x00, 0x01, 0x02, 0x03, 0xfe}) {
		t.Error("FaviconHash collided for different icons")
	}
}

// itoa renders a signed integer the way strconv.FormatInt does, without
// pulling strconv into the test's expectations.
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [24]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
