package detect

import (
	"encoding/base64"
	"math/bits"
	"strconv"
)

// murmur3 computes the 32 bit MurmurHash3 (x86 variant) of data.
func murmur3(data []byte, seed uint32) uint32 {
	const c1 = 0xcc9e2d51
	const c2 = 0x1b873593

	h1 := seed
	blocks := len(data) / 4

	for i := 0; i < blocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	var k1 uint32
	tail := data[blocks*4:]
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

// FaviconHash returns the well known favicon fingerprint: the MurmurHash3
// of the base64 encoded favicon bytes, rendered as a signed decimal string
// and base64 encoded again.
func FaviconHash(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	sum := murmur3([]byte(encoded), 0)
	return base64.StdEncoding.EncodeToString([]byte(strconv.FormatInt(int64(int32(sum)), 10)))
}
