package cryptopals

import (
	"bytes"
	"math"
)

// pkcs7pad appends PKCS#7 padding to b to guarantee block size n. It returns
// the updated slice.
func pkcs7pad(b []byte, n int) []byte {
	if n < 0 || n >= math.MaxUint8 {
		panic("invalid block size")
	}

	p := byte(n - len(b)%n)

	padding := bytes.Repeat([]byte{p}, int(p))

	return append(b, padding...)
}
