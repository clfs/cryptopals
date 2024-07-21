package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
)

// hexToBase64 converts a hex-encoded string to a Base64-encoded string.
func hexToBase64(s string) (string, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// xor returns a xor b.
//
// It panics if the lengths of a and b differ.
func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("different lengths")
	}
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res
}
