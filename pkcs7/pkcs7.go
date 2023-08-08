package pkcs7

import "bytes"

func repeat(b byte) []byte {
	return bytes.Repeat([]byte{b}, int(b))
}

func Pad(b []byte, n int) []byte {
	if n <= 0 {
		panic("invalid block size")
	}
	if len(b)%n == 0 {
		return append(b, repeat(byte(n))...)
	}
	return append(b, repeat(byte(n-len(b)%n))...)
}
