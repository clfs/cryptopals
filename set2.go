package cryptopals

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"math"
)

// pkcs7pad appends PKCS#7 padding to b to guarantee block size n. It returns
// the updated slice.
func pkcs7pad(b []byte, n int) []byte {
	if n < 0 || n > math.MaxUint8 {
		panic("invalid block size")
	}

	p := byte(n - len(b)%n)

	padding := bytes.Repeat([]byte{p}, int(p))

	return append(b, padding...)
}

type cbcDecrypter struct {
	b  cipher.Block
	iv []byte
}

func (c *cbcDecrypter) BlockSize() int {
	return c.b.BlockSize()
}

func (c *cbcDecrypter) CryptBlocks(dst, src []byte) {
	bs := c.b.BlockSize()

	if len(src)%bs != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("dst too small")
	}
	if len(src) == 0 {
		return
	}

	// Loop over the blocks backwards to reduce copying.
	//
	// See crypto/cipher/cbc.go in the standard library for the technique
	// this is inspired by.

	var (
		prev  = len(src) - 2*bs // Start of the previous block.
		start = len(src) - bs   // Start of the current block.
		end   = len(src)        // End of the current block.
	)

	// Save this to use as the new IV later.
	tmp := bytes.Clone(src[start:end])

	// Loop over every block but the first one.
	for start > 0 {
		// Decrypt the current ciphertext block into the current plaintext block.
		c.b.Decrypt(dst[start:end], src[start:end])

		// XOR the previous ciphertext block into the current plaintext block.
		subtle.XORBytes(dst[start:end], dst[start:end], src[prev:start])

		// Move backwards a block.
		end -= bs
		start -= bs
		prev -= bs
	}

	// The first block uses the IV in place of a "previous ciphertext block".
	c.b.Decrypt(dst[start:end], src[start:end])
	subtle.XORBytes(dst[start:end], dst[start:end], c.iv)

	// Update the IV in preparation for subsequent calls.
	c.iv = tmp
}

func newCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("invalid iv length")
	}
	return &cbcDecrypter{b, iv}
}
