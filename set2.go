package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"math"
	"math/big"
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

// newCBCDecrypter returns a cipher.BlockMode which decrypts in cipher block
// chaining mode.
func newCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("invalid iv length")
	}
	return &cbcDecrypter{b, iv}
}

// challenge11Encrypt returns an encryption of the given input, following
// specific steps provided in challenge 11.
//
// It randomly generates these parameters:
//
//   - A 16-byte key.
//   - A 16-byte IV.
//   - A prefix of 5 to 10 bytes.
//   - A suffix of 5 to 10 bytes.
//   - A boolean indicating whether to encrypt with AES-128-ECB or AES-128-CBC.
//
// It then returns encrypt(pad(prefix || input || suffix)).
//
// If ECB mode is chosen, the IV is discarded.
//
// TODO: Reduce the number of rand.Read calls.
func challenge11Encrypt(input []byte) []byte {
	var (
		big5 = big.NewInt(5)
		big6 = big.NewInt(6)
	)

	prefixLen, err := rand.Int(rand.Reader, big6) // [0, 6)
	if err != nil {
		panic(err)
	}

	suffixLen, err := rand.Int(rand.Reader, big6) // [0, 6)
	if err != nil {
		panic(err)
	}

	prefixLen.Add(prefixLen, big5) // [5, 11)
	suffixLen.Add(suffixLen, big5) // [5, 11)

	var (
		key    = make([]byte, 16)
		iv     = make([]byte, 16)
		prefix = make([]byte, prefixLen.Int64())
		suffix = make([]byte, suffixLen.Int64())
		useECB = make([]byte, 1)
	)

	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}
	if _, err := rand.Read(prefix); err != nil {
		panic(err)
	}
	if _, err := rand.Read(suffix); err != nil {
		panic(err)
	}
	if _, err := rand.Read(useECB); err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var mode cipher.BlockMode

	// Choose either ECB or CBC with 1:1 odds.
	if useECB[0]%2 == 0 {
		mode = newECBEncrypter(block)
	} else {
		mode = cipher.NewCBCEncrypter(block, iv)
	}

	var res []byte

	res = append(res, prefix...)
	res = append(res, input...)
	res = append(res, suffix...)

	res = pkcs7pad(res, mode.BlockSize())

	mode.CryptBlocks(res, res)

	return res
}

// challenge11Oracle takes a encryption function and calls it once.
// challenge11Oracle returns true if the encrypter used 128-bit ECB mode.
func challenge11Oracle(enc func([]byte) []byte) (isECB bool) {
	// Large enough to guarantee that 128-bit ECB mode outputs a repeated block.
	input := make([]byte, aes.BlockSize*3)
	ct := enc(input)
	return is128ECBCiphertext(ct)
}
