// Package ecb implements the electronic codebook (ECB) block cipher mode.
package ecb

import (
	"crypto/cipher"

	"github.com/clfs/cryptopals/alias"
	"golang.org/x/exp/slices"
)

type encrypter struct {
	b cipher.Block
}

type decrypter struct {
	b cipher.Block
}

func (e encrypter) BlockSize() int {
	return e.b.BlockSize()
}

func (d decrypter) BlockSize() int {
	return d.b.BlockSize()
}

func (e encrypter) CryptBlocks(dst, src []byte) {
	bs := e.b.BlockSize()

	if len(src)%bs != 0 {
		panic("ecb: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("ecb: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("ecb: invalid buffer overlap")
	}
	if len(src) == 0 {
		return
	}

	for len(src) > 0 {
		e.b.Encrypt(dst, src)
		src = src[bs:]
		dst = dst[bs:]
	}
}

func (d decrypter) CryptBlocks(dst, src []byte) {
	bs := d.b.BlockSize()

	if len(src)%bs != 0 {
		panic("ecb: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("ecb: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("ecb: invalid buffer overlap")
	}
	if len(src) == 0 {
		return
	}

	for len(src) > 0 {
		d.b.Decrypt(dst, src)
		src = src[bs:]
		dst = dst[bs:]
	}
}

// NewEncrypter returns a cipher.BlockMode which encrypts in electronic codebook
// mode, using the given cipher.Block.
func NewEncrypter(b cipher.Block) cipher.BlockMode {
	return encrypter{b}
}

// NewDecrypter returns a cipher.BlockMode which decrypts in electronic codebook
// mode, using the given cipher.Block.
func NewDecrypter(b cipher.Block) cipher.BlockMode {
	return decrypter{b}
}

// FindCiphertext finds the first ciphertext likely to be ECB-encrypted.
// If none of the ciphertexts are candidates, it returns nil.
func FindCiphertext(cts [][]byte) []byte {
	i := slices.IndexFunc(cts, isECB)
	if i == -1 {
		return nil
	}
	return cts[i]
}

// isECB returns true if a 16-byte block shows up more than once.
func isECB(ct []byte) bool {
	seen := make(map[[16]byte]struct{})
	for i := 0; i < len(ct); i += 16 {
		var block [16]byte
		copy(block[:], ct[i:i+16])
		if _, ok := seen[block]; ok {
			return true
		}
		seen[block] = struct{}{}
	}
	return false
}
