// Package ecb implements the electronic codebook (ECB) block cipher mode.
package ecb

import (
	"crypto/cipher"

	"github.com/clfs/cryptopals/alias"
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
