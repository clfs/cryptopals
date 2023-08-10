package cbc

import (
	"crypto/cipher"
	"crypto/subtle"

	"github.com/clfs/cryptopals/alias"
)

type decrypter struct {
	b  cipher.Block
	iv []byte
}

func (d *decrypter) BlockSize() int {
	return d.b.BlockSize()
}

func (d *decrypter) CryptBlocks(dst, src []byte) {
	bs := d.b.BlockSize()

	if len(src)%bs != 0 {
		panic("cbc: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("cbc: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cbc: invalid buffer overlap")
	}
	if len(src) == 0 {
		return
	}

	iv := d.iv

	for len(src) > 0 {
		d.b.Decrypt(dst, src)
		subtle.XORBytes(dst, dst, iv)
		iv = src[:bs]
		src = src[bs:]
		dst = dst[bs:]
	}

	d.iv = iv
}

func NewDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cbc: invalid iv length")
	}
	return &decrypter{b, iv}
}
