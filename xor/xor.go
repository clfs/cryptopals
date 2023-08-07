package xor

import (
	"github.com/clfs/cryptopals"
	"golang.org/x/exp/slices"
)

// RecoverSingleByteKey recovers the key of a single-byte xor'd ciphertext.
func RecoverSingleByteKey(ct []byte) byte {
	var bestK byte
	var bestP float64

	for k := 0; k <= 255; k++ {
		pt := cryptopals.XORByte(ct, byte(k))
		p := cryptopals.ProbabilityIsEnglish(pt)
		if p > bestP {
			bestK, bestP = byte(k), p
		}
	}

	return bestK
}

// RecoverSingleBytePlaintext recovers the plaintext from a single-byte xor'd
// ciphertext.
func RecoverSingleBytePlaintext(ct []byte) []byte {
	return cryptopals.XORByte(ct, RecoverSingleByteKey(ct))
}

// FindSingleByteXOR finds the ciphertext most likely to be single-byte xor'd.
// It panics if ct is empty.
func FindSingleByteXOR(cts [][]byte) []byte {
	cmp := func(a, b []byte) int {
		pa := cryptopals.ProbabilityIsEnglish(a)
		pb := cryptopals.ProbabilityIsEnglish(b)
		switch {
		case pa > pb:
			return 1
		case pa < pb:
			return -1
		default:
			return 0
		}
	}
	return slices.MaxFunc(cts, cmp)
}
