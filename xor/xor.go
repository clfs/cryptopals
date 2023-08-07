package xor

import (
	"github.com/clfs/cryptopals"
)

// RecoverSingleByteKey recovers the key of a single-byte xor'd ciphertext.
func RecoverSingleByteKey(ct []byte) byte {
	var (
		bestK byte
		bestP float64
	)

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

// FindSingleByteCiphertext finds the ciphertext most likely to be single-byte xor'd.
func FindSingleByteCiphertext(cts [][]byte) []byte {
	var (
		bestCt []byte
		bestP  float64
	)

	for _, ct := range cts {
		p := cryptopals.ProbabilityIsEnglish(RecoverSingleBytePlaintext(ct))
		if p > bestP {
			bestCt, bestP = ct, p
		}
	}

	return bestCt
}
