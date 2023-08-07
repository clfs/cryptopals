package xor

import (
	"math"

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

// RecoverRepeatingKey recovers the key from a repeating-key xor'd ciphertext.
// It assumes the key size is between a and b inclusive.
//
// It panics if a > b.
//
// TODO: It also panics if 8 * b > len(ct). Fix that.
func RecoverRepeatingKey(ct []byte, a, b int) []byte {
	keySize := findRepeatingKeySize(ct, a, b)
	chunkSize := (len(ct) + keySize - 1) / keySize

	var (
		key   = make([]byte, keySize)
		chunk = make([]byte, chunkSize)
	)

	for i := range key {
		// Read the chunk.
		for j := range chunk {
			k := j*keySize + i
			if k < len(ct) {
				chunk[j] = ct[k]
			}
		}

		// Find one byte of key material.
		key[i] = RecoverSingleByteKey(chunk)
	}

	return key
}

// findRepeatingKeySize estimates a likely key size for a repeating-key xor'd
// ciphertext. The estimated key size is between a and b inclusive.
func findRepeatingKeySize(ct []byte, a, b int) int {
	var (
		bestKeySize int
		bestScore   = math.MaxFloat64 // lower is better
	)

	for ks := a; ks <= b; ks++ {
		x, y := ct[:ks*4], ct[ks*4:ks*8]
		h := cryptopals.HammingDistance(x, y)

		score := float64(h) / float64(ks)
		if score < bestScore {
			bestKeySize = ks
			bestScore = score
		}
	}

	return bestKeySize
}
