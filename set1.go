package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"math"
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

// singleByteXORCipher represents a single-byte XOR cipher.
type singleByteXORCipher struct {
	key byte
}

var _ cipher.Stream = singleByteXORCipher{}

func (s singleByteXORCipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("dst too small")
	}
	for i := range src {
		dst[i] = src[i] ^ s.key
	}
}

// englishness scores s on how much it resembles English.
//
// Scores are length-normalized and between 0 and 1 inclusive. Higher is better.
//
// If s is empty, it returns 0.
func englishness(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}

	var points int

	for i := range b {
		switch b[i] {
		case ' ':
			points += 5
		case 'e', 't', 'a':
			points += 2
		}
	}

	normalized := float64(points) / float64(len(b))

	return normalized
}

// recoverSingleByteXORKey returns the most likely key for a single-byte XOR
// ciphertext.
//
// It assumes the plaintext is English.
func recoverSingleByteXORKey(ct []byte) byte {
	var (
		bestKey   byte
		bestScore float64 // higher is better
	)

	pt := make([]byte, len(ct))

	for i := range math.MaxUint8 {
		key := byte(i)
		cipher := singleByteXORCipher{key: key}

		cipher.XORKeyStream(pt, ct)

		score := englishness(pt)

		if score > bestScore {
			bestScore = score
			bestKey = key
		}
	}

	return bestKey
}

// findSingleByteXORCiphertext returns the ciphertext most likely to be
// single-byte XOR encrypted.
//
// TODO: This should take an iter.Seq instead.
func findSingleByteXORCiphertext(cts [][]byte) []byte {
	if len(cts) == 0 {
		panic("no ciphertexts")
	}

	var (
		bestCt    []byte
		bestScore float64 // higher is better
	)

	for _, ct := range cts {
		pt := make([]byte, len(ct))

		for i := range math.MaxUint8 {
			key := byte(i)
			cipher := singleByteXORCipher{key: key}

			cipher.XORKeyStream(pt, ct)

			score := englishness(pt)

			if score > bestScore {
				bestScore = score
				bestCt = ct
			}
		}
	}

	return bestCt
}
