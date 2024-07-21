package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"math"
	"math/bits"
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

// newSingleByteXORCipher returns a new single-byte XOR cipher.
func newSingleByteXORCipher(key byte) cipher.Stream {
	return singleByteXORCipher{key: key}
}

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

// repeatingKeyXORCipher represents a repeating-key XOR cipher.
type repeatingKeyXORCipher struct {
	key []byte
	i   int
}

// newRepeatingKeyXORCipher returns a new repeating-key XOR cipher.
func newRepeatingKeyXORCipher(key []byte) cipher.Stream {
	return &repeatingKeyXORCipher{key: key}
}

func (r *repeatingKeyXORCipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("dst too small")
	}
	for i := range src {
		dst[i] = src[i] ^ r.key[r.i]
		r.i = (r.i + 1) % len(r.key)
	}
}

// hamming returns the Hamming distance between a and b.
//
// It panics if a and b have different lengths.
func hamming(a, b []byte) int {
	if len(a) != len(b) {
		panic("different lengths")
	}

	var res int
	for i := range a {
		res += bits.OnesCount8(a[i] ^ b[i])
	}
	return res
}

// recoverRepeatingKeyXORKeySize returns the most likely key size for a
// repeating-key XOR ciphertext, within a to b inclusive.
//
// It assumes that the plaintext is English.
//
// TODO: Avoid panicking when a or b is large compared to len(ct).
func recoverRepeatingKeyXORKeySize(ct []byte, a, b int) int {
	var (
		bestKeySize int
		bestScore   = math.MaxFloat64 // lower is better
	)

	for ks := a; ks <= b; ks++ {
		x, y := ct[:ks*4], ct[ks*4:ks*8]
		h := hamming(x, y)

		score := float64(h) / float64(ks)

		if score < bestScore {
			bestScore = score
			bestKeySize = ks
		}
	}

	return bestKeySize
}

// recoverRepeatingKeyXORKey returns the most likely key for a repeating-key
// XOR ciphertext.
//
// It assumes the plaintext is English.
//
// It also assumes that the key size is between 2 and 40 bytes.
func recoverRepeatingKeyXORKey(ct []byte) []byte {
	var key []byte

	ks := recoverRepeatingKeyXORKeySize(ct, 2, 40)

	for i := range ks {
		var column []byte
		for j := i; j < len(ct); j += ks {
			column = append(column, ct[j])
		}
		key = append(key, recoverSingleByteXORKey(column))
	}

	return key
}

type ecbDecrypter struct {
	b cipher.Block
}

func (e ecbDecrypter) BlockSize() int {
	return e.b.BlockSize()
}

func (e ecbDecrypter) CryptBlocks(dst, src []byte) {
	bs := e.b.BlockSize()

	if len(src)%bs != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("dst too small")
	}
	if len(src) == 0 {
		return
	}

	for len(src) > 0 {
		e.b.Decrypt(dst, src)
		src = src[bs:]
		dst = dst[bs:]
	}
}

// newECBDecrypter returns a cipher.BlockMode which decrypts in electronic
// codebook mode.
func newECBDecrypter(b cipher.Block) cipher.BlockMode {
	return ecbDecrypter{b}
}
