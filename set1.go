package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"math"
	"math/bits"
)

// HexToBase64 converts a hex-encoded string to a Base64-encoded string.
func HexToBase64(s string) (string, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// XOR returns a xor b.
//
// It panics if a and b have different lengths.
func XOR(a, b []byte) []byte {
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

// NewSingleByteXORCipher returns a new single-byte XOR cipher.
func NewSingleByteXORCipher(key byte) cipher.Stream {
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

// Englishness scores b on how much it resembles English.
//
// Scores are length-normalized and between 0 and 1 inclusive. Higher is better.
//
// If len(b) == 0, Englishness returns 0.
func Englishness(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}

	weights := map[byte]float64{
		' ': 5,
		'e': 2,
		't': 2,
		'a': 2,
	}

	var n float64
	for _, v := range b {
		n += weights[v]
	}
	return n / float64(len(b))
}

// RecoverSingleByteXORKey returns the most likely key for a single-byte XOR
// ciphertext.
//
// It assumes the plaintext is English.
func RecoverSingleByteXORKey(ct []byte) byte {
	var (
		bestKey   byte
		bestScore float64 // Higher is better.
	)

	pt := make([]byte, len(ct))

	for i := range math.MaxUint8 {
		key := byte(i)

		NewSingleByteXORCipher(key).XORKeyStream(pt, ct)

		score := Englishness(pt)

		if score > bestScore {
			bestScore = score
			bestKey = key
		}
	}

	return bestKey
}

// FindSingleByteXORCiphertext returns the index of the ciphertext most likely
// to be single-byte XOR encrypted.
//
// FindSingleByteXORCiphertext returns -1 if no ciphertext was found.
func FindSingleByteXORCiphertext(cts [][]byte) int {
	if len(cts) == 0 {
		return -1
	}

	var (
		bestIndex int
		bestScore float64 // Higher is better.
	)

	for i, ct := range cts {
		pt := make([]byte, len(ct))

		for k := range math.MaxUint8 {
			key := byte(k)

			NewSingleByteXORCipher(key).XORKeyStream(pt, ct)

			score := Englishness(pt)

			if score > bestScore {
				bestScore = score
				bestIndex = i
			}
		}
	}

	return bestIndex
}

// repeatingKeyXORCipher represents a repeating-key XOR cipher.
type repeatingKeyXORCipher struct {
	key []byte
	i   int
}

// NewRepeatingKeyXORCipher returns a new repeating-key XOR cipher.
func NewRepeatingKeyXORCipher(key []byte) cipher.Stream {
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

// Hamming returns the Hamming distance between a and b.
//
// It panics if a and b have different lengths.
func Hamming(a, b []byte) int {
	if len(a) != len(b) {
		panic("different lengths")
	}

	var res int
	for i := range a {
		res += bits.OnesCount8(a[i] ^ b[i])
	}
	return res
}

// RecoverRepeatingKeyXORKeySize returns the most likely key size for a
// repeating-key XOR ciphertext, within lo to hi inclusive.
//
// It assumes that the plaintext is English.
//
// TODO: Avoid panicking when a or b is large compared to len(ct).
func RecoverRepeatingKeyXORKeySize(ct []byte, lo, hi int) int {
	if lo > hi {
		panic("lo > hi")
	}

	var (
		bestKeySize int
		bestScore   = math.MaxFloat64 // Lower is better.
	)

	for ks := lo; ks <= hi; ks++ {
		x, y := ct[:ks*4], ct[ks*4:ks*8]

		h := Hamming(x, y)

		score := float64(h) / float64(ks)

		if score < bestScore {
			bestScore = score
			bestKeySize = ks
		}
	}

	return bestKeySize
}

// RecoverRepeatingKeyXORKey returns the most likely key for a repeating-key
// XOR ciphertext.
//
// It assumes the plaintext is English. It also assumes that the key size is
// between 2 and 40 bytes.
func RecoverRepeatingKeyXORKey(ct []byte) []byte {
	var key []byte

	ks := RecoverRepeatingKeyXORKeySize(ct, 2, 40)

	for i := range ks {
		var b []byte
		for j := i; j < len(ct); j += ks {
			b = append(b, ct[j])
		}
		key = append(key, RecoverSingleByteXORKey(b))
	}

	return key
}

type ecbEncrypter struct {
	b cipher.Block
}

type ecbDecrypter struct {
	b cipher.Block
}

func (e ecbEncrypter) BlockSize() int {
	return e.b.BlockSize()
}

func (e ecbDecrypter) BlockSize() int {
	return e.b.BlockSize()
}

func (e ecbEncrypter) CryptBlocks(dst, src []byte) {
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
		e.b.Encrypt(dst, src)
		src = src[bs:]
		dst = dst[bs:]
	}
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

// newECBEncrypter returns a cipher.BlockMode which encrypts in electronic
// codebook mode.
func newECBEncrypter(b cipher.Block) cipher.BlockMode {
	return ecbEncrypter{b}
}

// newECBDecrypter returns a cipher.BlockMode which decrypts in electronic
// codebook mode.
func newECBDecrypter(b cipher.Block) cipher.BlockMode {
	return ecbDecrypter{b}
}

// isAESECBCiphertext returns true if b is likely to be AES-ECB encrypted.
func isAESECBCiphertext(b []byte) bool {
	return isECBCiphertext(b, aes.BlockSize)
}

// isECBCiphertext returns true if b is likely to be ECB encrypted.
func isECBCiphertext(b []byte, blockSize int) bool {
	if len(b)%blockSize != 0 {
		return false
	}

	// TODO: Use slices.Chunks once it's available in the standard library.
	seen := make(map[string]struct{})
	for i := 0; i < len(b); i += blockSize {
		block := string(b[i : i+blockSize])
		if _, ok := seen[block]; ok {
			return true
		}
		seen[block] = struct{}{}
	}
	return false
}
