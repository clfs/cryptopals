package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"math"
	"math/big"
	"net/url"
	"slices"

	"github.com/google/uuid"
)

// PadPKCS7 returns a new slice that concatenates b with PKCS #7 padding to
// guarantee block size n.
func PadPKCS7(b []byte, n int) []byte {
	if n < 1 || n > math.MaxUint8 {
		panic("invalid block size")
	}

	p := byte(n - len(b)%n)

	padding := bytes.Repeat([]byte{p}, int(p))

	return slices.Concat(b, padding)
}

// UnpadPKCS7 returns a subslice of b with PKCS #7 padding removed.
func UnpadPKCS7(b []byte) []byte {
	n := int(b[len(b)-1])
	return b[:len(b)-n]
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

// NewCBCDecrypter returns a cipher.BlockMode which decrypts in cipher block
// chaining mode.
func NewCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("invalid iv length")
	}
	return &cbcDecrypter{b, iv}
}

// randBool returns a random boolean.
func randBool() bool {
	return randInt64(2) == 0
}

// NewECBOrCBCPrefixSuffixOracle returns a new oracle that encrypts inputs
// as described in challenge 11.
//
// The oracle returns encrypt(pad(prefix || input || suffix)) under either
// AES-128-ECB or AES-128-CBC.
func NewECBOrCBCPrefixSuffixOracle() func([]byte) []byte {
	var (
		key    = randBytes(16)
		iv     = randBytes(16)
		prefix = randBytes(5 + randInt64(6))
		suffix = randBytes(5 + randInt64(6))
		useECB = randBool()
	)

	return func(input []byte) []byte {
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		var mode cipher.BlockMode

		if useECB {
			mode = NewECBEncrypter(block)
		} else {
			mode = cipher.NewCBCEncrypter(block, iv)
		}

		res := slices.Concat(prefix, input, suffix)
		res = PadPKCS7(res, mode.BlockSize())

		mode.CryptBlocks(res, res)

		return res
	}
}

// IsECBOracle returns true if an encryption oracle uses ECB mode.
func IsECBOracle(oracle func([]byte) []byte) bool {
	bs := FindBlockSize(oracle)

	if bs == 1 {
		return false
	}

	// Choose an input large enough to guarantee that ECB encryption outputs a
	// repeated block.
	input := make([]byte, bs*3)
	ct := oracle(input)

	return IsECBCiphertext(ct, bs)
}

// NewECBSuffixOracle returns an oracle that encrypts inputs as described in
// challenge 12.
//
// The oracle returns encrypt(pad(input || secret)).
func NewECBSuffixOracle(secret []byte) func([]byte) []byte {
	key := randBytes(16)

	return func(input []byte) []byte {
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		mode := NewECBEncrypter(block)

		// input || secret
		b := slices.Concat(input, secret)

		// pad(input || secret)
		b = PadPKCS7(b, aes.BlockSize)

		// encrypt(pad(input || secret))
		mode.CryptBlocks(b, b)

		return b
	}
}

// FindBlockSize returns the block size used by an encryption oracle.
func FindBlockSize(oracle func([]byte) []byte) int {
	// Find the ciphertext length for a 1-byte input.
	input := make([]byte, 1)
	start := len(oracle(input))

	// Grow the input until the ciphertext length changes.
	n := start
	for n == start {
		input = append(input, 0)
		n = len(oracle(input))
	}

	// The delta is the block size.
	return n - start
}

// RecoverECBSuffixOracleSecret takes an encryption oracle that behaves as
// described in challenge 12 and recovers the secret used.
func RecoverECBSuffixOracleSecret(oracle func([]byte) []byte) []byte {
	bs := FindBlockSize(oracle)

	if !IsECBOracle(oracle) {
		panic("not ecb")
	}

	var res []byte

outer:
	for {
		// Choose an prefix length such that our 'guess' byte b will be the last
		// byte of a plaintext block.
		prefix := make([]byte, bs-(len(res)%bs)-1)

		// Create a reference output to compare guesses against.
		//
		// encrypt(prefix || secret || pad)
		want := oracle(prefix)

		for i := range math.MaxUint8 {
			b := byte(i)

			// prefix || res || b
			input := slices.Concat(prefix, res, []byte{b})

			// encrypt(prefix || res || b || secret || pad)
			output := oracle(input)

			// We now know these two values:
			//
			//  1. encrypt(prefix || secret || ... )
			//  2. encrypt(prefix || res || b || ... )
			//
			// Compare leading blocks to determine if b was the correct guess.
			if bytes.Equal(output[:len(input)], want[:len(input)]) {
				res = append(res, b)
				continue outer
			}
		}

		// No guesses were correct, so we're done.
		//
		// TODO: Use len(input) == len(want) as the completion criteria instead.
		break
	}

	// We guessed some padding as well, so remove it.
	//
	// TODO: Can we avoid guessing any padding?
	res = UnpadPKCS7(res)

	return res
}

// ProfileManager manages profiles as described in challenge 13.
type ProfileManager struct {
	key []byte
}

// NewProfileManager returns a new profile manager.
func NewProfileManager() *ProfileManager {
	key := randBytes(16)
	return &ProfileManager{key: key}
}

// NewUserProfile returns a new profile with user permissions.
func (p ProfileManager) NewUserProfile(email string) []byte {
	vals := url.Values{}

	vals.Add("email", email)
	vals.Add("uid", uuid.NewString())
	vals.Add("role", "user")

	res := []byte(vals.Encode())
	res = PadPKCS7(res, aes.BlockSize)

	block, err := aes.NewCipher(p.key)
	if err != nil {
		panic(err)
	}

	mode := NewECBEncrypter(block)
	mode.CryptBlocks(res, res)

	return res
}

// IsAdmin returns true if the profile has admin permissions.
func (p ProfileManager) IsAdmin(profile []byte) bool {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		panic(err)
	}

	pt := make([]byte, len(profile))

	mode := NewECBDecrypter(block)
	mode.CryptBlocks(pt, profile)

	pt = UnpadPKCS7(pt)

	vals, err := url.ParseQuery(string(pt))
	if err != nil {
		return false
	}

	return vals.Get("role") == "admin"
}

// NewAdminProfile performs a cut-and-paste ECB attack to create an admin
// profile from multiple user profiles.
//
// TODO: Is this possible to do without using an invalid TLD (.admin)?
func NewAdminProfile(m *ProfileManager) []byte {
	// Note that profileManager decodes profiles into url.Values, which exhibits
	// these behaviors:
	//
	//  - url.Values.Encode sorts by key.
	//  - url.Values.Get returns the first value only.

	// Force a1 to end in "&role=".
	//
	// |<-----a0----->||<-----a1----->||<-----a2----->|
	// email=acorns%40example.com&role=user&uid=...

	a := m.NewUserProfile("acorns@example.com")

	// Force b1 to start with "admin&".
	//
	// |<-----b0----->||<-----b1----->||<-----b2----->|
	// email=bagel%40x.admin&role=user&uid=...

	b := m.NewUserProfile("bagel@x.admin")

	// Put a1 and b1 next to each other to create the substring "&role=admin&".
	//
	// |<-----a0----->||<-----a1----->||<-----b1----->||<-----b2----->|
	// email=acorns%40example.com&role=admin&role=user&uid=...

	return append(a[:32], b[16:]...)
}

// randInt64 generates a random int64 using crypto/rand.Int.
func randInt64(max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(err)
	}
	return n.Int64()
}

// randBytes generates random bytes using crypto/rand.Read.
func randBytes(n int64) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// NewECBPrefixSuffixOracle returns an encryption oracle that behaves as
// described in challenge 14.
//
// It returns AES-128-ECB(key, prefix || input || secret). The key and prefix
// are random and fixed.
func NewECBPrefixSuffixOracle(secret []byte) func([]byte) []byte {
	var (
		key    = randBytes(16)
		prefix = randBytes(1 + randInt64(50))
	)

	return func(input []byte) []byte {
		b := slices.Concat(prefix, input, secret)
		b = PadPKCS7(b, aes.BlockSize)

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		mode := NewECBEncrypter(block)

		mode.CryptBlocks(b, b)

		return b
	}
}

// // recoverChallenge14Secret recovers the secret from a challenge 14 encryption
// // function.
// func recoverChallenge14Secret(enc func([]byte) []byte) []byte {
// 	// Skip finding the block size, since we've done that a few times already.
// 	bs := aes.BlockSize

// 	randBlock := randBytes(bs)
// 	for i := range bs {

// 	}
// }
