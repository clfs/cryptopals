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

// pkcs7pad appends PKCS#7 padding to b to guarantee block size n. It returns
// the updated slice.
//
// TODO: Stop modifying the input slice.
func pkcs7pad(b []byte, n int) []byte {
	if n < 0 || n > math.MaxUint8 {
		panic("invalid block size")
	}

	p := byte(n - len(b)%n)

	padding := bytes.Repeat([]byte{p}, int(p))

	return append(b, padding...)
}

// pkcs7unpad returns a new slice with PKCS#7 padding removed.
func pkcs7unpad(b []byte) []byte {
	n := int(b[len(b)-1])
	return bytes.Clone(b[:len(b)-n])
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

// newCBCDecrypter returns a cipher.BlockMode which decrypts in cipher block
// chaining mode.
func newCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("invalid iv length")
	}
	return &cbcDecrypter{b, iv}
}

// challenge11Encrypt returns an encryption of the given input, following
// specific steps provided in challenge 11.
//
// It randomly generates these parameters:
//
//   - A 16-byte key.
//   - A 16-byte IV.
//   - A prefix of 5 to 10 bytes.
//   - A suffix of 5 to 10 bytes.
//   - A boolean indicating whether to encrypt with AES-128-ECB or AES-128-CBC.
//
// It then returns encrypt(pad(prefix || input || suffix)).
//
// If ECB mode is chosen, the IV is discarded.
//
// TODO: Reduce the number of rand.Read calls.
//
// TODO: Refactor this to return a function.
//
// TODO: Pick a more appropriate name for the function.
func challenge11Encrypt(input []byte) []byte {
	var (
		big5 = big.NewInt(5)
		big6 = big.NewInt(6)
	)

	prefixLen, err := rand.Int(rand.Reader, big6) // [0, 6)
	if err != nil {
		panic(err)
	}

	suffixLen, err := rand.Int(rand.Reader, big6) // [0, 6)
	if err != nil {
		panic(err)
	}

	prefixLen.Add(prefixLen, big5) // [5, 11)
	suffixLen.Add(suffixLen, big5) // [5, 11)

	var (
		key    = make([]byte, 16)
		iv     = make([]byte, 16)
		prefix = make([]byte, prefixLen.Int64())
		suffix = make([]byte, suffixLen.Int64())
		useECB = make([]byte, 1)
	)

	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}
	if _, err := rand.Read(prefix); err != nil {
		panic(err)
	}
	if _, err := rand.Read(suffix); err != nil {
		panic(err)
	}
	if _, err := rand.Read(useECB); err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var mode cipher.BlockMode

	// Choose either ECB or CBC with 1:1 odds.
	if useECB[0]%2 == 0 {
		mode = newECBEncrypter(block)
	} else {
		mode = cipher.NewCBCEncrypter(block, iv)
	}

	var res []byte

	res = append(res, prefix...)
	res = append(res, input...)
	res = append(res, suffix...)

	res = pkcs7pad(res, mode.BlockSize())

	mode.CryptBlocks(res, res)

	return res
}

// challenge11Oracle takes a encryption function and calls it once.
// challenge11Oracle returns true if the encryption function used 128-bit ECB
// mode.
func challenge11Oracle(enc func([]byte) []byte) (isECB bool) {
	// Large enough to guarantee that 128-bit ECB mode outputs a repeated block.
	input := make([]byte, aes.BlockSize*3)
	ct := enc(input)
	return is128ECBCiphertext(ct)
}

// newChallenge12EncryptFunc returns a function that encrypts inputs under the
// scheme described in challenge 12.
//
// The function follows these steps:
//  1. It appends a secret suffix to the input.
//  2. It encrypts the result under ECB mode with a consistent key.
//
// TODO: Pick a more appropriate name for the function.
func newChallenge12EncryptFunc(suffix []byte) func([]byte) []byte {
	key := make([]byte, 16)

	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	mode := newECBEncrypter(block)

	return func(input []byte) []byte {
		// input || suffix
		b := slices.Concat(input, suffix)

		// pad(input || suffix)
		b = pkcs7pad(b, aes.BlockSize)

		// encrypt(k, pad(input || suffix))
		mode.CryptBlocks(b, b)

		return b
	}
}

// gcd returns the greatest common divisor of two non-negative integers.
func gcd(x, y int) int {
	if x < 0 || y < 0 {
		panic("negative")
	}
	for y != 0 {
		x, y = y, x%y
	}
	return x
}

// recoverChallenge12Suffix takes a challenge-12 encryption function and
// recovers the secret suffix used.
func recoverChallenge12Suffix(enc func([]byte) []byte) []byte {
	// Recover the block size by taking the greatest common divisor of 100
	// ciphertext lengths.
	var (
		input []byte
		bs    int
	)

	for range 100 {
		input = append(input, 0)
		ct := enc(input)
		bs = gcd(bs, len(ct))
	}

	// Confirm that the encryption function is using ECB.
	if !is128ECBCiphertext(enc(input)) {
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
		want := enc(prefix)

		for i := range math.MaxUint8 {
			b := byte(i)

			// prefix || res || b
			input = slices.Concat(prefix, res, []byte{b})

			// encrypt(prefix || res || b || secret || pad)
			output := enc(input)

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
	res = pkcs7unpad(res)

	return res
}

// profileManager manages profiles as described in challenge 13.
type profileManager struct {
	key []byte
}

// newProfileManager returns a new profile manager.
func newProfileManager() *profileManager {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &profileManager{key: key}
}

// newUserProfile returns a new profile with user permissions.
func (p profileManager) newUserProfile(email string) []byte {
	vals := url.Values{}

	vals.Add("email", email)
	vals.Add("uid", uuid.NewString())
	vals.Add("role", "user")

	res := []byte(vals.Encode())
	res = pkcs7pad(res, aes.BlockSize)

	block, err := aes.NewCipher(p.key)
	if err != nil {
		panic(err)
	}

	mode := newECBEncrypter(block)
	mode.CryptBlocks(res, res)

	return res
}

// isAdmin returns true if the profile has admin permissions.
func (p profileManager) isAdmin(profile []byte) bool {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		panic(err)
	}

	pt := make([]byte, len(profile))

	mode := newECBDecrypter(block)
	mode.CryptBlocks(pt, profile)

	pt = pkcs7unpad(pt)

	vals, err := url.ParseQuery(string(pt))
	if err != nil {
		return false
	}

	return vals.Get("role") == "admin"
}

// newAdminProfile performs a cut-and-paste ECB attack to create an admin
// profile from multiple user profiles.
//
// TODO: Is this possible to do without using an invalid TLD (.admin)?
func newAdminProfile(m *profileManager) []byte {
	// Note that profileManager decodes profiles into url.Values, which exhibits
	// these behaviors:
	//
	//  - url.Values.Encode sorts by key.
	//  - url.Values.Get returns the first value only.

	// Force a1 to end in "&role=".
	//
	// |<-----a0----->||<-----a1----->||<-----a2----->|
	// email=acorns%40example.com&role=user&uid=...

	a := m.newUserProfile("acorns@example.com")

	// Force b1 to start with "admin&".
	//
	// |<-----b0----->||<-----b1----->||<-----b2----->|
	// email=bagel%40x.admin&role=user&uid=...

	b := m.newUserProfile("bagel@x.admin")

	// Put a1 and b1 next to each other to create the substring "&role=admin&".
	//
	// |<-----a0----->||<-----a1----->||<-----b1----->||<-----b2----->|
	// email=acorns%40example.com&role=admin&role=user&uid=...

	return append(a[:32], b[16:]...)
}
