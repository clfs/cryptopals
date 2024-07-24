package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"testing"
)

func TestChallenge9(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	n := 20
	want := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	got := PKCS7Pad(in, n)
	if !bytes.Equal(want, got) {
		t.Errorf("want %q, got %q", want, got)
	}
}

func TestChallenge10(t *testing.T) {
	in := decodeBase64FromFile(t, "testdata/10.txt")
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	want := []byte("I'm back and I'm ringin' the bell \nA rockin' on") // first few bytes

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	mode := newCBCDecrypter(block, iv)

	mode.CryptBlocks(in, in)

	got := in[:len(want)]
	if !bytes.Equal(want, got) {
		t.Errorf("wrong first bytes: want %q, got %q", want, got)
	}

	t.Logf("plaintext: %q", in)
}

func TestChallenge11(t *testing.T) {
	var (
		nECB int
		nCBC int
	)

	for range 100 {
		oracle := newECBOrCBCPrefixSuffixOracle()
		if isECBOracle(oracle) {
			nECB++
		} else {
			nCBC++
		}
	}

	// Within 4 standard deviations.
	if nECB < 30 || nECB > 70 {
		t.Errorf("bias: nECB=%d, nCBC=%d", nECB, nCBC)
	}

	t.Logf("nECB=%d, nCBC=%d", nECB, nCBC)
}

// decodeBase64 is a wrapper around base64.StdEncoding.DecodeString for testing.
func decodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestChallenge12(t *testing.T) {
	secret := decodeBase64(t, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	enc := newChallenge12EncryptFunc(secret)

	got := recoverChallenge12Suffix(enc)

	if !bytes.Equal(secret, got) {
		// Avoid revealing the answer if the test fails.
		t.Error("got wrong value for secret")
	}

	t.Logf("got: %q", got)
}

func TestChallenge13(t *testing.T) {
	m := newProfileManager()

	profile := newAdminProfile(m)

	if !m.isAdmin(profile) {
		t.Errorf("not an admin profile: %x", profile)
	}
}
