package cryptopals

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestChallenge9(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	n := 20
	want := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	got := pkcs7pad(in, n)
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