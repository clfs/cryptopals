package solutions

import (
	"crypto/aes"
	"testing"

	"github.com/clfs/cryptopals"
	"github.com/clfs/cryptopals/cbc"
)

func TestChallenge10(t *testing.T) {
	in := readBase64(t, "testdata/10.txt")
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	mode := cbc.NewDecrypter(block, iv)
	got := make([]byte, len(in))
	mode.CryptBlocks(got, in)

	if cryptopals.ProbabilityIsEnglish(got) < 0.95 {
		t.Errorf("non-English plaintext: %x", got)
	} else {
		t.Logf("%s", got)
	}
}
