package solutions

import (
	"crypto/aes"
	"testing"

	"github.com/clfs/cryptopals"
	"github.com/clfs/cryptopals/ecb"
)

func TestChallenge07(t *testing.T) {
	in := readBase64(t, "testdata/7.txt")
	key := []byte("YELLOW SUBMARINE")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	mode := ecb.NewDecrypter(block)
	got := make([]byte, len(in))
	mode.CryptBlocks(got, in)

	if cryptopals.ProbabilityIsEnglish(got) < 0.95 {
		t.Errorf("non-English plaintext: %q", got)
	}

	t.Logf("%s", got)
}
