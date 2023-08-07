package solutions

import (
	"testing"

	"github.com/clfs/cryptopals"
	"github.com/clfs/cryptopals/xor"
)

func TestChallenge03(t *testing.T) {
	in := hexDecode(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	want := byte('X')

	got := xor.RecoverSingleByteKey(in)
	if want != got {
		t.Errorf("want %q, got %q", want, got)
	}

	t.Logf("%q", cryptopals.XORByte(in, got))
}
