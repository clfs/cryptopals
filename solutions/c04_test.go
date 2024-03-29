package solutions

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/clfs/cryptopals/xor"
)

func readHexLines(t *testing.T, name string) [][]byte {
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var res [][]byte

	s := bufio.NewScanner(f)
	for s.Scan() {
		b, err := hex.DecodeString(s.Text())
		if err != nil {
			t.Fatal(err)
		}
		res = append(res, b)
	}

	if err := s.Err(); err != nil {
		t.Fatal(err)
	}

	return res
}

func TestChallenge04(t *testing.T) {
	in := readHexLines(t, "testdata/4.txt")
	want := hexDecode(t, "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")

	got := xor.FindSingleByteCiphertext(in)
	if !bytes.Equal(want, got) {
		t.Errorf("want %x, got %x", want, got)
	}

	t.Logf("%q", xor.RecoverSingleBytePlaintext(got))
}
