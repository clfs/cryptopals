package solutions

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"testing"

	"github.com/clfs/cryptopals"
	"github.com/clfs/cryptopals/xor"
)

func readBase64(t *testing.T, name string) []byte {
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	res, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, f))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestChallenge06(t *testing.T) {
	in := readBase64(t, "testdata/6.txt")
	want := hexDecode(t, "5465726d696e61746f7220583a204272696e6720746865206e6f697365")

	got := xor.RecoverRepeatingKey(in, 2, 40)
	if !bytes.Equal(want, got) {
		t.Errorf("want %x, got %x", want, got)
	}

	t.Logf("%s", cryptopals.XORRepeat(in, got))
}
