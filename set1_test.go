package cryptopals

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"slices"
	"testing"
)

func TestChallenge1(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	got, err := hexToBase64(in)
	if err != nil {
		t.Error(err)
	}

	if want != got {
		t.Errorf("want %q, got %q", want, got)
	}
}

// decodeHex wraps hex.DecodeString for testing.
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestChallenge2(t *testing.T) {
	a := decodeHex(t, "1c0111001f010100061a024b53535009181c")
	b := decodeHex(t, "686974207468652062756c6c277320657965")
	want := decodeHex(t, "746865206b696420646f6e277420706c6179")

	got := xor(a, b)
	if !bytes.Equal(want, got) {
		t.Errorf("want %q, got %q", want, got)
	}
}

func TestChallenge3(t *testing.T) {
	ct := decodeHex(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	want := byte(88)

	got := recoverSingleByteXORKey(ct)

	if want != got {
		t.Errorf("want %d, got %d", want, got)
	}

	newSingleByteXORCipher(got).XORKeyStream(ct, ct)
	t.Logf("plaintext: %q", ct)
}

// decodeHexStringsFromFile decodes newline-delimited, hex-encoded strings from
// a file.
func decodeHexStringsFromFile(t *testing.T, name string) [][]byte {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var res [][]byte

	s := bufio.NewScanner(f)
	for s.Scan() {
		data := decodeHex(t, s.Text())
		res = append(res, data)
	}

	if err := s.Err(); err != nil {
		t.Fatal(err)
	}

	return res
}

func TestChallenge4(t *testing.T) {
	in := decodeHexStringsFromFile(t, "testdata/4.txt")
	want := decodeHex(t, "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")

	got := findSingleByteXORCiphertext(in)

	if !bytes.Equal(want, got) {
		t.Errorf("want %x, got %x", want, got)
	}

	key := recoverSingleByteXORKey(got)
	newSingleByteXORCipher(key).XORKeyStream(got, got)
	t.Logf("plaintext: %q", got)
}

func TestChallenge5(t *testing.T) {
	pt := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
	key := []byte("ICE")
	want := decodeHex(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

	newRepeatingKeyXORCipher(key).XORKeyStream(pt, pt)

	if !bytes.Equal(want, pt) {
		t.Errorf("want %q, got %q", pt, pt)
	}
}

// decodeBase64FromFile decodes Base64-encoded data from a file for testing.
func decodeBase64FromFile(t *testing.T, name string) []byte {
	t.Helper()

	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	dec := base64.NewDecoder(base64.StdEncoding, f)

	res, err := io.ReadAll(dec)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestHamming(t *testing.T) {
	a := []byte("this is a test")
	b := []byte("wokka wokka!!!")
	want := 37

	got := hamming(a, b)
	if want != got {
		t.Errorf("want %d, got %d", want, got)
	}
}

func TestChallenge6(t *testing.T) {
	in := decodeBase64FromFile(t, "testdata/6.txt")
	want := []byte("Terminator X: Bring the noise")

	got := recoverRepeatingKeyXORKey(in)

	if !bytes.Equal(want, got) {
		t.Errorf("want %q, got %q", want, got)
	}

	newRepeatingKeyXORCipher(got).XORKeyStream(in, in)
	t.Logf("plaintext: %q", in)
}

func TestChallenge7(t *testing.T) {
	in := decodeBase64FromFile(t, "testdata/7.txt")
	key := []byte("YELLOW SUBMARINE")
	want := []byte("I'm back and I'm ringin' the bell \nA rockin'") // first few bytes

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	mode := newECBDecrypter(block)

	mode.CryptBlocks(in, in)

	got := in[:len(want)]
	if !bytes.Equal(want, got) {
		t.Errorf("first %d bytes: want %q, got %q", len(want), want, got)
	}

	t.Logf("plaintext: %q", in)
}

func TestChallenge8(t *testing.T) {
	in := decodeHexStringsFromFile(t, "testdata/8.txt")
	want := 132 // block 2, 4, 8, and 10 are all "08649af70dc06f4fd5d2d69c744cd283"

	got := slices.IndexFunc(in, is128ECBCiphertext)
	if want != got {
		t.Errorf("wrong index: want %d, got %d", want, got)
	}

	t.Logf("picked ciphertext: %x", in[got])
}
