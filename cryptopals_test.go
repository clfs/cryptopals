package cryptopals

import "testing"

func TestProbabilityIsEnglish(t *testing.T) {
	got := ProbabilityIsEnglish(englishCorpus)
	if got < 0.99 {
		t.Errorf("got %f, too low", got)
	}
}

func TestHammingDistance(t *testing.T) {
	a := []byte("this is a test")
	b := []byte("wokka wokka!!!")
	want := 37

	got := HammingDistance(a, b)
	if want != got {
		t.Errorf("want %d, got %d", want, got)
	}
}
