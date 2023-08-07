package cryptopals

import "testing"

func TestProbabilityIsEnglish(t *testing.T) {
	got := ProbabilityIsEnglish(englishCorpus)
	if got < 0.99 {
		t.Errorf("got %f, too low", got)
	}
}
