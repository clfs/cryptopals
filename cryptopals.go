// Package cryptopals contains utility functions for the Cryptopals challenges.
package cryptopals

import (
	"bytes"
	_ "embed"
	"math"
)

// XOR returns a new byte slice with each element set to x[i] ^ y[i].
// If len(x) != len(y), XOR panics.
func XOR(x, y []byte) []byte {
	if len(x) != len(y) {
		panic("different lengths")
	}
	res := bytes.Clone(x)
	for i := range res {
		res[i] ^= y[i]
	}
	return res
}

// XORByte returns a new byte slice with each element set to x[i] ^ y.
func XORByte(x []byte, y byte) []byte {
	res := bytes.Clone(x)
	for i := range res {
		res[i] ^= y
	}
	return res
}

func frequencyDistribution(b []byte) map[byte]int {
	m := make(map[byte]int)
	for i := range b {
		m[b[i]]++
	}
	return m
}

func probabilityDistribution(b []byte) map[byte]float64 {
	m := make(map[byte]float64)
	denom := float64(len(b))
	for k, v := range frequencyDistribution(b) {
		m[k] = float64(v) / denom
	}
	return m
}

//go:embed english-corpus.txt
var englishCorpus []byte
var pEnglish = probabilityDistribution(englishCorpus)

// ProbabilityIsEnglish returns the probability that b is English text.
func ProbabilityIsEnglish(b []byte) float64 {
	var res float64
	for k, v := range probabilityDistribution(b) {
		res += math.Sqrt(v * pEnglish[k])
	}
	return res
}
