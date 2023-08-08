// Package cryptopals contains utility functions for the Cryptopals challenges.
package cryptopals

import (
	_ "embed"
	"math"
	"math/bits"
)

// XOR returns x ^ y.
// If len(x) != len(y), it panics.
func XOR(x, y []byte) []byte {
	if len(x) != len(y) {
		panic("different lengths")
	}
	res := make([]byte, len(x))
	for i := range res {
		res[i] = x[i] ^ y[i]
	}
	return res
}

// XORByte returns the result of xor'ing each byte of x with y.
func XORByte(x []byte, y byte) []byte {
	res := make([]byte, len(x))
	for i := range res {
		res[i] = x[i] ^ y
	}
	return res
}

// XORRepeat returns x ^ y, repeating y if it's too short.
// The result has length len(x).
func XORRepeat(x, y []byte) []byte {
	res := make([]byte, len(x))
	for i := range res {
		res[i] = x[i] ^ y[i%len(y)]
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
	var res float64 // Bhattacharyya coefficient of b and the English corpus.
	for k, v := range probabilityDistribution(b) {
		res += math.Sqrt(v * pEnglish[k])
	}
	return res
}

// HammingDistance returns the Hamming distance between a and b.
// If len(a) != len(b), it panics.
func HammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("different lengths")
	}
	var res int
	for i := range a {
		res += bits.OnesCount8(a[i] ^ b[i])
	}
	return res
}

// Blocks returns consecutive subslices of b of length n, except for the final
// block which may be shorter than n.
func Blocks(b []byte, n int) [][]byte {
	var res [][]byte
	for len(b) > 0 {
		res = append(res, b[:n])
		b = b[n:]
	}
	return res
}
