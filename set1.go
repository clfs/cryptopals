package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
)

// hexToBase64 converts a hex-encoded string to a Base64-encoded string.
func hexToBase64(s string) (string, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}
