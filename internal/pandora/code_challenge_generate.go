package pandora

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// GenerateCodeVerifier
//
//	@Description: 生成校验code
//	@return string
func GenerateCodeVerifier() (string, error) {
	// Generate a random token with length 32
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	// Encode the token in base64url format
	codeVerifier := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(token)
	return codeVerifier, nil
}

// GenerateCodeChallenge
//
//	@Description: 校验code challenge
//	@param codeVerifier
//	@return string
func GenerateCodeChallenge(codeVerifier string) string {
	// Calculate the SHA256 hash of the codeVerifier
	sha256Hash := sha256.Sum256([]byte(codeVerifier))

	// Encode the token in base64url format
	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha256Hash[:])
	return codeChallenge
}
