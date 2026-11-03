package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost     = 12
	numericCharset = "0123456789"
	alphaCharset   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// HashPassword hashes a password using bcrypt with a production-grade cost factor.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword compares a password against its bcrypt hash.
func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// SHA256Hash computes a SHA-256 hex digest of the input.
func SHA256Hash(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// HMACSign creates an HMAC-SHA256 signature of data using the given key.
func HMACSign(data, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// HMACVerify validates an HMAC-SHA256 signature.
func HMACVerify(data, signature, key string) bool {
	expected := HMACSign(data, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// Encrypt performs AES-256-GCM encryption on plaintext using a hex-encoded key.
// Returns base64-encoded ciphertext with prepended nonce.
func Encrypt(plaintext []byte, keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding encryption key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encoded, ciphertext)

	return encoded, nil
}

// Decrypt performs AES-256-GCM decryption on base64-encoded ciphertext.
func Decrypt(encodedCiphertext []byte, keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding encryption key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(encodedCiphertext)))
	n, err := base64.StdEncoding.Decode(ciphertext, encodedCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 ciphertext: %w", err)
	}
	ciphertext = ciphertext[:n]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// GenerateRandomString creates a cryptographically secure random string of
// the specified length using alphanumeric characters.
func GenerateRandomString(length int) (string, error) {
	var sb strings.Builder
	sb.Grow(length)

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphaCharset))))
		if err != nil {
			return "", fmt.Errorf("generating random char: %w", err)
		}
		sb.WriteByte(alphaCharset[idx.Int64()])
	}

	return sb.String(), nil
}

// GenerateNumericCode creates a cryptographically secure numeric code
// of the specified length (for OTP codes).
func GenerateNumericCode(length int) (string, error) {
	var sb strings.Builder
	sb.Grow(length)

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(numericCharset))))
		if err != nil {
			return "", fmt.Errorf("generating random digit: %w", err)
		}
		sb.WriteByte(numericCharset[idx.Int64()])
	}

	return sb.String(), nil
}

// GenerateEncryptionKey generates a random 256-bit key as a hex string.
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("generating encryption key: %w", err)
	}
	return hex.EncodeToString(key), nil
}
