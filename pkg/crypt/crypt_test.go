package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptAndDecrypt(t *testing.T) {
	secret := "6368616e676520746869732070617373776f726420746f206120736563726574" // 32-byte key
	plaintext := "test message for encryption"

	// Test encryption
	encrypted, err := Encrypt(plaintext, secret)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, plaintext, encrypted)

	// Test decryption
	decrypted, err := Decrypt(encrypted, secret)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncrypt_InvalidSecret(t *testing.T) {
	invalidSecret := "invalid_hex_string"
	plaintext := "test message"

	_, err := Encrypt(plaintext, invalidSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode secret key")
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	secret := "6368616e676520746869732070617373776f726420746f206120736563726574"
	invalidCiphertext := "invalid_hex_ciphertext"

	_, err := Decrypt(invalidCiphertext, secret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode ciphertext")
}

func TestDecrypt_ShortCiphertext(t *testing.T) {
	secret := "6368616e676520746869732070617373776f726420746f206120736563726574"
	shortCiphertext := "123456" // Too short for AES block size

	_, err := Decrypt(shortCiphertext, secret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestDecrypt_WrongSecret(t *testing.T) {
	secret1 := "6368616e676520746869732070617373776f726420746f206120736563726574"
	secret2 := "616e6f7468657220736563726574206b657920666f722074657374696e672031" // Different key
	plaintext := "test message"

	encrypted, err := Encrypt(plaintext, secret1)
	require.NoError(t, err)

	// Try to decrypt with wrong secret
	_, err = Decrypt(encrypted, secret2)
	assert.Error(t, err)
	// This might fail during unpadding or produce garbage
}

func TestEncrypt_EmptyString(t *testing.T) {
	secret := "6368616e676520746869732070617373776f726420746f206120736563726574"

	encrypted, err := Encrypt("", secret)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := Decrypt(encrypted, secret)
	require.NoError(t, err)
	assert.Equal(t, "", decrypted)
}

func TestEncrypt_LongMessage(t *testing.T) {
	secret := "6368616e676520746869732070617373776f726420746f206120736563726574"
	longMessage := "This is a very long message that should be properly encrypted and decrypted without any issues. " +
		"It contains multiple sentences and various characters to test the encryption algorithm thoroughly."

	encrypted, err := Encrypt(longMessage, secret)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := Decrypt(encrypted, secret)
	require.NoError(t, err)
	assert.Equal(t, longMessage, decrypted)
}
