package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"

	"github.com/zenazn/pkcs7pad"
)

func Encrypte(content string, secret string) string {
	key, _ := hex.DecodeString(secret)
	plaintext := []byte(content)

	plaintext = pkcs7pad.Pad(plaintext, aes.BlockSize)

	//TODO разобраться с пояснением

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(plaintext)%aes.BlockSize != 0 {
		slog.Error("plaintext is not a multiple of the block size")
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		slog.Error("Не удалось конвертировать ключ", err)
		os.Exit(1)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		slog.Error("Не удалось прочитать блок", err)
		os.Exit(1)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	return hex.EncodeToString(ciphertext)
}

func Decrypte(content string, secret string) string {
	key, _ := hex.DecodeString(secret)
	ciphertext, _ := hex.DecodeString(content)

	block, err := aes.NewCipher(key)
	if err != nil {
		slog.Error("Не удалось конвертировать ключ", err)
		os.Exit(1)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		slog.Error("ciphertext too short")
		os.Exit(1)
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		slog.Error("ciphertext is not a multiple of the block size")
		os.Exit(1)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	//TODO разобраться с пояснением

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	ciphertext, err = pkcs7pad.Unpad(ciphertext)
	if err != nil {
		slog.Error("Ошибка при удалении padding", err)
		os.Exit(1)
	}

	return string(ciphertext)
}
