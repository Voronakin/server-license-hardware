package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Voronakin/server-license-hardware/pkg/hosthash"
	"github.com/Voronakin/server-license-hardware/pkg/license"
)

// TestRunGenerateHashExample проверяет процесс генерации и шифрования хэша
func TestRunGenerateHashExample(t *testing.T) {
	// Выполняем генерацию хэша
	encryptedHash, err := RunGenerateHashExample()
	if err != nil {
		t.Fatalf("Ошибка выполнения генерации хэша: %v", err)
	}

	// Проверяем, что хэш не пустой
	if encryptedHash == "" {
		t.Fatal("Зашифрованный хэш не должен быть пустым")
	}

	// Проверяем, что хэш не содержит неожиданных символов
	if strings.Contains(encryptedHash, " ") || strings.Contains(encryptedHash, "\n") || strings.Contains(encryptedHash, "\t") {
		t.Error("Зашифрованный хэш не должен содержать пробелов или символов новой строки")
	}
}

// TestRunGenerateHashExampleWithInvalidKey проверяет поведение при невалидном ключе
func TestRunGenerateHashExampleWithInvalidKey(t *testing.T) {
	// Генерируем хэш
	hash, err := hosthash.GenHash()
	if err != nil {
		t.Fatalf("Ошибка генерации хэша: %v", err)
	}

	// Пытаемся зашифровать с невалидным ключом
	invalidKey := "invalid-key-too-short"
	_, err = license.EncryptHash(hash, invalidKey)
	if err == nil {
		t.Error("Ожидалась ошибка при шифровании с невалидным ключом")
	}
}

// TestHashKeyLength проверяет корректность длины ключа шифрования
func TestHashKeyLength(t *testing.T) {
	// Проверяем, что ключ имеет правильную длину (32 байта для AES-256)
	expectedLength := 64 // hex-encoded 32 bytes = 64 characters
	if len([]rune(hashKey)) != expectedLength {
		t.Errorf("Ключ шифрования должен быть длиной %d символов (32 байта в hex), получено: %d", expectedLength, len([]rune(hashKey)))
	}

	// Проверяем, что ключ состоит только из hex символов
	_, err := hex.DecodeString(hashKey)
	if err != nil {
		t.Errorf("Ключ шифрования должен содержать только hex символы: %v", err)
	}
}

// TestEncryptionDecryptionCycle проверяет полный цикл шифрования-дешифрования
func TestEncryptionDecryptionCycle(t *testing.T) {
	// Генерируем оригинальный хэш
	originalHash, err := hosthash.GenHash()
	if err != nil {
		t.Fatalf("Ошибка генерации хэша: %v", err)
	}

	// Шифруем хэш
	encryptedHash, err := license.EncryptHash(originalHash, hashKey)
	if err != nil {
		t.Fatalf("Ошибка шифрования хэша: %v", err)
	}

	// Дешифруем хэш
	decryptedHash, err := license.DecryptHash(encryptedHash, hashKey)
	if err != nil {
		t.Fatalf("Ошибка дешифрования хэша: %v", err)
	}

	// Проверяем, что оригинальный и дешифрованный хэши совпадают
	if originalHash != decryptedHash {
		t.Error("Оригинальный и дешифрованный хэши должны совпадать")
	}
}

// BenchmarkHashGeneration проверяет производительность только генерации хэша
func BenchmarkHashGeneration(b *testing.B) {
	for b.Loop() {
		_, _ = hosthash.GenHash()
	}
}

// BenchmarkEncryption проверяет производительность шифрования хэша
func BenchmarkEncryption(b *testing.B) {
	// Предварительно генерируем хэш
	hash, err := hosthash.GenHash()
	if err != nil {
		b.Fatalf("Ошибка генерации хэша для бенчмарка: %v", err)
	}

	for b.Loop() {
		_, _ = license.EncryptHash(hash, hashKey)
	}
}
