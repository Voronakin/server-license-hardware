package main

import (
	"fmt"
	"log"

	"github.com/Voronakin/server-license-hardware/pkg/hosthash"
	"github.com/Voronakin/server-license-hardware/pkg/license"
)

// Ключ шифрования хэша - должен быть зашит в коде приложения
// В реальном проекте этот ключ должен быть одинаковым на сервере генерации лицензий
// и во всех клиентских приложениях
const hashKey = "6368616e676520746869732070617373776f726420746f206120736563726574" // 32-байтный ключ AES

func main() {
	_, err := RunGenerateHashExample()
	if err != nil {
		log.Fatalf("Ошибка выполнения примера: %v", err)
	}
}

// RunGenerateHashExample выполняет генерацию и шифрование хэша сервера
// Возвращает зашифрованный хэш и ошибку, если таковая возникла
func RunGenerateHashExample() (string, error) {

	fmt.Println("=== Генератор хэша сервера ===")
	fmt.Println()

	// Генерация хэша машины
	hash, err := hosthash.GenHash()
	if err != nil {
		return "", fmt.Errorf("ошибка генерации хэша машины: %w", err)
	}

	// Шифрование хэша
	encryptedHash, err := license.EncryptHash(hash, hashKey)
	if err != nil {
		return "", fmt.Errorf("ошибка шифрования хэша: %w", err)
	}

	// Вывод зашифрованного хэша
	fmt.Println("=== Зашифрованный хэш машины ===")
	fmt.Println(encryptedHash)
	fmt.Println("=== Конец хэша ===")
	fmt.Println()
	fmt.Println("✓ Хэш успешно сгенерирован и зашифрован")
	fmt.Println("  Предоставьте этот хэш сервису генерации лицензий")

	return encryptedHash, nil
}
