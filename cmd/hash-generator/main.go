package main

import (
	"fmt"
	"log"

	"server-license-hardware/pkg/hosthash"
	"server-license-hardware/pkg/license"
)

// Ключ шифрования хэша - должен быть зашит в коде приложения
// В реальном проекте этот ключ должен быть одинаковым на сервере генерации лицензий
// и во всех клиентских приложениях
const hashKey = "6368616e676520746869732070617373776f726420746f206120736563726574" // 32-байтный ключ AES

func main() {
	fmt.Println("=== Генератор хэша сервера ===")
	fmt.Println()

	// Генерация хэша машины
	hash, err := hosthash.GenHash()
	if err != nil {
		log.Fatalf("Ошибка генерации хэша машины: %v", err)
	}

	// Шифрование хэша
	encryptedHash, err := license.EncryptHash(hash, hashKey)
	if err != nil {
		log.Fatalf("Ошибка шифрования хэша: %v", err)
	}

	// Вывод зашифрованного хэша
	fmt.Println("=== Зашифрованный хэш машины ===")
	fmt.Println(encryptedHash)
	fmt.Println("=== Конец хэша ===")
	fmt.Println()
	fmt.Println("✓ Хэш успешно сгенерирован и зашифрован")
	fmt.Println("  Предоставьте этот хэш сервису генерации лицензий")
}
