package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Voronakin/server-license-hardware/pkg/hosthash"
	"github.com/Voronakin/server-license-hardware/pkg/license"
)

// Основное назначение: простой сервер генерации лицензий
// Может использоваться как самостоятельное приложение для выдачи лицензий
// Или как основа для более сложной системы лицензирования

func main() {
	_, err := RunGenerateLicenseExample()
	if err != nil {
		log.Fatalf("Ошибка выполнения примера: %v", err)
	}
}

func RunGenerateLicenseExample() (string, error) {
	fmt.Println("=== Сервер генерации лицензий ===")
	fmt.Println("Основное назначение: внедрение в проекты для защиты ПО")
	fmt.Println("Дополнительно: может использоваться как простой сервер лицензий")
	fmt.Println()

	// Проверка режима работы
	if len(os.Args) > 1 && os.Args[1] != "--interactive" {
		return generateWithArgs()
	} else {
		return generateInteractive()
	}
}

// generateWithArgs генерирует лицензию с использованием аргументов командной строки
// Используется для автоматизации процесса генерации лицензий
func generateWithArgs() (string, error) {
	if len(os.Args) < 6 {
		fmt.Println("Использование для прямой генерации:")
		fmt.Println("  go run cmd/license-generator/main.go <файл_приватного_ключа> <ключ_хэша> <название_лицензии> <дней_действия> <scope>")
		fmt.Println()
		fmt.Println("Пример:")
		fmt.Println(`  go run cmd/license-generator/main.go private.pem myhashkey123 "Моя лицензия" 365 read,write,admin`)
		fmt.Println()
		fmt.Println("Или используйте интерактивный режим:")
		fmt.Println("  go run cmd/license-generator/main.go --interactive")
		fmt.Println()
		fmt.Println("Параметры:")
		fmt.Println("  файл_приватного_ключа - путь к файлу с приватным RSA ключом")
		fmt.Println("  ключ_хэша - 32-байтный ключ для шифрования хэша машины")
		fmt.Println("  название_лицензии - произвольное название лицензии")
		fmt.Println("  дней_действия - срок действия лицензии в днях")
		fmt.Println("  scope - список разрешений через запятую (read,write,admin)")
		return "", nil
	}

	privateKeyFile := os.Args[1]
	hashKey := os.Args[2]
	licenseName := os.Args[3]
	daysValid, err := strconv.Atoi(os.Args[4])
	if err != nil {
		fmt.Printf("Ошибка парсинга дней действия: %v\n", err)
		return "", fmt.Errorf("ошибка парсинга дней действия: %w", err)
	}
	scopesStr := os.Args[5]
	scopes := strings.Split(scopesStr, ",")

	// Чтение приватного ключа из файла
	privateKeyBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		fmt.Printf("Ошибка чтения файла приватного ключа: %v\n", err)
		return "", fmt.Errorf("ошибка чтения файла приватного ключа: %w", err)
	}

	// Генерация лицензии
	licenseToken, err := generateLicense(privateKeyBytes, hashKey, licenseName, daysValid, scopes)
	if err != nil {
		fmt.Printf("Ошибка генерации лицензии: %v\n", err)
		return "", fmt.Errorf("ошибка генерации лицензии: %w", err)
	}

	fmt.Println("\n=== Сгенерированная лицензия ===")
	fmt.Println(licenseToken)
	fmt.Println("\n=== Конец лицензии ===")
	fmt.Println()
	fmt.Println("✓ Лицензия успешно сгенерирована")
	fmt.Printf("✓ Название: %s\n", licenseName)
	fmt.Printf("✓ Срок действия: %d дней\n", daysValid)
	fmt.Printf("✓ Разрешения: %s\n", strings.Join(scopes, ", "))

	return licenseToken, nil
}

// generateInteractive генерирует лицензию с использованием интерактивного диалога
// Идеально подходит для ручной выдачи лицензий
func generateInteractive() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Интерактивный генератор лицензий")
	fmt.Println("=================================")
	fmt.Println("Этот режим позволяет создать лицензию через пошаговый диалог")
	fmt.Println()

	// Получение приватного ключа
	fmt.Print("Введите путь к файлу приватного ключа: ")
	privateKeyFile, _ := reader.ReadString('\n')
	privateKeyFile = strings.TrimSpace(privateKeyFile)

	privateKeyBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		fmt.Printf("Ошибка чтения файла приватного ключа: %v\n", err)
		return "", fmt.Errorf("ошибка чтения файла приватного ключа: %w", err)
	}

	// Получение ключа хэша
	fmt.Print("Введите ключ хэша (для шифрования хэша машины): ")
	hashKey, _ := reader.ReadString('\n')
	hashKey = strings.TrimSpace(hashKey)

	// Получение названия лицензии
	fmt.Print("Введите название лицензии: ")
	licenseName, _ := reader.ReadString('\n')
	licenseName = strings.TrimSpace(licenseName)

	// Получение срока действия
	fmt.Print("Введите количество дней действия лицензии: ")
	daysStr, _ := reader.ReadString('\n')
	daysStr = strings.TrimSpace(daysStr)
	daysValid, err := strconv.Atoi(daysStr)
	if err != nil {
		fmt.Printf("Ошибка парсинга дней: %v\n", err)
		return "", fmt.Errorf("ошибка парсинга дней: %w", err)
	}

	// Получение scope
	fmt.Print("Введите разрешения (через запятую, например: read,write,admin): ")
	scopesStr, _ := reader.ReadString('\n')
	scopesStr = strings.TrimSpace(scopesStr)
	scopes := strings.Split(scopesStr, ",")

	// Очистка scope
	for i := range scopes {
		scopes[i] = strings.TrimSpace(scopes[i])
	}

	// Генерация лицензии
	licenseToken, err := generateLicense(privateKeyBytes, hashKey, licenseName, daysValid, scopes)
	if err != nil {
		fmt.Printf("Ошибка генерации лицензии: %v\n", err)
		return "", fmt.Errorf("ошибка генерации лицензии: %w", err)
	}

	fmt.Println("\n=== Сгенерированная лицензия ===")
	fmt.Println(licenseToken)
	fmt.Println("\n=== Конец лицензии ===")

	// Сводка по лицензии
	fmt.Println("\n✓ Лицензия успешно сгенерирована!")
	fmt.Printf("✓ Название: %s\n", licenseName)
	fmt.Printf("✓ Срок действия: %d дней\n", daysValid)
	fmt.Printf("✓ Разрешения: %s\n", strings.Join(scopes, ", "))

	// Сохранение в файл
	fmt.Print("\nХотите сохранить лицензию в файл? (y/n): ")
	saveChoice, _ := reader.ReadString('\n')
	saveChoice = strings.TrimSpace(strings.ToLower(saveChoice))

	if saveChoice == "y" || saveChoice == "yes" {
		fmt.Print("Введите имя файла для сохранения лицензии: ")
		filename, _ := reader.ReadString('\n')
		filename = strings.TrimSpace(filename)

		err := os.WriteFile(filename, []byte(licenseToken), 0644)
		if err != nil {
			fmt.Printf("Ошибка сохранения лицензии в файл: %v\n", err)
			return "", fmt.Errorf("ошибка сохранения лицензии в файл: %w", err)
		} else {
			fmt.Printf("✓ Лицензия сохранена в файл: %s\n", filename)
		}
	}

	fmt.Println("\n=== Генерация завершена ===")
	return licenseToken, nil
}

// generateLicense создает токен лицензии с использованием предоставленных параметров
// Эта функция демонстрирует использование библиотеки для генерации лицензий
func generateLicense(privateKeyBytes []byte, hashKey, licenseName string, daysValid int, scopes []string) (string, error) {
	// Генерация хэша машины
	hash, err := hosthash.GenHash()
	if err != nil {
		return "", fmt.Errorf("не удалось сгенерировать хэш машины: %w", err)
	}

	// Шифрование хэша машины
	encryptedHash, err := license.EncryptHash(hash, hashKey)
	if err != nil {
		return "", fmt.Errorf("не удалось зашифровать хэш машины: %w", err)
	}

	// Определение доступных scope
	// В реальном проекте scope должны быть определены в соответствии с бизнес-логикой
	allScopes := []license.Scope{
		{ID: "read", Name: "Чтение", Description: "Доступ на чтение данных"},
		{ID: "write", Name: "Запись", Description: "Доступ на запись данных"},
		{ID: "admin", Name: "Администрирование", Description: "Полный доступ к системе"},
		{ID: "export", Name: "Экспорт", Description: "Доступ к экспорту данных"},
		{ID: "premium", Name: "Премиум", Description: "Премиум функционал"},
	}

	// Создание генератора
	generator := license.NewGenerator(privateKeyBytes, allScopes)

	// Создание лицензии
	licenseToken, err := generator.Create(license.CreateOptions{
		HardwareHash: encryptedHash,
		Name:         licenseName,
		ExpiresAt:    time.Now().AddDate(0, 0, daysValid),
		NotBefore:    time.Now(),
		Scopes:       scopes,
	})

	if err != nil {
		return "", fmt.Errorf("не удалось создать лицензию: %w", err)
	}

	return licenseToken, nil
}
