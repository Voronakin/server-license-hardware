package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"server-license-hardware/pkg/hosthash"
	"server-license-hardware/pkg/license"
)

// ПРИМЕР публичного ключа для проверки подписи JWT
var publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArvVXSJaDX2d0fBlVig2+
iQYjlwG1v9B8WO35Q7h6ewpSG2LrBfSoah1tw/dK/Ve10Q9J8i09Ad+Zz3GzaVOt
N/h14Y5l/uouWGDeQIPnIygHtXcXbBnQDiYzXwhXLLhxHoZ/tUpLKUT9C/URZset
2zaHhzB5uRz5PCYPqA+RJKJqIOvhBzE/qKKiUvtXCjnb+Uz5WeZy+bg7zl2KaDji
EMB6y3I7Qv4LqWKoMvHh82clhfSjj+Y9au5XtAMOtaitEto+yzhpNImBHxL5Fvh9
5UQ8K6I9ME5lu4zdJSYHIq6DcNg3Zz9UFL0sh4jDC9o0KtNK9UPiMeSd+3IXrxz7
3wIDAQAB
-----END PUBLIC KEY-----`

// ПРИМЕР приватного ключа для подписи JWT (RSA)
var privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu9VdIloNfZ3R8
GVWKDb6JBiOXAbW/0HxY7flDuHp7ClIbYusF9KhqHW3D90r9V7XRD0nyLT0B35nP
cbNpU603+HXhjmX+6i5YYN5Ag+cjKAe1dxdsGdAOJjNfCFcsuHEehn+1SkspRP0L
9RFmx63bNoeHMHm5HPk8Jg+oD5Ekomog6+EHMT+ooqJS+1cKOdv5TPlZ5nL5uDvO
XYpoOOIQwHrLcjtC/gupYqgy8eHzZyWF9KOP5j1q7le0Aw61qK0S2j7LOGk0iYEf
EvkW+H3lRDwroj0wTmW7jN0lJgciroNw2DdnP1QUvSyHiMML2jQq00r1Q+Ix5J37
chevHPvfAgMBAAECggEAQhOv2N7bk/sfH8VzrHWfaeHTLDN9oImNhQqvkxeHzpNp
yiUUTUYHGzitHY92l3L6XJAxJdFXEq+PyCyRjWyIZbSlVMAynlF0mnVPSz9l2r3C
F5N4WZ/wF3/u8+vS/LVWJ6i1b9M0ysve5Ba08UPl0f5otjKlLjgWm1RmolrqvtIm
SgGbf+a+rb7wSIOCIQ+vlIsmCuPBienRH3pO7mD6v/xJYk74ni8quW+7EMl1/8me
HpyYDgnwn9atb3takt73/gso73tbMwrmXJDHVmJmYlviLnCf/xA2CVXK/Z6BGrpd
M7NIEUjQsOjkGfh4zqRxKrJJcLZM9oSuC20j0C5suQKBgQDdqeVBN+1vGxW+mbiG
y+mPwfPN/2C47N4X2eP7XDcMpf/yjTowD2esiwhBTZ8alMUZaoeDf2uhpa+0yaKu
uxafBKry+p/n2aI0k0VN6gITZMEUnWNEdQKWgMmzt70bW4db3dsSmxQXvGXR2AXo
OIfojK27RsIVnIL3d81VIk5y9wKBgQDKD1cd+e0sEPG0rLubCg78kazDorJSDTCT
LbEkV+ilyJeM2Dg7DlsCjKOSdaLi08ZA1RfM8Bcqdk93as4nJIqMJPqNn+i7iiNZ
r99bGZU2J4UhK7jvRWwT+PflfIP8Xt3jCXH32NW6EJOpvLKNjZ0QxVtWV1XZywx+
BrX+Z9wcWQKBgBx+38rvjqVu3O/AwTkK876YV2hPATcktDRqvWUt6KHGoU2kHCvb
fx9uTCRg/ygioefvivY7pjGEpD7ggPpncLQGnJdZ4r6ieri5ifpHL/cgR7YHuaAu
TqPccJGa+EORE6iar7QHnaCjho9gbvn4cnhRxW/C2+Z9VVTM4Oel3mHnAoGAab7h
fsSfhOJRPJbxj9ARy8iJO9FXtW1FsKDHBhgjny99cK5vryhyJMFpkWqTFlZyeNeM
nyo/VW+ZYwu4W+/ZukJYBepcKFnA6l0KbWjUGAVSvOte24nfaAxx393sTRVw1jLJ
PEZ0g+3M+ZXRdBdazb4bcPI/8b08CnCEqmG8ZfECgYEAlaqCjrlqQ7I8e2/v783A
XDjwpvyy4NoXSCSDF8TUGZUk5lgxGIEdMLk+1Vmtt/Wxm1T4tiGyDs9SQC2RDOaj
tQfPnP+RKyzH0cHaSCE4iNeCwwM9a19h+tNfZzKSpQWIdHS7dTSCrdUWj57j3LDq
8viG/LjvUmB4d6aQhH+oALM=
-----END PRIVATE KEY-----`

// ПРИМЕР ключа шибрования hash
var hashKey = "6368616e676520746869732070617373776f726420746f206120736563726574" // 32-байтный ключ AES

// Пример интеграции библиотеки в реальный проект
// Демонстрирует основные сценарии использования для внедрения в приложения

func main() {
	fmt.Println("=== Пример интеграции библиотеки лицензирования ===")
	fmt.Println("Основное назначение: внедрение в проекты для защиты ПО")
	fmt.Println()

	// Сценарий 1: Генерация лицензии (для сервера лицензий)
	fmt.Println("1. Сценарий генерации лицензии:")
	licenseToken := generateLicenseExample()

	fmt.Println("\n" + strings.Repeat("=", 60) + "\n")

	// Сценарий 2: Валидация лицензии (для клиентских приложений)
	fmt.Println("2. Сценарий валидации лицензии:")
	validateLicenseExample(licenseToken)
}

// демонстрирует процесс генерации лицензии
func generateLicenseExample() string {
	fmt.Println("\n--- Генерация лицензии (для сервера лицензий) ---")

	// Генерация хэша машины
	hash, err := hosthash.GenHash()
	if err != nil {
		log.Fatalf("Ошибка генерации хэша машины: %v", err)
	}
	fmt.Printf("✓ Хэш машины сгенерирован (%d символов)\n", len(hash))

	// Определение scope для конкретного приложения
	allScopes := []license.Scope{
		{ID: "read", Name: "Чтение", Description: "Доступ на чтение данных"},
		{ID: "write", Name: "Запись", Description: "Доступ на запись данных"},
		{ID: "admin", Name: "Администрирование", Description: "Полный доступ к системе"},
		{ID: "export", Name: "Экспорт", Description: "Доступ к экспорту данных"},
	}

	// Создание генератора (для сервера лицензий)
	generator := license.NewGenerator([]byte(privateKey), allScopes)
	fmt.Println("✓ Генератор лицензий инициализирован")

	// Шифрование хэша машины
	encryptedHash, err := license.EncryptHash(hash, hashKey)
	if err != nil {
		log.Fatalf("Ошибка шифрования хэша машины: %v", err)
	}
	fmt.Println("✓ Хэш машины зашифрован")

	name := "Премиум лицензия"
	scopes := []string{"read", "write", "export"}

	// Создание лицензии
	expTime := time.Now().AddDate(1, 0, 0) // Лицензия на 1 год
	licenseToken, err := generator.Create(license.CreateOptions{
		HardwareHash: encryptedHash,
		Name:         name,
		ExpiresAt:    expTime,
		NotBefore:    time.Now(),
		Scopes:       scopes,
	})
	if err != nil {
		log.Fatalf("Ошибка создания лицензии: %v", err)
	}

	fmt.Printf("✓ Лицензия создана (%d символов)\n", len(licenseToken))
	fmt.Printf("  Название: %s\n", name)
	fmt.Printf("  Действительна до: %s\n", expTime.Format("02.01.2006"))
	fmt.Printf("  Разрешения: %s\n", strings.Join(scopes, ", "))

	return licenseToken
}

// validateLicenseExample демонстрирует процесс валидации лицензии
func validateLicenseExample(licenseToken string) {
	fmt.Println("\n--- Валидация лицензии (для клиентских приложений) ---")

	// Определение scope (должно совпадать с использованным при генерации)
	allScopes := []license.Scope{
		{ID: "read", Name: "Чтение", Description: "Доступ на чтение данных"},
		{ID: "write", Name: "Запись", Description: "Доступ на запись данных"},
		{ID: "admin", Name: "Администрирование", Description: "Полный доступ к системе"},
		{ID: "export", Name: "Экспорт", Description: "Доступ к экспорту данных"},
	}

	// Создание валидатора (для клиентских приложений)
	validator := license.NewValidator([]byte(publicKey), allScopes)
	fmt.Println("✓ Валидатор лицензий инициализирован")

	// В реальном проекте лицензия загружается из файла, БД или переменной окружения
	// Для демонстрации используем сгенерированную ранее лицензию

	// Простая проверка валидности
	isValid := validator.Validate(licenseToken, hashKey)
	fmt.Printf("✓ Простая проверка: %v\n", isValid)

	// Детальная проверка с получением информации
	licenseDetails := validator.ValidateDetails(licenseToken, hashKey)

	fmt.Printf("✓ Детальная проверка завершена\n")
	fmt.Printf("  Активна: %v\n", licenseDetails.Active)
	fmt.Printf("  Токен валиден: %v\n", licenseDetails.TokenActive)
	fmt.Printf("  Хэш валиден: %v\n", licenseDetails.HashActive)

	if len(licenseDetails.Errors) > 0 {
		fmt.Printf("  Ошибки валидации: %v\n", licenseDetails.Errors)
	}

	// Проверка scope
	fmt.Println("\n--- Проверка разрешений ---")
	requiredScopes := []string{"read", "write", "export", "admin"}
	for _, scope := range requiredScopes {
		if licenseDetails.CheckScope(scope) {
			fmt.Printf("  ✓ Разрешение '%s': ДОСТУП РАЗРЕШЕН\n", scope)
		} else {
			fmt.Printf("  ✗ Разрешение '%s': доступ запрещен\n", scope)
		}
	}

	// Пример сериализации информации о лицензии для логирования
	jsonData, _ := json.MarshalIndent(licenseDetails, "", "  ")
	fmt.Printf("\nИнформация о лицензии (JSON):\n%s\n", string(jsonData))
}
