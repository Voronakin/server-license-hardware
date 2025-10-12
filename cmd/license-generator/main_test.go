package main

import (
	"os"
	"strings"
	"testing"

	"github.com/Voronakin/server-license-hardware/pkg/license"
)

// TestGenerateLicense проверяет базовую генерацию лицензии
func TestGenerateLicense(t *testing.T) {
	// Читаем тестовый приватный ключ
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}

	hashKey := "6368616e676520746869732070617373776f726420746f206120736563726574"
	licenseName := "Тестовая лицензия"
	daysValid := 30
	scopes := []string{"read", "write"}

	// Генерируем лицензию
	licenseToken, err := generateLicense(privateKeyBytes, hashKey, licenseName, daysValid, scopes)
	if err != nil {
		t.Fatalf("Ошибка генерации лицензии: %v", err)
	}

	// Проверяем, что токен не пустой
	if licenseToken == "" {
		t.Fatal("Сгенерированный токен лицензии не должен быть пустым")
	}

	// Проверяем, что токен содержит точки (JWT формат)
	if !strings.Contains(licenseToken, ".") {
		t.Error("Токен должен быть в формате JWT (содержать точки)")
	}
}

// TestGenerateLicenseWithInvalidPrivateKey проверяет поведение при невалидном приватном ключе
func TestGenerateLicenseWithInvalidPrivateKey(t *testing.T) {
	invalidPrivateKey := []byte("invalid-private-key")
	hashKey := "6368616e676520746869732070617373776f726420746f206120736563726574"
	licenseName := "Тестовая лицензия"
	daysValid := 30
	scopes := []string{"read"}

	// Пытаемся сгенерировать лицензию с невалидным ключом
	_, err := generateLicense(invalidPrivateKey, hashKey, licenseName, daysValid, scopes)
	if err == nil {
		t.Error("Ожидалась ошибка при генерации лицензии с невалидным приватным ключом")
	}
}

// TestGenerateLicenseWithInvalidHashKey проверяет поведение при невалидном ключе хэша
func TestGenerateLicenseWithInvalidHashKey(t *testing.T) {
	// Читаем тестовый приватный ключ
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}

	invalidHashKey := "invalid-hash-key-too-short"
	licenseName := "Тестовая лицензия"
	daysValid := 30
	scopes := []string{"read"}

	// Пытаемся сгенерировать лицензию с невалидным ключом хэша
	_, err = generateLicense(privateKeyBytes, invalidHashKey, licenseName, daysValid, scopes)
	if err == nil {
		t.Error("Ожидалась ошибка при генерации лицензии с невалидным ключом хэша")
	}
}

// TestGenerateLicenseValidation проверяет, что сгенерированная лицензия может быть провалидирована
func TestGenerateLicenseValidation(t *testing.T) {
	// Читаем тестовый приватный ключ
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}

	hashKey := "6368616e676520746869732070617373776f726420746f206120736563726574"
	licenseName := "Валидируемая лицензия"
	daysValid := 365
	scopes := []string{"read", "write", "admin"}

	// Генерируем лицензию
	licenseToken, err := generateLicense(privateKeyBytes, hashKey, licenseName, daysValid, scopes)
	if err != nil {
		t.Fatalf("Ошибка генерации лицензии: %v", err)
	}

	// Создаем валидатор с публичным ключом
	publicKey, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}

	allScopes := []license.Scope{
		{ID: "read", Name: "Чтение", Description: "Доступ на чтение данных"},
		{ID: "write", Name: "Запись", Description: "Доступ на запись данных"},
		{ID: "admin", Name: "Администрирование", Description: "Полный доступ к системе"},
		{ID: "export", Name: "Экспорт", Description: "Доступ к экспорту данных"},
		{ID: "premium", Name: "Премиум", Description: "Премиум функционал"},
	}

	validator := license.NewValidator([]byte(publicKey), allScopes)
	isValid := validator.Validate(licenseToken, hashKey)
	if !isValid {
		t.Error("Сгенерированная лицензия должна быть валидной")
	}

	// Детальная проверка
	licenseDetails := validator.ValidateDetails(licenseToken, hashKey)
	if !licenseDetails.Active {
		t.Error("Лицензия должна быть активной")
	}

	if !licenseDetails.TokenActive {
		t.Error("Токен лицензии должен быть активным")
	}

	if !licenseDetails.HashActive {
		t.Error("Хэш лицензии должен быть активным")
	}

	// Проверяем scope
	if !licenseDetails.CheckScope("read") {
		t.Error("Лицензия должна иметь scope 'read'")
	}

	if !licenseDetails.CheckScope("write") {
		t.Error("Лицензия должна иметь scope 'write'")
	}

	if !licenseDetails.CheckScope("admin") {
		t.Error("Лицензия должна иметь scope 'admin'")
	}

	if licenseDetails.CheckScope("export") {
		t.Error("Лицензия НЕ должна иметь scope 'export'")
	}
}

// TestGenerateLicenseWithEmptyScopes проверяет генерацию лицензии с пустыми scope
func TestGenerateLicenseWithEmptyScopes(t *testing.T) {
	// Читаем тестовый приватный ключ
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}

	hashKey := "6368616e676520746869732070617373776f726420746f206120736563726574"
	licenseName := "Лицензия без scope"
	daysValid := 7
	emptyScopes := []string{}

	// Генерируем лицензию с пустыми scope
	licenseToken, err := generateLicense(privateKeyBytes, hashKey, licenseName, daysValid, emptyScopes)
	if err != nil {
		t.Fatalf("Ошибка генерации лицензии с пустыми scope: %v", err)
	}

	// Проверяем, что токен создан
	if licenseToken == "" {
		t.Fatal("Сгенерированный токен лицензии не должен быть пустым")
	}

	// Проверяем, что токен содержит точки (JWT формат)
	if !strings.Contains(licenseToken, ".") {
		t.Error("Токен должен быть в формате JWT (содержать точки)")
	}
}

// TestGenerateLicenseWithNegativeDays проверяет поведение при отрицательном сроке действия
func TestGenerateLicenseWithNegativeDays(t *testing.T) {
	// Читаем тестовый приватный ключ
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}

	hashKey := "6368616e676520746869732070617373776f726420746f206120736563726574"
	licenseName := "Лицензия с отрицательным сроком"
	negativeDays := -1
	scopes := []string{"read"}

	// Пытаемся сгенерировать лицензию с отрицательным сроком
	licenseToken, err := generateLicense(privateKeyBytes, hashKey, licenseName, negativeDays, scopes)
	if err != nil {
		t.Fatalf("Ошибка генерации лицензии с отрицательным сроком: %v", err)
	}

	// Проверяем, что токен создан
	if licenseToken == "" {
		t.Fatal("Сгенерированный токен лицензии не должен быть пустым")
	}

	// Проверяем, что токен содержит точки (JWT формат)
	if !strings.Contains(licenseToken, ".") {
		t.Error("Токен должен быть в формате JWT (содержать точки)")
	}
}

// BenchmarkGenerateLicense проверяет производительность генерации лицензии
func BenchmarkGenerateLicense(b *testing.B) {
	// Читаем тестовый приватный ключ
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		b.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}

	hashKey := "6368616e676520746869732070617373776f726420746f206120736563726574"
	licenseName := "Бенчмарк лицензия"
	daysValid := 365
	scopes := []string{"read", "write"}

	b.ResetTimer()
	for b.Loop() {
		_, _ = generateLicense(privateKeyBytes, hashKey, licenseName, daysValid, scopes)
	}
}
