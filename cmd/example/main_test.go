package main

import (
	"strings"
	"testing"

	"github.com/Voronakin/server-license-hardware/pkg/license"
)

// TestGenerateLicenseExample проверяет процесс генерации лицензии
func TestGenerateLicenseExample(t *testing.T) {
	// Генерируем лицензию
	licenseToken, err := generateLicenseExample()
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

// TestValidateLicenseExample проверяет процесс валидации лицензии
func TestValidateLicenseExample(t *testing.T) {
	// Сначала генерируем валидную лицензию
	licenseToken, err := generateLicenseExample()
	if err != nil {
		t.Fatalf("Ошибка генерации тестовой лицензии: %v", err)
	}

	if licenseToken == "" {
		t.Fatal("Не удалось сгенерировать тестовую лицензию")
	}

	// Создаём валидатор
	allScopes := []license.Scope{
		{ID: "read", Name: "Чтение", Description: "Доступ на чтение данных"},
		{ID: "write", Name: "Запись", Description: "Доступ на запись данных"},
		{ID: "admin", Name: "Администрирование", Description: "Полный доступ к системе"},
		{ID: "export", Name: "Экспорт", Description: "Доступ к экспорту данных"},
	}

	validator := license.NewValidator([]byte(publicKey), allScopes)

	// Проверяем валидность лицензии
	isValid := validator.Validate(licenseToken, hashKey)
	if !isValid {
		t.Error("Сгенерированная лицензия должна быть валидной")
	}

	// Проверяем детальную валидацию
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

	if len(licenseDetails.Errors) > 0 {
		t.Errorf("Не должно быть ошибок валидации: %v", licenseDetails.Errors)
	}
}

// TestScopeValidation проверяет корректность работы с разрешениями
func TestScopeValidation(t *testing.T) {
	// Генерируем лицензию
	licenseToken, err := generateLicenseExample()
	if err != nil {
		t.Fatalf("Ошибка генерации лицензии: %v", err)
	}

	// Создаём валидатор
	allScopes := []license.Scope{
		{ID: "read", Name: "Чтение", Description: "Доступ на чтение данных"},
		{ID: "write", Name: "Запись", Description: "Доступ на запись данных"},
		{ID: "admin", Name: "Администрирование", Description: "Полный доступ к системе"},
		{ID: "export", Name: "Экспорт", Description: "Доступ к экспорту данных"},
	}

	validator := license.NewValidator([]byte(publicKey), allScopes)
	licenseDetails := validator.ValidateDetails(licenseToken, hashKey)

	// Тестируем таблицу scope
	tests := []struct {
		scope       string
		shouldHave  bool
		description string
	}{
		{"read", true, "Лицензия должна иметь scope 'read'"},
		{"write", true, "Лицензия должна иметь scope 'write'"},
		{"export", true, "Лицензия должна иметь scope 'export'"},
		{"admin", false, "Лицензия НЕ должна иметь scope 'admin'"},
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			hasScope := licenseDetails.CheckScope(tt.scope)
			if hasScope != tt.shouldHave {
				t.Errorf("%s: ожидалось %v, получено %v", tt.description, tt.shouldHave, hasScope)
			}
		})
	}
}

// TestRunLicenseExample проверяет полный цикл работы с лицензиями через RunLicenseExample
func TestRunLicenseExample(t *testing.T) {
	// Выполняем полный пример работы с библиотекой
	licenseToken, err := RunLicenseExample()
	if err != nil {
		t.Fatalf("Ошибка выполнения полного примера: %v", err)
	}

	// Проверяем, что токен не пустой
	if licenseToken == "" {
		t.Fatal("Сгенерированный токен лицензии не должен быть пустым")
	}

	// Проверяем, что токен содержит точки (JWT формат)
	if !strings.Contains(licenseToken, ".") {
		t.Error("Токен должен быть в формате JWT (содержать точки)")
	}

	// Дополнительная проверка: убедимся, что лицензия может быть провалидирована
	allScopes := []license.Scope{
		{ID: "read", Name: "Чтение", Description: "Доступ на чтение данных"},
		{ID: "write", Name: "Запись", Description: "Доступ на запись данных"},
		{ID: "admin", Name: "Администрирование", Description: "Полный доступ к системе"},
		{ID: "export", Name: "Экспорт", Description: "Доступ к экспорту данных"},
	}

	validator := license.NewValidator([]byte(publicKey), allScopes)
	isValid := validator.Validate(licenseToken, hashKey)
	if !isValid {
		t.Error("Лицензия, сгенерированная через RunLicenseExample, должна быть валидной")
	}
}
