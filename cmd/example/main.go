package main

import (
	"fmt"
	"log/slog"
	"time"

	"server-license-hardware/pkg/hosthash"
	"server-license-hardware/pkg/license"
)

func main() {
	// Пример использования библиотеки
	slog.Info("Демонстрация работы библиотеки лицензирования")

	// Генерация хэша машины
	hash := hosthash.GenHash()
	fmt.Printf("Хэш машины: %s\n", hash)

	// Пример ключей (в реальном проекте должны быть настоящие ключи)
	hashKey := "6368616e676520746869732070617373776f726420746f206120736563726574" // 32-байтный ключ AES
	tokenPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz7J8wR2tZf6p2V7m8g9X6Yt1cR3vM8L2n5s8wV1qP3x
... (пример приватного ключа) ...
-----END RSA PRIVATE KEY-----`
	tokenPublicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz7J8wR2tZf6p2V7m8g9X
... (пример публичного ключа) ...
-----END PUBLIC KEY-----`

	// Пример создания лицензии
	expTime := time.Now().AddDate(1, 0, 0) // Лицензия на 1 год
	scopes := []license.Scope{
		{ID: license.ScopeReportDayBalanceId},
		{ID: license.ScopeNotificationAppointmentReminderId},
	}

	// Шифрование хэша машины
	encryptedHash := license.EncryptHash(hash, hashKey)
	fmt.Printf("Зашифрованный хэш: %s\n", encryptedHash)

	// Создание лицензии
	licenseToken := license.CreateLicense(encryptedHash, tokenPrivateKey, "Test License", expTime, scopes)
	fmt.Printf("Токен лицензии: %s\n", licenseToken)

	// Проверка лицензии
	licenseInfo := license.GetLicenseInfo(licenseToken, tokenPublicKey, hashKey)
	fmt.Printf("Лицензия активна: %v\n", licenseInfo.Active)
	fmt.Printf("Токен активен: %v\n", licenseInfo.TokenActive)
	fmt.Printf("Хэш активен: %v\n", licenseInfo.HashActive)
	if licenseInfo.ErrorMessage != "" {
		fmt.Printf("Ошибка: %s\n", licenseInfo.ErrorMessage)
	}

	// Проверка scope
	if licenseInfo.CheckScope(license.ScopeReportDayBalanceId) {
		fmt.Println("Доступ к отчетам кассы разрешен")
	}
}
