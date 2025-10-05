package license

import (
	"fmt"
	"os"

	"server-license-hardware/pkg/crypt"
	"server-license-hardware/pkg/hosthash"
)

type LicenseDetails struct {
	Active        bool     // Общий статус активности лицензии
	TokenActive   bool     // Статус валидности токена
	HashActive    bool     // Статус соответствия хэша машины
	Errors        []string // Список всех ошибок валидации
	TokenValue    string   // Исходное значение токена
	HostHashValue string   // Расшифрованный хэш машины из лицензии
	CurrentHash   string   // Текущий хэш машины
	Scopes        []Scope  // Список scope из лицензии
	ExpiresAt     string   // Время истечения лицензии
	IssuedAt      string   // Время выдачи лицензии
	Name          string   // Название лицензии
}

func GetLicense(filePath ...string) (string, error) {
	path := "license.txt"
	if len(filePath) > 0 && filePath[0] != "" {
		path = filePath[0]
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read license file: %w", err)
	}

	return string(content), nil
}

func GetHash(key string) (string, error) {
	hash, err := hosthash.GenHash()
	if err != nil {
		return "", err
	}
	return EncryptHash(hash, key)
}

func EncryptHash(hash, hashKey string) (string, error) {
	return crypt.Encrypt(hash, hashKey)
}

func DecryptHash(tokenHash, hashKey string) (string, error) {
	return crypt.Decrypt(tokenHash, hashKey)
}

func (lic *LicenseDetails) CheckScope(id string) bool {
	for _, scope := range lic.Scopes {
		if id == scope.ID {
			return true
		}
	}
	return false
}

func (lic *LicenseDetails) CheckScopes(ids []string) bool {
nextScope:
	for _, id := range ids {
		for _, scope := range lic.Scopes {
			if id == scope.ID {
				continue nextScope
			}
		}
		return false
	}
	return true
}
