package license

import (
	"log/slog"
	"os"

	"server-license-hardware/pkg/crypt"
	"server-license-hardware/pkg/hosthash"
)

type LicenseInfo struct {
	Active        bool
	TokenActive   bool
	HashActive    bool
	ErrorMessage  string
	TokenValue    string
	HostHashValue string
	Scopes        []Scope
}

func GetLicense(filePath ...string) (string, error) {
	path := "license.txt"
	if len(filePath) > 0 && filePath[0] != "" {
		path = filePath[0]
	}

	content, err := os.ReadFile(path)
	if err != nil {
		slog.Error("Failed to read license file", err)
		return "", err
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
	return crypt.Encrypte(hash, hashKey)
}

func DecrypteHash(tokenHash, hashKey string) (string, error) {
	return crypt.Decrypte(tokenHash, hashKey)
}

func (lic *LicenseInfo) CheckScope(id string) bool {
	for _, scope := range lic.Scopes {
		if id == scope.ID {
			return true
		}
	}
	return false
}

func (lic *LicenseInfo) CheckScopes(ids []string) bool {
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
