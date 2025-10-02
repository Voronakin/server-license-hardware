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

func GetLicense() string {
	content, err := os.ReadFile("license.txt")
	if err != nil {
		slog.Error("Failed to read license file", err)
		os.Exit(1)
	}

	return string(content)
}

func GetHash(key string) string {
	return EncryptHash(hosthash.GenHash(), key)
}

func EncryptHash(hash, hashKey string) string {
	return crypt.Encrypte(hash, hashKey)
}

func DecrypteHash(tokenHash, hashKey string) string {
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
