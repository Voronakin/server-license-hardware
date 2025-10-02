package license

import (
	"fmt"

	"server-license-hardware/pkg/hosthash"

	"github.com/golang-jwt/jwt/v5"
)

type Validator struct {
	publicKey []byte
	scopes    []Scope
}

func NewValidator(publicKey []byte, scopes []Scope) *Validator {
	return &Validator{
		publicKey: publicKey,
		scopes:    scopes,
	}
}

func (v *Validator) Validate(tokenString, hashKey string) (*LicenseInfo, error) {
	token, claims, err := v.parseToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга токена: %w", err)
	}

	sub, err := token.Claims.GetSubject()
	if err != nil {
		return nil, fmt.Errorf("не удалось получить subject из токена: %w", err)
	}

	// Декодируем хэш машины из токена
	decryptedHash := DecrypteHash(sub, hashKey)
	currentHash := hosthash.GenHash()
	hashValid := decryptedHash == currentHash

	if !hashValid {
		return nil, fmt.Errorf("лицензия предназначена для другой машины")
	}

	_, err = token.Claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("не удалось получить время окончания действия: %w", err)
	}

	// Получаем scope из claims
	var scopeIds []string
	if scopeClaim, ok := claims["scope"].([]interface{}); ok {
		for _, s := range scopeClaim {
			if str, ok := s.(string); ok {
				scopeIds = append(scopeIds, str)
			}
		}
	}

	if len(scopeIds) == 0 {
		return nil, fmt.Errorf("не удалось определить scope лицензии")
	}

	return &LicenseInfo{
		Active:        true,
		TokenActive:   true,
		HashActive:    hashValid,
		ErrorMessage:  "",
		TokenValue:    tokenString,
		HostHashValue: decryptedHash,
		Scopes:        v.getScopesByIds(scopeIds),
	}, nil
}

func (v *Validator) parseToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	myPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(v.publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("неверный публичный ключ: %w", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("неожиданный метод подписания: %s", token.Header["alg"])
		}
		return myPublicKey, nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("ошибка валидации токена: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return token, claims, nil
	}

	return nil, nil, fmt.Errorf("недействительный токен")
}

func (v *Validator) getScopesByIds(ids []string) []Scope {
	var result []Scope
	for _, id := range ids {
		for _, scope := range v.scopes {
			if scope.ID == id {
				result = append(result, scope)
				break
			}
		}
	}
	return result
}
