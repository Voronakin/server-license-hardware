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
		return nil, fmt.Errorf("token parsing error: %w", err)
	}

	sub, err := token.Claims.GetSubject()
	if err != nil {
		return nil, fmt.Errorf("failed to get subject from token: %w", err)
	}

	// Декодируем хэш машины из токена
	decryptedHash, err := DecryptHash(sub, hashKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt machine hash: %w", err)
	}
	currentHash, err := hosthash.GenHash()
	if err != nil {
		return nil, fmt.Errorf("failed to generate current machine hash: %w", err)
	}
	hashValid := decryptedHash == currentHash

	if !hashValid {
		return nil, fmt.Errorf("license is intended for another machine")
	}

	_, err = token.Claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("failed to get expiration time: %w", err)
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
		return nil, fmt.Errorf("failed to determine license scopes")
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
		return nil, nil, fmt.Errorf("invalid public key: %w", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}
		return myPublicKey, nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("token validation error: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return token, claims, nil
	}

	return nil, nil, fmt.Errorf("invalid token")
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
