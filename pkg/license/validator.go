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

func (v *Validator) Validate(tokenString, hashKey string) bool {
	return v.ValidateDetails(tokenString, hashKey).Active
}

func (v *Validator) ValidateDetails(tokenString, hashKey string) *LicenseDetails {
	licenseDetails := &LicenseDetails{
		TokenValue: tokenString,
	}

	token, claims, err := v.parseToken(tokenString)
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, fmt.Sprintf("token parsing error: %v", err))
		return licenseDetails
	}

	licenseDetails.TokenActive = true

	// Получение subject из токена
	sub, err := token.Claims.GetSubject()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, fmt.Sprintf("failed to get subject from token: %v", err))
		return licenseDetails
	}

	// Декодирование хэша машины из токена
	decryptedHash, err := DecryptHash(sub, hashKey)
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, fmt.Sprintf("failed to decrypt machine hash: %v", err))
		return licenseDetails
	}
	licenseDetails.HostHashValue = decryptedHash

	// Генерация текущего хэша машины
	currentHash, err := hosthash.GenHash()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, fmt.Sprintf("failed to generate current machine hash: %v", err))
		return licenseDetails
	}
	licenseDetails.CurrentHash = currentHash

	// Проверка соответствия хэшей
	hashValid := decryptedHash == currentHash
	licenseDetails.HashActive = hashValid
	if !hashValid {
		licenseDetails.Errors = append(licenseDetails.Errors, "license is intended for another machine")
	}

	// Получение времени истечения
	exp, err := token.Claims.GetExpirationTime()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, fmt.Sprintf("failed to get expiration time: %v", err))
	} else if exp != nil {
		licenseDetails.ExpiresAt = exp.String()
	}

	// Получение времени выдачи
	iat, err := token.Claims.GetIssuedAt()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, fmt.Sprintf("failed to get issued at time: %v", err))
	} else if iat != nil {
		licenseDetails.IssuedAt = iat.String()
	}

	// Получение названия лицензии
	if name, ok := claims["name"].(string); ok {
		licenseDetails.Name = name
	}

	// Получение scope из claims
	var scopeIds []string
	if scopeClaim, ok := claims["scope"].([]interface{}); ok {
		for _, s := range scopeClaim {
			if str, ok := s.(string); ok {
				scopeIds = append(scopeIds, str)
			}
		}
	}

	if len(scopeIds) == 0 {
		licenseDetails.Errors = append(licenseDetails.Errors, "failed to determine license scopes")
	} else {
		licenseDetails.Scopes = v.getScopesByIds(scopeIds)
	}

	// Определение общего статуса активности
	licenseDetails.Active = licenseDetails.TokenActive && licenseDetails.HashActive && len(licenseDetails.Errors) == 0

	return licenseDetails
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
