package license

import (
	"errors"
	"fmt"
	"github.com/Voronakin/server-license-hardware/pkg/hosthash"

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
		if errors.Is(err, jwt.ErrTokenExpired) {
			licenseDetails.Errors = append(licenseDetails.Errors, NewLicenseExpired())
			return licenseDetails
		}

		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			licenseDetails.Errors = append(licenseDetails.Errors, NewLicenseNotYetActive())
			return licenseDetails
		}

		licenseDetails.Errors = append(licenseDetails.Errors, NewValidationError(
			TokenParseError,
			fmt.Sprintf("failed to parse JWT token: %s", err.Error()),
		))
		return licenseDetails
	}

	licenseDetails.TokenActive = token.Valid

	// Получение subject из токена
	sub, err := token.Claims.GetSubject()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, NewClaimGetError("subject"))
		return licenseDetails
	}

	// Декодирование хэша машины из токена
	decryptedHash, err := DecryptHash(sub, hashKey)
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, NewValidationError(
			HashDecryptError,
			fmt.Sprintf("failed to decrypt machine hash: %s", err.Error()),
		))
		return licenseDetails
	}
	licenseDetails.HostHashValue = decryptedHash

	// Генерация текущего хэша машины
	currentHash, err := hosthash.GenHash()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, NewValidationError(
			HashGenerateError,
			fmt.Sprintf("failed to generate current machine hash: %s", err.Error()),
		))
		return licenseDetails
	}
	licenseDetails.CurrentHash = currentHash

	// Проверка соответствия хэшей
	hashValid := decryptedHash == currentHash
	licenseDetails.HashActive = hashValid
	if !hashValid {
		licenseDetails.Errors = append(licenseDetails.Errors, NewHashMismatchError())
	}

	// Получение времени истечения
	exp, err := token.Claims.GetExpirationTime()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, NewClaimGetError("expiration time"))
	} else if exp != nil {
		licenseDetails.ExpiresAt = exp.Time
	}

	// Получение времени выдачи
	iat, err := token.Claims.GetIssuedAt()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, NewClaimGetError("issued at time"))
	} else if iat != nil {
		licenseDetails.IssuedAt = iat.Time
	}

	// Получение времени начала действия
	nbf, err := token.Claims.GetNotBefore()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, NewClaimGetError("not before time"))
	} else if nbf != nil {
		licenseDetails.NotBefore = nbf.Time
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

	if len(scopeIds) > 0 {
		licenseDetails.Scopes = v.getScopesByIds(scopeIds)
	}

	// Определение общего статуса активности
	licenseDetails.Active = licenseDetails.TokenActive && licenseDetails.HashActive && len(licenseDetails.Errors) == 0

	return licenseDetails
}

func (v *Validator) parseToken(tokenString string) (token *jwt.Token, claims jwt.MapClaims, e error) {
	myPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(v.publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key: %w", err)
	}

	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}
		return myPublicKey, nil
	})

	claims, ok := token.Claims.(jwt.MapClaims)

	if err == nil && ok && token.Valid {
		return
	}

	if err != nil {
		e = err
		return
	}

	if !ok || !token.Valid {
		e = fmt.Errorf("error get clims")
		return
	}

	e = fmt.Errorf("error validate token")
	return
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
