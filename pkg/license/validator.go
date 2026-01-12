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

func (lic *LicenseDetails) validateBaseClimes(claims jwt.MapClaims, v *Validator, hashKey string) *LicenseDetails {
	if claims == nil {
		lic.Errors = append(lic.Errors, NewClaimGetError("no claims"))
		return lic
	}

	claimFail := false

	// Получение времени истечения
	exp, err := claims.GetExpirationTime()
	if err != nil {
		claimFail = true
		lic.Errors = append(lic.Errors, NewClaimGetError("expiration time"))
	} else if exp != nil {
		lic.ExpiresAt = exp.Time
	}

	// Получение времени выдачи
	iat, err := claims.GetIssuedAt()
	if err != nil {
		claimFail = true
		lic.Errors = append(lic.Errors, NewClaimGetError("issued at time"))
	} else if iat != nil {
		lic.IssuedAt = iat.Time
	}

	// Получение времени начала действия
	nbf, err := claims.GetNotBefore()
	if err != nil {
		claimFail = true
		lic.Errors = append(lic.Errors, NewClaimGetError("not before time"))
	} else if nbf != nil {
		lic.NotBefore = nbf.Time
	}

	// Получение названия лицензии
	if name, ok := claims["name"].(string); ok {
		lic.Name = name
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
		lic.Scopes = v.getScopesByIds(scopeIds)
	}

	if claimFail {
		lic.TokenActive = false
	}

	return lic.validateHash(claims, hashKey)
}

func (lic *LicenseDetails) validateHash(claims jwt.MapClaims, hashKey string) *LicenseDetails {
	if claims == nil {
		return lic
	}

	// Получение subject из токена
	sub, err := claims.GetSubject()
	if err != nil {
		lic.Errors = append(lic.Errors, NewClaimGetError("subject"))
		return lic
	}

	// Декодирование хэша машины из токена
	decryptedHash, err := DecryptHash(sub, hashKey)
	if err != nil {
		lic.Errors = append(lic.Errors, NewValidationError(
			HashDecryptError,
			fmt.Sprintf("failed to decrypt machine hash: %s", err.Error()),
		))
		return lic
	}
	lic.HostHashValue = decryptedHash

	// Генерация текущего хэша машины
	currentHash, err := hosthash.GenHash()
	if err != nil {
		lic.Errors = append(lic.Errors, NewValidationError(
			HashGenerateError,
			fmt.Sprintf("failed to generate current machine hash: %s", err.Error()),
		))
		return lic
	}
	lic.CurrentHash = currentHash

	// Проверка соответствия хэшей
	hashValid := decryptedHash == currentHash
	lic.HashActive = hashValid
	if !hashValid {
		lic.Errors = append(lic.Errors, NewHashMismatchError())
	}

	return lic
}

func (v *Validator) ValidateDetails(tokenString, hashKey string) *LicenseDetails {
	licenseDetails := &LicenseDetails{
		TokenValue: tokenString,
	}

	token, claims, err := v.parseToken(tokenString)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			licenseDetails.Errors = append(licenseDetails.Errors, NewLicenseExpired())
			return licenseDetails.validateBaseClimes(claims, v, hashKey)
		}

		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			licenseDetails.Errors = append(licenseDetails.Errors, NewLicenseNotYetActive())
			return licenseDetails.validateBaseClimes(claims, v, hashKey)
		}

		licenseDetails.Errors = append(licenseDetails.Errors, NewValidationError(
			TokenParseError,
			fmt.Sprintf("failed to parse JWT token: %s", err.Error()),
		))
		return licenseDetails.validateBaseClimes(claims, v, hashKey)
	}

	licenseDetails.TokenActive = token.Valid

	licenseDetails = licenseDetails.validateBaseClimes(claims, v, hashKey)

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
