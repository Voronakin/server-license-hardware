package license

import (
	"errors"
	"fmt"
	"server-license-hardware/pkg/hosthash"
	"time"

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
		licenseDetails.Errors = append(licenseDetails.Errors, NewValidationError(
			TokenParseError,
			fmt.Sprintf("failed to parse JWT token: %s", err.Error()),
		))
		return licenseDetails
	}

	// TokenActive true если токен валиден с точки зрения подписи (включая токены с временными ошибками)
	// Временные ошибки обрабатываются отдельно в нашей собственной валидации
	licenseDetails.TokenActive = true

	// Получение subject из токена
	sub, err := token.Claims.GetSubject()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, NewValidationError(
			TokenSubjectError,
			fmt.Sprintf("failed to get subject from token: %s", err.Error()),
		))
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
		licenseDetails.Errors = append(licenseDetails.Errors, NewValidationError(
			ExpirationTimeError,
			"",
		))
	} else if exp != nil {
		licenseDetails.ExpiresAt = exp.Time
	}

	// Получение времени выдачи
	iat, err := token.Claims.GetIssuedAt()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, NewValidationError(
			IssuedAtTimeError,
			"",
		))
	} else if iat != nil {
		licenseDetails.IssuedAt = iat.Time
	}

	// Получение времени начала действия
	nbf, err := token.Claims.GetNotBefore()
	if err != nil {
		licenseDetails.Errors = append(licenseDetails.Errors, NewValidationError(
			NotBeforeTimeError,
			"",
		))
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

	// Проверка временной валидации
	currentTime := time.Now()

	//TODO продумать необходимость с учетом  того что в пасинге может проигнорироваться валидация по времени
	// (технически это может и НЕ компенсировать проблемы повторного парсинга с выдачей,
	// если например валидация внутри используемого пакета jwt сначала идет по времени, а потом по каким-либо другим важным критериям)
	if currentTime.Before(licenseDetails.NotBefore) {
		licenseDetails.Errors = append(licenseDetails.Errors, NewLicenseNotYetActive())
	}

	if currentTime.After(licenseDetails.ExpiresAt) {
		licenseDetails.Errors = append(licenseDetails.Errors, NewLicenseExpired())
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

	// Если ошибка связана с временными claims (nbf/exp), все равно возвращаем токен для дальнейшей проверки
	if err != nil {
		//TODO продумать вынос в отдельную функцию  кейс с проблемой по времени

		// Проверяем, является ли ошибка временной (nbf/exp)
		if isTimeValidationError(err) {
			// Парсим токен без временной валидации, чтобы получить claims
			token, parseErr := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
				}
				return myPublicKey, nil
			}, jwt.WithoutClaimsValidation())

			if parseErr != nil {
				return nil, nil, fmt.Errorf("token parsing error: %w", parseErr)
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				//TODO !!! доработать, так как нельзя в рамках текущей функции просто выдать,
				// так как получается игнорируется ошибка по времени действия
				//TODO разобраться почему тесты не отслеживают данный баг
				return token, claims, nil
			}
			return nil, nil, fmt.Errorf("invalid token claims")
		}

		return nil, nil, fmt.Errorf("token validation error: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return token, claims, nil
	}

	return nil, nil, fmt.Errorf("invalid token")
}

// isTimeValidationError проверяет, является ли ошибка связанной с временной валидацией (nbf/exp)
func isTimeValidationError(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) || errors.Is(err, jwt.ErrTokenUsedBeforeIssued)
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
