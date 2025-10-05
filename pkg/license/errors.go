package license

import "fmt"

// ValidationErrorType представляет тип ошибки валидации лицензии
type ValidationErrorType string

const (
	// TokenParseError - ошибка парсинга JWT токена
	TokenParseError ValidationErrorType = "token_parse_error"
	// ClaimGetError - ошибка получения данных из claims токена
	ClaimGetError ValidationErrorType = "claim_get_error"
	// HashDecryptError - ошибка дешифрования хэша машины
	HashDecryptError ValidationErrorType = "hash_decrypt_error"
	// HashGenerateError - ошибка генерации текущего хэша машины
	HashGenerateError ValidationErrorType = "hash_generate_error"
	// HashMismatchError - несоответствие хэшей машины
	HashMismatchError ValidationErrorType = "hash_mismatch_error"
	// LicenseNotYetActive - лицензия еще не активна
	LicenseNotYetActive ValidationErrorType = "license_not_yet_active"
	// LicenseExpired - лицензия истекла
	LicenseExpired ValidationErrorType = "license_expired"
)

// ValidationError представляет типизированную ошибку валидации лицензии
type ValidationError struct {
	Type    ValidationErrorType `json:"type"`
	Message string              `json:"message"`
}

// Error возвращает строковое представление ошибки
func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// errorMessages содержит предопределенные сообщения для каждого типа ошибки
var errorMessages = map[ValidationErrorType]string{
	TokenParseError:     "failed to parse JWT token",
	ClaimGetError:       "failed to get claim data",
	HashDecryptError:    "failed to decrypt machine hash",
	HashGenerateError:   "failed to generate current machine hash",
	HashMismatchError:   "license is intended for another machine",
	LicenseNotYetActive: "license is not yet active",
	LicenseExpired:      "license has expired",
}

// NewValidationError создает новую типизированную ошибку валидации
// Если message пустая строка, используется предопределенное сообщение из errorMessages
func NewValidationError(errorType ValidationErrorType, message string) ValidationError {
	if message == "" {
		if predefinedMessage, exists := errorMessages[errorType]; exists {
			message = predefinedMessage
		} else {
			message = string(errorType) // fallback to type name
		}
	}

	return ValidationError{
		Type:    errorType,
		Message: message,
	}
}

// Специализированные конструкторы для часто используемых ошибок
func NewLicenseNotYetActive() ValidationError {
	return NewValidationError(LicenseNotYetActive, "")
}

func NewLicenseExpired() ValidationError {
	return NewValidationError(LicenseExpired, "")
}

func NewHashMismatchError() ValidationError {
	return NewValidationError(HashMismatchError, "")
}

// NewClaimGetError создает ошибку получения данных из claims токена
// claimName - название claim, который не удалось получить (например, "subject", "expiration time")
func NewClaimGetError(claimName string) ValidationError {
	message := fmt.Sprintf("failed to get %s", claimName)
	return NewValidationError(ClaimGetError, message)
}
