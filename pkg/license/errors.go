package license

import "fmt"

// ValidationErrorType представляет тип ошибки валидации лицензии
type ValidationErrorType string

const (
	// TokenParseError - ошибка парсинга JWT токена
	TokenParseError ValidationErrorType = "token_parse_error"
	// TokenSubjectError - ошибка получения subject из токена
	TokenSubjectError ValidationErrorType = "token_subject_error"
	// HashDecryptError - ошибка дешифрования хэша машины
	HashDecryptError ValidationErrorType = "hash_decrypt_error"
	// HashGenerateError - ошибка генерации текущего хэша машины
	HashGenerateError ValidationErrorType = "hash_generate_error"
	// HashMismatchError - несоответствие хэшей машины
	HashMismatchError ValidationErrorType = "hash_mismatch_error"
	// ExpirationTimeError - ошибка получения времени истечения
	ExpirationTimeError ValidationErrorType = "expiration_time_error"
	// IssuedAtTimeError - ошибка получения времени выдачи
	IssuedAtTimeError ValidationErrorType = "issued_at_time_error"
	// NotBeforeTimeError - ошибка получения времени начала действия
	NotBeforeTimeError ValidationErrorType = "not_before_time_error"
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
	TokenSubjectError:   "failed to get subject from token",
	HashDecryptError:    "failed to decrypt machine hash",
	HashGenerateError:   "failed to generate current machine hash",
	HashMismatchError:   "license is intended for another machine",
	ExpirationTimeError: "failed to get expiration time",
	IssuedAtTimeError:   "failed to get issued at time",
	NotBeforeTimeError:  "failed to get not before time",
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
