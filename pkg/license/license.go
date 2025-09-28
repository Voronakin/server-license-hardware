package license

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"server-license-hardware/pkg/crypt"
	"server-license-hardware/pkg/hosthash"

	"github.com/golang-jwt/jwt/v5"
)

type PublicLicenseInfo struct {
	Active       bool
	TokenActive  bool
	HashActive   bool
	ErrorMessage string
	Token
	TokenValue string
	Scopes     []Scope
}

type PrivateLicenseInfo struct {
	Active       bool
	TokenActive  bool
	HashActive   bool
	ErrorMessage string
	Token
	TokenValue    string
	HostHashValue string
	Scopes        []Scope
}

type Token struct {
	Issuer         string
	Subject        string
	Audience       string
	ExpirationTime jwt.NumericDate
	NotBeforeTime  jwt.NumericDate
	IssuedAtTime   jwt.NumericDate
	JwtId          string
}

type CustomClaims struct {
	Scopes               []string `json:"scope"`
	jwt.RegisteredClaims          // Встроенные стандартные claims
}

func Check(tokenKey, hashKey string) (bool, error) {
	slog.Info("Проверка лицензии")
	token := GetLicense()
	slog.Info("Токен: " + token)

	licenseInfo := GetLicenseInfo(token, tokenKey, hashKey)

	return licenseInfo.Active, fmt.Errorf(licenseInfo.ErrorMessage)
}

func GetLicenseInfo(tokenString, tokenKey, hashKey string) PrivateLicenseInfo {
	tokenActive := true
	errMes := ""

	token, claims, err := parseToken(tokenString, tokenKey)
	if err != nil {
		tokenActive = false
		slog.Error("Не удалось разобрать данные лицензии", err)
		errMes = err.Error()
	}

	sub, err := token.Claims.GetSubject()
	if err != nil {
		tokenActive = false
		slog.Error("Не удалось определить хеш машины в лицензии", err)
		errMes = err.Error()
	}

	hashActive := DecrypteHash(sub, hashKey) == hosthash.GenHash()
	if hashActive == false {
		errMes = "Лицензия предназначена для другой машины"
		slog.Error(errMes)
	}

	exp, err := token.Claims.GetExpirationTime()
	if err != nil {
		tokenActive = false
		slog.Error("Не удалось определить время окончания действия лицензии", err)
		errMes = err.Error()
	}

	scopeIds := claims.Scopes
	if len(scopeIds) == 0 {
		tokenActive = false
		errMes := "Не удалось определить список применения лицензии"
		slog.Error(errMes)
	}

	return PrivateLicenseInfo{
		Active:       tokenActive && hashActive,
		TokenActive:  tokenActive,
		HashActive:   hashActive,
		ErrorMessage: errMes,
		Token: Token{
			Subject:        sub,
			ExpirationTime: *exp,
		},
		TokenValue:    tokenString,
		HostHashValue: DecrypteHash(sub, hashKey),
		Scopes:        GetScopesByIds(scopeIds),
	}
}

func parseToken(tokenString, tokenKey string) (*jwt.Token, *CustomClaims, error) {
	myPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(tokenKey))
	if err != nil {
		return nil, nil, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		//TODO разобраться с синтаксисом как работает проверка метода
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("неожиданный метод подписания: %s", token.Header["alg"])
		}

		return myPublicKey, nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("ошибка валидации токена: %w", err)
	}

	// Извлекаем claims
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return token, claims, nil
	}

	return nil, nil, fmt.Errorf("недействительный токен или неверные claims")
}

func GetLicense() string {
	content, err := os.ReadFile("license.txt")
	if err != nil {
		slog.Error("Не удалось прочитать файл лицензии из файла", err)
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

func CreateLicense(systemHash, tokenKey, name string, exp time.Time, scopes []Scope) string {
	myPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(tokenKey))
	if err != nil {
		slog.Error("Не удалось определить хеш машины в лицензии", err)
		os.Exit(1)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"name":  name,
		"sub":   systemHash,
		"nbf":   time.Now().Unix(),
		"exp":   exp.Unix(),
		"iat":   time.Now().Unix(),
		"scope": GetScopeIds(scopes),
	})

	tokenString, err := token.SignedString(myPrivateKey)
	if err != nil {
		slog.Error("Не удалось подписать токен лицензии", err)
		os.Exit(1)
	}

	return tokenString
}

func (lic PrivateLicenseInfo) CheckScope(id string) bool {

	for _, scope := range lic.Scopes {
		if id == scope.ID {
			return true
		}
	}

	return false
}

func (lic PrivateLicenseInfo) CheckScopes(ids []string) bool {
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

func (lic PrivateLicenseInfo) GetPublicLicenseInfo() PublicLicenseInfo {
	return PublicLicenseInfo{
		Active:       lic.Active,
		TokenActive:  lic.TokenActive,
		HashActive:   lic.HashActive,
		ErrorMessage: lic.ErrorMessage,
		Token:        lic.Token,
		TokenValue:   lic.TokenValue,
		Scopes:       lic.Scopes,
	}
}
