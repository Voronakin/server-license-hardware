package main

import (
	"fmt"
	"log/slog"
	"time"

	"server-license-hardware/pkg/hosthash"
	"server-license-hardware/pkg/license"
)

func main() {
	// Пример использования библиотеки
	slog.Info("Демонстрация работы библиотеки лицензирования")

	// Генерация хэша машины
	hash := hosthash.GenHash()
	fmt.Printf("Хэш машины: %s\n", hash)

	// Пример ключей (в реальном проекте должны быть настоящие ключи)
	hashKey := "6368616e676520746869732070617373776f726420746f206120736563726574" // 32-байтный ключ AES
	tokenPrivateKey := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu9VdIloNfZ3R8
GVWKDb6JBiOXAbW/0HxY7flDuHp7ClIbYusF9KhqHW3D90r9V7XRD0nyLT0B35nP
cbNpU603+HXhjmX+6i5YYN5Ag+cjKAe1dxdsGdAOJjNfCFcsuHEehn+1SkspRP0L
9RFmx63bNoeHMHm5HPk8Jg+oD5Ekomog6+EHMT+ooqJS+1cKOdv5TPlZ5nL5uDvO
XYpoOOIQwHrLcjtC/gupYqgy8eHzZyWF9KOP5j1q7le0Aw61qK0S2j7LOGk0iYEf
EvkW+H3lRDwroj0wTmW7jN0lJgciroNw2DdnP1QUvSyHiMML2jQq00r1Q+Ix5J37
chevHPvfAgMBAAECggEAQhOv2N7bk/sfH8VzrHWfaeHTLDN9oImNhQqvkxeHzpNp
yiUUTUYHGzitHY92l3L6XJAxJdFXEq+PyCyRjWyIZbSlVMAynlF0mnVPSz9l2r3C
F5N4WZ/wF3/u8+vS/LVWJ6i1b9M0ysve5Ba08UPl0f5otjKlLjgWm1RmolrqvtIm
SgGbf+a+rb7wSIOCIQ+vlIsmCuPBienRH3pO7mD6v/xJYk74ni8quW+7EMl1/8me
HpyYDgnwn9atb3takt73/gso73tbMwrmXJDHVmJmYlviLnCf/xA2CVXK/Z6BGrpd
M7NIEUjQsOjkGfh4zqRxKrJJcLZM9oSuC20j0C5suQKBgQDdqeVBN+1vGxW+mbiG
y+mPwfPN/2C47N4X2eP7XDcMpf/yjTowD2esiwhBTZ8alMUZaoeDf2uhpa+0yaKu
uxafBKry+p/n2aI0k0VN6gITZMEUnWNEdQKWgMmzt70bW4db3dsSmxQXvGXR2AXo
OIfojK27RsIVnIL3d81VIk5y9wKBgQDKD1cd+e0sEPG0rLubCg78kazDorJSDTCT
LbEkV+ilyJeM2Dg7DlsCjKOSdaLi08ZA1RfM8Bcqdk93as4nJIqMJPqNn+i7iiNZ
r99bGZU2J4UhK7jvRWwT+PflfIP8Xt3jCXH32NW6EJOpvLKNjZ0QxVtWV1XZywx+
BrX+Z9wcWQKBgBx+38rvjqVu3O/AwTkK876YV2hPATcktDRqvWUt6KHGoU2kHCvb
fx9uTCRg/ygioefvivY7pjGEpD7ggPpncLQGnJdZ4r6ieri5ifpHL/cgR7YHuaAu
TqPccJGa+EORE6iar7QHnaCjho9gbvn4cnhRxW/C2+Z9VVTM4Oel3mHnAoGAab7h
fsSfhOJRPJbxj9ARy8iJO9FXtW1FsKDHBhgjny99cK5vryhyJMFpkWqTFlZyeNeM
nyo/VW+ZYwu4W+/ZukJYBepcKFnA6l0KbWjUGAVSvOte24nfaAxx393sTRVw1jLJ
PEZ0g+3M+ZXRdBdazb4bcPI/8b08CnCEqmG8ZfECgYEAlaqCjrlqQ7I8e2/v783A
XDjwpvyy4NoXSCSDF8TUGZUk5lgxGIEdMLk+1Vmtt/Wxm1T4tiGyDs9SQC2RDOaj
tQfPnP+RKyzH0cHaSCE4iNeCwwM9a19h+tNfZzKSpQWIdHS7dTSCrdUWj57j3LDq
8viG/LjvUmB4d6aQhH+oALM=
-----END PRIVATE KEY-----`
	tokenPublicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArvVXSJaDX2d0fBlVig2+
iQYjlwG1v9B8WO35Q7h6ewpSG2LrBfSoah1tw/dK/Ve10Q9J8i09Ad+Zz3GzaVOt
N/h14Y5l/uouWGDeQIPnIygHtXcXbBnQDiYzXwhXLLhxHoZ/tUpLKUT9C/URZset
2zaHhzB5uRz5PCYPqA+RJKJqIOvhBzE/qKKiUvtXCjnb+Uz5WeZy+bg7zl2KaDji
EMB6y3I7Qv4LqWKoMvHh82clhfSjj+Y9au5XtAMOtaitEto+yzhpNImBHxL5Fvh9
5UQ8K6I9ME5lu4zdJSYHIq6DcNg3Zz9UFL0sh4jDC9o0KtNK9UPiMeSd+3IXrxz7
3wIDAQAB
-----END PUBLIC KEY-----`

	// Определение scope для конкретного приложения
	allScopes := []license.Scope{
		{ID: "read", Name: "Чтение", Description: "Доступ на чтение данных"},
		{ID: "write", Name: "Запись", Description: "Доступ на запись данных"},
		{ID: "admin", Name: "Администрирование", Description: "Полный доступ к системе"},
	}

	// Создание генератора (для сервера лицензирования)
	generator := license.NewGenerator([]byte(tokenPrivateKey), allScopes)

	// Создание валидатора (для клиентских приложений)
	validator := license.NewValidator([]byte(tokenPublicKey), allScopes)

	// Пример создания лицензии
	expTime := time.Now().AddDate(1, 0, 0) // Лицензия на 1 год

	// Шифрование хэша машины
	encryptedHash := license.EncryptHash(hash, hashKey)
	fmt.Printf("Зашифрованный хэш: %s\n", encryptedHash)

	// Создание лицензии с помощью генератора
	licenseToken, err := generator.Create(license.CreateOptions{
		HardwareHash: encryptedHash,
		Name:         "Test License",
		ExpiresAt:    expTime,
		Scopes:       []string{"read", "write"},
	})
	if err != nil {
		slog.Error("Ошибка создания лицензии", err)
		return
	}
	fmt.Printf("Токен лицензии: %s\n", licenseToken)

	// Проверка лицензии с помощью валидатора
	licenseInfo, err := validator.Validate(licenseToken, hashKey)
	if err != nil {
		slog.Error("Ошибка проверки лицензии", err)
		return
	}

	fmt.Printf("Лицензия активна: %v\n", licenseInfo.Active)
	fmt.Printf("Токен активен: %v\n", licenseInfo.TokenActive)
	fmt.Printf("Хэш валиден: %v\n", licenseInfo.HashActive)
	if licenseInfo.ErrorMessage != "" {
		fmt.Printf("Ошибка: %s\n", licenseInfo.ErrorMessage)
	}

	// Проверка scope
	if licenseInfo.CheckScope("read") {
		fmt.Println("Доступ на чтение разрешен")
	}
	if licenseInfo.CheckScope("write") {
		fmt.Println("Доступ на запись разрешен")
	}
	if licenseInfo.CheckScope("admin") {
		fmt.Println("Административный доступ разрешен")
	} else {
		fmt.Println("Административный доступ запрещен")
	}
}
