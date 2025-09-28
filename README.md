# server-license-hardware

Библиотека на Golang для генерации и валидации лицензий для программного обеспечения.

## Описание

Библиотека создаёт токены JWT, содержащие хэши сервера, на основе его характеристик, что предотвращает повторное использование лицензий на других серверах. Токены JWT подписываются с использованием асимметричного шифрования. Библиотека разработана для ОС Windows.

## Архитектура

Пакет включает в себя 4 подпакета:

1. **Генератор хэша машины** (`pkg/hosthash`) - создает JSON с характеристиками оборудования, уникальный для каждой машины
2. **Шифрование** (`pkg/crypt`) - симметричное шифрование хэша машины с использованием AES
3. **Генератор лицензий** (`pkg/license`) - создает JWT токен на основе зашифрованного хэша, подписанный асимметричным ключом
4. **Валидатор лицензий** (`pkg/license`) - проверяет подпись лицензии и сравнивает характеристики с текущей машиной

## Использование

```go
import (
    "server-license-hardware/pkg/hosthash"
    "server-license-hardware/pkg/license"
)

// Генерация хэша машины
hash := hosthash.GenHash()

// Создание лицензии
licenseToken := license.CreateLicense(
    license.EncryptHash(hash, hashKey),
    privateKey,
    "Test License",
    expTime,
    scopes,
)

// Проверка лицензии
licenseInfo := license.GetLicenseInfo(licenseToken, publicKey, hashKey)
```

## Установка

```bash
go get github.com/your-username/server-license-hardware
```

## Пример

См. `cmd/example/main.go` для полного примера использования.

## Лицензия

MIT License