# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Агент

Ты - первоклассный разработчик, технический лидер и архитектор программного обеспечения. 
Ты должен применить весь свой многолетний опыт для реализации следующего проекта.

## Обзор проекта

Это библиотека Go для генерации и проверки лицензий на программное обеспечение. Библиотека создаёт токены JWT,
содержащие хэши сервера, на основе его характеристик, что предотвращает повторное использование лицензий на других серверах.
Токены JWT подписываются с использованием асимметричного шифрования. Библиотека поддерживает ОС Windows и Linux.

## Цель проекта

- **Генерация лицензий**: создание лицензий на основе JWT с хешами, специфичными для сервера
- **Проверка лицензий**: проверка лицензий на соответствие характеристикам сервера
- **Привязка к оборудованию**: предотвращение передачи лицензий между разными серверами
- **Асимметричное шифрование**: использование пар открытого и закрытого ключей для подписи JWT
- **Система разрешений**: гибкая система scope для управления правами доступа

## Техническая архитектура

Пакет включает в себя 4 подпакета:
1) **hosthash** - генератор хэша машины в виде JSON с характеристиками оборудования
2) **crypt** - симметричное шифрование AES-CBC для хэшей
3) **license** - основной пакет для работы с лицензиями
4) **cmd/example** - пример использования библиотеки

### Основные компоненты:

- **Генерация хэша машины**: сбор данных об оборудовании (hostname, CPU, память, диск, MAC-адрес)
- **Симметричное шифрование**: AES-CBC с PKCS7 padding для шифрования хэшей
- **JWT токены**: создание и валидация лицензий с RSA подписью
- **Scope система**: универсальная система разрешений с внешней инициализацией
- **Разделение ответственности**: отдельные генератор и валидатор для безопасности

## API библиотеки

### Основные структуры:

```go
// Генератор лицензий (для сервера)
generator := license.NewGenerator(privateKey, scopes)

// Валидатор лицензий (для клиентов)
validator := license.NewValidator(publicKey, scopes)
```

### Основные функции:

```go
// Генерация лицензии
licenseToken, err := generator.Create(license.CreateOptions{
    HardwareHash: encryptedHash,
    Name: "License Name",
    ExpiresAt: time.Now().AddDate(1, 0, 0),
    Scopes: []string{"read", "write"},
})

// Валидация лицензии
licenseInfo, err := validator.Validate(licenseToken, hashKey)

// Проверка scope
if licenseInfo.CheckScope("read") {
    // Разрешить доступ
}
```

### Структура scope:

```go
type Scope struct {
    ID          string // Уникальный идентификатор
    Name        string // Человекочитаемое название
    Description string // Описание
}
```

## Платформенные особенности

- **Кросс-платформенность**: поддерживает Windows и Linux
- **Привязка к оборудованию**: характеристики сервера должны быть стабильными и уникальными
- **Безопасность**: правильное управление ключами и криптографические методы
- **Производительность**: эффективное сканирование оборудования и генерация хэшей
- **Гибкость**: универсальная система scope для разных проектов

## Пример использования

См. `cmd/example/main.go` для полного примера работы с библиотекой.

Отвечай пользователю всегда на русском языке

## Go-Specific Guidelines for Claude Code

- Always run `go fmt`, `goimports`, and `golangci-lint` after any edit.
- Write clear, idiomatic Go: avoid complex patterns, use short and meaningful names, and prefer simplicity over cleverness.
- Exported names must have documentation comments, written as full sentences starting with the name.
- Never ignore errors; always handle or propagate them appropriately.
- Use context for goroutine lifecycle management.
- Always write tests for new features and changes.
- Run `go test` before committing any change.
- When in doubt, ask for human review or leave a TODO comment for follow-up.
- Prefer struct composition over inheritance.
- Interfaces belong to the consumer, not the implementer.
- Table-driven tests are preferred for repetitive test cases.
- For performance-critical code, use benchmarks (go test -bench).
