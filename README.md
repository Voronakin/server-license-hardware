# server-license-hardware

Golang library for generating and validating software licenses.

## Description

The library creates JWT tokens containing server hashes based on its hardware characteristics, which prevents license reuse on other servers. JWT tokens are signed using asymmetric encryption. The library is designed for Windows/Linux OS.

## Architecture

The package includes 4 subpackages:

1. **Machine hash generator** (`pkg/hosthash`) - creates JSON with hardware characteristics, unique for each machine
2. **Encryption** (`pkg/crypt`) - symmetric encryption of machine hash using AES
3. **License generator** (`pkg/license`) - creates JWT token based on encrypted hash, signed with asymmetric key
4. **License validator** (`pkg/license`) - verifies license signature and compares characteristics with current machine

## Usage

```go
import (
    "server-license-hardware/pkg/hosthash"
    "server-license-hardware/pkg/license"
)

// Generate machine hash
hash := hosthash.GenHash()

// Define application scopes
allScopes := []license.Scope{
    {ID: "read", Name: "Read", Description: "Read data access"},
    {ID: "write", Name: "Write", Description: "Write data access"},
    {ID: "admin", Name: "Administration", Description: "Full system access"},
}

// Create generator (for license server)
generator := license.NewGenerator([]byte(privateKey), allScopes)

// Create validator (for client applications)
validator := license.NewValidator([]byte(publicKey), allScopes)

// Create license
licenseToken, err := generator.Create(license.CreateOptions{
    HardwareHash: license.EncryptHash(hash, hashKey),
    Name:         "Test License",
    ExpiresAt:    expTime,
    Scopes:       []string{"read", "write"},
})

// Validate license
licenseInfo, err := validator.Validate(licenseToken, hashKey)
```

## Installation

```bash
go get github.com/your-username/server-license-hardware
```

## Example

See `cmd/example/main.go` for complete usage example.

## License

MIT License