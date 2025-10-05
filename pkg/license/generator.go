package license

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Generator struct {
	privateKey []byte
	scopes     []Scope
}

type CreateOptions struct {
	HardwareHash string
	Name         string
	ExpiresAt    time.Time
	NotBefore    time.Time // Время начала действия (по умолчанию IssuedAt)
	Scopes       []string
}

func NewGenerator(privateKey []byte, scopes []Scope) *Generator {
	return &Generator{
		privateKey: privateKey,
		scopes:     scopes,
	}
}

func (g *Generator) Create(opts CreateOptions) (string, error) {
	myPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(g.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Checking that the requested scope exists
	if !g.validateScopes(opts.Scopes) {
		return "", fmt.Errorf("unknown scopes: %v", opts.Scopes)
	}

	issuedAt := time.Now()
	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = issuedAt
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"name":  opts.Name,
		"sub":   opts.HardwareHash,
		"nbf":   notBefore.Unix(),
		"exp":   opts.ExpiresAt.Unix(),
		"iat":   issuedAt.Unix(),
		"scope": opts.Scopes,
	})

	tokenString, err := token.SignedString(myPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign license token: %w", err)
	}

	return tokenString, nil
}

func (g *Generator) validateScopes(requestedScopes []string) bool {
	for _, requested := range requestedScopes {
		found := false
		for _, available := range g.scopes {
			if requested == available.ID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
