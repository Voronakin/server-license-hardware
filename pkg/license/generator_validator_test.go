package license

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Voronakin/server-license-hardware/pkg/hosthash"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testScopes = []Scope{
		{ID: "read", Name: "Read", Description: "Read data access"},
		{ID: "write", Name: "Write", Description: "Write data access"},
		{ID: "admin", Name: "Administration", Description: "Full system access"},
	}
	testHashKey = "6368616e676520746869732070617373776f726420746f206120736563726574"
)

func TestGenerator_Create(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)

	// Create a test hardware hash
	hardwareHash := "test-hardware-hash"
	encryptedHash, err := EncryptHash(hardwareHash, testHashKey)
	require.NoError(t, err)

	opts := CreateOptions{
		HardwareHash: encryptedHash,
		Name:         "Test License",
		ExpiresAt:    time.Now().AddDate(1, 0, 0), // 1 year
		Scopes:       []string{"read", "write"},
	}

	licenseToken, err := generator.Create(opts)
	require.NoError(t, err)
	assert.NotEmpty(t, licenseToken)
}

func TestGenerator_Create_InvalidPrivateKey(t *testing.T) {
	generator := NewGenerator([]byte("invalid-private-key"), testScopes)

	opts := CreateOptions{
		HardwareHash: "test-hash",
		Name:         "Test License",
		ExpiresAt:    time.Now().AddDate(1, 0, 0),
		Scopes:       []string{"read"},
	}

	_, err := generator.Create(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse private key")
}

func TestGenerator_Create_InvalidScopes(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)

	opts := CreateOptions{
		HardwareHash: "test-hash",
		Name:         "Test License",
		ExpiresAt:    time.Now().AddDate(1, 0, 0),
		Scopes:       []string{"read", "nonexistent"},
	}

	_, err = generator.Create(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown scopes")
}

func TestGenerator_Create_NoScopes(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)

	// Use real machine hash for testing
	realHash, err := hosthash.GenHash()
	require.NoError(t, err)
	encryptedHash, err := EncryptHash(realHash, testHashKey)
	require.NoError(t, err)

	opts := CreateOptions{
		HardwareHash: encryptedHash,
		Name:         "Test License Without Scopes",
		ExpiresAt:    time.Now().AddDate(1, 0, 0),
		Scopes:       []string{}, // Empty scopes
	}

	licenseToken, err := generator.Create(opts)
	require.NoError(t, err)
	assert.NotEmpty(t, licenseToken)

	// Validate the license without scopes
	publicKeyBytes, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}
	validator := NewValidator(publicKeyBytes, testScopes)
	licenseDetails := validator.ValidateDetails(licenseToken, testHashKey)
	assert.True(t, licenseDetails.Active)
	assert.Empty(t, licenseDetails.Scopes) // Should have no scopes
	assert.Empty(t, licenseDetails.Errors) // Should have no errors about missing scopes
}

func TestGenerator_ValidateScopes(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)

	// Test valid scopes
	assert.True(t, generator.validateScopes([]string{"read"}))
	assert.True(t, generator.validateScopes([]string{"read", "write"}))
	assert.True(t, generator.validateScopes([]string{"admin"}))
	assert.True(t, generator.validateScopes([]string{"read", "write", "admin"}))

	// Test invalid scopes
	assert.False(t, generator.validateScopes([]string{"nonexistent"}))
	assert.False(t, generator.validateScopes([]string{"read", "nonexistent"}))

	// Test empty scopes
	assert.True(t, generator.validateScopes([]string{}))
}

func TestValidator_Validate_InvalidToken(t *testing.T) {
	publicKeyBytes, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}
	validator := NewValidator(publicKeyBytes, testScopes)

	result := validator.Validate("invalid.token.string", testHashKey)
	assert.False(t, result)
}

func TestValidator_Validate_InvalidPublicKey(t *testing.T) {
	validator := NewValidator([]byte("invalid-public-key"), testScopes)

	result := validator.Validate("some.token", testHashKey)
	assert.False(t, result)
}

func TestValidator_GetScopesByIds(t *testing.T) {
	publicKeyBytes, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}
	validator := NewValidator(publicKeyBytes, testScopes)

	scopes := validator.getScopesByIds([]string{"read", "admin"})
	assert.Len(t, scopes, 2)
	assert.Equal(t, "read", scopes[0].ID)
	assert.Equal(t, "admin", scopes[1].ID)

	// Test with non-existing scope
	scopes = validator.getScopesByIds([]string{"read", "nonexistent"})
	assert.Len(t, scopes, 1)
	assert.Equal(t, "read", scopes[0].ID)

	// Test empty input
	scopes = validator.getScopesByIds([]string{})
	assert.Empty(t, scopes)
}

func TestValidator_Validate_NotYetActive(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)
	publicKeyBytes, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}
	validator := NewValidator(publicKeyBytes, testScopes)

	// Use real machine hash for testing
	realHash, err := hosthash.GenHash()
	require.NoError(t, err)
	encryptedHash, err := EncryptHash(realHash, testHashKey)
	require.NoError(t, err)

	// Create license that will be active in the future
	opts := CreateOptions{
		HardwareHash: encryptedHash,
		Name:         "Future License",
		ExpiresAt:    time.Now().AddDate(1, 0, 0), // 1 year from now
		NotBefore:    time.Now().AddDate(0, 0, 1), // Active from tomorrow
		Scopes:       []string{"read"},
	}

	licenseToken, err := generator.Create(opts)
	require.NoError(t, err)

	// Validate license - should be not active yet
	licenseDetails := validator.ValidateDetails(licenseToken, testHashKey)
	assert.False(t, licenseDetails.Active)
	assert.Len(t, licenseDetails.Errors, 1)
	firstErr := licenseDetails.FirstError()
	assert.NotNil(t, firstErr)
	if firstErr != nil {
		assert.Equal(t, LicenseNotYetActive, firstErr.Type)
	}
	assert.False(t, licenseDetails.TokenActive)
}

func TestValidator_Validate_Expired(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)
	publicKeyBytes, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}
	validator := NewValidator(publicKeyBytes, testScopes)

	// Use real machine hash for testing
	realHash, err := hosthash.GenHash()
	require.NoError(t, err)
	encryptedHash, err := EncryptHash(realHash, testHashKey)
	require.NoError(t, err)

	// Create license that has already expired
	opts := CreateOptions{
		HardwareHash: encryptedHash,
		Name:         "Expired License",
		ExpiresAt:    time.Now().AddDate(-1, 0, 0), // Expired 1 year ago
		NotBefore:    time.Now().AddDate(-2, 0, 0), // Was active 2 years ago
		Scopes:       []string{"read"},
	}

	licenseToken, err := generator.Create(opts)
	require.NoError(t, err)

	// Validate license - should be expired
	licenseDetails := validator.ValidateDetails(licenseToken, testHashKey)
	assert.False(t, licenseDetails.Active)
	assert.Len(t, licenseDetails.Errors, 1)
	firstErr := licenseDetails.FirstError()
	assert.NotNil(t, firstErr)
	if firstErr != nil {
		assert.Equal(t, LicenseExpired, firstErr.Type)
	}
	assert.False(t, licenseDetails.TokenActive)
}

func TestValidator_Validate_Active(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)
	publicKeyBytes, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}
	validator := NewValidator(publicKeyBytes, testScopes)

	// Use real machine hash for testing
	realHash, err := hosthash.GenHash()
	require.NoError(t, err)
	encryptedHash, err := EncryptHash(realHash, testHashKey)
	require.NoError(t, err)

	// Create license that is currently active
	opts := CreateOptions{
		HardwareHash: encryptedHash,
		Name:         "Active License",
		ExpiresAt:    time.Now().AddDate(1, 0, 0),  // Expires in 1 year
		NotBefore:    time.Now().AddDate(0, 0, -1), // Was active since yesterday
		Scopes:       []string{"read"},
	}

	licenseToken, err := generator.Create(opts)
	require.NoError(t, err)

	// Validate license - should be active
	licenseDetails := validator.ValidateDetails(licenseToken, testHashKey)
	assert.True(t, licenseDetails.Active)
	assert.Empty(t, licenseDetails.Errors)
	assert.True(t, licenseDetails.TokenActive)
	assert.True(t, licenseDetails.HashActive)
}

func TestValidator_Validate_NoTimeValidation(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)
	publicKeyBytes, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}
	validator := NewValidator(publicKeyBytes, testScopes)

	// Use real machine hash for testing
	realHash, err := hosthash.GenHash()
	require.NoError(t, err)
	encryptedHash, err := EncryptHash(realHash, testHashKey)
	require.NoError(t, err)

	// Create license without explicit NotBefore (should use IssuedAt as default)
	opts := CreateOptions{
		HardwareHash: encryptedHash,
		Name:         "License Without NotBefore",
		ExpiresAt:    time.Now().AddDate(1, 0, 0), // Expires in 1 year
		// NotBefore is not set - should default to IssuedAt
		Scopes: []string{"read"},
	}

	licenseToken, err := generator.Create(opts)
	require.NoError(t, err)

	// Validate license - should be active
	licenseDetails := validator.ValidateDetails(licenseToken, testHashKey)
	assert.True(t, licenseDetails.Active)
	assert.Empty(t, licenseDetails.Errors)
	assert.True(t, licenseDetails.TokenActive)
	assert.True(t, licenseDetails.HashActive)
	// NotBefore should be equal to IssuedAt when not explicitly set
	assert.Equal(t, licenseDetails.NotBefore, licenseDetails.IssuedAt)
}

func TestValidator_Validate_HashMismatch(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)
	publicKeyBytes, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}
	validator := NewValidator(publicKeyBytes, testScopes)

	// Create a fake hardware hash that doesn't match the current machine
	fakeHash := "fake-hardware-hash"
	encryptedHash, err := EncryptHash(fakeHash, testHashKey)
	require.NoError(t, err)

	// Create license with fake hash
	opts := CreateOptions{
		HardwareHash: encryptedHash,
		Name:         "License With Fake Hash",
		ExpiresAt:    time.Now().AddDate(1, 0, 0),  // Expires in 1 year
		NotBefore:    time.Now().AddDate(0, 0, -1), // Was active since yesterday
		Scopes:       []string{"read"},
	}

	licenseToken, err := generator.Create(opts)
	require.NoError(t, err)

	// Validate license - should fail due to hash mismatch
	licenseDetails := validator.ValidateDetails(licenseToken, testHashKey)
	assert.False(t, licenseDetails.Active)
	assert.Len(t, licenseDetails.Errors, 1)
	firstErr := licenseDetails.FirstError()
	assert.NotNil(t, firstErr)
	if firstErr != nil {
		assert.Equal(t, HashMismatchError, firstErr.Type)
	}
	assert.True(t, licenseDetails.TokenActive)
	assert.False(t, licenseDetails.HashActive)
}

func TestValidator_Validate_TamperedSignature(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)
	publicKeyBytes, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}
	validator := NewValidator(publicKeyBytes, testScopes)

	// Use real machine hash for testing
	realHash, err := hosthash.GenHash()
	require.NoError(t, err)
	encryptedHash, err := EncryptHash(realHash, testHashKey)
	require.NoError(t, err)

	// Create valid license
	opts := CreateOptions{
		HardwareHash: encryptedHash,
		Name:         "Valid License",
		ExpiresAt:    time.Now().AddDate(1, 0, 0),  // Expires in 1 year
		NotBefore:    time.Now().AddDate(0, 0, -1), // Was active since yesterday
		Scopes:       []string{"read"},
	}

	licenseToken, err := generator.Create(opts)
	require.NoError(t, err)

	// Tamper with the signature by modifying the last part of the token (signature)
	// JWT token format: header.payload.signature
	parts := strings.Split(licenseToken, ".")
	if len(parts) != 3 {
		t.Fatal("Invalid JWT token format")
	}

	// Modify the signature part by inserting a character in the middle
	signature := parts[2]
	if len([]rune(signature)) == 0 {
		t.Fatal("Empty signature")
	}
	// Insert "X" in the middle of the signature
	midPoint := len([]rune(signature)) / 2
	tamperedSignature := signature[:midPoint-1] + "X" + signature[midPoint:]
	tamperedToken := parts[0] + "." + parts[1] + "." + tamperedSignature

	// Validate tampered token - should fail due to invalid signature
	licenseDetails := validator.ValidateDetails(tamperedToken, testHashKey)
	assert.False(t, licenseDetails.Active)
	assert.False(t, licenseDetails.TokenActive)

	// Check that we have TokenParseError in the errors list
	foundTokenParseError := false
	for _, err := range licenseDetails.Errors {
		if err.Type == TokenParseError {
			foundTokenParseError = true
			break
		}
	}
	assert.True(t, foundTokenParseError, "Should have TokenParseError in errors list")
}

func TestValidator_Validate_WrongSigningMethod(t *testing.T) {
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	validator := NewValidator(privateKeyBytes, testScopes)

	// Use real machine hash for testing
	realHash, err := hosthash.GenHash()
	require.NoError(t, err)
	encryptedHash, err := EncryptHash(realHash, testHashKey)
	require.NoError(t, err)

	// Create token with wrong signing method (HS256 instead of RS256)
	claims := jwt.MapClaims{
		"sub":   encryptedHash,
		"name":  "License With Wrong Method",
		"exp":   time.Now().AddDate(1, 0, 0).Unix(),
		"iat":   time.Now().Unix(),
		"nbf":   time.Now().AddDate(0, 0, -1).Unix(),
		"scope": []string{"read"},
	}

	// Create token with HMAC (HS256) instead of RSA (RS256)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("wrong-secret-key"))
	require.NoError(t, err)

	// Validate token with wrong signing method - should fail
	licenseDetails := validator.ValidateDetails(tokenString, testHashKey)
	assert.False(t, licenseDetails.Active)
	assert.False(t, licenseDetails.TokenActive)

	// Check that we have TokenParseError in the errors list
	foundTokenParseError := false
	for _, err := range licenseDetails.Errors {
		if err.Type == TokenParseError {
			foundTokenParseError = true
			break
		}
	}
	assert.True(t, foundTokenParseError, "Should have TokenParseError in errors list")
}

func TestValidator_Validate_NoneAlgorithm(t *testing.T) {
	publicKeyBytes, err := os.ReadFile("../../testdata/test_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового публичного ключа: %v", err)
	}
	validator := NewValidator(publicKeyBytes, testScopes)

	// Use real machine hash for testing
	realHash, err := hosthash.GenHash()
	require.NoError(t, err)
	encryptedHash, err := EncryptHash(realHash, testHashKey)
	require.NoError(t, err)

	// Create token with "none" algorithm (no signature)
	claims := jwt.MapClaims{
		"sub":   encryptedHash,
		"name":  "License With None Algorithm",
		"exp":   time.Now().AddDate(1, 0, 0).Unix(),
		"iat":   time.Now().Unix(),
		"nbf":   time.Now().AddDate(0, 0, -1).Unix(),
		"scope": []string{"read"},
	}

	// Create token with "none" algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)

	// Sign with "none" method (no signature)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	// Validate token with "none" algorithm - should fail
	licenseDetails := validator.ValidateDetails(tokenString, testHashKey)
	assert.False(t, licenseDetails.Active)
	assert.False(t, licenseDetails.TokenActive)

	// Check that we have TokenParseError in the errors list
	foundTokenParseError := false
	for _, err := range licenseDetails.Errors {
		if err.Type == TokenParseError {
			foundTokenParseError = true
			break
		}
	}
	assert.True(t, foundTokenParseError, "Should have TokenParseError in errors list")
}

func TestValidator_Validate_WrongPublicKey(t *testing.T) {
	// Create license with one key pair
	privateKeyBytes, err := os.ReadFile("../../testdata/test_private_key.pem")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового приватного ключа: %v", err)
	}
	generator := NewGenerator(privateKeyBytes, testScopes)

	// Use real machine hash for testing
	realHash, err := hosthash.GenHash()
	require.NoError(t, err)
	encryptedHash, err := EncryptHash(realHash, testHashKey)
	require.NoError(t, err)

	// Create valid license
	opts := CreateOptions{
		HardwareHash: encryptedHash,
		Name:         "Valid License",
		ExpiresAt:    time.Now().AddDate(1, 0, 0),  // Expires in 1 year
		NotBefore:    time.Now().AddDate(0, 0, -1), // Was active since yesterday
		Scopes:       []string{"read"},
	}

	licenseToken, err := generator.Create(opts)
	require.NoError(t, err)

	// Try to validate with wrong public key (from different key pair)
	otherPublicKeyBytes, err := os.ReadFile("../../testdata/test_other_public_key.pub")
	if err != nil {
		t.Fatalf("Ошибка чтения тестового альтернативного публичного ключа: %v", err)
	}
	validator := NewValidator(otherPublicKeyBytes, testScopes)
	licenseDetails := validator.ValidateDetails(licenseToken, testHashKey)

	// Should fail because signature was created with different private key
	assert.False(t, licenseDetails.Active)
	assert.False(t, licenseDetails.TokenActive)

	// Check that we have TokenParseError in the errors list
	foundTokenParseError := false
	for _, err := range licenseDetails.Errors {
		if err.Type == TokenParseError {
			foundTokenParseError = true
			break
		}
	}
	assert.True(t, foundTokenParseError, "Should have TokenParseError in errors list")
}
