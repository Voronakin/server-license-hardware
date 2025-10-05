package license

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testPrivateKey = `-----BEGIN PRIVATE KEY-----
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
	testPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArvVXSJaDX2d0fBlVig2+
iQYjlwG1v9B8WO35Q7h6ewpSG2LrBfSoah1tw/dK/Ve10Q9J8i09Ad+Zz3GzaVOt
N/h14Y5l/uouWGDeQIPnIygHtXcXbBnQDiYzXwhXLLhxHoZ/tUpLKUT9C/URZset
2zaHhzB5uRz5PCYPqA+RJKJqIOvhBzE/qKKiUvtXCjnb+Uz5WeZy+bg7zl2KaDji
EMB6y3I7Qv4LqWKoMvHh82clhfSjj+Y9au5XtAMOtaitEto+yzhpNImBHxL5Fvh9
5UQ8K6I9ME5lu4zdJSYHIq6DcNg3Zz9UFL0sh4jDC9o0KtNK9UPiMeSd+3IXrxz7
3wIDAQAB
-----END PUBLIC KEY-----`
	testScopes = []Scope{
		{ID: "read", Name: "Read", Description: "Read data access"},
		{ID: "write", Name: "Write", Description: "Write data access"},
		{ID: "admin", Name: "Administration", Description: "Full system access"},
	}
	testHashKey = "6368616e676520746869732070617373776f726420746f206120736563726574"
)

func TestGenerator_Create(t *testing.T) {
	generator := NewGenerator([]byte(testPrivateKey), testScopes)

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
	generator := NewGenerator([]byte(testPrivateKey), testScopes)

	opts := CreateOptions{
		HardwareHash: "test-hash",
		Name:         "Test License",
		ExpiresAt:    time.Now().AddDate(1, 0, 0),
		Scopes:       []string{"read", "nonexistent"},
	}

	_, err := generator.Create(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown scopes")
}

func TestGenerator_ValidateScopes(t *testing.T) {
	generator := NewGenerator([]byte(testPrivateKey), testScopes)

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
	validator := NewValidator([]byte(testPublicKey), testScopes)

	result := validator.Validate("invalid.token.string", testHashKey)
	assert.False(t, result)
}

func TestValidator_Validate_InvalidPublicKey(t *testing.T) {
	validator := NewValidator([]byte("invalid-public-key"), testScopes)

	result := validator.Validate("some.token", testHashKey)
	assert.False(t, result)
}

func TestValidator_GetScopesByIds(t *testing.T) {
	validator := NewValidator([]byte(testPublicKey), testScopes)

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
