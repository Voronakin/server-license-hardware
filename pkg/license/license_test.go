package license

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetLicense_DefaultFile(t *testing.T) {
	// Create a temporary license file
	licenseContent := "test license content"

	// Test with default file path
	oldPath := "license.txt"
	if _, err := os.Stat(oldPath); err == nil {
		// Backup existing license.txt if it exists
		os.Rename(oldPath, oldPath+".backup")
		defer os.Rename(oldPath+".backup", oldPath)
	}

	err := os.WriteFile("license.txt", []byte(licenseContent), 0644)
	require.NoError(t, err)
	defer os.Remove("license.txt")

	result, err := GetLicense()
	require.NoError(t, err)
	assert.Equal(t, licenseContent, result)
}

func TestGetLicense_CustomFile(t *testing.T) {
	// Create a temporary license file
	licenseContent := "custom license content"
	tempFile, err := os.CreateTemp("", "custom_license_test.txt")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.WriteString(licenseContent)
	require.NoError(t, err)
	tempFile.Close()

	// Test with custom file path
	result, err := GetLicense(tempFile.Name())
	require.NoError(t, err)
	assert.Equal(t, licenseContent, result)
}

func TestGetLicense_FileNotFound(t *testing.T) {
	_, err := GetLicense("nonexistent_file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read license file")
}

func TestEncryptHashAndDecrypteHash(t *testing.T) {
	hashKey := "6368616e676520746869732070617373776f726420746f206120736563726574"
	originalHash := "test hardware hash data"

	// Test encryption
	encryptedHash, err := EncryptHash(originalHash, hashKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedHash)
	assert.NotEqual(t, originalHash, encryptedHash)

	// Test decryption
	decryptedHash, err := DecryptHash(encryptedHash, hashKey)
	require.NoError(t, err)
	assert.Equal(t, originalHash, decryptedHash)
}

func TestLicenseInfo_CheckScope(t *testing.T) {
	licenseInfo := &LicenseInfo{
		Scopes: []Scope{
			{ID: "read", Name: "Read", Description: "Read access"},
			{ID: "write", Name: "Write", Description: "Write access"},
			{ID: "admin", Name: "Admin", Description: "Admin access"},
		},
	}

	// Test existing scopes
	assert.True(t, licenseInfo.CheckScope("read"))
	assert.True(t, licenseInfo.CheckScope("write"))
	assert.True(t, licenseInfo.CheckScope("admin"))

	// Test non-existing scope
	assert.False(t, licenseInfo.CheckScope("nonexistent"))
	assert.False(t, licenseInfo.CheckScope(""))
}

func TestLicenseInfo_CheckScopes(t *testing.T) {
	licenseInfo := &LicenseInfo{
		Scopes: []Scope{
			{ID: "read", Name: "Read", Description: "Read access"},
			{ID: "write", Name: "Write", Description: "Write access"},
			{ID: "admin", Name: "Admin", Description: "Admin access"},
		},
	}

	// Test all scopes exist
	assert.True(t, licenseInfo.CheckScopes([]string{"read", "write"}))
	assert.True(t, licenseInfo.CheckScopes([]string{"admin"}))
	assert.True(t, licenseInfo.CheckScopes([]string{"read", "write", "admin"}))

	// Test with missing scope
	assert.False(t, licenseInfo.CheckScopes([]string{"read", "nonexistent"}))
	assert.False(t, licenseInfo.CheckScopes([]string{"nonexistent"}))

	// Test empty scopes
	assert.True(t, licenseInfo.CheckScopes([]string{}))
}

func TestGetHash(t *testing.T) {
	hashKey := "6368616e676520746869732070617373776f726420746f206120736563726574"

	hash, err := GetHash(hashKey)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify that the hash can be decrypted
	decryptedHash, err := DecryptHash(hash, hashKey)
	require.NoError(t, err)
	assert.NotEmpty(t, decryptedHash)
}
