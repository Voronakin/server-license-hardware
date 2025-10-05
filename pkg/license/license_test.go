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
		err := os.Rename(oldPath, oldPath+".backup")
		require.NoError(t, err)
		defer func() {
			err := os.Rename(oldPath+".backup", oldPath)
			require.NoError(t, err)
		}()
	}

	err := os.WriteFile("license.txt", []byte(licenseContent), 0644)
	require.NoError(t, err)
	defer func() {
		err := os.Remove("license.txt")
		require.NoError(t, err)
	}()

	result, err := GetLicense()
	require.NoError(t, err)
	assert.Equal(t, licenseContent, result)
}

func TestGetLicense_CustomFile(t *testing.T) {
	// Create a temporary license file
	licenseContent := "custom license content"
	tempFile, err := os.CreateTemp("", "custom_license_test.txt")
	require.NoError(t, err)
	defer func() {
		err := os.Remove(tempFile.Name())
		require.NoError(t, err)
	}()

	_, err = tempFile.WriteString(licenseContent)
	require.NoError(t, err)
	err = tempFile.Close()
	require.NoError(t, err)

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

func TestLicenseDetails_CheckScope(t *testing.T) {
	licenseDetails := &LicenseDetails{
		Scopes: []Scope{
			{ID: "read", Name: "Read", Description: "Read access"},
			{ID: "write", Name: "Write", Description: "Write access"},
			{ID: "admin", Name: "Admin", Description: "Admin access"},
		},
	}

	// Test existing scopes
	assert.True(t, licenseDetails.CheckScope("read"))
	assert.True(t, licenseDetails.CheckScope("write"))
	assert.True(t, licenseDetails.CheckScope("admin"))

	// Test non-existing scope
	assert.False(t, licenseDetails.CheckScope("nonexistent"))
	assert.False(t, licenseDetails.CheckScope(""))
}

func TestLicenseDetails_CheckScopes(t *testing.T) {
	licenseDetails := &LicenseDetails{
		Scopes: []Scope{
			{ID: "read", Name: "Read", Description: "Read access"},
			{ID: "write", Name: "Write", Description: "Write access"},
			{ID: "admin", Name: "Admin", Description: "Admin access"},
		},
	}

	// Test all scopes exist
	assert.True(t, licenseDetails.CheckScopes([]string{"read", "write"}))
	assert.True(t, licenseDetails.CheckScopes([]string{"admin"}))
	assert.True(t, licenseDetails.CheckScopes([]string{"read", "write", "admin"}))

	// Test with missing scope
	assert.False(t, licenseDetails.CheckScopes([]string{"read", "nonexistent"}))
	assert.False(t, licenseDetails.CheckScopes([]string{"nonexistent"}))

	// Test empty scopes
	assert.True(t, licenseDetails.CheckScopes([]string{}))
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
