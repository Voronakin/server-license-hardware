package hosthash

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenHash(t *testing.T) {
	hash, err := GenHash()
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify that the hash is valid JSON
	var hashData Hash
	err = json.Unmarshal([]byte(hash), &hashData)
	require.NoError(t, err)

	// Check that required fields are present
	assert.NotEmpty(t, hashData.Hostname)
	assert.NotEmpty(t, hashData.Platform)
	assert.NotEmpty(t, hashData.CpuModelName)
	assert.Greater(t, hashData.Memory, uint64(0))
	assert.Greater(t, hashData.DiskSpace, uint64(0))
}

func TestGenHash_Consistency(t *testing.T) {
	// Generate hash multiple times and verify consistency
	hash1, err := GenHash()
	require.NoError(t, err)

	hash2, err := GenHash()
	require.NoError(t, err)

	// On the same machine, the hash should be the same
	assert.Equal(t, hash1, hash2)
}

func TestGetHardwareData_ValidStructure(t *testing.T) {
	hardwareData, err := getHardwareData()
	require.NoError(t, err)
	require.NotNil(t, hardwareData)

	// Check that all fields are populated
	assert.NotEmpty(t, hardwareData.Hostname)
	assert.NotEmpty(t, hardwareData.Platform)
	assert.NotEmpty(t, hardwareData.HostID)
	assert.NotEmpty(t, hardwareData.CpuModelName)
	assert.Greater(t, hardwareData.Memory, uint64(0))
	assert.Greater(t, hardwareData.DiskSpace, uint64(0))
	// MAC might be empty on some systems, so we don't require it
}

func TestHash_JSONMarshaling(t *testing.T) {
	hash := &Hash{
		Hostname:     "test-host",
		Platform:     "test-platform",
		HostID:       "test-host-id",
		CpuModelName: "test-cpu",
		Memory:       8589934592,   // 8GB
		DiskSpace:    107374182400, // 100GB
		MAC:          "00:11:22:33:44:55",
	}

	jsonData, err := json.Marshal(hash)
	require.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Verify JSON structure
	var decodedHash Hash
	err = json.Unmarshal(jsonData, &decodedHash)
	require.NoError(t, err)
	assert.Equal(t, hash.Hostname, decodedHash.Hostname)
	assert.Equal(t, hash.Platform, decodedHash.Platform)
	assert.Equal(t, hash.HostID, decodedHash.HostID)
	assert.Equal(t, hash.CpuModelName, decodedHash.CpuModelName)
	assert.Equal(t, hash.Memory, decodedHash.Memory)
	assert.Equal(t, hash.DiskSpace, decodedHash.DiskSpace)
	assert.Equal(t, hash.MAC, decodedHash.MAC)
}
