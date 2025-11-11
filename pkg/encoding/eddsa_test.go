package encoding

import (
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeEDDSAPubKey(t *testing.T) {
	// Generate a test EdDSA key pair using the correct API
	privateKey, err := edwards.GeneratePrivateKey()
	require.NoError(t, err)

	pubKey := privateKey.PubKey()

	// Test encoding
	encoded, err := EncodeEDDSAPubKey(pubKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// EdDSA compressed public key should be 32 bytes (not 33 as initially assumed)
	assert.Equal(t, 32, len(encoded))
}

func TestDecodeEDDSAPubKey(t *testing.T) {
	// Generate a test EdDSA key pair
	privateKey, err := edwards.GeneratePrivateKey()
	require.NoError(t, err)

	originalPubKey := privateKey.PubKey()

	// Encode the public key
	encoded, err := EncodeEDDSAPubKey(originalPubKey)
	require.NoError(t, err)

	// Decode the public key
	decodedPubKey, err := DecodeEDDSAPubKey(encoded)
	require.NoError(t, err)
	assert.NotNil(t, decodedPubKey)

	// Verify the decoded key matches the original by comparing serialized forms
	originalSerialized := originalPubKey.SerializeCompressed()
	decodedSerialized := decodedPubKey.SerializeCompressed()
	assert.Equal(t, originalSerialized, decodedSerialized)
}

func TestDecodeEDDSAPubKey_InvalidData(t *testing.T) {
	// Test with invalid data
	invalidData := []byte("invalid key data")

	_, err := DecodeEDDSAPubKey(invalidData)
	assert.Error(t, err)
}

func TestDecodeEDDSAPubKey_EmptyData(t *testing.T) {
	// Test with empty data
	emptyData := []byte{}

	_, err := DecodeEDDSAPubKey(emptyData)
	assert.Error(t, err)
}

func TestEncodeDecodeEDDSA_RoundTrip(t *testing.T) {
	// Test multiple round trips to ensure consistency
	for i := 0; i < 10; i++ {
		// Generate a new key pair
		privateKey, err := edwards.GeneratePrivateKey()
		require.NoError(t, err)

		originalPubKey := privateKey.PubKey()

		// Encode
		encoded, err := EncodeEDDSAPubKey(originalPubKey)
		require.NoError(t, err)

		// Decode
		decodedPubKey, err := DecodeEDDSAPubKey(encoded)
		require.NoError(t, err)

		// Verify they match by comparing serialized forms
		originalSerialized := originalPubKey.SerializeCompressed()
		decodedSerialized := decodedPubKey.SerializeCompressed()
		assert.Equal(t, originalSerialized, decodedSerialized, "Round trip %d failed", i)
	}
}
