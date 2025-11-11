package encoding

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComposeECDSASignature(t *testing.T) {
	tests := []struct {
		name     string
		r        []byte
		s        []byte
		recovery []byte
		wantLen  int
		checkFn  func(t *testing.T, sig []byte)
	}{
		{
			name:     "full 32-byte R and S",
			r:        []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			s:        []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
			recovery: []byte{0x01},
			wantLen:  65,
			checkFn: func(t *testing.T, sig []byte) {
				// Check R is in first 32 bytes
				assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, sig[0:32])
				// Check S is in next 32 bytes
				assert.Equal(t, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}, sig[32:64])
				// Check V is in last byte
				assert.Equal(t, byte(0x01), sig[64])
			},
		},
		{
			name:     "short R and S (needs left padding)",
			r:        []byte{0x12, 0x34},
			s:        []byte{0x56, 0x78},
			recovery: []byte{0x00},
			wantLen:  65,
			checkFn: func(t *testing.T, sig []byte) {
				// R should be left-padded with zeros
				rBig := new(big.Int).SetBytes([]byte{0x12, 0x34})
				expectedR := make([]byte, 32)
				rBig.FillBytes(expectedR)
				assert.Equal(t, expectedR, sig[0:32])

				// S should be left-padded with zeros
				sBig := new(big.Int).SetBytes([]byte{0x56, 0x78})
				expectedS := make([]byte, 32)
				sBig.FillBytes(expectedS)
				assert.Equal(t, expectedS, sig[32:64])

				// Check V
				assert.Equal(t, byte(0x00), sig[64])

				// Verify left padding: first 30 bytes should be zeros
				for i := 0; i < 30; i++ {
					assert.Equal(t, byte(0x00), sig[i], "R padding at index %d should be zero", i)
				}
				// Last 2 bytes of R should be 0x12, 0x34
				assert.Equal(t, byte(0x12), sig[30])
				assert.Equal(t, byte(0x34), sig[31])
			},
		},
		{
			name:     "single byte R and S",
			r:        []byte{0x42},
			s:        []byte{0x84},
			recovery: []byte{0x01},
			wantLen:  65,
			checkFn: func(t *testing.T, sig []byte) {
				// R should be left-padded: last byte should be 0x42
				assert.Equal(t, byte(0x42), sig[31], "Last byte of R should be 0x42")
				// First 31 bytes should be zeros
				for i := 0; i < 31; i++ {
					assert.Equal(t, byte(0x00), sig[i], "R padding at index %d should be zero", i)
				}

				// S should be left-padded: last byte should be 0x84
				assert.Equal(t, byte(0x84), sig[63], "Last byte of S should be 0x84")
				// Bytes 32-62 should be zeros
				for i := 32; i < 63; i++ {
					assert.Equal(t, byte(0x00), sig[i], "S padding at index %d should be zero", i)
				}

				// Check V
				assert.Equal(t, byte(0x01), sig[64])
			},
		},
		{
			name:     "31-byte R and S (almost full)",
			r:        func() []byte { r := make([]byte, 31); r[30] = 0xab; return r }(),
			s:        func() []byte { s := make([]byte, 31); s[30] = 0xcd; return s }(),
			recovery: []byte{0x01},
			wantLen:  65,
			checkFn: func(t *testing.T, sig []byte) {
				// First byte should be zero (left padding)
				assert.Equal(t, byte(0x00), sig[0])
				// Last byte of R should be 0xab
				assert.Equal(t, byte(0xab), sig[31])
				// First byte of S section should be zero
				assert.Equal(t, byte(0x00), sig[32])
				// Last byte of S should be 0xcd
				assert.Equal(t, byte(0xcd), sig[63])
				// V should be 0x01
				assert.Equal(t, byte(0x01), sig[64])
			},
		},
		{
			name:     "zero R and S",
			r:        []byte{0x00},
			s:        []byte{0x00},
			recovery: []byte{0x00},
			wantLen:  65,
			checkFn: func(t *testing.T, sig []byte) {
				// All bytes should be zero
				for i := 0; i < 65; i++ {
					assert.Equal(t, byte(0x00), sig[i], "Byte at index %d should be zero", i)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := ComposeECDSASignature(tt.r, tt.s, tt.recovery)

			// Check length
			assert.Equal(t, tt.wantLen, len(sig), "Signature should be 65 bytes")

			// Run custom checks if provided
			if tt.checkFn != nil {
				tt.checkFn(t, sig)
			}

			// Verify structure: R (32 bytes) + S (32 bytes) + V (1 byte)
			assert.Equal(t, 32, len(sig[0:32]), "R section should be 32 bytes")
			assert.Equal(t, 32, len(sig[32:64]), "S section should be 32 bytes")
			assert.Equal(t, 1, len(sig[64:65]), "V section should be 1 byte")
		})
	}
}

func TestComposeECDSASignature_Format(t *testing.T) {
	// Test that the signature format matches Ethereum/secp256k1 standard
	r := []byte{0x12, 0x34, 0x56, 0x78}
	s := []byte{0x9a, 0xbc, 0xde, 0xf0}
	recovery := []byte{0x01}

	sig := ComposeECDSASignature(r, s, recovery)

	// Verify total length
	require.Equal(t, 65, len(sig), "Signature must be exactly 65 bytes")

	// Verify R is in first 32 bytes (left-padded)
	rBig := new(big.Int).SetBytes(r)
	expectedR := make([]byte, 32)
	rBig.FillBytes(expectedR)
	assert.Equal(t, expectedR, sig[0:32], "R should be left-padded in first 32 bytes")

	// Verify S is in next 32 bytes (left-padded)
	sBig := new(big.Int).SetBytes(s)
	expectedS := make([]byte, 32)
	sBig.FillBytes(expectedS)
	assert.Equal(t, expectedS, sig[32:64], "S should be left-padded in next 32 bytes")

	// Verify V is in last byte
	assert.Equal(t, recovery[0], sig[64], "V should be in last byte")
}

func TestComposeECDSASignature_Consistency(t *testing.T) {
	// Test that composing the same values multiple times produces the same result
	r := []byte{0x12, 0x34, 0x56, 0x78}
	s := []byte{0x9a, 0xbc, 0xde, 0xf0}
	recovery := []byte{0x01}

	sig1 := ComposeECDSASignature(r, s, recovery)
	sig2 := ComposeECDSASignature(r, s, recovery)
	sig3 := ComposeECDSASignature(r, s, recovery)

	// All should be identical
	assert.Equal(t, sig1, sig2, "Multiple calls should produce same result")
	assert.Equal(t, sig2, sig3, "Multiple calls should produce same result")
}

func TestEncodeS256PubKey(t *testing.T) {
	// Generate a test ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey := &privateKey.PublicKey

	// Test encoding
	encoded, err := EncodeS256PubKey(pubKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// The encoded key should contain both X and Y coordinates appended together
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	expectedLength := len(xBytes) + len(yBytes)
	assert.Equal(t, expectedLength, len(encoded))

	// Verify the encoded data contains the coordinates
	assert.Equal(t, xBytes, encoded[:len(xBytes)])
	assert.Equal(t, yBytes, encoded[len(xBytes):])
}

func TestEncodeS256PubKey_SpecificValues(t *testing.T) {
	// Create a public key with specific values
	x := big.NewInt(12345)
	y := big.NewInt(67890)
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	encoded, err := EncodeS256PubKey(pubKey)
	require.NoError(t, err)

	// Verify the encoding - should be X bytes followed by Y bytes
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	expected := append(xBytes, yBytes...)

	assert.Equal(t, expected, encoded)
}

func TestEncodeS256PubKey_NilPublicKey(t *testing.T) {
	// Test with nil public key - this should panic or return an error
	// depending on the implementation
	defer func() {
		if r := recover(); r != nil {
			// Expected panic due to nil pointer
			t.Log("Correctly panicked on nil public key")
		}
	}()

	_, err := EncodeS256PubKey(nil)
	if err == nil {
		t.Error("Expected error or panic with nil public key")
	}
}

func TestEncodeS256PubKey_ZeroCoordinates(t *testing.T) {
	// Test with zero coordinates
	x := big.NewInt(0)
	y := big.NewInt(0)
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	encoded, err := EncodeS256PubKey(pubKey)
	require.NoError(t, err)

	// Should still work, though the result will be a very short byte array
	assert.NotNil(t, encoded)
}
