package encoding

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

func EncodeS256PubKey(pubKey *ecdsa.PublicKey) ([]byte, error) {
	publicKeyBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
	return publicKeyBytes, nil
}

func DecodeECDSAPubKey(encodedKey []byte) (*ecdsa.PublicKey, error) {
	if len(encodedKey) == 65 && encodedKey[0] == 0x04 {
		encodedKey = encodedKey[1:] // Strip uncompressed prefix
	}
	if len(encodedKey) != 64 {
		return nil, errors.New("invalid encoded key length, expected 64 bytes")
	}

	x := new(big.Int).SetBytes(encodedKey[:32])
	y := new(big.Int).SetBytes(encodedKey[32:])

	curve := btcec.S256()
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("invalid public key: point not on secp256k1 curve")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ComposeECDSASignature composes R, S, V into a 65-byte signature
// Format: [R (32 bytes)][S (32 bytes)][V (1 byte)] = 65 bytes total
// Uses big.Int.FillBytes to ensure proper left-padding with zeros
func ComposeECDSASignature(r, s, recovery []byte) []byte {
	sigBytes := make([]byte, 65)
	copy(sigBytes[0:32], new(big.Int).SetBytes(r).FillBytes(make([]byte, 32)))  // Left-pad R to 32 bytes
	copy(sigBytes[32:64], new(big.Int).SetBytes(s).FillBytes(make([]byte, 32))) // Left-pad S to 32 bytes
	sigBytes[64] = recovery[0]
	return sigBytes
}
