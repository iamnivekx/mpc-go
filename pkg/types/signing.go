package types

type SigningMessage struct {
	KeyType   KeyType `json:"key_type"`
	WalletID  string  `json:"wallet_id"`
	TxID      string  `json:"tx_id"`
	Tx        []byte  `json:"tx"`
	Signature []byte  `json:"signature"`
}

type SigningResponse struct {
	ErrorCode   ErrorCode `json:"error_code"`
	ErrorReason string    `json:"error_reason"`
	IsTimeout   bool      `json:"is_timeout"`
	WalletID    string    `json:"wallet_id"`
	TxID        string    `json:"tx_id"`

	// ECDSA (e.g. secp256k1) signature = [R (32 bytes)][S (32 bytes)][V (1 byte)]
	//   - R: x-coordinate of (k*G)
	//   - S: scalar signature component
	//   - V: recovery id (used to recover public key, e.g. Ethereum)
	//   Total = 65 bytes -> 130 hex chars
	//
	// EdDSA (e.g. Ed25519) signature = [R (32 bytes)][S (32 bytes)]
	//   - R: encoded curve point (not just x-coordinate)
	//   - S: scalar signature component
	//   Total = 64 bytes -> 128 hex chars
	Signature []byte `json:"signature"`
}

type SigningResultErrorEvent struct {
	WalletID    string    `json:"wallet_id"`
	TxID        string    `json:"tx_id"`
	ErrorCode   ErrorCode `json:"error_code"`
	ErrorReason string    `json:"error_reason"`
	IsTimeout   bool      `json:"is_timeout"`
}
