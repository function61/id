package main

import (
	"crypto/ed25519"
	"encoding/base64"
)

func marshalPrivateKey(privKey ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(privKey)
}

func unmarshalPrivateKey(privKeyStr string) (ed25519.PrivateKey, error) {
	privKeyBytes, err := base64.RawURLEncoding.DecodeString(privKeyStr)
	if err != nil {
		return nil, err
	}

	return ed25519.PrivateKey(privKeyBytes), nil
}
