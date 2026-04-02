package dave

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

type SigningKeyPair struct {
	Private []byte
	Public  []byte
}

func GenerateP256Keypair() (*SigningKeyPair, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate P-256 keypair: %w", err)
	}

	return &SigningKeyPair{
		Private: priv.Bytes(),
		Public:  priv.PublicKey().Bytes(),
	}, nil
}

func parseSigningKeyPair(pair *SigningKeyPair) (*ecdsa.PrivateKey, error) {
	if pair == nil {
		return nil, fmt.Errorf("signing key pair is nil")
	}
	if len(pair.Private) == 0 {
		return nil, fmt.Errorf("signing private key is empty")
	}
	if len(pair.Public) == 0 {
		return nil, fmt.Errorf("signing public key is empty")
	}

	publicKey, err := ecdh.P256().NewPublicKey(pair.Public)
	if err != nil {
		return nil, fmt.Errorf("invalid uncompressed P-256 public key: %w", err)
	}

	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), pair.Private)
	if err != nil {
		return nil, fmt.Errorf("parse raw P-256 private key: %w", err)
	}

	derivedPublicKey, err := priv.PublicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert signing public key to ECDH: %w", err)
	}
	if !bytes.Equal(derivedPublicKey.Bytes(), publicKey.Bytes()) {
		return nil, fmt.Errorf("signing public key does not match signing private key")
	}

	return priv, nil
}
