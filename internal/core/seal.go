package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// NewSealer returns a Sealer using AES-256-GCM with the given key: 32 bytes,
// base64 (standard or URL, padded or not).
func NewSealer(masterKeyBase64 string) (Sealer, error) {
	var key []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err = enc.DecodeString(masterKeyBase64); err == nil {
			break
		}
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("master key must be 32 bytes, base64-encoded")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &gcmSealer{aead: aead}, nil
}

type gcmSealer struct{ aead cipher.AEAD }

func (s *gcmSealer) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *gcmSealer) Open(sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed value is too short")
	}
	out, err := s.aead.Open(nil, sealed[:n], sealed[n:], nil)
	if err != nil {
		return nil, fmt.Errorf("cannot open sealed value (wrong master key?): %w", err)
	}
	return out, nil
}
