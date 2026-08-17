package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"scanvault/internal/model"
)

type Sealer struct {
	Namespace string
}

func NewSealer(namespace string) *Sealer {
	if strings.TrimSpace(namespace) == "" {
		namespace = "scanvault-default"
	}
	return &Sealer{Namespace: namespace}
}

func (s *Sealer) derive(label, material string) [32]byte {
	return sha256.Sum256([]byte(s.Namespace + "|" + label + "|" + material))
}

func (s *Sealer) block(label, material string) (cipher.Block, error) {
	key := s.derive(label, material)
	return aes.NewCipher(key[:])
}

func (s *Sealer) SealCommunicationSecret(publicKey, secret string) (string, string, error) {
	if strings.TrimSpace(publicKey) == "" {
		return "", "", errors.New("public key is required")
	}
	if err := model.ValidateSecret(secret); err != nil {
		return "", "", err
	}
	block, err := s.block("wrap", publicKey)
	if err != nil {
		return "", "", fmt.Errorf("create wrapper: %w", err)
	}
	nonceDigest := s.derive("nonce", publicKey+"|"+secret)
	nonce := nonceDigest[:aes.BlockSize]
	stream := cipher.NewCTR(block, nonce)
	plain := []byte(secret)
	ciphertext := make([]byte, len(plain))
	stream.XORKeyStream(ciphertext, plain)
	encoded := base64.RawURLEncoding.EncodeToString(append(nonce, ciphertext...))
	fingerprint := Fingerprint(publicKey, secret)
	return encoded, fingerprint, nil
}

func (s *Sealer) OpenCommunicationSecret(privateKey, publicKey, wrapped string) (string, error) {
	if err := model.ValidatePrivateKey(privateKey); err != nil {
		return "", err
	}
	if strings.TrimSpace(publicKey) == "" {
		return "", errors.New("public key is required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(wrapped)
	if err != nil {
		return "", fmt.Errorf("decode wrapped secret: %w", err)
	}
	if len(raw) <= aes.BlockSize {
		return "", errors.New("wrapped secret payload is empty")
	}
	block, err := s.block("wrap", publicKey)
	if err != nil {
		return "", fmt.Errorf("create unwrapper: %w", err)
	}
	stream := cipher.NewCTR(block, raw[:aes.BlockSize])
	plain := make([]byte, len(raw)-aes.BlockSize)
	stream.XORKeyStream(plain, raw[aes.BlockSize:])
	if err := model.ValidateSecret(string(plain)); err != nil {
		return "", errors.New("wrapped secret failed validation")
	}
	return string(plain), nil
}

func Fingerprint(publicKey, secret string) string {
	digest := sha256.Sum256([]byte(publicKey + "|" + secret))
	return base64.RawURLEncoding.EncodeToString(digest[:8])
}

func VerifyFingerprint(publicKey, secret, expected string) bool {
	if strings.TrimSpace(expected) == "" {
		return false
	}
	return Fingerprint(publicKey, secret) == expected
}

func (s *Sealer) VerifyFingerprint(publicKey, secret, expected string) bool {
	return VerifyFingerprint(publicKey, secret, expected)
}

func Digest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (s *Sealer) NamespaceDigest(value string) string {
	return Digest(s.Namespace + "|" + value)
}

func (s *Sealer) FingerprintFor(publicKey, secret string) string {
	return Fingerprint(publicKey, secret)
}

func (s *Sealer) SameNamespace(other *Sealer) bool {
	if other == nil {
		return false
	}
	return s.Namespace == other.Namespace
}

func (s *Sealer) ValidateNamespace() error {
	if strings.TrimSpace(s.Namespace) == "" {
		return errors.New("sealer namespace is empty")
	}
	if len(s.Namespace) > 128 {
		return errors.New("sealer namespace is too long")
	}
	return nil
}

func (s *Sealer) SealForDevice(device model.Device, secret string) (model.KeyEnvelope, error) {
	if err := model.ValidateDevice(device); err != nil {
		return model.KeyEnvelope{}, err
	}
	wrapped, fingerprint, err := s.SealCommunicationSecret(device.PublicKey, secret)
	if err != nil {
		return model.KeyEnvelope{}, err
	}
	return model.KeyEnvelope{
		DeviceID:    device.ID,
		Version:     1,
		Wrapped:     wrapped,
		Fingerprint: fingerprint,
		Algorithm:   "AES-CTR-SHA256",
		CreatedAt:   "sealed",
		Active:      true,
	}, nil
}

func (s *Sealer) RecoverForDevice(device model.Device, envelope model.KeyEnvelope, privateKey string) (string, error) {
	if envelope.DeviceID != device.ID {
		return "", errors.New("envelope device mismatch")
	}
	if !envelope.Active {
		return "", errors.New("envelope is inactive")
	}
	secret, err := s.OpenCommunicationSecret(privateKey, device.PublicKey, envelope.Wrapped)
	if err != nil {
		return "", err
	}
	if !VerifyFingerprint(device.PublicKey, secret, envelope.Fingerprint) {
		return "", errors.New("envelope fingerprint mismatch")
	}
	return secret, nil
}

func WrapForTransport(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func UnwrapTransport(value string) (string, error) {
	if value == "" {
		return "", errors.New("transport value is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 {
		return "", errors.New("transport payload is empty")
	}
	return string(raw), nil
}
