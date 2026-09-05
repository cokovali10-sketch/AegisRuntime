//go:build linux

package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ArtifactSignature represents a signed artifact with metadata
type ArtifactSignature struct {
	Version     int       `json:"version"`
	Algorithm   string    `json:"algorithm"`
	PublicKey   string    `json:"public_key"`
	Signature   string    `json:"signature"`
	ContentHash string    `json:"content_hash"`
	SignedAt    time.Time `json:"signed_at"`
	SignedBy    string    `json:"signed_by"`
	FilePath    string    `json:"file_path"`
	FileSize    int64     `json:"file_size"`
}

// KeyPair holds an Ed25519 key pair
type KeyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	KeyPath    string
}

// SigningEngine manages cryptographic signing operations
type SigningEngine struct {
	keyDir     string
	keyPairs   map[string]*KeyPair
	signatures map[string]*ArtifactSignature
}

const (
	signatureVersion   = 1
	signatureExtension = ".sig"
	keyFileExtension   = ".key"
	pubKeyExtension    = ".pub"
)

// NewSigningEngine creates a new signing engine
func NewSigningEngine(keyDir string) (*SigningEngine, error) {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	se := &SigningEngine{
		keyDir:     keyDir,
		keyPairs:   make(map[string]*KeyPair),
		signatures: make(map[string]*ArtifactSignature),
	}

	if err := se.loadExistingKeys(); err != nil {
		return nil, fmt.Errorf("failed to load existing keys: %w", err)
	}

	return se, nil
}

// GenerateKeyPair generates a new Ed25519 key pair
func (se *SigningEngine) GenerateKeyPair(name string) (*KeyPair, error) {
	if _, exists := se.keyPairs[name]; exists {
		return nil, fmt.Errorf("key pair %q already exists", name)
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	kp := &KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		KeyPath:    filepath.Join(se.keyDir, name),
	}

	if err := se.saveKeyPair(name, kp); err != nil {
		return nil, fmt.Errorf("failed to save key pair: %w", err)
	}

	se.keyPairs[name] = kp
	return kp, nil
}

// LoadKeyPair loads a key pair from disk
func (se *SigningEngine) LoadKeyPair(name string) (*KeyPair, error) {
	if kp, exists := se.keyPairs[name]; exists {
		return kp, nil
	}

	privKeyPath := filepath.Join(se.keyDir, name+keyFileExtension)
	privKeyBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privKeyBytes))
	}

	privKey := ed25519.PrivateKey(privKeyBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	kp := &KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		KeyPath:    filepath.Join(se.keyDir, name),
	}

	se.keyPairs[name] = kp
	return kp, nil
}

// Sign signs a file and returns the signature
func (se *SigningEngine) Sign(keyName, filePath string) (*ArtifactSignature, error) {
	kp, err := se.LoadKeyPair(keyName)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	contentHash := HashBytes(data)
	signature := ed25519.Sign(kp.PrivateKey, data)

	artifact := &ArtifactSignature{
		Version:     signatureVersion,
		Algorithm:   "Ed25519",
		PublicKey:   hex.EncodeToString(kp.PublicKey),
		Signature:   hex.EncodeToString(signature),
		ContentHash: contentHash,
		SignedAt:    time.Now().UTC(),
		SignedBy:    keyName,
		FilePath:    filePath,
		FileSize:    info.Size(),
	}

	se.signatures[filePath] = artifact
	return artifact, nil
}

// SignBytes signs arbitrary bytes
func (se *SigningEngine) SignBytes(keyName string, data []byte) (*ArtifactSignature, error) {
	kp, err := se.LoadKeyPair(keyName)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	contentHash := HashBytes(data)
	signature := ed25519.Sign(kp.PrivateKey, data)

	artifact := &ArtifactSignature{
		Version:     signatureVersion,
		Algorithm:   "Ed25519",
		PublicKey:   hex.EncodeToString(kp.PublicKey),
		Signature:   hex.EncodeToString(signature),
		ContentHash: contentHash,
		SignedAt:    time.Now().UTC(),
		SignedBy:    keyName,
		FilePath:    "<bytes>",
		FileSize:    int64(len(data)),
	}

	return artifact, nil
}

// Verify verifies a file's signature
func (se *SigningEngine) Verify(filePath string, sig *ArtifactSignature) (bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to read file: %w", err)
	}

	currentHash := HashBytes(data)
	if currentHash != sig.ContentHash {
		return false, nil
	}

	pubKeyBytes, err := hex.DecodeString(sig.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	sigBytes, err := hex.DecodeString(sig.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)
	if len(pubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubKey))
	}

	valid := ed25519.Verify(pubKey, data, sigBytes)
	return valid, nil
}

// VerifyFile verifies a file against its .sig file
func (se *SigningEngine) VerifyFile(filePath string) (bool, *ArtifactSignature, error) {
	sigPath := filePath + signatureExtension
	sig, err := se.LoadSignature(sigPath)
	if err != nil {
		return false, nil, fmt.Errorf("failed to load signature: %w", err)
	}

	valid, err := se.Verify(filePath, sig)
	if err != nil {
		return false, sig, fmt.Errorf("verification failed: %w", err)
	}

	return valid, sig, nil
}

// SaveSignature saves signature to .sig file
func (se *SigningEngine) SaveSignature(sig *ArtifactSignature, sigPath string) error {
	data, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal signature: %w", err)
	}

	dir := filepath.Dir(sigPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create signature directory: %w", err)
	}

	if err := os.WriteFile(sigPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}

	return nil
}

// LoadSignature loads signature from .sig file
func (se *SigningEngine) LoadSignature(sigPath string) (*ArtifactSignature, error) {
	data, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature file: %w", err)
	}

	var sig ArtifactSignature
	if err := json.Unmarshal(data, &sig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	if sig.Version != signatureVersion {
		return nil, fmt.Errorf("unsupported signature version: %d", sig.Version)
	}

	if sig.Algorithm != "Ed25519" {
		return nil, fmt.Errorf("unsupported algorithm: %s", sig.Algorithm)
	}

	return &sig, nil
}

// HashFile computes SHA-256 hash of a file
func HashFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// HashBytes computes SHA-256 hash of bytes
func HashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ListKeys lists all available keys
func (se *SigningEngine) ListKeys() []string {
	keys := make([]string, 0, len(se.keyPairs))
	for name := range se.keyPairs {
		keys = append(keys, name)
	}
	return keys
}

// GetPublicKeyHex returns the public key in hex
func (kp *KeyPair) GetPublicKeyHex() string {
	return hex.EncodeToString(kp.PublicKey)
}

// saveKeyPair saves key pair to disk
func (se *SigningEngine) saveKeyPair(name string, kp *KeyPair) error {
	privKeyPath := filepath.Join(se.keyDir, name+keyFileExtension)
	pubKeyPath := filepath.Join(se.keyDir, name+pubKeyExtension)

	if err := os.WriteFile(privKeyPath, kp.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	if err := os.WriteFile(pubKeyPath, kp.PublicKey, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// loadExistingKeys loads all existing keys from the key directory
func (se *SigningEngine) loadExistingKeys() error {
	entries, err := os.ReadDir(se.keyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read key directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) == keyFileExtension {
			keyName := name[:len(name)-len(keyFileExtension)]
			if _, err := se.LoadKeyPair(keyName); err != nil {
				continue
			}
		}
	}

	return nil
}
