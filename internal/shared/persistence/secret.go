package persistence

import "context"

// SecretProvider manages encrypted secrets
type SecretProvider interface {
	StoreSecret(ctx context.Context, name string, plaintext []byte) error
	RetrieveSecret(ctx context.Context, name string) ([]byte, error)
	RotateKey(ctx context.Context, newMasterKey []byte) error // Supports Key Versioning
}

// KeyStore abstraction specifically for cryptographic keys
type KeyStore interface {
	StorePrivateKey(ctx context.Context, id string, privateKey []byte) error
	GetPrivateKey(ctx context.Context, id string) ([]byte, error)
}
