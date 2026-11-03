package persistence

import (
	"fmt"
	"os"
	"strings"
)

// PersistenceFactory bootstraps the persistence layer and providers
type PersistenceFactory interface {
	GetUnitOfWork() UnitOfWork
	GetSecretProvider() SecretProvider
	GetKeyStore() KeyStore
	GetEventStore() EventStore
	GetCacheProvider() CacheProvider
	GetBackupProvider() BackupProvider
}

// LoadMasterKey attempts to load the master encryption key following the priority:
// Environment Variable -> Docker Secret -> Future Vault Provider -> Fail
func LoadMasterKey() ([]byte, error) {
	// 1. Environment Variable
	if key := os.Getenv("SAMLGUARD_SECURITY_MASTER_KEY"); key != "" {
		return []byte(key), nil
	}

	// 2. Docker Secret
	secretFile := os.Getenv("SAMLGUARD_SECRET_FILE")
	if secretFile == "" {
		secretFile = "/run/secrets/samlguard_master_key"
	}
	
	data, err := os.ReadFile(secretFile)
	if err == nil {
		key := strings.TrimSpace(string(data))
		if key != "" {
			return []byte(key), nil
		}
	}

	// 3. Future Vault Provider (Stub)
	// if vaultProvider != nil { return vaultProvider.GetMasterKey() }

	// 4. Fail
	return nil, fmt.Errorf("master key could not be loaded from environment or docker secret")
}
