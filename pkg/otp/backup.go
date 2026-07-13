package otp

import (
	"encoding/json"
	"fmt"

	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// BackupCodeService manages backup/recovery codes for MFA.
// Codes are single-use and stored as bcrypt hashes.
type BackupCodeService struct {
	codeCount  int
	codeLength int
}

// NewBackupCodeService creates a backup code service.
func NewBackupCodeService(count, length int) *BackupCodeService {
	return &BackupCodeService{
		codeCount:  count,
		codeLength: length,
	}
}

// GenerateCodes creates a set of backup codes and returns both the
// plain-text codes (to show to the user once) and their bcrypt hashes
// (to store in the database).
func (s *BackupCodeService) GenerateCodes() (plainCodes []string, hashedJSON string, err error) {
	plainCodes = make([]string, 0, s.codeCount)
	hashes := make([]string, 0, s.codeCount)

	for i := 0; i < s.codeCount; i++ {
		code, err := utils.GenerateRandomString(s.codeLength)
		if err != nil {
			return nil, "", fmt.Errorf("generating backup code %d: %w", i, err)
		}

		hash, err := utils.HashPassword(code)
		if err != nil {
			return nil, "", fmt.Errorf("hashing backup code %d: %w", i, err)
		}

		plainCodes = append(plainCodes, code)
		hashes = append(hashes, hash)
	}

	hashBytes, err := json.Marshal(hashes)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling backup code hashes: %w", err)
	}

	return plainCodes, string(hashBytes), nil
}

// ValidateCode checks a code against stored hashes. If valid, the matching
// hash is removed and the updated hashes JSON is returned.
func (s *BackupCodeService) ValidateCode(code, hashedJSON string) (updatedHashedJSON string, valid bool, err error) {
	var hashes []string
	if err := json.Unmarshal([]byte(hashedJSON), &hashes); err != nil {
		return "", false, fmt.Errorf("unmarshaling backup code hashes: %w", err)
	}

	for i, hash := range hashes {
		if utils.CheckPassword(code, hash) {
			hashes = append(hashes[:i], hashes[i+1:]...)

			updated, err := json.Marshal(hashes)
			if err != nil {
				return "", false, fmt.Errorf("marshaling updated hashes: %w", err)
			}

			return string(updated), true, nil
		}
	}

	return hashedJSON, false, nil
}

// RemainingCount returns the number of unused backup codes.
func (s *BackupCodeService) RemainingCount(hashedJSON string) (int, error) {
	var hashes []string
	if err := json.Unmarshal([]byte(hashedJSON), &hashes); err != nil {
		return 0, fmt.Errorf("unmarshaling backup code hashes: %w", err)
	}
	return len(hashes), nil
}
