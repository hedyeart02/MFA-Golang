package persistence

import "context"

// BackupProvider handles enterprise backup routines for the underlying persistence layer
type BackupProvider interface {
	CreateBackup(ctx context.Context, destination string) error
	RestoreBackup(ctx context.Context, source string) error
	ListBackups(ctx context.Context) ([]string, error)
}
