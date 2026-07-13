package database

import (
	"fmt"

	"github.com/go-gormigrate/gormigrate/v2"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Migrate runs all pending database migrations in order.
// Each migration is versioned and supports rollback.
func Migrate(db *gorm.DB, log *zap.Logger) error {
	m := gormigrate.New(db, gormigrate.DefaultOptions, migrations())

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	log.Info("database migrations completed successfully")
	return nil
}

// migrations returns the ordered list of database migrations.
func migrations() []*gormigrate.Migration {
	return []*gormigrate.Migration{
		{
			ID: "202407120001_create_users",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&User{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable("users")
			},
		},
		{
			ID: "202407120002_create_mfa_secrets",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&MFASecret{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable("mfa_secrets")
			},
		},
		{
			ID: "202407120003_create_sessions",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&Session{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable("sessions")
			},
		},
		{
			ID: "202407120004_create_audit_logs",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&AuditLog{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable("audit_logs")
			},
		},
		{
			ID: "202407120005_create_configuration",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&Configuration{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable("configuration")
			},
		},
		{
			ID: "202407120006_create_trusted_devices",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&TrustedDevice{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable("trusted_devices")
			},
		},
	}
}
