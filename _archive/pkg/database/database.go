// Package database provides GORM-based database initialization and management
// for SQLite with proper connection pooling, foreign key enforcement, and
// graceful shutdown support.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"go.uber.org/zap"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/hidayat-SE/samlguard/pkg/config"
)

// DB wraps GORM's database connection with lifecycle management.
type DB struct {
	Conn   *gorm.DB
	sqlDB  *sql.DB
	logger *zap.Logger
}

// New initializes a new SQLite database connection using the provided config.
// It ensures the data directory exists and enables foreign key constraints.
func New(cfg config.DatabaseConfig, log *zap.Logger) (*DB, error) {
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("creating database directory %s: %w", dir, err)
	}

	dsn := cfg.Path
	if cfg.EnableForeignKs {
		dsn = fmt.Sprintf("%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)", cfg.Path)
	}

	gormCfg := &gorm.Config{
		Logger:                                   gormlogger.Discard,
		DisableForeignKeyConstraintWhenMigrating: false,
		PrepareStmt:                              true,
	}

	db, err := gorm.Open(sqlite.Open(dsn), gormCfg)
	if err != nil {
		return nil, fmt.Errorf("opening database at %s: %w", cfg.Path, err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("getting underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)

	log.Info("database connected",
		zap.String("path", cfg.Path),
		zap.Bool("foreign_keys", cfg.EnableForeignKs),
		zap.Int("max_idle_conns", cfg.MaxIdleConns),
		zap.Int("max_open_conns", cfg.MaxOpenConns),
	)

	return &DB{
		Conn:   db,
		sqlDB:  sqlDB,
		logger: log,
	}, nil
}

// Close gracefully closes the database connection.
func (d *DB) Close() error {
	if d.sqlDB != nil {
		d.logger.Info("closing database connection")
		if err := d.sqlDB.Close(); err != nil {
			return fmt.Errorf("closing database: %w", err)
		}
	}
	return nil
}

// Ping verifies the database connection is alive.
func (d *DB) Ping() error {
	if d.sqlDB == nil {
		return fmt.Errorf("database connection is nil")
	}
	return d.sqlDB.Ping()
}
