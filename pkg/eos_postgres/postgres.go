// pkg/eos_postgres/postgres.go
package eos_postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ───────────────────────── Connection helpers ───────────────────────────

// Open opens a *sql.DB using pgx and verifies connectivity with Ping.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// Connect returns a *gorm.DB for high-level use – kept for backward-compat.
func Connect() (*gorm.DB, error) {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		dsn = "host=localhost user=postgres password=postgres " +
			"dbname=eos_kvm port=5432 sslmode=disable"
	}
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}

// Gorm upgrades an existing *sql.DB.
func Gorm(db *sql.DB) (*gorm.DB, error) {
	return gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})
}

// Health pings the database with a short timeout.
func Health(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}

// WithTx runs fn inside a serialisable tx that automatically rolls back on err.
func WithTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// AutoMigrate wraps GORM’s automigrate.
func AutoMigrate(db *gorm.DB, models ...any) error { return db.AutoMigrate(models...) }

// ───────────────────────── HashStore thin wrapper ───────────────────────

// HashStore is exported so other packages don’t need to duplicate it.
type HashStore interface {
	Seen(hash string) bool
	Mark(hash string) error
}

// pgHashStore saves SHA-256 hashes in `sent_alerts` table.
type pgHashStore struct{ db *sql.DB }

const createSentAlerts = `
create table if not exists sent_alerts(
	hash text primary key,
	sent_at timestamptz default now()
)`

// NewHashStore creates the table if needed and returns a HashStore.
func NewHashStore(ctx context.Context, db *sql.DB) (HashStore, error) {
	if _, err := db.ExecContext(ctx, createSentAlerts); err != nil {
		return nil, err
	}
	return &pgHashStore{db: db}, nil
}

func (p *pgHashStore) Seen(h string) bool {
	var ok bool
	_ = p.db.QueryRow(`select exists(select 1 from sent_alerts where hash=$1)`, h).Scan(&ok)
	return ok
}
func (p *pgHashStore) Mark(h string) error {
	_, err := p.db.Exec(`insert into sent_alerts(hash) values($1) on conflict do nothing`, h)
	return err
}

// ───────────────────────── Legacy helpers (kept) ─────────────────────────

// Migrate kept for compatibility with older code (auto-migrates KVM model).
func Migrate(db *gorm.DB) error {
	type KVM struct {
		ID  uint   `gorm:"primaryKey"`
		Key string `gorm:"uniqueIndex"`
		Val string
	}
	return db.AutoMigrate(&KVM{})
}

// NewPGHashStore is the legacy name used elsewhere; now just a shim.
func NewPGHashStore(ctx context.Context) (HashStore, error) {
	db, err := Open(ctx, os.Getenv("POSTGRES_DSN"))
	if err != nil {
		return nil, err
	}
	return NewHashStore(ctx, db)
}

// ------------------------------------------------------------------------

// ErrNotFound can be reused by callers that need a sentinel.
var ErrNotFound = errors.New("record not found")

// GetKV example helper (shows how wrapping can look; remove if unused).
func GetKV(ctx context.Context, db *sql.DB, key string) (string, error) {
	var val string
	err := db.QueryRowContext(ctx, `select val from kvm where key=$1`, key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return val, err
}

// PutKV upserts a key/value pair.
func PutKV(ctx context.Context, db *sql.DB, key, val string) error {
	_, err := db.ExecContext(ctx,
		`insert into kvm(key,val) values($1,$2)
		 on conflict(key) do update set val=excluded.val`, key, val)
	return err
}
