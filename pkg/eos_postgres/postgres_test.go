// pkg/eos_postgres/postgres_test.go
package eos_postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpen tests the Open function with various scenarios
func TestOpen(t *testing.T) {
	tests := []struct {
		name    string
		dsn     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty DSN",
			dsn:     "",
			wantErr: true,
			errMsg:  "empty DSN",
		},
		{
			name:    "invalid DSN format",
			dsn:     "not-a-valid-dsn",
			wantErr: true,
			errMsg:  "invalid DSN",
		},
		{
			name:    "valid DSN format but unreachable",
			dsn:     "postgres://user:pass@localhost:5432/dbname?sslmode=disable",
			wantErr: true,
			errMsg:  "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			db, err := Open(ctx, tt.dsn)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, db)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, db)
				if db != nil {
					db.Close()
				}
			}
		})
	}
}

// TestConnect tests the Connect function
func TestConnect(t *testing.T) {
	tests := []struct {
		name    string
		envVar  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "missing POSTGRES_DSN",
			envVar:  "",
			wantErr: true,
			errMsg:  "POSTGRES_DSN environment variable is required",
		},
		{
			name:    "invalid POSTGRES_DSN",
			envVar:  "invalid-dsn",
			wantErr: true, // GORM will fail to parse invalid DSN
			errMsg:  "cannot parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env var
			original := os.Getenv("POSTGRES_DSN")
			defer os.Setenv("POSTGRES_DSN", original)

			// Set test env var
			if tt.envVar == "" {
				_ = os.Unsetenv("POSTGRES_DSN")
			} else {
				_ = os.Setenv("POSTGRES_DSN", tt.envVar)
			}

			db, err := Connect()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, db)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, db)
			}
		})
	}
}

// TestHealth tests the Health function
func TestHealth(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	defer db.Close()

	tests := []struct {
		name    string
		setup   func()
		wantErr bool
	}{
		{
			name: "successful ping",
			setup: func() {
				mock.ExpectPing()
			},
			wantErr: false,
		},
		{
			name: "ping failure",
			setup: func() {
				mock.ExpectPing().WillReturnError(errors.New("connection lost"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			err := Health(db)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestWithTx tests transaction handling
func TestWithTx(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	tests := []struct {
		name    string
		setup   func()
		fn      func(*sql.Tx) error
		wantErr bool
	}{
		{
			name: "successful transaction",
			setup: func() {
				mock.ExpectBegin()
				mock.ExpectExec("INSERT INTO test").WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
			},
			fn: func(tx *sql.Tx) error {
				_, err := tx.Exec("INSERT INTO test VALUES (?)", "value")
				return err
			},
			wantErr: false,
		},
		{
			name: "transaction rollback on error",
			setup: func() {
				mock.ExpectBegin()
				mock.ExpectExec("INSERT INTO test").WillReturnError(errors.New("constraint violation"))
				mock.ExpectRollback()
			},
			fn: func(tx *sql.Tx) error {
				_, err := tx.Exec("INSERT INTO test VALUES (?)", "value")
				return err
			},
			wantErr: true,
		},
		{
			name: "begin transaction failure",
			setup: func() {
				mock.ExpectBegin().WillReturnError(errors.New("cannot begin transaction"))
			},
			fn: func(tx *sql.Tx) error {
				return nil
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			ctx := context.Background()
			err := WithTx(ctx, db, tt.fn)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestHashStore tests the HashStore implementation
func TestHashStore(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Test NewHashStore
	t.Run("NewHashStore", func(t *testing.T) {
		mock.ExpectExec("create table if not exists sent_alerts").
			WillReturnResult(sqlmock.NewResult(0, 0))

		ctx := context.Background()
		store, err := NewHashStore(ctx, db)
		assert.NoError(t, err)
		assert.NotNil(t, store)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Create store for remaining tests
	store := &pgHashStore{db: db}

	// Test Seen
	t.Run("Seen", func(t *testing.T) {
		testHash := "abc123"

		// Hash exists
		mock.ExpectQuery("select exists").
			WithArgs(testHash).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		assert.True(t, store.Seen(testHash))

		// Hash doesn't exist
		mock.ExpectQuery("select exists").
			WithArgs(testHash).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		assert.False(t, store.Seen(testHash))

		// Query error (should return false)
		mock.ExpectQuery("select exists").
			WithArgs(testHash).
			WillReturnError(errors.New("db error"))
		assert.False(t, store.Seen(testHash))

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test Mark
	t.Run("Mark", func(t *testing.T) {
		testHash := "def456"

		// Successful insert
		mock.ExpectExec("insert into sent_alerts").
			WithArgs(testHash).
			WillReturnResult(sqlmock.NewResult(1, 1))
		assert.NoError(t, store.Mark(testHash))

		// Insert error
		mock.ExpectExec("insert into sent_alerts").
			WithArgs(testHash).
			WillReturnError(errors.New("unique constraint violation"))
		assert.Error(t, store.Mark(testHash))

		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestKVOperations tests key-value operations
func TestKVOperations(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	// Test GetKV
	t.Run("GetKV", func(t *testing.T) {
		// Key exists
		mock.ExpectQuery("select val from kvm").
			WithArgs("testkey").
			WillReturnRows(sqlmock.NewRows([]string{"val"}).AddRow("testvalue"))
		val, err := GetKV(ctx, db, "testkey")
		assert.NoError(t, err)
		assert.Equal(t, "testvalue", val)

		// Key doesn't exist
		mock.ExpectQuery("select val from kvm").
			WithArgs("notfound").
			WillReturnError(sql.ErrNoRows)
		val, err = GetKV(ctx, db, "notfound")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
		assert.Empty(t, val)

		// Database error
		mock.ExpectQuery("select val from kvm").
			WithArgs("error").
			WillReturnError(errors.New("database error"))
		val, err = GetKV(ctx, db, "error")
		assert.Error(t, err)
		assert.NotErrorIs(t, err, ErrNotFound)

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test PutKV
	t.Run("PutKV", func(t *testing.T) {
		// Successful insert/update
		mock.ExpectExec("insert into kvm").
			WithArgs("key1", "value1").
			WillReturnResult(sqlmock.NewResult(1, 1))
		assert.NoError(t, PutKV(ctx, db, "key1", "value1"))

		// Database error
		mock.ExpectExec("insert into kvm").
			WithArgs("key2", "value2").
			WillReturnError(errors.New("constraint violation"))
		assert.Error(t, PutKV(ctx, db, "key2", "value2"))

		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestNewPGHashStore tests the legacy NewPGHashStore function
func TestNewPGHashStore(t *testing.T) {
	// Save original env var
	original := os.Getenv("POSTGRES_DSN")
	defer os.Setenv("POSTGRES_DSN", original)

	// Test missing POSTGRES_DSN
	_ = os.Unsetenv("POSTGRES_DSN")
	ctx := context.Background()
	store, err := NewPGHashStore(ctx)
	assert.Error(t, err)
	assert.Nil(t, store)
	assert.Contains(t, err.Error(), "POSTGRES_DSN environment variable is required")

	// Test with invalid DSN (connection will fail)
	_ = os.Setenv("POSTGRES_DSN", "invalid-dsn")
	store, err = NewPGHashStore(ctx)
	assert.Error(t, err)
	assert.Nil(t, store)
}

// TestConcurrentHashStore tests concurrent access to HashStore
func TestConcurrentHashStore(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Create store
	mock.ExpectExec("create table if not exists sent_alerts").
		WillReturnResult(sqlmock.NewResult(0, 0))
	ctx := context.Background()
	store, err := NewHashStore(ctx, db)
	require.NoError(t, err)

	// Test concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			hash := "hash" + string(rune(id))
			
			// Each goroutine does a Seen followed by Mark
			mock.ExpectQuery("select exists").
				WithArgs(hash).
				WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
			mock.ExpectExec("insert into sent_alerts").
				WithArgs(hash).
				WillReturnResult(sqlmock.NewResult(1, 1))

			if !store.Seen(hash) {
				_ = store.Mark(hash)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}