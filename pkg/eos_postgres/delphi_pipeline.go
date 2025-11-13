// pkg/eos_postgres/delphi_pipeline.go

package eos_postgres

import (
	"context"
	"database/sql"
	"fmt"

	"gorm.io/gorm"

	_ "github.com/lib/pq"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS alerts (
  id            BIGSERIAL PRIMARY KEY,
  raw           JSONB        NOT NULL,
  level         INT          GENERATED ALWAYS AS ((raw->'rule'->>'level')::INT) STORED,
  created_at    TIMESTAMPTZ  DEFAULT now(),
  summarized_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS llm_responses (
  id           BIGSERIAL PRIMARY KEY,
  alert_id     BIGINT       REFERENCES alerts(id) ON DELETE CASCADE,
  response_txt TEXT         NOT NULL,
  created_at   TIMESTAMPTZ  DEFAULT now(),
  emailed_at   TIMESTAMPTZ
);

CREATE OR REPLACE FUNCTION notify_new_alert()  
  RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('new_alert', NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION notify_new_resp()  
  RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('new_response', NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = '_alert_notify'
  ) THEN
    CREATE TRIGGER _alert_notify
      AFTER INSERT ON alerts
      FOR EACH ROW EXECUTE FUNCTION notify_new_alert();
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = '_resp_notify'
  ) THEN
    CREATE TRIGGER _resp_notify
      AFTER INSERT ON llm_responses
      FOR EACH ROW EXECUTE FUNCTION notify_new_resp();
  END IF;
END;
$$;
`

// DeploySchemaSQL runs the CREATEs via database/sql + lib/pq.
// e.g. db, _ := sql.Open("postgres", dsn)
func DeploySchemaSQL(ctx context.Context, db *sql.DB) error {
	// Make sure we respect context cancellation
	_, err := db.ExecContext(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("eos_postgres: failed to deploy schema via sql.DB: %w", err)
	}
	return nil
}

// DeploySchemaGORM runs the same DDL via GORM.
// e.g. gormDB, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
func DeploySchemaGORM(ctx context.Context, gormDB *gorm.DB) error {
	// GORM does not accept ExecContext, but you can attach context here
	if err := gormDB.WithContext(ctx).Exec(schemaSQL).Error; err != nil {
		return fmt.Errorf("eos_postgres: failed to deploy schema via GORM: %w", err)
	}
	return nil
}
