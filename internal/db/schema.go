package db

import (
	"context"
	"database/sql"
	"fmt"
)

// schemaStatements — DDL для таблиц users и sessions.
// Повторяет содержимое migrations/000001_init.up.sql.
// Применяется при старте приложения (EnsureSchema) и в тестах.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id            BIGSERIAL PRIMARY KEY,
		login         TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		created_at    TIMESTAMPTZ NOT NULL,
		updated_at    TIMESTAMPTZ NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS sessions (
		id                 TEXT PRIMARY KEY,
		user_id            BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash         TEXT NOT NULL UNIQUE,
		refresh_token_hash TEXT NOT NULL,
		created_at         TIMESTAMPTZ NOT NULL,
		expires_at         TIMESTAMPTZ NOT NULL,
		revoked_at         TIMESTAMPTZ
	)`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
}

// EnsureSchema проверяет наличие таблиц users и sessions в БД и создаёт их
// при необходимости. Вызов идемпотентен (CREATE IF NOT EXISTS).
func EnsureSchema(ctx context.Context, conn *sql.DB) error {
	for _, stmt := range schemaStatements {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("не удалось применить DDL: %w", err)
		}
	}
	return nil
}
