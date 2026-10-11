package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pinatree/identity-service/internal/db"
)

// pqUniqueViolation — код ошибки PostgreSQL 23505 (unique_violation).
const pqUniqueViolation = "23505"

// postgresRepository — реализация UserRepository, работающая через database/sql
// с реальной PostgreSQL.
type postgresRepository struct {
	db  *sql.DB
	now func() time.Time
}

// NewPostgresRepository создаёт репозиторий, подключённый к существующей БД.
// Схема (таблицы users, sessions) должна быть создана заранее — например,
// вызовом db.EnsureSchema или через миграции.
func NewPostgresRepository(database *sql.DB) UserRepository {
	return &postgresRepository{db: database, now: time.Now}
}

const userColumns = "id, login, password_hash, created_at, updated_at"

func (r *postgresRepository) GetUserWithActiveSessions(login string) (*UserWithSessions, error) {
	user, err := r.GetUserByLogin(login)
	if err != nil {
		return nil, err
	}

	now := r.now()
	rows, err := r.db.QueryContext(context.Background(),
		`SELECT id, user_id, token_hash, refresh_token_hash, created_at, expires_at, revoked_at
		 FROM sessions
		 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
		 ORDER BY created_at, id`,
		user.ID, now)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить активные сессии пользователя %q: %w", login, err)
	}
	defer rows.Close()

	var sessions []*db.Session
	for rows.Next() {
		var s db.Session
		var revoked sql.NullTime
		if err := rows.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.RefreshTokenHash,
			&s.CreatedAt, &s.ExpiresAt, &revoked); err != nil {
			return nil, fmt.Errorf("не удалось прочитать сессию пользователя %q: %w", login, err)
		}
		if revoked.Valid {
			s.RevokedAt = &revoked.Time
		}
		sessions = append(sessions, &s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при обходе сессий пользователя %q: %w", login, err)
	}
	return &UserWithSessions{User: user, Sessions: sessions}, nil
}

func (r *postgresRepository) ListUsers(filter UserFilter, limit int) ([]*db.User, error) {
	query := `SELECT ` + userColumns + ` FROM users`
	args := make([]any, 0, 2)

	if f := strings.TrimSpace(filter.Login); f != "" {
		query += ` WHERE login ILIKE $1 ESCAPE '\'`
		args = append(args, likePattern(f))
	}
	query += ` ORDER BY login`
	if limit > 0 {
		args = append(args, limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	rows, err := r.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil, fmt.Errorf("не удалось выполнить ListUsers: %w", err)
	}
	defer rows.Close()

	users := make([]*db.User, 0, 8)
	for rows.Next() {
		var u db.User
		if err := rows.Scan(&u.ID, &u.Login, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("не удалось прочитать пользователя: %w", err)
		}
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при обходе пользователей: %w", err)
	}
	return users, nil
}

// likePattern экранирует спецсимволы LIKE и оборачивает строку в %…%.
func likePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return "%" + s + "%"
}
func (r *postgresRepository) CreateUser(login, passwordHash string) (*db.User, error) {
	now := r.now()

	// ID присваивает база: users.id — BIGSERIAL, значение генерируется
	// автоматически, приложение получает его через RETURNING id.
	user := &db.User{
		Login:        login,
		PasswordHash: passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	err := r.db.QueryRowContext(context.Background(),
		`INSERT INTO users (login, password_hash, created_at, updated_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, created_at, updated_at`,
		login, passwordHash, now, now).
		Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pqUniqueViolation {
			return nil, ErrLoginExists
		}
		return nil, fmt.Errorf("не удалось создать пользователя %q: %w", login, err)
	}

	slog.Info("создан пользователь", "login", login, "id", user.ID)
	return user, nil
}

func (r *postgresRepository) GetUserByLogin(login string) (*db.User, error) {
	var u db.User
	err := r.db.QueryRowContext(context.Background(),
		`SELECT `+userColumns+` FROM users WHERE login = $1`, login).
		Scan(&u.ID, &u.Login, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("пользователь %q не найден", login)
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось получить пользователя %q: %w", login, err)
	}
	return &u, nil
}

func (r *postgresRepository) CreateSession(userID int64, tokenHash, refreshTokenHash string, expiresAt time.Time) (*db.Session, error) {
	now := r.now()
	s := &db.Session{
		ID:               uuid.NewString(),
		UserID:           userID,
		TokenHash:        tokenHash,
		RefreshTokenHash: refreshTokenHash,
		CreatedAt:        now,
		ExpiresAt:        expiresAt,
	}
	err := r.db.QueryRowContext(context.Background(),
		`INSERT INTO sessions (id, user_id, token_hash, refresh_token_hash, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, created_at`,
		s.ID, userID, tokenHash, refreshTokenHash, now, expiresAt).
		Scan(&s.ID, &s.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать сессию для пользователя %d: %w", userID, err)
	}
	return s, nil
}

func (r *postgresRepository) GetUserBySessionTokenHash(tokenHash string) (*db.User, error) {
	var u db.User
	err := r.db.QueryRowContext(context.Background(),
		`SELECT `+userColumns+` FROM users
		 WHERE id = (SELECT user_id FROM sessions WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2)`,
		tokenHash, r.now()).
		Scan(&u.ID, &u.Login, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("сессия с хешем токена %q не найдена или неактивна", tokenHash)
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось найти пользователя по хешу токена: %w", err)
	}
	return &u, nil
}

func (r *postgresRepository) RevokeSession(tokenHash string) (*db.Session, error) {
	now := r.now()
	var s db.Session
	var revoked sql.NullTime
	err := r.db.QueryRowContext(context.Background(),
		`UPDATE sessions SET revoked_at = $1
		 WHERE token_hash = $2 AND revoked_at IS NULL AND expires_at > $3
		 RETURNING id, user_id, token_hash, refresh_token_hash, created_at, expires_at, revoked_at`,
		now, tokenHash, now).
		Scan(&s.ID, &s.UserID, &s.TokenHash, &s.RefreshTokenHash,
			&s.CreatedAt, &s.ExpiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("активная сессия с хешем токена %q не найдена (или уже отозвана)", tokenHash)
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось отозвать сессию: %w", err)
	}
	if revoked.Valid {
		s.RevokedAt = &revoked.Time
	}
	slog.Info("сессия отозвана", "session_id", s.ID, "revoked_at", now.UTC().Format(time.RFC3339))
	return &s, nil
}

func (r *postgresRepository) SessionExists(tokenHash string) bool {
	var exists bool
	err := r.db.QueryRowContext(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash = $1)`, tokenHash).Scan(&exists)
	if err != nil {
		slog.Warn("ошибка проверки хеша токена", "token_hash", tokenHash, "err", err)
		return false
	}
	return exists
}

func (r *postgresRepository) UpdatePassword(userID int64, passwordHash string) error {
	now := r.now()
	res, err := r.db.ExecContext(context.Background(),
		`UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3`,
		passwordHash, now, userID)
	if err != nil {
		return fmt.Errorf("не удалось обновить пароль пользователя %d: %w", userID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("пользователь %q не найден", userID)
	}
	slog.Info("пароль пользователя изменён", "user_id", userID)
	return nil
}
