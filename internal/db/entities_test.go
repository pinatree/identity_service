// Файл содержит модульные тесты для сущностей пакета db.
//
// Сущности — «чистые» структуры данных: они не содержат логики обращения
// к БД, поэтому тесты проверяют контракт полей и инварианты, закодированные
// в методах (например, признак активности сессии).
package db

import (
	"testing"
	"time"
)

// TestUserFieldsRoundTrip проверяет, что все поля User заполняются литералом
// и читаются обратно без потерь.
func TestUserFieldsRoundTrip(t *testing.T) {
	now := time.Now()
	u := &User{
		ID:           1,
		Login:        "alice",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$...",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if u.ID != 1 {
		t.Fatalf("ID: ожидалось 1, получено %d", u.ID)
	}
	if u.Login != "alice" {
		t.Fatalf("Login: ожидалось alice, получено %q", u.Login)
	}
	if u.PasswordHash == "" {
		t.Fatal("PasswordHash не должен быть пустым")
	}
	// Моменты времени сравниваем через одинаковый формат: у обеих сторон
	// одно и то же значение time.Time, значит и строка будет идентичной.
	if u.CreatedAt.UTC().Format(time.RFC3339) != now.UTC().Format(time.RFC3339) {
		t.Fatal("CreatedAt должен сохранить переданный момент времени")
	}
	if u.UpdatedAt.UTC().Format(time.RFC3339) != now.UTC().Format(time.RFC3339) {
		t.Fatal("UpdatedAt должен сохранить переданный момент времени")
	}
}

// TestSessionActiveByDefault проверяет инвариант модели сессии:
// RevokedAt == nil означает, что сессия активна (не отозвана).
func TestSessionActiveByDefault(t *testing.T) {
	now := time.Now()
	s := &Session{
		ID:        "22222222-2222-4222-8222-222222222222",
		UserID:    1,
		TokenHash: "0123456789abcdef...",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Minute),
	}

	if s.RevokedAt != nil {
		t.Fatal("у новой сессии RevokedAt должен быть nil")
	}
	if !s.IsActive() {
		t.Fatal("сессия без RevokedAt должна считаться активной")
	}
}

// TestSessionRevokedIsInactive проверяет, что установка RevokedAt отзывает
// сессию: IsActive возвращает false, пока RevokedAt != nil.
func TestSessionRevokedIsInactive(t *testing.T) {
	now := time.Now()
	s := &Session{
		ID:        "22222222-2222-4222-8222-222222222222",
		UserID:    1,
		TokenHash: "0123456789abcdef...",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Minute),
	}

	revokedAt := now.Add(30 * time.Second)
	s.RevokedAt = &revokedAt
	if s.RevokedAt == nil {
		t.Fatal("после отзыва RevokedAt должен быть заполнен")
	}
	if s.IsActive() {
		t.Fatal("отозванная сессия не должна считаться активной")
	}
}
