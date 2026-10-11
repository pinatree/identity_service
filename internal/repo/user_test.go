// Файл содержит модульные тесты для репозитория пользователей.
//
// Репозиторий отдаёт замокированные данные, поэтому тесты проверяют контракт
// функции GetUserWithActiveSessions: поиск пользователя по логину, фильтрацию
// «активных» сессий и поведение при неизвестном логине.
package repo

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestGetAdminWithActiveSessions проверяет «счастливый путь»: для admin
// возвращается пользователь и ровно две активные сессии. Отозванная сессия
// из мокапа в выборку попадать не должна.
func TestGetAdminWithActiveSessions(t *testing.T) {
	r := NewUserRepository()

	res, err := r.GetUserWithActiveSessions("admin")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if res.User == nil {
		t.Fatal("ожидался пользователь admin")
	}
	if res.User.Login != "admin" {
		t.Fatalf("login: ожидалось admin, получено %q", res.User.Login)
	}
	if len(res.Sessions) != 2 {
		t.Fatalf("ожидалось 2 активные сессии, получено %d", len(res.Sessions))
	}

	now := time.Now()
	seen := make(map[string]bool)
	for _, s := range res.Sessions {
		seen[s.TokenHash] = true

		if s.UserID != res.User.ID {
			t.Errorf("сессия %q принадлежит другому пользователю", s.ID)
		}
		if !s.IsActive() {
			t.Errorf("сессия %q должна быть активной (не отозванной)", s.ID)
		}
		if !now.Before(s.ExpiresAt) {
			t.Errorf("срок сессии %q должен ещё не истечь", s.ID)
		}
		// Мокированные сессии действительны «до 9999 года»: проверяем
		// префикс форматированной даты, чтобы тест не «протух» раньше срока.
		if !strings.HasPrefix(s.ExpiresAt.UTC().Format(time.RFC3339), "9999") {
			t.Errorf("сессия %q должна истекать в 9999 году", s.ID)
		}
	}

	if !seen["mock-token-hash-1"] || !seen["mock-token-hash-2"] {
		t.Fatal("в выборке должны быть обе активные мок-сессии")
	}
	if seen["mock-token-hash-revoked"] {
		t.Fatal("отозванная сессия не должна попадать в выборку")
	}
}

// TestGetUnknownUserReturnsError проверяет, что неизвестный логин
// возвращает ошибку и nil вместо результата.
func TestGetUnknownUserReturnsError(t *testing.T) {
	r := NewUserRepository()

	res, err := r.GetUserWithActiveSessions("no-such-user")
	if err == nil {
		t.Fatal("неизвестный логин должен возвращать ошибку")
	}
	if res != nil {
		t.Fatal("при ошибке результат должен быть nil")
	}
}

// TestListUsers проверяет выборку пользователей: сортировку по логину,
// регистронезависимый поиск по подстроке и ограничение сверху.
func TestListUsers(t *testing.T) {
	r := NewUserRepository()

	// Без фильтра возвращаются все мок-пользователи, отсортированные по логину.
	all, err := r.ListUsers(UserFilter{}, 100)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ожидалось 3 пользователя, получено %d", len(all))
	}
	for i, want := range []string{"admin", "alice", "bob"} {
		if all[i].Login != want {
			t.Errorf("позиция %d: ожидался логин %q, получен %q", i, want, all[i].Login)
		}
	}

	// Лимит обрезает список сверху.
	limited, err := r.ListUsers(UserFilter{}, 2)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(limited) != 2 || limited[0].Login != "admin" || limited[1].Login != "alice" {
		t.Fatalf("при limit=2 ожидались admin и alice, получено: %#v", limited)
	}

	// Фильтр по логину — регистронезависимая подстрока.
	found, err := r.ListUsers(UserFilter{Login: "ALI"}, 100)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(found) != 1 || found[0].Login != "alice" {
		t.Fatalf("по фильтру ALI ожидался alice, получено: %#v", found)
	}

	// Подстрока «a» находит admin и alice.
	partial, err := r.ListUsers(UserFilter{Login: "a"}, 100)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(partial) != 2 {
		t.Fatalf("по фильтру a ожидалось 2 пользователя, получено %d", len(partial))
	}

	// Нет совпадений — пустой список без ошибки.
	none, err := r.ListUsers(UserFilter{Login: "no-such-user"}, 100)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("ожидался пустой список, получено %d записей", len(none))
	}
}

// TestCreateUser проверяет «счастливый путь»: пользователь создаётся,
// получает сгенерированный ID и становится видимым в списке.
func TestCreateUser(t *testing.T) {
	r := NewUserRepository()

	u, err := r.CreateUser("newuser", "phc-hash")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if u.Login != "newuser" {
		t.Fatalf("login: ожидался newuser, получено %q", u.Login)
	}
	if u.PasswordHash != "phc-hash" {
		t.Fatalf("password_hash: ожидался phc-hash, получено %q", u.PasswordHash)
	}
	if u.ID == 0 {
		t.Fatal("у созданного пользователя должен быть сгенерирован ID")
	}
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Fatal("у созданного пользователя должны быть заполнены CreatedAt и UpdatedAt")
	}

	// Новый пользователь виден и в списке (3 мок-пользователя + новый).
	all, err := r.ListUsers(UserFilter{}, 100)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("ожидалось 4 пользователя, получено %d", len(all))
	}
}

// TestCreateUserDuplicate проверяет, что повторное создание пользователя
// с занятым логином возвращает ErrLoginExists и не перезаписывает запись.
func TestCreateUserDuplicate(t *testing.T) {
	r := NewUserRepository()

	if _, err := r.CreateUser("newuser", "phc-hash-1"); err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	_, err := r.CreateUser("newuser", "phc-hash-2")
	if !errors.Is(err, ErrLoginExists) {
		t.Fatalf("ожидалась ошибка ErrLoginExists, получено: %v", err)
	}

	// Исходный хеш не должен быть перезаписан повторной регистрацией.
	got, err := r.GetUserWithActiveSessions("newuser")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if got.User.PasswordHash != "phc-hash-1" {
		t.Fatalf("существующий пользователь был перезаписан: %q", got.User.PasswordHash)
	}
}

// TestCreateUserConflictsWithMock проверяет, что логин мок-пользователя
// тоже считается занятым.
func TestCreateUserConflictsWithMock(t *testing.T) {
	r := NewUserRepository()

	if _, err := r.CreateUser("admin", "phc-hash"); !errors.Is(err, ErrLoginExists) {
		t.Fatalf("для admin ожидалась ошибка ErrLoginExists, получено: %v", err)
	}
}

// TestGetUserByLogin проверяет поиск пользователя по логину: существующий
// логин возвращает запись, неизвестный — ошибку.
func TestGetUserByLogin(t *testing.T) {
	r := NewUserRepository()

	u, err := r.GetUserByLogin("admin")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if u.Login != "admin" {
		t.Fatalf("login: ожидался admin, получено %q", u.Login)
	}

	if _, err := r.GetUserByLogin("no-such-user"); err == nil {
		t.Fatal("неизвестный логин должен возвращать ошибку")
	}
}

// TestCreateSession проверяет сохранение сессии при входе: генерируется ID,
// заполняются хеши токенов и срок действия, а сама сессия попадает в общий
// массив и видна через выборку активных сессий пользователя.
func TestCreateSession(t *testing.T) {
	r := NewUserRepository()

	u, err := r.GetUserByLogin("admin")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	expiresAt := time.Now().Add(time.Hour)
	s, err := r.CreateSession(u.ID, "token-hash", "refresh-token-hash", expiresAt)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if s.ID == "" {
		t.Fatal("у созданной сессии должен быть ID")
	}
	if s.UserID != u.ID {
		t.Fatalf("UserID: ожидался %d, получено %d", u.ID, s.UserID)
	}
	if s.TokenHash != "token-hash" || s.RefreshTokenHash != "refresh-token-hash" {
		t.Fatalf("хеши токенов сохранились неверно: %q / %q", s.TokenHash, s.RefreshTokenHash)
	}
	if s.CreatedAt.IsZero() {
		t.Fatal("CreatedAt должен быть заполнен")
	}
	if !s.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("ExpiresAt: ожидался %v, получено %v", expiresAt, s.ExpiresAt)
	}
	if !s.IsActive() {
		t.Fatal("новая сессия должна быть активной (не отозванной)")
	}

	// Новая сессия видна в выборке активных сессий пользователя:
	// у admin в мокапе 2 активные сессии, после добавления становится 3.
	res, err := r.GetUserWithActiveSessions("admin")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(res.Sessions) != 3 {
		t.Fatalf("ожидалось 3 активные сессии (2 мок + 1 новая), получено %d", len(res.Sessions))
	}
}

// TestGetUserBySessionTokenHash проверяет переиспользуемый метод поиска
// пользователя по хешу access-токена сессии: активная сессия находит
// владельца, а отозванная/неизвестная/пустая — возвращают ошибку.
func TestGetUserBySessionTokenHash(t *testing.T) {
	r := NewUserRepository()

	// Активная мок-сессия admin с хешем "mock-token-hash-1".
	u, err := r.GetUserBySessionTokenHash("mock-token-hash-1")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if u == nil || u.Login != "admin" {
		t.Fatalf("ожидался пользователь admin, получено: %#v", u)
	}

	// Отозванная сессия ("mock-token-hash-revoked") доступ давать не должна.
	if _, err := r.GetUserBySessionTokenHash("mock-token-hash-revoked"); err == nil {
		t.Fatal("отозванная сессия не должна давать доступ")
	}

	// Неизвестный хеш — ошибка.
	if _, err := r.GetUserBySessionTokenHash("no-such-hash"); err == nil {
		t.Fatal("неизвестный хеш должен возвращать ошибку")
	}

	// Пустой хеш — ошибка.
	if _, err := r.GetUserBySessionTokenHash(""); err == nil {
		t.Fatal("пустой хеш должен возвращать ошибку")
	}
}

// TestUpdatePassword проверяет обновление хеша пароля и метки UpdatedAt,
// а также ошибку для несуществующего пользователя.
func TestUpdatePassword(t *testing.T) {
	r := NewUserRepository()

	u, err := r.GetUserByLogin("admin")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	oldUpdatedAt := u.UpdatedAt

	if err := r.UpdatePassword(u.ID, "new-phc-hash"); err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	got, err := r.GetUserByLogin("admin")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if got.PasswordHash != "new-phc-hash" {
		t.Fatalf("хеш пароля не обновлён: %q", got.PasswordHash)
	}
	if !got.UpdatedAt.After(oldUpdatedAt) {
		t.Errorf("UpdatedAt должен обновиться после смены пароля")
	}

	// Несуществующий пользователь — ошибка, и хранилище не должно измениться.
	if err := r.UpdatePassword(99999, "hash"); err == nil {
		t.Fatal("несуществующий пользователь должен возвращать ошибку")
	}
}
