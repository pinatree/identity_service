// Package repo — слой репозиториев: доступ к данным через сущности db.
//
// Репозиторий скрывает источник данных (БД, внешний API или мокап в памяти)
// за узким интерфейсом предметной области: вызывающий код оперирует сущностями
// db и не знает, откуда они пришли. Сейчас данные замоканы, поэтому слой можно
// разрабатывать параллельно с подключением настоящей СУБД — интерфейс
// репозитория при этом не изменится.
package repo

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pinatree/identity-service/internal/db"
)

// UserWithSessions — результат запроса «пользователь и его активные сессии».
type UserWithSessions struct {
	// User — найденный пользователь.
	User *db.User

	// Sessions — активные (не отозванные и не истёкшие) сессии пользователя.
	Sessions []*db.Session
}

// UserRepository — репозиторий пользователей.
//
// Временная реализация: данные «зашиты» в конструктор (мокап), обращения
// к БД пока нет. Поле now подменяемо в тестах, поэтому проверка истечения
// сессий не зависит от реального течения времени.
//
// ErrLoginExists — возвращается при попытке создать пользователя с логином,
// который уже есть в хранилище. HTTP-слой транслирует его в ответ 409 Conflict.
var ErrLoginExists = errors.New("пользователь с таким логином уже существует")

// UserRepository — интерфейс доступа к пользователям и сессиям.
//
// Две реализации:
//   - memoryRepository — in-memory хранилище для тестов;
//   - postgresRepository — продакшен-реализация через database/sql + PostgreSQL.
//
// Выбор реализации осуществляется на уровне main/тестов через конструктор.
type UserRepository interface {
	GetUserWithActiveSessions(login string) (*UserWithSessions, error)
	ListUsers(filter UserFilter, limit int) ([]*db.User, error)
	CreateUser(login, passwordHash string) (*db.User, error)
	GetUserByLogin(login string) (*db.User, error)
	CreateSession(userID int64, tokenHash, refreshTokenHash string, expiresAt time.Time) (*db.Session, error)
	GetUserBySessionTokenHash(tokenHash string) (*db.User, error)
	RevokeSession(tokenHash string) (*db.Session, error)
	SessionExists(tokenHash string) bool
	UpdatePassword(userID int64, passwordHash string) error
}
type memoryRepository struct {
	// mu защищает users и sessions от конкурентного доступа: регистрация
	// выполняется параллельно с запросами списков и сессий.
	mu sync.RWMutex

	// users сопоставляет логин с пользователем.
	users map[string]*db.User

	// sessions — все известные сессии (активные и отозванные).
	sessions []*db.Session

	// nextUserID — счётчик идентификаторов новых пользователей.
	// Работает как BIGSERIAL из PostgreSQL, но в памяти: инкремент
	// выполняется под блокировкой mu, поэтому параллельные регистрации
	// получают строго разные id.
	nextUserID int64

	// now — «часы» репозитория. В проде это time.Now, в тестах подменяется
	// фиксированным временем.
	now func() time.Time
}

// NewUserRepository создаёт репозиторий с замокированными данными.
//
// Мокап содержит одного пользователя — admin — и его сессии:
//   - две активные сессии, действительные до 9999 года;
//   - одну отозванную сессию — она не должна попадать в выборку.
//
// Отозванная сессия добавлена намеренно: так фильтр «активные сессии»
// можно проверить на реальных (хоть и вымышленных) данных.
//
// Структуры собираются через make + присваивание по индексу — без
// экзотических форм литералов, на которых легко споткнуться при смене
// версии компилятора.
func NewUserRepository() UserRepository {
	now := time.Now()
	admin := &db.User{
		ID:           1,
		Login:        "admin",
		PasswordHash: "mock-password-hash",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// alwaysActive — 1 января 9999 года UTC. Срок «очень нескоро»: удобный
	// заменитель бессрочных сессий в мокапе (год 9999 представим в time.Time).
	alwaysActive := time.Date(9999, time.January, 1, 0, 0, 0, 0, time.UTC)

	activeSession1 := &db.Session{
		ID:        "00000000-0000-4000-8000-0000000000a1",
		UserID:    admin.ID,
		TokenHash: "mock-token-hash-1",
		CreatedAt: now,
		ExpiresAt: alwaysActive,
	}
	activeSession2 := &db.Session{
		ID:        "00000000-0000-4000-8000-0000000000a2",
		UserID:    admin.ID,
		TokenHash: "mock-token-hash-2",
		CreatedAt: now,
		ExpiresAt: alwaysActive,
	}

	revokedAt := now
	revokedSession := &db.Session{
		ID:        "00000000-0000-4000-8000-0000000000a3",
		UserID:    admin.ID,
		TokenHash: "mock-token-hash-revoked",
		CreatedAt: now,
		ExpiresAt: alwaysActive,
		RevokedAt: &revokedAt,
	}

	// Дополнительные пользователи мокапа: нужны, чтобы список пользователей
	// и фильтры по логину было на чём проверять. Сессии для них не создаём —
	// выборке по логину они не требуются.
	alice := &db.User{
		ID:           2,
		Login:        "alice",
		PasswordHash: "mock-password-hash-alice",
		CreatedAt:    now.Add(-time.Hour),
		UpdatedAt:    now.Add(-time.Hour),
	}
	bob := &db.User{
		ID:           3,
		Login:        "bob",
		PasswordHash: "mock-password-hash-bob",
		CreatedAt:    now.Add(-2 * time.Hour),
		UpdatedAt:    now.Add(-2 * time.Hour),
	}

	users := make(map[string]*db.User)
	users["admin"] = admin
	users["alice"] = alice
	users["bob"] = bob

	sessions := make([]*db.Session, 3)
	sessions[0] = activeSession1
	sessions[1] = activeSession2
	sessions[2] = revokedSession

	return &memoryRepository{
		users:      users,
		sessions:   sessions,
		nextUserID: 3, // мокап содержит трёх пользователей: admin, alice, bob
		now:        time.Now,
	}
}

// GetUserWithActiveSessions возвращает пользователя по логину вместе
// с его активными сессиями.
//
// Активной считается сессия, которая не отозвана (RevokedAt == nil)
// и срок действия которой ещё не истёк (ExpiresAt позже «сейчас»).
// Если пользователь с таким логином не найден — возвращается ошибка.
//
// Результат собирается в два прохода: сначала подсчёт совпадений, потом
// заполнение массива точного размера (массивы в Go фиксированного размера,
// расти «в лоб» без переаллокации они не умеют).
func (r *memoryRepository) GetUserWithActiveSessions(login string) (*UserWithSessions, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, err := r.getUserLocked(login)
	if err != nil {
		return nil, err
	}

	now := r.now()
	match := func(s *db.Session) bool {
		return s.UserID == u.ID && s.IsActive() && now.Before(s.ExpiresAt)
	}

	count := 0
	for _, s := range r.sessions {
		if match(s) {
			count++
		}
	}

	sessions := make([]*db.Session, count)
	i := 0
	for _, s := range r.sessions {
		if match(s) {
			sessions[i] = s
			i++
		}
	}

	return &UserWithSessions{User: u, Sessions: sessions}, nil
}

// UserFilter — критерии выборки пользователей для ListUsers.
//
// Пустые поля означают «без ограничения». Сейчас реализован только поиск
// по логину, но структура намеренно расширяемая: при подключении настоящей
// СУБД сюда добавятся фильтры по дате создания, статусу и т.п.
type UserFilter struct {
	// Login — искомая подстрока логина. Поиск регистронезависимый:
	// фильтр "ALI" находит пользователя alice.
	Login string
}

// ListUsers возвращает пользователей, подходящих под фильтр, не более
// limit записей. Порядок ответа — по логину по возрастанию.
//
// Сортировка задана явно, потому что обход map в Go недетерминирован:
// клиентам нужен стабильный порядок независимо от внутреннего устройства
// репозитория.
func (r *memoryRepository) ListUsers(filter UserFilter, limit int) ([]*db.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := strings.ToLower(strings.TrimSpace(filter.Login))

	matched := make([]*db.User, 0, len(r.users))
	for _, u := range r.users {
		if query != "" && !strings.Contains(strings.ToLower(u.Login), query) {
			continue
		}
		matched = append(matched, u)
	}

	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Login < matched[j].Login
	})

	// Ограничение сверху. limit <= 0 трактуем как «вернуть всё»: HTTP-слой
	// сам валидирует лимит, здесь это лишь защита от случайного нуля.
	if limit > 0 && limit < len(matched) {
		matched = matched[:limit]
	}

	return matched, nil
}

// CreateUser создаёт нового пользователя с указанным логином и хешем пароля
// и сохраняет его в хранилище. Возвращает ErrLoginExists, если логин уже
// занят — в этом случае пользователь не создаётся и запись не перезаписывается.
//
// Пароль в открытом виде в хранилище не передаётся: вызывающий код обязан
// передать уже вычисленный криптографический хеш (см. internal/password).
func (r *memoryRepository) CreateUser(login, passwordHash string) (*db.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.users[login]; ok {
		return nil, fmt.Errorf("%w: логин %q", ErrLoginExists, login)
	}

	// ID присваивается из собственного счётчика — аналог BIGSERIAL в
	// PostgreSQL: значения увеличиваются на 1 под блокировкой mu.
	r.nextUserID++

	now := r.now()
	u := &db.User{
		ID:           r.nextUserID,
		Login:        login,
		PasswordHash: passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	r.users[login] = u
	return u, nil
}

// getUserLocked возвращает пользователя по логину. Вызывающий обязан
// удерживать как минимум RLock блокировки r.mu — на это указывает
// суффикс *Locked (подсказка для коллег).
func (r *memoryRepository) getUserLocked(login string) (*db.User, error) {
	u, ok := r.users[login]
	if !ok {
		return nil, fmt.Errorf("пользователь %q не найден", login)
	}
	return u, nil
}

// GetUserByLogin возвращает пользователя по логину.
//
// Используется при входе в систему: здесь выполняется только поиск записи
// по уникальному ключу (логин), а проверка пароля — в HTTP-слое.
func (r *memoryRepository) GetUserByLogin(login string) (*db.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, err := r.getUserLocked(login)
	if err != nil {
		slog.Debug("пользователь не найден", "login", login)
		return nil, err
	}
	slog.Debug("пользователь найден", "login", login, "id", u.ID)
	return u, nil
}

// CreateSession создаёт новую сессию пользователя и сохраняет её в общем
// массиве сессий (по аналогии с пользователями — всё пока in-memory).
//
// ID генерируется автоматически, CreatedAt берётся из «часов» репозитория,
// ExpiresAt передаёт вызывающий код (обычно «сейчас» + TTL токена
// из конфигурации).
//
// В хранилище попадают только хеши токенов (tokenHash, refreshTokenHash),
// а не сами токены: даже при утечке данных восстановить токен по хешу
// невозможно.
func (r *memoryRepository) CreateSession(userID int64, tokenHash, refreshTokenHash string, expiresAt time.Time) (*db.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	id, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать идентификатор сессии: %w", err)
	}

	s := &db.Session{
		ID:               id,
		UserID:           userID,
		TokenHash:        tokenHash,
		RefreshTokenHash: refreshTokenHash,
		CreatedAt:        r.now(),
		ExpiresAt:        expiresAt,
	}
	r.sessions = append(r.sessions, s)
	slog.Info("сессия создана", "session_id", s.ID, "user_id", s.UserID, "expires_at", s.ExpiresAt.UTC().Format(time.RFC3339))
	return s, nil
}

// GetUserBySessionTokenHash возвращает пользователя по хешу access-токена сессии.
//
// Это метод, пригодный для повторного использования: любому защищённому
// эндпоинту, которому нужно узнать владельца сессии по bearer-токену,
// достаточно захешировать токен (SHA-256) и вызвать этот метод — вместо
// того, чтобы каждый раз дублировать обход общего массива сессий.
//
// Поиск ведётся в потокобезопасном массиве сессий (r.sessions, защищён
// RWMutex). Сессия учитывается только если она активна (не отозвана)
// и срок её действия ещё не истёк: отозванная/просроченная сессия не должна
// давать доступ к чувствительным операциям (например, к смене пароля).
//
// Если сессия не найдена, неактивна или принадлежит несуществующему
// пользователю — возвращается ошибка.
func (r *memoryRepository) GetUserBySessionTokenHash(tokenHash string) (*db.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if tokenHash == "" {
		return nil, fmt.Errorf("хеш токена пуст")
	}

	now := r.now()
	for _, s := range r.sessions {
		if s.TokenHash == tokenHash && s.IsActive() && now.Before(s.ExpiresAt) {
			return r.getUserByIDLocked(s.UserID)
		}
	}
	return nil, fmt.Errorf("сессия с хешем токена %q не найдена или неактивна", tokenHash)
}

// getUserByIDLocked возвращает пользователя по его числовому ID. Вызывающий
// обязан удерживать как минимум RLock блокировки r.mu — на это указывает
// суффикс *Locked (подсказка для коллег).
//
// Карта r.users индексирована по логину, поэтому поиск по ID — это обход
// всех записей. На масштабах in-memory репозитория обход приемлем.
func (r *memoryRepository) getUserByIDLocked(userID int64) (*db.User, error) {
	for _, u := range r.users {
		if u.ID == userID {
			return u, nil
		}
	}
	return nil, fmt.Errorf("пользователь с id %d не найден", userID)
}

// RevokeSession отзывает сессию по хешу токена: устанавливает RevokedAt
// равным текущему моменту времени и возвращает отозванную сессию.
//
// Если сессия с указанным токеном не найдена — возвращается ошибка.
// Уже отозванная сессия повторно не отзывается (но ошибкой не считается —
// идемпотентность: повторный logout с тем же токеном не вредит).
func (r *memoryRepository) RevokeSession(tokenHash string) (*db.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, s := range r.sessions {
		if s.TokenHash == tokenHash && s.IsActive() {
			now := r.now()
			s.RevokedAt = &now
			slog.Info("сессия отозвана", "session_id", s.ID, "revoked_at", now.UTC().Format(time.RFC3339))
			return s, nil
		}
	}
	return nil, fmt.Errorf("активная сессия с хешем токена %q не найдена", tokenHash)
}

// SessionExists проверяет, существует ли сессия с указанным хешем токена
// (независимо от статуса активности).
//
// Используется middleware RequireSessionAuth для поддержки идемпотентности
// logout: если сессия есть, но отозвана — middleware пропускает запрос к
// обработчику LogoutUser, который корректно обрабатывает уже отозванную
// сессию и возвращает 200 с флагом already_logged_out.
func (r *memoryRepository) SessionExists(tokenHash string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sessions {
		if s.TokenHash == tokenHash {
			return true
		}
	}
	return false
}

// UpdatePassword заменяет хеш пароля пользователя и обновляет метку
// UpdatedAt — пароль считается изменённым, и это отражается в аудите.
//
// Вызывается при смене пароля (POST /api/pass_reset). В хранилище попадает
// только новый криптографический хеш: открытый пароль через этот метод
// не передаётся. Обновляется запись с указанным userID — чужие учётные
// записи этот метод не затрагивает.
//
// Если пользователь с указанным ID не найден — возвращается ошибка.
func (r *memoryRepository) UpdatePassword(userID int64, passwordHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, u := range r.users {
		if u.ID == userID {
			u.PasswordHash = passwordHash
			u.UpdatedAt = r.now()
			return nil
		}
	}
	return fmt.Errorf("пользователь %d не найден", userID)
}

// newUUID генерирует случайный UUID версии 4 (RFC 4122) в виде строки.
// Внешние библиотеки для генерации UUID в проект не подключаются: версии 4
// достаточно криптостойкого источника случайности crypto/rand.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Версия 4: старшие 4 бита байта 6 равны 0100.
	b[6] = (b[6] & 0x0f) | 0x40
	// Вариант 10: старшие 2 бита байта 8 равны 10.
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
