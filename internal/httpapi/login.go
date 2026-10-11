package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/pinatree/identity-service/internal/password"
)

// LoginRequest — тело запроса POST /api/login.
//
// Структура аналогична RegistrationRequest: логин и пароль в открытом виде
// существуют только в момент запроса и нигде не сохраняются.
type LoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// loginSuccess — результат успешного входа: пара токенов.
// Сырые токены возвращаются клиенту один раз; в хранилище (сессия) попадают
// только их хеши.
type loginSuccess struct {
	// AccessToken — токен для авторизации запросов (Authorization: Bearer).
	AccessToken string `json:"access_token"`

	// RefreshToken — токен для продления сессии без повторного ввода пароля.
	RefreshToken string `json:"refresh_token"`

	// TokenType — тип токена (bearer).
	TokenType string `json:"token_type"`

	// ExpiresAt — момент истечения access-токена (UTC).
	ExpiresAt time.Time `json:"expires_at"`
}

// loginTokenLenBytes — количество случайных байт на один токен входа.
// 32 байта = 256 бит энтропии; в base64url без padding это 43 символа.
const loginTokenLenBytes = 32

// LoginUser обрабатывает POST /api/login — вход по логину и паролю.
//
// Последовательность шагов:
//  1. Разобрать тело запроса (аналогично регистрации);
//  2. Найти пользователя по логину в общем хранилище (глобальный массив);
//  3. Проверить пароль против сохранённого argon2id-хеша;
//  4. Сгенерировать пару токенов (access + refresh) и сохранить в сессию
//     только их SHA-256-хеши;
//  5. Вернуть оба токена в теле ответа (200).
//
// Ответы:
//   - 200 OK — токены выпущены;
//   - 400 Bad Request — невалидный JSON либо пустые логин/пароль;
//   - 401 Unauthorized — пользователь не найден или пароль неверен.
//
// «Пользователь не найден» и «пароль неверен» отвечают одинаково (401
// с одним сообщением): раскрытие того, что логин существует, облегчает
// злоумышленнику подбор учётных записей.
func (h *UserHandler) LoginUser(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[login] ошибка разбора тела запроса: %v", err)
		JSONResponse(w, http.StatusBadRequest, nil, "Некорректный JSON-запрос", nil)
		return
	}

	// Логин нормализуем так же, как при регистрации: ведущие/замыкающие
	// пробелы — почти всегда опечатка.
	req.Login = strings.TrimSpace(req.Login)
	if req.Login == "" || req.Password == "" {
		log.Printf("[login] пустые учётные данные: login=%q, длина пароля=%d", req.Login, len(req.Password))
		JSONResponse(w, http.StatusBadRequest, nil, "Логин и пароль обязательны", nil)
		return
	}

	log.Printf("[login] вход в систему: login=%q, длина пароля=%d", req.Login, len(req.Password))

	user, err := h.users.GetUserByLogin(req.Login)
	if err != nil {
		log.Printf("[login] пользователь %q не найден", req.Login)
		JSONResponse(w, http.StatusUnauthorized, nil, "Неверный логин или пароль", nil)
		return
	}
	log.Printf("[login] пользователь %q найден (id=%d), проверяем пароль", req.Login, user.ID)

	// Проверяем пароль против сохранённого PHC-хеша. Ошибка разбора хеша
	// (например, у мок-пользователей хранится не-PHC-строка) трактуется как
	// неверные учётные данные, а не как сбой сервера.
	ok, err := password.Verify(req.Password, user.PasswordHash)
	if err != nil || !ok {
		log.Printf("[login] неверный пароль для %q (ok=%v, err=%v)", req.Login, ok, err)
		JSONResponse(w, http.StatusUnauthorized, nil, "Неверный логин или пароль", nil)
		return
	}
	log.Printf("[login] пароль для %q подтверждён", req.Login)

	// Токены генерируются независимо друг от друга: access — для авторизации
	// запросов, refresh — для продления сессии. Клиенту отдаются сырые токены,
	// в сессии сохраняются только их хеши.
	accessToken, err := newLoginToken()
	if err != nil {
		log.Printf("[login] не удалось выпустить access-токен: %v", err)
		JSONResponse(w, http.StatusInternalServerError, nil, "Не удалось выпустить токены", nil)
		return
	}
	log.Printf("[login] access-токен сгенерирован (len=%d)", len(accessToken))
	refreshToken, err := newLoginToken()
	if err != nil {
		log.Printf("[login] не удалось выпустить refresh-токен: %v", err)
		JSONResponse(w, http.StatusInternalServerError, nil, "Не удалось выпустить токены", nil)
		return
	}
	log.Printf("[login] refresh-токен сгенерирован (len=%d)", len(refreshToken))

	// Срок действия токенов (и сессии) — из конфигурации (token_ttl).
	expiresAt := time.Now().Add(h.sessionTTL)
	log.Printf("[login] срок действия токенов/сессии: %s (TTL=%v)", expiresAt.UTC().Format(time.RFC3339), h.sessionTTL)
	s, err := h.users.CreateSession(
		user.ID,
		hashToken(accessToken),
		hashToken(refreshToken),
		expiresAt,
	)
	if err != nil {
		log.Printf("[login] не удалось создать сессию для %q: %v", req.Login, err)
		JSONResponse(w, http.StatusInternalServerError, nil, "Не удалось создать сессию", nil)
		return
	}
	log.Printf("[login] сессия создана: id=%s, user_id=%d, expires_at=%s", s.ID, s.UserID, s.ExpiresAt.UTC().Format(time.RFC3339))

	JSONResponse(w, http.StatusOK, loginSuccess{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "bearer",
		ExpiresAt:    expiresAt.UTC(),
	}, "", map[string]any{
		"expires_in": int(h.sessionTTL.Seconds()),
	})

	log.Printf("[login] вход выполнен успешно: login=%q, сессия=%s", req.Login, s.ID)
}

// newLoginToken генерирует криптостойкий случайный токен в формате
// base64url без padding (RFC 4648 §5): base64url(random_bytes(32)).
//
// Такой формат безопасен для использования в URL и HTTP-заголовках без
// дополнительного кодирования. Источник — crypto/rand, тот же пул энтропии,
// что использует TLS.
func newLoginToken() (string, error) {
	b := make([]byte, loginTokenLenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("не удалось получить случайные байты из crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// LogoutUser обрабатывает POST /api/logout — завершение сессии пользователя.
//
// Bearer-токен из заголовка Authorization хешируется (SHA-256) и ищется
// среди активных сессий. Найденная сессия отзывается (RevokedAt = now),
// после чего токен перестаёт действовать.
//
// Ответы:
//   - 200 OK — сессия завершена (даже если токен уже недействителен);
//   - 401 Unauthorized — отсутствует или невалиден bearer-токен.
//
// Идемпотентность: повторный вызов logout с тем же токеном возвращает 200,
// так как сессия уже отозвана — повторный отзыв безопасен.
func (h *UserHandler) LogoutUser(w http.ResponseWriter, r *http.Request) {
	// Token гарантированно присутствует — проверку выполняет middleware RequireSessionAuth.
	tk := bearerToken(r)

	tokenHash := hashToken(tk)

	s, err := h.users.RevokeSession(tokenHash)
	if err != nil {
		// Сессия не найдена или уже неактивна — это не ошибка,
		// а идемпотентный случай: токен уже недействителен.
		log.Printf("[logout] сессия по токену не найдена или уже неактивна: %v", err)
		JSONResponse(w, http.StatusOK, nil, "", map[string]any{
			"already_logged_out": true,
		})
		return
	}

	log.Printf("[logout] сессия %s завершена для пользователя %d", s.ID, s.UserID)
	JSONResponse(w, http.StatusOK, nil, "", map[string]any{
		"session_id": s.ID,
	})
}

// hashToken вычисляет SHA-256-хеш токена в hex-представлении.
//
// В сессии сохраняется только хеш: даже при утечке данных из памяти
// восстановить токен по хешу невозможно.
func hashToken(tk string) string {
	sum := sha256.Sum256([]byte(tk))
	token := hex.EncodeToString(sum[:])
	return token
}
