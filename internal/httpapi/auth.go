package httpapi

import (
	"log"
	"net/http"
	"strings"

	"github.com/pinatree/identity-service/internal/repo"
)

// bearerPrefix — схема авторизации, ожидаемая в заголовке Authorization.
// Полный формат заголовка: "Bearer <token>".
const bearerPrefix = "Bearer "

// bearerToken извлекает сырой токен из заголовка Authorization.
//
// Возвращает пустую строку, если заголовок отсутствует или не начинается
// с "Bearer " (схема авторизации bearerPrefix). Сырой токен нужен не только
// middleware, но и обработчикам, которые хешируют его для поиска сессии
// в репозитории — поэтому извлечение вынесено в отдельную функцию,
// пригодную для повторного использования.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, bearerPrefix) {
		return ""
	}
	return strings.TrimPrefix(header, bearerPrefix)
}

// RequireSessionAuth — HTTP-middleware, которое пропускает запрос только при
// наличии действующего bearer-токена. Access-токены выпускаются при входе
// (/api/login) и проверяются поиском активной сессии по хешу токена
// в users.GetUserBySessionTokenHash(). Если активная сессия найдена,
// запрос пропускается к next.
func RequireSessionAuth(users repo.UserRepository, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			log.Printf("[auth] %s %s: заголовок Authorization отсутствует → 401", r.Method, r.URL.Path)
			JSONResponse(w, http.StatusUnauthorized, nil, "unauthorized: missing, invalid or expired token", nil)
			return
		}
		tk := bearerToken(r)
		if tk == "" {
			log.Printf("[auth] %s %s: заголовок не в формате Bearer <token> → 401", r.Method, r.URL.Path)
			JSONResponse(w, http.StatusUnauthorized, nil, "unauthorized: missing, invalid or expired token", nil)
			return
		}

		// Проверка через сессию.
		tokenHash := hashToken(tk)
		if _, err := users.GetUserBySessionTokenHash(tokenHash); err == nil {
			log.Printf("[auth] %s %s: токен (длина=%d) принят через сессию → доступ разрешён", r.Method, r.URL.Path, len(tk))
			next.ServeHTTP(w, r)
			return
		}

		// Если активная сессия не найдена, но сессия с таким хешем существует
		// (уже отозвана), пропускаем запрос — обработчик LogoutUser сам
		// вернёт 200 с флагом already_logged_out для идемпотентного logout.
		// Для pass_reset обработчик самостоятельно вызовет GetUserBySessionTokenHash
		// и отклонит запрос с отозванной сессией (401).
		if users.SessionExists(tokenHash) {
			log.Printf("[auth] %s %s: токен (длина=%d) найден, но сессия отозвана → пропускаем для идемпотентности", r.Method, r.URL.Path, len(tk))
			next.ServeHTTP(w, r)
			return
		}

		log.Printf("[auth] %s %s: токен (длина=%d) недействителен → 401", r.Method, r.URL.Path, len(tk))
		JSONResponse(w, http.StatusUnauthorized, nil, "unauthorized: missing, invalid or expired token", nil)
	})
}
