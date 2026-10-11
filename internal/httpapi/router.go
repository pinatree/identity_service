package httpapi

import (
	"net/http"
	"time"

	"github.com/pinatree/identity-service/internal/repo"
)

// Router собирает воедино HTTP-маршруты сервиса и их обработчики.
// Маршруты регистрируются в конструкторе — отдельного метода RegisterRoutes
// не существует, поэтому «забыть вызвать регистрацию» невозможно.
type Router struct {
	// version — версия сервиса, отдаваемая в эндпоинте /version.
	version string

	// serviceName — имя сервиса для health-ответа.
	serviceName string

	userHandler *UserHandler

	// mux — стандартный мультиплексор net/http.
	mux *http.ServeMux
}

// NewRouter создаёт роутер и сразу регистрирует все маршруты.
//
// Параметры:
//   - version — версия сервиса (подставляется в /version);
//   - serviceName — имя сервиса (подставляется в /health);
//   - users — репозиторий пользователей (сейчас — мокап);
//   - sessionTTL — срок жизни сессии и выдаваемых при входе токенов
//     (берётся из конфигурации, token_ttl).
func NewRouter(version, serviceName string, users repo.UserRepository, sessionTTL time.Duration) *Router {
	r := &Router{
		version:     version,
		serviceName: serviceName,
		userHandler: NewUserHandler(users, sessionTTL),
		mux:         http.NewServeMux(),
	}
	r.registerRoutes()
	return r
}

// registerRoutes регистрирует все эндпоинты сервиса.
//
// Публичные (авторизация не требуется):
//   - GET  /health            — проверка живости сервиса;
//   - GET  /version           — версия сервиса;
//   - POST /api/registration  — регистрация нового пользователя;
//   - POST /api/login         — вход по логину и паролю (пара токенов).
//
// Защищённые (нужен заголовок "Authorization: Bearer <токен>"):
//   - POST /api/pass_reset — смена пароля (идентификация по сессии);
//   - POST /api/logout — выход (отзыв сессии).
//
// Каждый маршрут оборачивается в requireMethod — middleware, которое
// отклоняет неподдерживаемые HTTP-методы кодом 405.
func (r *Router) registerRoutes() {
	// Health — проверка живости. Используется балансировщиками
	// и оркестраторами (Kubernetes, docker healthcheck).
	r.mux.Handle("/health", requireMethod(http.MethodGet)(http.HandlerFunc(r.handleHealth)))

	// Version — версия сервиса для диагностики и мониторинга.
	r.mux.Handle("/version", requireMethod(http.MethodGet)(http.HandlerFunc(r.handleVersion)))

	// Регистрация — публичный эндпоинт. Создаёт пользователя с argon2id-хешем
	// пароля; дубликат логина отклоняется кодом 409.
	r.mux.Handle("/api/registration", requireMethod(http.MethodPost)(http.HandlerFunc(r.userHandler.RegisterUser)))

	// Вход — публичный эндпоинт. Проверяет логин и пароль; при успехе выдаёт
	// пару токенов (access + refresh). Неверные учётные данные — 401.
	r.mux.Handle("/api/login", requireMethod(http.MethodPost)(http.HandlerFunc(r.userHandler.LoginUser)))

	// Выход — защищённый эндпоинт. Оборачиваем в RequireSessionAuth, чтобы
	// без валидного bearer-токена запрос отклонялся кодом 401.
	r.mux.Handle("/api/logout",
		requireMethod(http.MethodPost)(
			RequireSessionAuth(r.userHandler.users, http.HandlerFunc(r.userHandler.LogoutUser)),
		),
	)

	// Смена пароля — защищённый эндпоинт. Оборачиваем в RequireSessionAuth, чтобы
	// без валидного bearer-токена запрос отклонялся кодом 401. Идентификация
	// по сессии выполняется внутри обработчика через repo.UserRepository.
	r.mux.Handle("/api/pass_reset",
		requireMethod(http.MethodPost)(
			RequireSessionAuth(r.userHandler.users, http.HandlerFunc(r.userHandler.PassResetUser)),
		),
	)

	// Обработчик по умолчанию: ловит все пути, не совпавшие с указанными выше,
	// и отвечает 404 — незнакомый URL не должен «молча» возвращать 200.
	r.mux.HandleFunc("/", r.handleNotFound)
}

// handleHealth отдаёт статус сервиса и его имя.
func (r *Router) handleHealth(w http.ResponseWriter, req *http.Request) {
	JSONResponse(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"service": r.serviceName,
	}, "", nil)
}

// handleVersion отдаёт версию сервиса, переданную в конструктор роутера.
func (r *Router) handleVersion(w http.ResponseWriter, req *http.Request) {
	JSONResponse(w, http.StatusOK, map[string]string{
		"version": r.version,
	}, "", nil)
}

// handleNotFound отвечает 404 для неизвестных путей.
func (r *Router) handleNotFound(w http.ResponseWriter, req *http.Request) {
	JSONResponse(w, http.StatusNotFound, nil, "not found", nil)
}

// ServeMux возвращает внутренний мультиплексор, чтобы передать его
// в http.Server в качестве обработчика.
func (r *Router) ServeMux() *http.ServeMux {
	return r.mux
}

// requireMethod — middleware, разрешающее только указанные HTTP-методы.
// Для остальных методов возвращается 405 Method Not Allowed; список
// разрешённых методов отдаётся в поле meta — так клиентам-разработчикам
// проще понять, что они сделали не так.
func requireMethod(allowed ...string) func(http.Handler) http.Handler {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, m := range allowed {
		allowedSet[m] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := allowedSet[r.Method]; !ok {
				JSONResponse(w, http.StatusMethodNotAllowed, nil, "method not allowed", map[string]any{
					"allowed_methods": allowed,
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
