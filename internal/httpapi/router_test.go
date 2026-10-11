// Файл содержит интеграционные тесты HTTP-слоя.
//
// Роутер, middleware авторизации и обработчики проверяются через httptest
// (запросы выполняются в памяти процесса), поэтому запускать настоящий
// сервер для тестов не требуется.
package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinatree/identity-service/internal/repo"
)

// newTestRouter собирает роутер с минимальными зависимостями.
// TTL хранилища задаём нулём, чтобы использовался DefaultTTL (5 минут);
// срок жизни сессий при входе — фиксированные 5 минут.
func newTestRouter() *Router {
	return NewRouter(
		"test-version",
		"test-service",
		repo.NewUserRepository(),
		5*time.Minute,
	)
}

// decodeResponse разбирает JSON-ответ и заодно валидирует его формат.
func decodeResponse(t *testing.T, rec *httptest.ResponseRecorder) Response {
	t.Helper()

	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ не является валидным JSON: %v; тело: %s", err, rec.Body.String())
	}
	return resp
}

// counterValue извлекает числовое значение счётчика из поля data.
// JSON-числа декодируются во float64, поэтому требуется преобразование.
func counterValue(t *testing.T, resp Response) int {
	t.Helper()

	f, ok := resp.Data.(float64)
	if !ok {
		t.Fatalf("ожидалось число в поле data, получено: %#v", resp.Data)
	}
	return int(f)
}

// doRequest выполняет HTTP-запрос к роутеру и возвращает записанный ответ.
// Параметр bearer задаёт значение заголовка Authorization (если не пустой).
func doRequest(r *Router, method, path, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	rec := httptest.NewRecorder()
	r.ServeMux().ServeHTTP(rec, req)
	return rec
}

// TestHealth проверяет публичный эндпоинт /health.
func TestHealth(t *testing.T) {
	r := newTestRouter()
	rec := doRequest(r, http.MethodGet, "/health", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получено %d", rec.Code)
	}
	if resp := decodeResponse(t, rec); resp.Error != "" {
		t.Errorf("ошибки быть не должно, получено: %q", resp.Error)
	}
}

// TestVersion проверяет, что /version возвращает версию, переданную в роутер.
func TestVersion(t *testing.T) {
	r := newTestRouter()
	rec := doRequest(r, http.MethodGet, "/version", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получено %d", rec.Code)
	}
	resp := decodeResponse(t, rec)
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data должна быть объектом, получено: %#v", resp.Data)
	}
	if data["version"] != "test-version" {
		t.Errorf("version: ожидалось test-version, получено %v", data["version"])
	}
}

// TestGenerateToken и тесты счётчика удалены вместе с эндпоинтами
// /api/token и /counter: токены выпускаются только через /api/login.

// TestUnknownPathReturns404 проверяет, что несуществующий путь возвращает 404,
// а не «молчаливый» 200 (такое поведение маскирует опечатки в URL).
func TestUnknownPathReturns404(t *testing.T) {
	r := newTestRouter()
	rec := doRequest(r, http.MethodGet, "/definitely-not-a-route", "")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("ожидался 404, получено %d", rec.Code)
	}
}

// TestMethodNotAllowed проверяет, что неподдерживаемый HTTP-метод
// отклоняется с 405 Method Not Allowed.
func TestMethodNotAllowed(t *testing.T) {
	r := newTestRouter()
	rec := doRequest(r, http.MethodDelete, "/health", "")

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("ожидался 405, получено %d", rec.Code)
	}
}

// postRegistration выполняет POST /api/registration с переданным JSON-телом
// и возвращает записанный ответ.
func postRegistration(r *Router, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/registration", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeMux().ServeHTTP(rec, req)
	return rec
}

// TestRegistrationSuccess проверяет «счастливый путь»: валидные логин и пароль
// создают пользователя, ответ — 201 Created, без хеша пароля в ответе.
func TestRegistrationSuccess(t *testing.T) {
	r := newTestRouter()
	rec := postRegistration(r, `{"login":"newuser","password":"secret123"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("ожидался 201, получено %d", rec.Code)
	}
	resp := decodeResponse(t, rec)
	if resp.Error != "" {
		t.Fatalf("ошибки быть не должно, получено: %q", resp.Error)
	}

	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data должна быть объектом, получено: %#v", resp.Data)
	}
	if data["login"] != "newuser" {
		t.Errorf("login: ожидался newuser, получено %v", data["login"])
	}
	if _, ok := data["password_hash"]; ok {
		t.Error("в ответе не должен присутствовать password_hash")
	}

}

// TestRegistrationInvalidInput проверяет отбраковку некорректных данных:
// короткий/слишком длинный логин, короткий пароль и невалидный JSON
// возвращают 400.
func TestRegistrationInvalidInput(t *testing.T) {
	r := newTestRouter()

	cases := []string{
		`{"login":"ab","password":"secret123"}`,                    // логин короче 3
		`{"login":"123456789012345678901","password":"secret123"}`, // логин длиннее 20
		`{"login":"  ","password":"secret123"}`,                    // логин из пробелов
		`{"login":"newuser","password":"1234"}`,                    // пароль короче 5
		`not-json`,                                                 // невалидный JSON
	}
	for _, body := range cases {
		rec := postRegistration(r, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("тело %q: ожидался 400, получено %d", body, rec.Code)
		}
		if resp := decodeResponse(t, rec); resp.Error == "" {
			t.Errorf("тело %q: ожидалось описание ошибки, получена пустая строка", body)
		}
	}
}

// TestRegistrationDuplicateLogin проверяет, что повторная регистрация с тем же
// логином возвращает 409 Conflict с понятным сообщением.
func TestRegistrationDuplicateLogin(t *testing.T) {
	r := newTestRouter()

	first := postRegistration(r, `{"login":"dupuser","password":"secret123"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("первый запрос: ожидался 201, получено %d", first.Code)
	}

	second := postRegistration(r, `{"login":"dupuser","password":"other456"}`)
	if second.Code != http.StatusConflict {
		t.Fatalf("повторная регистрация: ожидался 409, получено %d", second.Code)
	}
	resp := decodeResponse(t, second)
	if resp.Error != "Логин уже существует" {
		t.Errorf("ошибка: ожидалось «Логин уже существует», получено %q", resp.Error)
	}
}

// TestRegistrationRequiresPost проверяет, что GET /api/registration
// отклоняется кодом 405 Method Not Allowed.
func TestRegistrationRequiresPost(t *testing.T) {
	r := newTestRouter()

	rec := doRequest(r, http.MethodGet, "/api/registration", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("ожидался 405, получено %d", rec.Code)
	}
}

// postLogin выполняет POST /api/login с переданным JSON-телом
// и возвращает записанный ответ.
func postLogin(r *Router, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeMux().ServeHTTP(rec, req)
	return rec
}

// registerUser регистрирует пользователя и проверяет успешность запроса.
// Возвращается роутер (данные общие для регистрации и входа).
func registerUser(t *testing.T, r *Router, login, password string) {
	t.Helper()

	body := `{"login":"` + login + `","password":"` + password + `"}`
	rec := postRegistration(r, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("регистрация %q: ожидался 201, получено %d", login, rec.Code)
	}
}

// TestLoginSuccess проверяет «счастливый путь»: после регистрации вход
// с корректными логином и паролем возвращает 200 и пару токенов —
// access и refresh, они непустые и не совпадают друг с другом.
func TestLoginSuccess(t *testing.T) {
	r := newTestRouter()
	registerUser(t, r, "loginuser", "secret123")

	rec := postLogin(r, `{"login":"loginuser","password":"secret123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получено %d", rec.Code)
	}
	resp := decodeResponse(t, rec)
	if resp.Error != "" {
		t.Fatalf("ошибки быть не должно, получено: %q", resp.Error)
	}

	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data должна быть объектом, получено: %#v", resp.Data)
	}

	access, _ := data["access_token"].(string)
	refresh, _ := data["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("ожидались непустые токены, получено: %#v", data)
	}
	if access == refresh {
		t.Error("access и refresh токены не должны совпадать")
	}
	if data["token_type"] != "bearer" {
		t.Errorf("token_type: ожидался bearer, получено %v", data["token_type"])
	}
	if expires, _ := data["expires_at"].(string); expires == "" {
		t.Error("expires_at не должен быть пустым")
	}
}

// TestLoginWrongPassword проверяет, что неверный пароль отклоняется 401
// даже для существующего пользователя.
func TestLoginWrongPassword(t *testing.T) {
	r := newTestRouter()
	registerUser(t, r, "wrongpw", "secret123")

	rec := postLogin(r, `{"login":"wrongpw","password":"wrong-password"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получено %d", rec.Code)
	}
	if resp := decodeResponse(t, rec); resp.Error == "" {
		t.Error("ожидалось описание ошибки, получена пустая строка")
	}
}

// TestLoginUnknownUser проверяет, что неизвестный логин отклоняется 401.
func TestLoginUnknownUser(t *testing.T) {
	r := newTestRouter()

	rec := postLogin(r, `{"login":"no-such-user","password":"secret123"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получено %d", rec.Code)
	}
}

// TestLoginInvalidInput проверяет отбраковку некорректных данных:
// невалидный JSON и пустые логин/пароль возвращают 400.
func TestLoginInvalidInput(t *testing.T) {
	r := newTestRouter()

	cases := []string{
		`not-json`,
		`{"login":"","password":"secret123"}`, // пустой логин
		`{"login":"alice","password":""}`,     // пустой пароль
	}
	for _, body := range cases {
		rec := postLogin(r, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("тело %q: ожидался 400, получено %d", body, rec.Code)
		}
		if resp := decodeResponse(t, rec); resp.Error == "" {
			t.Errorf("тело %q: ожидалось описание ошибки, получена пустая строка", body)
		}
	}
}

// TestLoginRequiresPost проверяет, что GET /api/login отклоняется кодом 405.
func TestLoginRequiresPost(t *testing.T) {
	r := newTestRouter()

	rec := doRequest(r, http.MethodGet, "/api/login", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("ожидался 405, получено %d", rec.Code)
	}
}

// loginAccessToken логинится и возвращает access-токен из ответа.
// Хелпер для тестов смены пароля: access-токен идёт в заголовок
// Authorization как bearer-токен.
func loginAccessToken(t *testing.T, r *Router, login, password string) string {
	t.Helper()

	rec := postLogin(r, `{"login":"`+login+`","password":"`+password+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("логин %q: ожидался 200, получено %d", login, rec.Code)
	}
	data, ok := decodeResponse(t, rec).Data.(map[string]any)
	if !ok {
		t.Fatalf("data должна быть объектом, получено: %#v", decodeResponse(t, rec).Data)
	}
	access, _ := data["access_token"].(string)
	if access == "" {
		t.Fatalf("не удалось получить access_token: %#v", data)
	}
	return access
}

// postPassReset выполняет POST /api/pass_reset с переданным bearer-токеном
// и JSON-телом и возвращает записанный ответ.
func postPassReset(r *Router, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/pass_reset", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	r.ServeMux().ServeHTTP(rec, req)
	return rec
}

// TestPassResetSuccess проверяет «счастливый путь»: после логина смена
// пароля по сессии проходит успешно; далее вход возможен только с новым
// паролем, а со старым — отклоняется 401.
func TestPassResetSuccess(t *testing.T) {
	r := newTestRouter()
	registerUser(t, r, "resetuser", "old-secret")

	access := loginAccessToken(t, r, "resetuser", "old-secret")

	// Смена пароля: старый пароль в теле, владелец — по сессии из заголовка.
	rec := postPassReset(r, access, `{"old_password":"old-secret","new_password":"new-secret"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("смена пароля: ожидался 200, получено %d (тело: %s)", rec.Code, rec.Body.String())
	}
	resp := decodeResponse(t, rec)
	if resp.Error != "" {
		t.Fatalf("ошибки быть не должно, получено: %q", resp.Error)
	}

	// Вход с новым паролем — успешен.
	if rec := postLogin(r, `{"login":"resetuser","password":"new-secret"}`); rec.Code != http.StatusOK {
		t.Errorf("вход с новым паролем: ожидался 200, получено %d", rec.Code)
	}
	// Вход со старым паролем — 401.
	if rec := postLogin(r, `{"login":"resetuser","password":"old-secret"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("вход со старым паролем: ожидался 401, получено %d", rec.Code)
	}
}

// TestPassResetRequiresAuth проверяет, что без токена и с несуществующим
// токеном запрос отклоняется 401: сессия не найдена.
func TestPassResetRequiresAuth(t *testing.T) {
	r := newTestRouter()

	body := `{"old_password":"whatever","new_password":"new-secret"}`
	if rec := postPassReset(r, "", body); rec.Code != http.StatusUnauthorized {
		t.Errorf("без токена: ожидался 401, получено %d", rec.Code)
	}
	if rec := postPassReset(r, "bogus-token", body); rec.Code != http.StatusUnauthorized {
		t.Errorf("с несуществующим токеном: ожидался 401, получено %d", rec.Code)
	}
}

// TestPassResetWrongOldPassword проверяет, что неверный старый пароль
// отклоняется 401 даже при валидной сессии.
func TestPassResetWrongOldPassword(t *testing.T) {
	r := newTestRouter()
	registerUser(t, r, "resetwrong", "old-secret")

	access := loginAccessToken(t, r, "resetwrong", "old-secret")

	rec := postPassReset(r, access, `{"old_password":"wrong-old","new_password":"new-secret"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получено %d (тело: %s)", rec.Code, rec.Body.String())
	}
}

// TestPassResetInvalidInput проверяет отбраковку некорректных данных:
// невалидный JSON, пустые пароли и слишком короткий новый пароль
// возвращают 400.
func TestPassResetInvalidInput(t *testing.T) {
	r := newTestRouter()
	registerUser(t, r, "resetinv", "old-secret")

	access := loginAccessToken(t, r, "resetinv", "old-secret")

	cases := []string{
		`not-json`,
		`{"old_password":"","new_password":"new-secret"}`,    // пустой старый
		`{"old_password":"old-secret","new_password":""}`,    // пустой новый
		`{"old_password":"old-secret","new_password":"123"}`, // новый короче 5
	}
	for _, body := range cases {
		rec := postPassReset(r, access, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("тело %q: ожидался 400, получено %d", body, rec.Code)
		}
	}
}

// TestPassResetRequiresPost проверяет, что GET /api/pass_reset
// отклоняется кодом 405 Method Not Allowed.
func TestPassResetRequiresPost(t *testing.T) {
	r := newTestRouter()

	rec := doRequest(r, http.MethodGet, "/api/pass_reset", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("ожидался 405, получено %d", rec.Code)
	}
}

// --- Logout ---

// postLogout выполняет POST /api/logout с переданным bearer-токеном
// и возвращает записанный ответ.
func postLogout(r *Router, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	r.ServeMux().ServeHTTP(rec, req)
	return rec
}

// TestLogoutSuccess проверяет «счастливый путь»: после логина
// logout возвращает 200 и отзывает сессию.
func TestLogoutSuccess(t *testing.T) {
	r := newTestRouter()
	registerUser(t, r, "logoutuser", "secret123")

	access := loginAccessToken(t, r, "logoutuser", "secret123")

	rec := postLogout(r, access)
	if rec.Code != http.StatusOK {
		t.Fatalf("ожидался 200, получено %d (тело: %s)", rec.Code, rec.Body.String())
	}
	resp := decodeResponse(t, rec)
	if resp.Error != "" {
		t.Errorf("ошибки быть не должно, получено: %q", resp.Error)
	}
	if resp.Meta == nil || resp.Meta["session_id"] == "" {
		t.Errorf("ожидался session_id в meta, получено: %#v", resp.Meta)
	}
}

// TestLogoutWithoutToken проверяет, что POST /api/logout без заголовка
// Authorization возвращает 401.
func TestLogoutWithoutToken(t *testing.T) {
	r := newTestRouter()

	rec := postLogout(r, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получено %d", rec.Code)
	}
}

// TestLogoutBogusToken проверяет, что POST /api/logout с несуществующим
// токеном возвращает 401: middleware RequireSessionAuth отклоняет запросы
// с недействительными токенами до вызова обработчика.
func TestLogoutBogusToken(t *testing.T) {
	r := newTestRouter()

	rec := postLogout(r, "bogus-token-that-does-not-exist")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получено %d (тело: %s)", rec.Code, rec.Body.String())
	}
}

// TestLogoutIdempotent проверяет, что повторный logout с тем же токеном
// также возвращает 200 и флаг already_logged_out.
func TestLogoutIdempotent(t *testing.T) {
	r := newTestRouter()
	registerUser(t, r, "idemuser", "secret123")

	access := loginAccessToken(t, r, "idemuser", "secret123")

	// Первый logout — успешный.
	rec1 := postLogout(r, access)
	if rec1.Code != http.StatusOK {
		t.Fatalf("первый logout: ожидался 200, получено %d", rec1.Code)
	}

	// Второй logout с тем же токеном — идемпотентно 200 + already_logged_out.
	rec2 := postLogout(r, access)
	if rec2.Code != http.StatusOK {
		t.Fatalf("второй logout: ожидался 200, получено %d", rec2.Code)
	}
	resp2 := decodeResponse(t, rec2)
	already, ok := resp2.Meta["already_logged_out"]
	if !ok || already != true {
		t.Errorf("второй logout: ожидался флаг already_logged_out=true, получено: %#v", resp2.Meta)
	}
}

// TestLogoutInvalidatesSession проверяет, что после logout сессия
// становится недействительной: запрос /api/pass_reset с тем же
// токеном отклоняется 401.
func TestLogoutInvalidatesSession(t *testing.T) {
	r := newTestRouter()
	registerUser(t, r, "logoutinv", "secret123")

	access := loginAccessToken(t, r, "logoutinv", "secret123")

	// Logout — отзываем сессию.
	recLogout := postLogout(r, access)
	if recLogout.Code != http.StatusOK {
		t.Fatalf("logout: ожидался 200, получено %d", recLogout.Code)
	}

	// Попытка смены пароля с тем же токеном — должна быть 401.
	recReset := postPassReset(r, access, `{"old_password":"secret123","new_password":"new-secret"}`)
	if recReset.Code != http.StatusUnauthorized {
		t.Fatalf("pass_reset после logout: ожидался 401, получено %d (тело: %s)", recReset.Code, recReset.Body.String())
	}
}

// TestLogoutRequiresPost проверяет, что GET /api/logout
// отклоняется кодом 405 Method Not Allowed.
func TestLogoutRequiresPost(t *testing.T) {
	r := newTestRouter()

	rec := doRequest(r, http.MethodGet, "/api/logout", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("ожидался 405, получено %d", rec.Code)
	}
}
