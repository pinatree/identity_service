package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/pinatree/identity-service/internal/password"
	"github.com/pinatree/identity-service/internal/repo"
)

// RegistrationRequest — тело запроса POST /api/registration.
type RegistrationRequest struct {
	// Login — будущий логин пользователя (3–20 символов).
	Login string `json:"login"`

	// Password — пароль пользователя (не менее 5 символов).
	Password string `json:"password"`
}

// Границы допустимой длины логина и минимальной длины пароля.
const (
	minLoginLen    = 3
	maxLoginLen    = 20
	minPasswordLen = 5
)

// RegisterUser обрабатывает POST /api/registration — создаёт нового
// пользователя и сохраняет argon2id-хеш его пароля.
//
// Ответы:
//   - 201 Created — пользователь создан, в data — его «безопасная» проекция
//     (без хеша пароля);
//   - 400 Bad Request — невалидный JSON либо логин/пароль не проходят проверку;
//   - 409 Conflict — логин уже занят;
//   - 500 Internal Server Error — ошибка подготовки хеша или записи в БД
//     (детали пишутся в лог, клиенту не раскрываются).
func (h *UserHandler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("регистрация: некорректный JSON",
			"err", err,
			"remote_addr", r.RemoteAddr,
		)
		JSONResponse(w, http.StatusBadRequest, nil, "Некорректный JSON-запрос", nil)
		return
	}

	// Логин нормализуем: ведущие/замыкающие пробелы — почти всегда опечатка,
	// но создавать две записи "alice" и "alice " нельзя.
	req.Login = strings.TrimSpace(req.Login)
	if !validLogin(req.Login) || !validPassword(req.Password) {
		slog.Warn("регистрация: данные не прошли валидацию",
			"login", req.Login,
			"login_len", utf8.RuneCountInString(req.Login),
			"password_len", utf8.RuneCountInString(req.Password),
		)
		JSONResponse(w, http.StatusBadRequest, nil, "Данные для регистрации не соответствуют формату", nil)
		return
	}

	// Пароль в хранилище и в ответах никогда не появляется в открытом виде:
	// только PHC-строка с argon2id-хешем и отдельная случайная соль.
	salt, err := password.GenerateSalt()
	if err != nil {
		slog.Error("регистрация: не удалось сгенерировать соль",
			"err", err,
			"login", req.Login,
		)
		JSONResponse(w, http.StatusInternalServerError, nil, "Не удалось подготовить данные для регистрации", nil)
		return
	}

	hash, err := password.CreateHash(req.Password, salt)
	if err != nil {
		slog.Error("регистрация: не удалось создать хеш пароля",
			"err", err,
			"login", req.Login,
		)
		JSONResponse(w, http.StatusInternalServerError, nil, "Не удалось подготовить данные для регистрации", nil)
		return
	}

	// Отладочный вывод создаваемого пользователя (соль и хеш — только в debug).
	slog.Debug("регистрация пользователя",
		"login", req.Login,
		"salt", fmt.Sprintf("%x", salt),
		"hash", hash,
	)

	user, err := h.users.CreateUser(req.Login, hash)
	if errors.Is(err, repo.ErrLoginExists) {
		slog.Info("регистрация: логин уже занят",
			"login", req.Login,
		)
		JSONResponse(w, http.StatusConflict, nil, "Логин уже существует", nil)
		return
	}
	if err != nil {
		slog.Error("регистрация: не удалось создать пользователя",
			"err", err,
			"login", req.Login,
		)
		JSONResponse(w, http.StatusInternalServerError, nil, "Не удалось создать пользователя", nil)
		return
	}

	slog.Info("регистрация: пользователь создан",
		"user_id", user.ID,
		"login", user.Login,
	)

	JSONResponse(w, http.StatusCreated, userListItem{
		ID:        user.ID,
		Login:     user.Login,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, "", map[string]any{
		"registered": true,
	})
}

// validLogin проверяет длину логина: от minLoginLen до maxLoginLen символов.
// Подсчёт ведётся по рунам, а не по байтам: кириллица в логине допустима.
func validLogin(login string) bool {
	n := utf8.RuneCountInString(login)
	return n >= minLoginLen && n <= maxLoginLen
}

// validPassword проверяет минимальную длину пароля.
func validPassword(password string) bool {
	return utf8.RuneCountInString(password) >= minPasswordLen
}
