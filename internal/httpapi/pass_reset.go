package httpapi

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/pinatree/identity-service/internal/password"
)

// PassResetRequest — тело запроса POST /api/pass_reset.
//
// Пароли в открытом виде существуют только в момент запроса и нигде
// не сохраняются: в хранилище попадает только argon2id-хеш нового пароля
// (так же, как при регистрации и входе).
type PassResetRequest struct {
	// OldPassword — текущий (действующий) пароль пользователя.
	// Нужен для подтверждения, что пароль меняет владелец учётной записи.
	OldPassword string `json:"old_password"`

	// NewPassword — новый пароль (не менее minPasswordLen символов).
	NewPassword string `json:"new_password"`
}

// PassResetSuccess — результат успешной смены пароля. Возвращается в поле
// data ответа; сам пароль (любой из двух) в ответе никогда не появляется.
type PassResetSuccess struct {
	// Login — логин пользователя, сменившего пароль.
	Login string `json:"login"`
}

// PassResetUser обрабатывает POST /api/pass_reset — смену пароля.
//
// Пользователь идентифицируется по сессии: bearer-токен из заголовка
// Authorization хешируется (SHA-256) и ищется в общем потокобезопасном
// массиве сессий (см. repo.UserRepository.GetUserBySessionTokenHash).
// Меняется пароль ТОЛЬКО владельца найденной сессии — чужие учётные записи
// этот эндпоинт не затрагивает.
//
// Последовательность шагов:
//  1. Разобрать тело запроса (старый и новый пароль);
//  2. Извлечь bearer-токен из заголовка Authorization;
//  3. Найти пользователя по хешу токена среди активных сессий;
//  4. Проверить старый пароль против сохранённого argon2id-хеша;
//  5. Проверить новый пароль (минимальная длина, как при регистрации);
//  6. Хешировать новый пароль и обновить его в хранилище.
//
// Ответы:
//   - 200 OK — пароль сменён;
//   - 400 Bad Request — невалидный JSON, пустые поля или короткий новый пароль;
//   - 401 Unauthorized — отсутствует/недействителен bearer-токен, сессия
//     не найдена либо старый пароль неверен.
//
// Сессии после смены пароля НЕ затрагиваются: пользователь продолжает
// работать со своими текущими токенами.
//
// ВАЖНО (на будущее): возможно, нужно будет предусмотреть в конфигурации,
// дропать ли при смене пароля ВСЕ сессии пользователя, только ДРУГИЕ
// сессии, или НЕ ТРОГАТЬ их вовсе. Сейчас мы их не трогаем.
func (h *UserHandler) PassResetUser(w http.ResponseWriter, r *http.Request) {
	var req PassResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[pass_reset] ошибка разбора тела запроса: %v", err)
		JSONResponse(w, http.StatusBadRequest, nil, "Некорректный JSON-запрос", nil)
		return
	}

	// Пустые поля — бессмысленный запрос: проверять и менять нечего.
	if req.OldPassword == "" || req.NewPassword == "" {
		log.Printf("[pass_reset] пустые пароли: old_len=%d, new_len=%d", len(req.OldPassword), len(req.NewPassword))
		JSONResponse(w, http.StatusBadRequest, nil, "Старый и новый пароль обязательны", nil)
		return
	}

	// Идентифицируем пользователя по сессии: хешируем bearer-токен и ищем
	// его среди активных сессий в общем потокобезопасном массиве. В хранилище
	// лежат только хеши токенов, поэтому искать надо именно по хешу.
	// Token гарантированно присутствует — проверку выполняет middleware RequireSessionAuth.
	tk := bearerToken(r)

	user, err := h.users.GetUserBySessionTokenHash(hashToken(tk))
	if err != nil {
		log.Printf("[pass_reset] сессия по токену не найдена: %v", err)
		JSONResponse(w, http.StatusUnauthorized, nil, "unauthorized: session not found or expired", nil)
		return
	}
	log.Printf("[pass_reset] пользователь %q (id=%d) идентифицирован по сессии", user.Login, user.ID)

	// Проверяем старый пароль. Ошибка разбора хеша (например, у мок-данных
	// репозитория лежит не-PHC-строка) трактуется как неверный старый пароль,
	// а не как сбой сервера — так же, как при входе в систему.
	ok, err := password.Verify(req.OldPassword, user.PasswordHash)
	if err != nil || !ok {
		log.Printf("[pass_reset] неверный старый пароль для %q (ok=%v, err=%v)", user.Login, ok, err)
		JSONResponse(w, http.StatusUnauthorized, nil, "Неверный старый пароль", nil)
		return
	}
	log.Printf("[pass_reset] старый пароль для %q подтверждён", user.Login)

	// Новый пароль должен проходить те же проверки, что и при регистрации.
	if !validPassword(req.NewPassword) {
		log.Printf("[pass_reset] новый пароль не соответствует формату (рун: %d)", len(req.NewPassword))
		JSONResponse(w, http.StatusBadRequest, nil, "Новый пароль не соответствует формату", nil)
		return
	}

	// Хешируем новый пароль: свежая случайная соль + argon2id.
	salt, err := password.GenerateSalt()
	if err != nil {
		log.Printf("[pass_reset] не удалось получить соль: %v", err)
		JSONResponse(w, http.StatusInternalServerError, nil, "Не удалось подготовить данные для смены пароля", nil)
		return
	}
	newHash, err := password.CreateHash(req.NewPassword, salt)
	if err != nil {
		log.Printf("[pass_reset] не удалось создать хеш: %v", err)
		JSONResponse(w, http.StatusInternalServerError, nil, "Не удалось подготовить данные для смены пароля", nil)
		return
	}

	// Обновляем пароль именно владельца сессии (user.ID): метод репозитория
	// UpdatePassword меняет только запись с этим идентификатором.
	if err := h.users.UpdatePassword(user.ID, newHash); err != nil {
		log.Printf("[pass_reset] не удалось обновить пароль для %q: %v", user.Login, err)
		JSONResponse(w, http.StatusInternalServerError, nil, "Не удалось сменить пароль", nil)
		return
	}

	// Политика сессий при смене пароля: сейчас существующие сессии мы НЕ
	// трогаем — пользователь продолжает работать со своими токенами.
	// Возможно, в будущем потребуется предусмотреть в конфигурации, дропать
	// ли ВСЕ сессии, только ДРУГИЕ сессии, или не трогать их вовсе.
	log.Printf("[pass_reset] пароль для %q успешно сменён (сессии не тронуты)", user.Login)

	JSONResponse(w, http.StatusOK, PassResetSuccess{Login: user.Login}, "", map[string]any{
		"password_changed": true,
	})
}
