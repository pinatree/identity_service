package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/pinatree/identity-service/internal/repo"
)

// Response — единая JSON-обёртка для всех ответов API.
// Клиенты могут рассчитывать на стабильную структуру: что бы ни произошло,
// в ответе будет либо data, либо error (или оба, когда частично успешно).
type Response struct {
	// Data — полезная нагрузка: строка (токен), число (счётчик) или объект.
	// благодаря omitempty пустое поле не попадает в JSON.
	Data any `json:"data,omitempty"`

	// Error — описание ошибки. Пустая строка при успешном запросе;
	// omitempty убирает её из ответа.
	Error string `json:"error,omitempty"`

	// Meta — дополнительные служебные поля (type, ttl, action и т.п.).
	Meta map[string]any `json:"meta,omitempty"`
}

// JSONResponse записывает ответ в формате JSON: выставляет заголовки,
// HTTP-статус и сериализует структуру Response.
//
// Параметры:
//   - status — HTTP-код ответа;
//   - data — полезная нагрузка (может быть nil);
//   - err — текст ошибки (пустая строка означает успех);
//   - meta — дополнительные поля.
//
// Пример успешного ответа: {"data":0,"meta":{"action":"get"}}
//
// Ошибка кодирования намеренно игнорируется: к этому моменту заголовки уже
// отправлены в ответ, и перезаписать статус невозможно. Это стандартная
// практика для небольших сервисов.
func JSONResponse(w http.ResponseWriter, status int, data any, err string, meta map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := Response{
		Data:  data,
		Error: err,
		Meta:  meta,
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// UserHandler — обработчики, связанные с пользователями.
type UserHandler struct {
	// users — репозиторий пользователей (сейчас — мокап в памяти).
	users repo.UserRepository

	// sessionTTL — срок жизни сессии и выдаваемых при входе токенов.
	// Значение берётся из конфигурации (token_ttl).
	sessionTTL time.Duration
}

// NewUserHandler создаёт обработчик пользователей на основе репозитория.
// sessionTTL — срок действия сессии, создаваемой при входе в систему.
func NewUserHandler(users repo.UserRepository, sessionTTL time.Duration) *UserHandler {
	return &UserHandler{users: users, sessionTTL: sessionTTL}
}

// userListItem — «безопасная» проекция пользователя для списка.
// Поле PasswordHash намеренно не включается: хеш пароля не должен
// покидать слой хранения даже в ответах админ-эндпоинта.
type userListItem struct {
	ID        int64     `json:"id"`
	Login     string    `json:"login"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
