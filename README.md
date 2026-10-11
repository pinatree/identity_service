# Identity Service

HTTP-сервис аутентификации на Go: регистрация и вход по логину/паролю
с выдачей bearer-токенов и защищёнными эндпоинтами.

Авторизация построена на парах токенов (access + refresh), выпускаемых
эндпоинтом `POST /api/login` и передаваемых заголовком
`Authorization: Bearer <token>`. В памяти хранятся только хеши токенов сессии.

## Возможности

- **Регистрация** — `POST /api/registration` создаёт пользователя; пароль хранится
  только как **argon2id-хеш** с отдельной солью (внутренний пакет `password`);
- **Вход в систему** — `POST /api/login` проверяет логин/пароль и выдаёт пару
  токенов (access + refresh); в памяти хранятся только хеши токенов сессии;
- **Защищённые эндпоинты** — `/api/logout`, `/api/pass_reset`
  требуют действующий bearer-токен и возвращают `401 Unauthorized` без него;
- **Соединение с БД при старте** — приложение подключается к PostgreSQL (строка `db_connection` / `DB_CONNECTION`) и не стартует, если БД недоступна; данные репозитория по-прежнему in-memory;
- **Настраиваемое время жизни сессии** — поле `token_ttl` (секунды), по умолчанию **300** (5 минут);
- **Конфигурация без файла** — работают значения по умолчанию; поверх них применяются
  переменные окружения `PORT`, `NAME`, `VERSION`, `TOKEN_TTL`, `DB_CONNECTION`;
- **Единый JSON-формат ответов** — `{ "data", "error", "meta" }`;
- **Корректные HTTP-коды** — `404` для неизвестных путей, `405` для неподдерживаемых методов;
- **Graceful-shutdown** — сервер отвечает на SIGINT/SIGTERM и завершает активные запросы;
- **Тесты** — модульные (config, password, repo, httpapi) и HTTP-интеграционные (httptest).

## Структура проекта

```
cmd/server/main.go            — точка входа: конфиг, зависимости, HTTP-сервер, shutdown
internal/config/config.go     — загрузка и валидация конфигурации (+ config_test.go)
internal/config/version.go    — версия сборки
internal/db/entities.go       — сущности БД: User и Session (+ entities_test.go)
internal/db/postgres.go       — подключение к PostgreSQL: пул соединений, ping при старте
internal/repo/user.go         — репозиторий пользователей, мокап данных (+ user_test.go)
internal/password/hash.go     — argon2id-хеширование паролей, PHC-формат (+ hash_test.go)
internal/httpapi/router.go    — маршрутизация и middleware (+ router_test.go)
internal/httpapi/handlers.go  — обработчики и JSON-обёртка ответов
internal/httpapi/registration.go — регистрация пользователей (POST /api/registration)
internal/httpapi/login.go      — вход по логину и паролю (POST /api/login)
internal/httpapi/auth.go      — middleware авторизации (Bearer-токены)
```

## Быстрый старт

```bash
make dev        # разработка с hot reload (файл ./cmd/server/main.go)
make build      # production-сборка → бинарник ./identity-service
make test       # модульные и HTTP-тесты (go test -race ./internal/...)
make run        # запуск собранного бинарника
```

Файл конфигурации **не обязателен**: без `config.json` сервис стартует
на порту `8080` со значениями по умолчанию.

## Проверка работы

```bash
# Проверка живости
curl http://localhost:8080/health

# Регистрация
curl -X POST http://localhost:8080/api/registration \
  -d '{"login":"alice","password":"secret123"}'

# Вход — пара токенов (access + refresh)
TOKEN=$(curl -s -X POST http://localhost:8080/api/login \
  -d '{"login":"alice","password":"secret123"}' | jq -r .data.access)

# Выход (защищённый)
curl -X POST http://localhost:8080/api/logout \
  -H "Authorization: Bearer $TOKEN"
```

## Документация

- [API](docs/api.md) — эндпоинты, форматы ответов, примеры curl;
- [Конфигурация](docs/config.md) — файл `config.json`, переменные окружения, приоритеты;
- [Развёртывание](docs/deploy.md) — Makefile, Docker, systemd, рекомендации.