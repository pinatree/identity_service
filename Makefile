# Makefile для identity-service.
#
# Основные команды:
#   make dev   — разработка с hot reload (только для локальной разработки)
#   make build — сборка production-бинарника
#   make test  — запуск модульных тестов (с детектором гонок -race)
#   make run   — запуск скомпилированного бинарника
#   make clean — удаление артефактов сборки

.PHONY: dev build test run clean

# Разработка: hot reload при изменении ./cmd/server/main.go
dev:
	http-server -s /dev/shm/identity-service.sock -w ./cmd/server/main.go

# Production-сборка в бинарник identity-service
build:
	go build -o identity-service ./cmd/server/main.go

# Тесты всех внутренних пакетов. Флаг -race включает детектор гонок данных,
# что важно для проверки потокобезопасности счётчика и хранилища токенов.
test:
	go test -race ./internal/...

# Запуск собранного бинарника
run:
	./identity-service

# Очистка артефактов сборки
clean:
	rm -f identity-service
