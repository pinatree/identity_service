# ---- Этап 1: сборка ----
FROM golang:1.25-alpine AS build
WORKDIR /src

# Сначала только манифесты — чтобы слой с зависимостями кешировался
# и не пересобирался при каждом изменении кода.
COPY go.mod go.sum ./
RUN go mod download

# Теперь исходники.
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations

# Собираем оба бинарника: сервис и мигратор.
# CGO_ENABLED=0  — статический бинарник, работает на alpine/distroless/scratch.
# -trimpath      — убирает пути сборки из бинарника (воспроизводимость).
# -ldflags="-s -w" — без debug-инфы, бинарник на 20–30% меньше.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath -ldflags="-s -w" \
        -o /out/identity-service ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath -ldflags="-s -w" \
        -o /out/migrate ./cmd/migrate

# ---- Этап 2: запуск ----
FROM alpine:3.20

# ca-certificates — для HTTPS-запросов наружу.
# tzdata          — чтобы time.LoadLocation() знал зоны.
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 appuser

WORKDIR /app

# Бинарники.
COPY --from=build /out/identity-service /app/identity-service
COPY --from=build /out/migrate          /app/migrate

# Миграции — нужны бинарнику migrate (он читает file://migrations).
COPY --from=build /src/migrations       /app/migrations

# config.json НЕ копируем: конфиг задаётся через env или монтируется.
# Если у тебя в нём только дефолты без секретов — раскомментируй:
# COPY config.json /app/config.json

USER appuser

EXPOSE 8080

# По умолчанию запускаем сервис.
# Для миграций: docker run --rm identity-service /app/migrate up
ENTRYPOINT ["/app/identity-service"]