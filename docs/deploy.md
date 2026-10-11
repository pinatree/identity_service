# Развёртывание Identity Service

Краткое руководство: локальная разработка, production-сборка, запуск через
systemd и Docker, диагностика.

## Сборка и запуск

| Команда      | Что делает                                                              |
|--------------|-------------------------------------------------------------------------|
| `make dev`   | Разработка с hot reload (требуется утилита `http-server`)               |
| `make build` | Сборка production-бинарника `./identity-service`                          |
| `make test`  | Модульные и HTTP-тесты (`go test -race ./internal/...`)                  |
| `make run`   | Запуск собранного бинарника                                              |
| `make clean` | Удаление артефактов сборки                                              |

Прямая компиляция и запуск:

```bash
go build -o identity-service ./cmd/server/main.go
./identity-service
```

Файл `config.json` не обязателен: сервис стартует со значениями по умолчанию
(порт **8080**). Подробнее — [docs/config.md](./config.md).

## Проверка после запуска

```bash
curl http://localhost:8080/health    # {"data":{"status":"healthy",...}}
curl -X POST http://localhost:8080/api/token  # выпуск токена
```

## Остановка

Сервис корректно завершается по **SIGINT** (Ctrl+C) и **SIGTERM** (systemd,
Kubernetes, `kill`): завершаются активные запросы и закрываются соединения.
Для принудительной остановки остаётся `kill -9`.

## Продакшен: три варианта

### Вариант 1: бинарник на сервере

```bash
make build
scp identity-service user@server:/opt/identity-service/
ssh user@server 'chmod +x /opt/identity-service/identity-service'
cd /opt/identity-service && ./identity-service
```

### Вариант 2: systemd

```bash
cat > /etc/systemd/system/identity-service.service <<'EOF'
[Unit]
Description=Identity Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/identity-service
ExecStart=/opt/identity-service/identity-service
Restart=on-failure
RestartSec=5
# Конфигурация через переменные окружения (приоритет выше config.json)
Environment=PORT=8080
Environment=NAME=identity-service
Environment=VERSION=1.0.0
Environment=TOKEN_TTL=300

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now identity-service
systemctl status identity-service
```

### Вариант 3: Docker

`Dockerfile` уже в репозитории (многоступенчатая сборка):

```bash
docker build -t identity-service .
docker run -d --name identity-service -p 8080:8080 identity-service
```

Конфигурация переопределяется без пересборки образа:

```bash
docker run -d --name identity-service -p 3000:8080 \
  -e PORT=3000 -e TOKEN_TTL=60 identity-service
```

Для healthcheck можно использовать эндпоинт `GET /health`.

## Рекомендации для продакшена

- Запускайте сервис под отдельным пользователем (`www-data`), не от root;
- Храните `config.json` рядом с бинарником либо задавайте параметры окружением;
- Установите `TOKEN_TTL` разумным: короткий TTL снижает риск перехвата токена;
- Токены живут в памяти процесса — **рестарт инвалидирует все токены**.
  Если это неприемлемо, нужен внешний источник (см. `internal/token`);
- Проксируйте через Nginx/обратный прокси при необходимости terminate TLS.

## Диагностика

| Симптом                                      | Что проверить                                  |
|----------------------------------------------|------------------------------------------------|
| Сервис не стартует (порт занят)               | `netstat -tlnp \| grep 8080`, лог процесса     |
| Ошибка чтения/парсинга конфигурации          | Валидность JSON: `jq . config.json`            |
| `401` на `/counter`                          | Ошибка в заголовке `Authorization: Bearer ...` |

Логи запуска — в stdout; при запуске через systemd — `journalctl -u identity-service`.
