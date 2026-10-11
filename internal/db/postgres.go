package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	// Пустой импорт регистрирует драйвер PostgreSQL («postgres») из lib/pq.
	// Без него database/sql не сможет открыть соединение по строкам вида
	// postgres://user:password@host:port/dbname.
	_ "github.com/lib/pq"
)

// connTimeout — максимальное время на установку соединения и проверку
// доступности СУБД при старте сервиса (PingContext).
const connTimeout = 5 * time.Second

// Open инициализирует пул соединений к PostgreSQL и проверяет, что СУБД
// реально доступна (PingContext). Строка подключения dsn приходит из
// конфигурации (Config.DBConnection) в формате
// postgres://user:password@host:port/dbname?sslmode=disable.
//
// Возвращённый *sql.DB потокобезопасен и живёт всё время работы сервиса;
// вызывающий код обязан закрыть его через Close (например, при graceful-shutdown).
func Open(dsn string) (*sql.DB, error) {
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть соединение к БД: %w", err)
	}

	// Разумные параметры пула для HTTP-сервиса: ограничение на число
	// одновременных соединений и время жизни, чтобы не копить устаревшие.
	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(10)
	conn.SetConnMaxIdleTime(5 * time.Minute)
	conn.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), connTimeout)
	defer cancel()
	if err := conn.PingContext(ctx); err != nil {
		// Закрываем неудачный пул, чтобы не оставлять «висящие» соединения.
		_ = conn.Close()
		return nil, fmt.Errorf("БД PostgreSQL недоступна: %w", err)
	}

	return conn, nil
}
