// Package main — точка входа в сервис identity-service.
//
// Здесь происходит «склейка» всех слоёв приложения:
//  1. Загрузка конфигурации (internal/config);
//  2. Подключение к БД (internal/db) и создание репозитория пользователей;
//  3. Настройка HTTP-роутера (internal/httpapi);
//  4. Запуск HTTP-сервера с таймаутами и graceful-завершением.
//
// Файл намеренно тонкий: вся бизнес-логика живёт в пакетах internal,
// а main только связывает их между собой и управляет жизненным циклом.
package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pinatree/identity-service/internal/config"
	"github.com/pinatree/identity-service/internal/db"
	"github.com/pinatree/identity-service/internal/httpapi"
	"github.com/pinatree/identity-service/internal/logger"
	"github.com/pinatree/identity-service/internal/repo"
)

func main() {
	// --- 1. Конфигурация -------------------------------------------------
	// Отсутствие файла конфигурации не является ошибкой: сервис стартует
	// со значениями по умолчанию. log.Fatalf печатает сообщение и завершает
	// процесс с ненулевым кодом — этого достаточно для точки входа.
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Не удалось загрузить конфигурацию: %v", err)
	}

	// --- 2. Логирование ------------------------------------------------
	// Инициализируем slog в файл (если cfg.LogFile задан) или в stderr.
	// После Init все вызовы slog.Info / slog.Error / slog.Debug потокобезопасны.
	if err := logger.Init(cfg.LogFile); err != nil {
		log.Fatalf("Не удалось инициализировать логгер: %v", err)
	}

	slog.Info("запуск сервиса", "name", cfg.Name, "version", cfg.Version)

	// --- 3. Зависимости ---------------------------------------------------
	// Соединение к PostgreSQL инициализируется при открытии приложения:
	database, err := db.Open(cfg.DBConnection)
	if err != nil {
		slog.Error("не удалось подключиться к БД", "err", err)
		os.Exit(1)
	}
	slog.Info("соединение с БД установлено")

	// Миграции схемы БД выполняются отдельно — через бинарник cmd/migrate.
	// Перед первым запуском сервера выполните:
	//
	//	go run ./cmd/migrate up
	//

	// Продакшен-репозиторий: все операции через PostgreSQL.
	// Для тестов используется repo.NewUserRepository() — in-memory аналог.
	userRepo := repo.NewPostgresRepository(database)

	// --- 3. Роутер --------------------------------------------------------
	// Конструктор NewRouter сразу регистрирует все маршруты —
	// отдельный метод RegisterRoutes больше не нужен.
	router := httpapi.NewRouter(cfg.Version, cfg.Name, userRepo, time.Duration(cfg.TokenTTLSeconds)*time.Second)

	// --- 4. HTTP-сервер ---------------------------------------------------
	// Явно задаём таймауты, чтобы «медленный» клиент не мог надолго
	// удерживать соединение и исчерпать ресурсы сервера.
	// IdleTimeout закрывает простаивающие keep-alive соединения.
	addr := ":" + cfg.Port
	srv := &http.Server{
		Addr:              addr,
		Handler:           router.ServeMux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Запускаем сервер в отдельной горутине, чтобы основной поток мог
	// дождаться сигнала завершения и корректно остановить сервер.
	// Канал с буфером 1 гарантирует, что горутина не «зависнет» на отправке,
	// даже если никто не прочитает значение.
	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("HTTP-сервер слушает", "addr", addr)
		serverErrors <- srv.ListenAndServe()
	}()

	// --- 5. Graceful-завершение ------------------------------------------
	// Ждём сигнал SIGINT (Ctrl+C в терминале) или SIGTERM (остановка через
	// systemd, Kubernetes или kill). Это стандартный механизм graceful-shutdown.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		// Сервер завершился сам (например, порт уже занят) — фатальная ошибка.
		slog.Error("HTTP-сервер завершился с ошибкой", "err", err)
		os.Exit(1)
	case sig := <-stop:
		slog.Info("получен сигнал, завершаем работу", "signal", sig)
	}

	// Даём серверу до 10 секунд на завершение уже принятых запросов.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		// ErrServerClosed — штатная ситуация при вызове Shutdown, не ошибка.
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("ошибка при завершении HTTP-сервера", "err", err)
		}
	}

	// Закрываем пул соединений с БД: корректное освобождение ресурсов
	// и завершение соединений с PostgreSQL.
	if err := database.Close(); err != nil {
		slog.Error("ошибка при закрытии соединения с БД", "err", err)
	}
	slog.Info("сервис остановлен")
}
