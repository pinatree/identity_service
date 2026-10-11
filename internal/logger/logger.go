// Package logger — потокобезопасное логирование в файл.
//
// Использует log/slog (build-in с Go 1.21) с текстовым форматом.
// slog является потокобезопасным: все методы (Info, Error, Debug и т.д.)
// могут вызываться из разных горутин без внешней синхронизации.
//
// Пример использования:
//
//	import "github.com/pinatree/identity-service/internal/logger"
//
//	if err := logger.Init(cfg.LogFile); err != nil {
//	    log.Fatalf(...)
//	}
//	slog.Info("сервер запущен", "port", cfg.Port)
//	slog.Error("не удалось подключиться к БД", "err", err)
//	slog.Debug("регистрация пользователя", "login", login)
package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

// Init настраивает глобальный логгер slog.
//
//   - Если path не пустой — лог пишется в файл (создаётся/дополняется).
//   - Если path пустой — лог пишется в stderr (поведение по умолчанию).
//
// Формат — текстовый (slog.NewTextHandler), человекочитаемый.
// Уровень логирования — Info (Debug-сообщения требуют явного переключения).
func Init(path string) error {
	var w io.Writer = os.Stderr

	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("не удалось открыть файл лога %q: %w", path, err)
		}
		w = f
	}

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
		// AddSource добавляет имя файла и номер строки к каждой записи —
		// удобно при отладке, но увеличивает размер лога.
		AddSource: false,
	}

	logger := slog.New(slog.NewTextHandler(w, opts))
	slog.SetDefault(logger)
	return nil
}
