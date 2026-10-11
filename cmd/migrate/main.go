// Package main — исполняемый файл для управления миграциями БД.
//
// Использует golang-migrate/migrate для применения/отката миграций
// из каталога migrations/. Строка подключения к БД берётся из общей
// конфигурации приложения (config.json или переменная DB_CONNECTION).
//
// Каталог с миграциями определяется так (в порядке приоритета):
//  1. переменная окружения MIGRATIONS_DIR (абсолютный путь или URL);
//  2. каталог migrations/ рядом с исполняемым файлом;
//  3. каталог migrations/ относительно текущего рабочего каталога.
//
// Примеры запуска:
//
//	# Применить все неприменённые миграции:
//	go run ./cmd/migrate up
//
//	# Откатить одну последнюю миграцию:
//	go run ./cmd/migrate down
//
//	# Перейти к конкретной версии:
//	go run ./cmd/migrate goto 1
//
//	# Показать текущую версию схемы:
//	go run ./cmd/migrate version
//
//	# Принудительно выставить версию (выход из dirty-состояния):
//	go run ./cmd/migrate force 3
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/pinatree/identity-service/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Использование: %s <up|down|goto N|force N|version>", os.Args[0])
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Не удалось загрузить конфигурацию: %v", err)
	}

	sourceURL, err := resolveMigrationsURL()
	if err != nil {
		log.Fatalf("Не удалось определить каталог миграций: %v", err)
	}
	log.Printf("Каталог миграций: %s", sourceURL)

	m, err := migrate.New(sourceURL, cfg.DBConnection)
	if err != nil {
		log.Fatalf("Не удалось инициализировать migrator: %v", err)
	}
	defer func() {
		srcErr, dbErr := m.Close()
		if srcErr != nil {
			log.Printf("Ошибка при закрытии source-драйвера: %v", srcErr)
		}
		if dbErr != nil {
			log.Printf("Ошибка при закрытии соединения БД: %v", dbErr)
		}
	}()

	cmd := strings.ToLower(os.Args[1])
	switch cmd {
	case "up":
		if err := m.Up(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				log.Println("Схема БД уже актуальна (нет неприменённых миграций).")
				return
			}
			log.Fatalf("Не удалось применить миграции: %v", err)
		}
		log.Println("Все неприменённые миграции успешно выполнены.")

	case "down":
		// Откатываем РОВНО одну миграцию, а не всё до нуля.
		// m.Down() откатил бы до версии 0 — это почти никогда не нужно.
		if err := m.Steps(-1); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				log.Println("Схема БД уже в версии 0 (нечего откатывать).")
				return
			}
			log.Fatalf("Не удалось откатить миграцию: %v", err)
		}
		log.Println("Последняя миграция откачена.")

	case "goto":
		version, err := argVersion(os.Args)
		if err != nil {
			log.Fatal(err)
		}
		if err := m.Migrate(version); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				log.Printf("Схема БД уже на версии %d.", version)
				return
			}
			log.Fatalf("Не удалось перейти к версии %d: %v", version, err)
		}
		log.Printf("Миграция к версии %d выполнена.", version)

	case "force":
		// Аварийный выход из dirty-состояния: помечает БД как находящуюся
		// на указанной версии и снимает флаг dirty.
		version, err := argVersion(os.Args)
		if err != nil {
			log.Fatal(err)
		}
		if err := m.Force(int(version)); err != nil {
			log.Fatalf("Не удалось выставить версию %d: %v", version, err)
		}
		log.Printf("Версия схемы принудительно выставлена в %d (dirty снят).", version)

	case "version":
		currentVersion, dirty, err := m.Version()
		if err != nil {
			if errors.Is(err, migrate.ErrNilVersion) {
				fmt.Println("Миграции не применялись (версия 0).")
				return
			}
			log.Fatalf("Не удалось получить текущую версию схемы: %v", err)
		}
		if dirty {
			fmt.Printf("Текущая версия схемы: %d (грязная — требуется восстановление)\n", currentVersion)
		} else {
			fmt.Printf("Текущая версия схемы: %d\n", currentVersion)
		}

	default:
		log.Fatalf("Неизвестная команда %q. Допустимые: up, down, goto N, force N, version", cmd)
	}
}

// argVersion разбирает целочисленный аргумент команды (goto/force).
func argVersion(args []string) (uint, error) {
	if len(args) < 3 {
		return 0, fmt.Errorf("использование: %s %s <версия>", args[0], args[1])
	}
	v, err := strconv.Atoi(args[2])
	if err != nil {
		return 0, fmt.Errorf("версия должна быть целым числом, получено %q: %w", args[2], err)
	}
	if v < 0 {
		return 0, fmt.Errorf("версия не может быть отрицательной: %d", v)
	}
	return uint(v), nil
}

// resolveMigrationsURL возвращает URL для source-драйвера migrate.
//
// Приоритет:
//  1. MIGRATIONS_DIR — если задан, используется как есть (можно передать
//     как абсолютный путь, так и полный URL, начинающийся с "file://").
//  2. migrations/ рядом с исполняемым файлом — работает и в контейнере,
//     где бинарник лежит в /app, и локально.
//  3. migrations/ относительно cwd — фолбэк для `go run`.
func resolveMigrationsURL() (string, error) {
	if dir := os.Getenv("MIGRATIONS_DIR"); dir != "" {
		if strings.HasPrefix(dir, "file://") {
			return dir, nil
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("не удалось получить абсолютный путь %q: %w", dir, err)
		}
		return "file://" + abs, nil
	}

	// Пытаемся найти migrations рядом с бинарником.
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidate := filepath.Join(exeDir, "migrations")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				return "", fmt.Errorf("не удалось получить абсолютный путь %q: %w", candidate, err)
			}
			return "file://" + abs, nil
		}
	}

	// Фолбэк: относительный путь от cwd (для `go run` из корня проекта).
	abs, err := filepath.Abs("migrations")
	if err != nil {
		return "", fmt.Errorf("не удалось получить абсолютный путь migrations: %w", err)
	}
	if info, err := os.Stat(abs); err != nil || !info.IsDir() {
		return "", fmt.Errorf("каталог %q не найден — задай MIGRATIONS_DIR", abs)
	}
	return "file://" + abs, nil
}
