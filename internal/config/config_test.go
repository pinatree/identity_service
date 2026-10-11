// Файл содержит модульные тесты для пакета config.
//
// Тесты используют временные файлы (t.TempDir), поэтому репозиторий
// не загрязняется тестовыми конфигурациями, а сами тесты не зависят
// от существующего config.json.
package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempConfig создаёт временный файл с указанным содержимым
// и возвращает его путь. Временная директория удаляется автоматически.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("не удалось создать временный конфигурационный файл: %v", err)
	}
	return path
}

// TestLoadFromDefaultsWhenFileMissing проверяет, что отсутствие файла
// не является ошибкой: применяются значения по умолчанию.
func TestLoadFromDefaultsWhenFileMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-file.json")

	cfg, err := LoadFrom(missing)
	if err != nil {
		t.Fatalf("отсутствие файла не должно быть ошибкой, получено: %v", err)
	}

	if cfg.Port != defaultPort {
		t.Errorf("port: ожидалось %q, получено %q", defaultPort, cfg.Port)
	}
	if cfg.Name != defaultName {
		t.Errorf("name: ожидалось %q, получено %q", defaultName, cfg.Name)
	}
	if cfg.TokenTTLSeconds != DefaultTokenTTLSeconds {
		t.Errorf("token_ttl: ожидалось %d, получено %d", DefaultTokenTTLSeconds, cfg.TokenTTLSeconds)
	}
	if cfg.DBConnection != defaultDBConnection {
		t.Errorf("db_connection: ожидалось %q, получено %q", defaultDBConnection, cfg.DBConnection)
	}
}

// TestLoadFromFile проверяет, что поля из файла корректно применяются.
func TestLoadFromFile(t *testing.T) {
	path := writeTempConfig(t, `{"port":"9999","name":"my-app","version":"2.5.0","token_ttl":60,"db_connection":"postgres://user:pass@localhost:5432/db"}`)

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	if cfg.Port != "9999" {
		t.Errorf("port: ожидалось 9999, получено %q", cfg.Port)
	}
	if cfg.Name != "my-app" {
		t.Errorf("name: ожидалось my-app, получено %q", cfg.Name)
	}
	if cfg.Version != "2.5.0" {
		t.Errorf("version: ожидалось 2.5.0, получено %q", cfg.Version)
	}
	if cfg.TokenTTLSeconds != 60 {
		t.Errorf("token_ttl: ожидалось 60, получено %d", cfg.TokenTTLSeconds)
	}
	if cfg.DBConnection != "postgres://user:pass@localhost:5432/db" {
		t.Errorf("db_connection: ожидалось %q, получено %q", "postgres://user:pass@localhost:5432/db", cfg.DBConnection)
	}
}

// TestLoadFromInvalidJSON проверяет, что невалидный JSON приводит к ошибке,
// а не к падению приложения через os.Exit.
func TestLoadFromInvalidJSON(t *testing.T) {
	path := writeTempConfig(t, `{это не json`)

	if _, err := LoadFrom(path); err == nil {
		t.Fatal("невалидный JSON должен возвращать ошибку")
	}
}

// TestTokenTTLZeroFallsBackToDefault проверяет, что поле token_ttl <= 0
// игнорируется — берётся значение по умолчанию.
func TestTokenTTLZeroFallsBackToDefault(t *testing.T) {
	path := writeTempConfig(t, `{"token_ttl":0}`)

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if cfg.TokenTTLSeconds != DefaultTokenTTLSeconds {
		t.Errorf("token_ttl: ожидалось %d, получено %d", DefaultTokenTTLSeconds, cfg.TokenTTLSeconds)
	}
}

// TestEnvOverridesFile проверяет, что переменные окружения имеют
// приоритет над значениями из файла конфигурации.
func TestEnvOverridesFile(t *testing.T) {
	path := writeTempConfig(t, `{"port":"8080","token_ttl":300,"db_connection":"file:test.db"}`)

	// t.Setenv автоматически восстанавливает переменную после теста,
	// поэтому тесты не влияют друг на друга.
	t.Setenv("PORT", "9000")
	t.Setenv("TOKEN_TTL", "120")
	t.Setenv("DB_CONNECTION", "postgres://prod:secret@db.internal:5432/proddb")

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	if cfg.Port != "9000" {
		t.Errorf("port: ожидалось 9000, получено %q", cfg.Port)
	}
	if cfg.TokenTTLSeconds != 120 {
		t.Errorf("token_ttl: ожидалось 120, получено %d", cfg.TokenTTLSeconds)
	}
	if cfg.DBConnection != "postgres://prod:secret@db.internal:5432/proddb" {
		t.Errorf("db_connection: ожидалось %q, получено %q", "postgres://prod:secret@db.internal:5432/proddb", cfg.DBConnection)
	}
}
