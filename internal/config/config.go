// Package config отвечает за загрузку и валидацию конфигурации приложения.
//
// Конфигурация собирается из трёх источников (в порядке возрастания приоритета):
//  1. Значения по умолчанию (см. константы default* ниже) — сервис работает
//     вообще без файла конфигурации.
//  2. Файл config.json, лежащий в рабочей директории приложения.
//  3. Переменные окружения (PORT, NAME, VERSION, TOKEN_TTL, DB_CONNECTION, LOG_FILE) —
//     переопределяют значения из файла; это стандарт «12-factor app» для продакшена.
//
// Главное отличие от «наивной» реализации: функции пакета НЕ вызывают os.Exit
// и НЕ создают файлы за пользователя. Ошибки возвращаются через error,
// а решение о завершении программы принимает вызывающий код (cmd/server/main.go).
// Такой подход делает пакет тестируемым и переиспользуемым.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// Имена и значения по умолчанию конфигурации.
const (
	// configFileName — имя файла конфигурации. Сервис ищет его в той директории,
	// из которой запущен процесс (рабочей директории). Путь можно переопределить
	// через config.LoadFrom.
	configFileName = "config.json"

	// DefaultTokenTTLSeconds — время жизни токена авторизации по умолчанию:
	// 5 минут = 300 секунд. Используется, если поле token_ttl не задано
	// в конфигурации или задано значением <= 0.
	DefaultTokenTTLSeconds = 300

	// defaultPort — TCP-порт по умолчанию.
	defaultPort = "8080"

	// defaultName — имя сервиса по умолчанию.
	defaultName = "identity-service"

	// defaultDBConnection — строка подключения к PostgreSQL по умолчанию.
	// Совпадает с dev-контейнером postgres из docker-compose.yml
	// (пользователь app, пароль secret, БД appdb, порт 5432).
	// sslmode=disable отключает TLS для локальной разработки.
	defaultDBConnection = "postgres://app:secret@localhost:5432/appdb?sslmode=disable"
)

// Config — итоговая «обогащённая» конфигурация приложения.
// В отличие от файла, здесь все поля гарантированно заполнены:
// пустые значения из файла заменяются значениями по умолчанию.
type Config struct {
	// Port — TCP-порт, на котором сервер принимает соединения.
	// Хранится строкой без ведущего двоеточия, например "8080".
	Port string

	// Name — человекочитаемое имя сервиса. Отдаётся в health-ответе.
	Name string

	// Version — версия сервиса. По умолчанию равна версии сборки
	// (переменная Version в version.go), но может быть переопределена
	// файлом конфигурации или переменной окружения VERSION.
	Version string

	// TokenTTLSeconds — время жизни токена в секундах.
	// Всегда положительное число (по умолчанию DefaultTokenTTLSeconds).
	TokenTTLSeconds int

	// DBConnection — строка подключения к PostgreSQL
	// (формат postgres://user:password@host:port/dbname). По умолчанию —
	// локальный dev-инстанс из docker-compose.yml.
	DBConnection string

	// LogFile — путь к файлу лога. Если пустой — лог пишется в stderr.
	// Переопределяется переменной окружения LOG_FILE.
	LogFile string
}

// configFile — «сырое» представление файла config.json.
// Поля отмечены json-тегами, совпадающими с именами полей файла.
//
// TokenTTLSeconds хранится как указатель (*int), а не int: это позволяет
// отличить «поле в файле отсутствует» (nil) от «поле равно нулю» (0).
// Для остальных полей достаточно пустой строки как признака «не задано».
type configFile struct {
	Port            string `json:"port"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	TokenTTLSeconds *int   `json:"token_ttl"`
	DBConnection    string `json:"db_connection"`
	LogFile         string `json:"log_file"`
}

// Load загружает конфигурацию из файла configFileName (config.json
// в рабочей директории). Если файла нет — используется конфигурация
// по умолчанию, это НЕ ошибка.
func Load() (*Config, error) {
	return LoadFrom(configFileName)
}

// LoadFrom загружает конфигурацию из указанного файла. Последовательность шагов:
//  1. Берём значения по умолчанию;
//  2. Если файл существует — накладываем его непустые поля;
//  3. Накладываем переменные окружения (наивысший приоритет).
//
// Ошибка возвращается только если файл невозможно прочитать (например,
// нет прав доступа) или он содержит невалидный JSON. Отсутствие файла
// ошибкой не является — сервис просто стартует с дефолтами.
func LoadFrom(path string) (*Config, error) {
	// Начинаем с безопасных значений по умолчанию.
	cfg := &Config{
		Port:            defaultPort,
		Name:            defaultName,
		Version:         Version, // версия сборки, см. version.go
		TokenTTLSeconds: DefaultTokenTTLSeconds,
		DBConnection:    defaultDBConnection,
	}

	// Накладываем файл (если он есть). Отсутствие файла — не ошибка.
	if err := mergeFile(cfg, path); err != nil {
		return nil, err
	}

	// Переменные окружения имеют наивысший приоритет и применяются
	// на ЛЮБОМ пути — в том числе когда файла нет.
	applyEnvOverrides(cfg)

	return cfg, nil
}

// mergeFile читает файл конфигурации и накладывает его непустые поля на cfg.
// Если файла нет — возвращает nil (не ошибка). Если JSON невалиден или
// файл нечитаем — возвращает обёрнутую ошибку.
func mergeFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("не удалось прочитать конфигурационный файл %q: %w", path, err)
	}

	// Разбираем JSON. Синтаксическая ошибка — веская причина остановиться.
	var raw configFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("конфигурационный файл %q содержит невалидный JSON: %w", path, err)
	}

	// Накладываем значения из файла, игнорируя пустые.
	if raw.Port != "" {
		cfg.Port = raw.Port
	}
	if raw.Name != "" {
		cfg.Name = raw.Name
	}
	if raw.Version != "" {
		cfg.Version = raw.Version
	}
	// TTL учитываем только для явно заданного положительного числа.
	if raw.TokenTTLSeconds != nil && *raw.TokenTTLSeconds > 0 {
		cfg.TokenTTLSeconds = *raw.TokenTTLSeconds
	}
	if raw.DBConnection != "" {
		cfg.DBConnection = raw.DBConnection
	}
	if raw.LogFile != "" {
		cfg.LogFile = raw.LogFile
	}

	return nil
}

// applyEnvOverrides накладывает переменные окружения поверх конфигурации.
// Имена переменных «кричащие» — так принято в 12-factor-app-стиле:
// манифест популяризировал такой подход с конца 2012-го.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PORT"); v != "" {
		cfg.Port = v
	}
	if v := os.Getenv("NAME"); v != "" {
		cfg.Name = v
	}
	if v := os.Getenv("VERSION"); v != "" {
		cfg.Version = v
	}
	if v := os.Getenv("TOKEN_TTL"); v != "" {
		// Некорректное или неположительное значение молча игнорируем:
		// оставляем то, что было задано файлом или по умолчанию.
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.TokenTTLSeconds = n
		}
	}
	if v := os.Getenv("DB_CONNECTION"); v != "" {
		cfg.DBConnection = v
	}
	if v := os.Getenv("LOG_FILE"); v != "" {
		cfg.LogFile = v
	}
}
