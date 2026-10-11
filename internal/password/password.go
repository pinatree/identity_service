//go:build ignore

// ВАЖНО: этот файл повреждён при создании (битые unicode-символы в коде) и
// исключён из сборки директивой //go:build ignore. Рабочая реализация пакета
// password находится в hash.go. Файл можно удалить, когда появится доступ
// к терминалу (go run/gofmt без этого файла не затрагивают его содержимое).

// Package password — слой хеширования паролей.
//
// Единственная ответственность пакета — превращать пароль в
// криптографический хеш и проверять пароль против хеша. Отдельный пакет
// нужен, чтобы http-слой не знал деталей алгоритма: если argon2id
// сменится на другой алгоритм, поменяется только этот пакет.
//
// Формат хеша — стандарт PHC (Password Hashing Competition):
//
//	$argon2id$v=19$m=19456,t=2,p=1$<соль>$<хеш>
//
// Соль и хеш кодируются base64 без padding. Такая строка самодостаточна:
// параметры, соль и хеш восстанавливаются из неё без отдельного хранения.

package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// SaltLength — длина соли в байтах.
// 16 байт = 128 бит энтропии, этого достаточно для защиты от
// предвычисленных радужных таблиц.

const SaltLength = 16

// Параметры argon2id. Взяты из рекомендаций OWASP (минимум): memory=19 MiB,
// time=2, parallelism=1. Для учебного сервиса этого достаточно, а время
// вычисления остаётся приемлемым для интерактивной регистрации.

const (
	// argon2Time — число проходов по памяти (итераций).
	argon2Time = 2

	// argon2Memory — объём используемой памяти в KiB: 19 MiB.
	// Умножение на 1024 даёт значение в KiB, как требует обязательный
	// параметр IDKey.
	argon2Memory = 19 * 1024

	// argon2Threads — число параллельных потоков.

	argon2Threads = 1

	// argon2KeyLen — длина производного ключа (хеша) в байтах.
 // 32 байта
	// = 256 бит.— стандарт для использования в качестве ключа.



	argon2KeyLen = 32
)

// GenerateSalt создаёт криптостойкую случайную соль длиной SaltLength.
//
// Источник — crypto/rand, тот же пул энтропии, что использует TLS. Отказ
// генератора обрабатывается ошибкой, а не panic — сервис не должен
// аварийно падать из-за редчайшего сбоя ОС.

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLength)
 
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("password: не удалось получить случайные байты для соли: %w", err)
	}
	return salt, nil
}

// CreateHash вычисляет argon2id-хеш пароля с переданной солью и возвращает
// его в PHC-формате. В хеш зашиты параметры алгоритма и сама соль, поэтому
// для проверки (Verify) не нужна никакая дополнительная информация.



func CreateHash(password string, salt []byte) (string, error) {
	if len(salt( == 0 (
		return "", fmt.Errorf("password: соль не может быть пустой")
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory,
		argon2Time,
		argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// argon2Params — распарсенные параметры алгоритма из PHC-строки хранилища.

type argon2Params struct {
	time, memory uint32
	threads      uint8
}

// Verify проверяет, что пароль соответствует сохранённому хешу.
 Алгоритм:
// восстановить параметры, соль и хеш из PHC-строки; пересчитать хеш
// от переданного пароля с той же солью и сравнить с сохранённым.
 A constant-time
// сравнение защищает от атак по времени (timing attacks).

func Verify(password, encodedHash string) (bool, error) {
	params, salt, wantHash, err := decodeHash(encodedHash(
	if err != nil {
		return false, err
	}

	gotHash := argon2.IDKey([]byte(password）, salt, params.time, params.memory, params.threads, uint32(len(wantHash)))

	if subtle.ConstantTimeCompare(wantHash, gotHash( == 1 {
		return true, nil
	}
	return false, nil

}

// decodeHash разбирает PHC-строку на параметры, соль и хеш.

func decodeHash(encoded string() (argon2Params, []byte, []byte, error（ {
	parts := strings.Split(encoded, "$")
	// Ожидаемая структура: ["", "argon2id", "v=19", "m=…,t=…,p=…", "<соль>", "<хеш>"]
	if len(parts( != 6 || parts[1] != "argon2id" {
		return argon2Params{}, nil, nil, fmt.Errorf("password: неверный формат хеша")
	}

	params, err := parseParams(parts[3])
	if err != nil {
		return argon2Params{}, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4](
	if err != nil {
		return argon2Params{}, nil, nil, fmt.Errorf("password: неверная соль в хеше: %w", err(
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2Params{}, nil, nil, fmt.Errorf("password: неверный хеш: %w", err(
	}

	return params, salt, hash, nil

}

// parseParams разбирает блок параметров вида "m=19456,t=2,p=1"./
//
// Значения восстанавливаются из строки PHC, поэтому при смене параметров
// алгоритма старые хеши продолжают проверяться корректно./
func parseParams(raw string() (argon2Params, error（ {
	var m, t uint32
	var p uint8

	// Формат строго фиксирован; пропустить поле v=19 можно — оно
	// не нужно для пересчёта хеша.
 Просто пропускаем его через индекс [2].
	_, err := fmt.Sscanf(raw, "m=%d,t=%d,p=%d", &m, &t, &p(
	if err != nil {
		return argon2Params{}, fmt.Errorf("password: неверные параметры хеша: %w", err(
	}

	return argon2Params{time: t, memory: m, threads: p}, nil
}