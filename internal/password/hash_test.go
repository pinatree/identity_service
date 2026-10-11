// Файл содержит модульные тесты для хеширования паролей argon2id
// (см. hash.go в этом пакете).
package password

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestGenerateSalt проверяет, что соль имеет длину SaltLength и генерируется
// без ошибок.
func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(salt) != SaltLength {
		t.Fatalf("ожидалась соль длиной %d байт, получено %d", SaltLength, len(salt))
	}
}

// TestGenerateSaltUnique проверяет, что две последовательные соли различаются
// (вероятность совпадения 128 случайных бит пренебрежимо мала).
func TestGenerateSaltUnique(t *testing.T) {
	a, err := GenerateSalt()
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	b, err := GenerateSalt()
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if string(a) == string(b) {
		t.Fatal("две последовательные соли совпали — это подозрительно")
	}
}

// TestCreateHashFormat проверяет PHC-формат результата и то, что переданная
// соль восстанавливается из строки хеша.
func TestCreateHashFormat(t *testing.T) {
	salt := make([]byte, SaltLength)
	for i := range salt {
		salt[i] = byte(i)
	}

	hash, err := CreateHash("secret123", salt)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("хеш не соответствует PHC-формату: %s", hash)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("ожидалось 6 частей PHC-строки, получено %d", len(parts))
	}
	// Соль в PHC кодируется base64 без padding.
	if parts[4] != base64.RawStdEncoding.EncodeToString(salt) {
		t.Errorf("соль в хеше не совпадает с исходной: %s != %s",
			parts[4], base64.RawStdEncoding.EncodeToString(salt))
	}
	if parts[5] == "" {
		t.Error("хеш не должен быть пустым")
	}
}

// TestCreateHashDeterministic проверяет, что одинаковые пароль и соль дают
// одинаковый хеш: это ключевое свойство для будущей проверки пароля.
func TestCreateHashDeterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")

	hash1, err := CreateHash("secret123", salt)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	hash2, err := CreateHash("secret123", salt)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if hash1 != hash2 {
		t.Fatal("одинаковые пароль и соль должны давать одинаковый хеш")
	}
}

// TestCreateHashEmptySalt проверяет, что пустая соль отклоняется.
func TestCreateHashEmptySalt(t *testing.T) {
	if _, err := CreateHash("secret123", nil); err == nil {
		t.Fatal("пустая соль должна возвращать ошибку")
	}
}

// TestVerifyCorrectPassword проверяет, что верный пароль проходит проверку
// против хеша, созданного CreateHash.
func TestVerifyCorrectPassword(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	hash, err := CreateHash("secret123", salt)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	ok, err := Verify("secret123", hash)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if !ok {
		t.Fatal("верный пароль должен проходить проверку")
	}
}

// TestVerifyWrongPassword проверяет, что неверный пароль не проходит
// проверку (без ошибки — это штатная ситуация).
func TestVerifyWrongPassword(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	hash, err := CreateHash("secret123", salt)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	ok, err := Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if ok {
		t.Fatal("неверный пароль не должен проходить проверку")
	}
}

// TestVerifyMalformedHash проверяет, что не-PHC-строка возвращает ошибку:
// такие значения не могут быть результатом CreateHash, поэтому ошибка
// разбора — корректное поведение, а не «вход разрешён».
func TestVerifyMalformedHash(t *testing.T) {
	if _, err := Verify("secret123", "mock-password-hash"); err == nil {
		t.Fatal("некорректный хеш должен возвращать ошибку")
	}
}
