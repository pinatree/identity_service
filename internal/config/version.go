package config

// Version — версия приложения, известная на момент сборки.
//
// Обычно значение подставляется при сборке через флаг линковщика:
//
//	go build -ldflags "-X github.com/pinatree/identity-service/internal/config.Version=v1.2.3" ./cmd/server
//
// Если флаг не указан — используется значение по умолчанию ниже.
var Version = "1.0.0"

// GetVersion возвращает версию приложения, заданную при сборке.
// Пригодится в точках входа и диагностических эндпоинтах (/version),
// чтобы не хардкодить одну и ту же строку в разных местах.
func GetVersion() string {
	return Version
}
