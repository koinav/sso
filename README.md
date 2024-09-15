# SSO на Go

Проект представляет собой реализацию системы единого входа (SSO) с использованием языка программирования Go. 

## Стек технологий

- **Язык программирования**: Go
- **gRPC**: для реализации межпроцедурного взаимодействия.
- **Protocol Buffers (Proto3)**: для сериализации данных в gRPC.
- **JWT (JSON Web Tokens)**: для аутентификации и авторизации.
- **SQLite**: в качестве хранилища данных.
- **Go Migrate**: для управления миграциями базы данных.
- **Taskfile**: для управления задачами разработки и развертывания.

**gRPC сервисы**: 
  - `Register`: Регистрация нового пользователя с использованием электронной почты и пароля.
  - `Login`: Авторизация пользователя и выдача токена JWT.
  - `IsAdmin`: Проверка, является ли пользователь администратором.

## Использование

### Запуск SSO сервиса

Сервис SSO можно запустить с помощью команды `run`, определенной в `Taskfile.yml`:

```bash
task run
```

### Применение миграций

Чтобы применить миграции базы данных, используйте следующую команду:
```bash
task migrate
```

## Конфигурация

Конфигурация проекта осуществляется с помощью YAML файла, который должен содержать необходимые параметры для настройки сервера и базы данных. Пример конфигурационного файла может быть найден в `./config/local.yaml`.

## gRPC API

Файл `auth.proto` определяет следующие сервисы и сообщения:

- **Сервисы**:
  - `Auth`: Включает методы `Register`, `Login`, `IsAdmin`.

- **Сообщения**:
  - `RegisterRequest`, `RegisterResponse`: Регистрация нового пользователя.
  - `LoginRequest`, `LoginResponse`: Авторизация пользователя.
  - `IsAdminRequest`, `IsAdminResponse`: Проверка администраторских прав.

## Аутентификация

Для аутентификации используется JWT (JSON Web Token). Токен выдается после успешной авторизации и используется для доступа к защищенным ресурсам.


