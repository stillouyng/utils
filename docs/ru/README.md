# twc — twc

> **Language:** [English](../en/README.md) | **Русский**

Минималистичный менеджер SSH-подключений. Храните SSH-профили и подключайтесь одной командой.

## Возможности

- Мгновенное подключение к сохранённым SSH-профилям
- Зашифрованное хранение паролей (AES-256-GCM + Argon2)
- Поддержка аутентификации по ключу и без пароля
- Linux и macOS: полная поддержка, включая аутентификацию по паролю
- Windows: только аутентификация по ключу и без пароля (`sshpass` недоступен на Windows)

## Дорожная карта и известные баги

Смотрите [ROADMAP.md](ROADMAP.md) для запланированных функций и известных проблем.

Также ознакомьтесь с [VULNERABILITIES.md](VULNERABILITIES.md) для известных ограничений безопасности.

## Установка

### macOS (Apple Silicon)

```bash
curl -L https://github.com/stillouyng/twc/releases/latest/download/twc-macos-aarch64 -o twc
chmod +x twc
sudo mv twc /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/twc  # обход Gatekeeper
```

### macOS (Intel)

```bash
curl -L https://github.com/stillouyng/twc/releases/latest/download/twc-macos-x86_64 -o twc
chmod +x twc
sudo mv twc /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/twc
```

### Linux

```bash
curl -L https://github.com/stillouyng/twc/releases/latest/download/twc-linux-x86_64 -o twc
chmod +x twc
sudo mv twc /usr/local/bin/
```

### Windows

Скачайте `twc-windows-x86_64.exe` из [последнего релиза](https://github.com/stillouyng/twc/releases/latest), переименуйте в `twc.exe` и поместите в папку из вашего PATH.

> **Примечание:** `sshpass` недоступен на Windows, поэтому профили с аутентификацией по паролю (`--password`) не поддерживаются. Используйте аутентификацию по ключу (`--key`) или без пароля.

## Зависимости

| Зависимость | Для чего | Установка |
|---|---|---|
| `sshpass` | Аутентификация по паролю (`twc <name>` с профилями `--password`) | `sudo apt install sshpass` / `brew install sshpass` |
| `ssh` | Всё остальное | Предустановлен на Linux и macOS; на Windows используйте OpenSSH из Параметров |

`sshpass` **не нужен**, если вы используете только профили с ключом или без пароля.

## Использование

```bash
# Добавить профиль (без пароля / по ключу)
twc add <name> <user> <host>
twc add <name> <user> <host> --port 2222
twc add <name> <user> <host> --key ~/.ssh/id_ed25519

# Добавить профиль с зашифрованным SSH-паролем
twc add <name> <user> <host> --password
# → запросит SSH-пароль, затем мастер-ключ (используется для шифрования)

# Подключиться
twc <name>

# Показать все профили
twc list

# Удалить профиль
twc remove <name>
```

## Шифрование паролей

Пароли никогда не хранятся в открытом виде. Они шифруются с помощью AES-256-GCM, используя ключ, производный от вашего мастер-ключа через Argon2. Мастер-ключ нигде не сохраняется — он запрашивается при каждом подключении.

## Использование SSH-ключей с мастер-ключом

Добавьте ключ в SSH-агент один раз, и `twc` подхватит его автоматически:

```bash
ssh-add ~/.ssh/id_ed25519
twc add prod user host --key ~/.ssh/id_ed25519
twc prod  # запроса мастер-ключа не будет
```

На macOS агент сохраняется между перезагрузками через Keychain. На Linux нужно повторно выполнять `ssh-add` после каждой перезагрузки.

## Сборка из исходников

```bash
git clone https://github.com/stillouyng/twc
cd twc
cargo build --release
```
