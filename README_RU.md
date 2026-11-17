<p align="center">
  <img src="docs/assets/ferroscout-mark.svg" width="132" alt="Логотип FerroScout">
</p>

<h1 align="center">FerroScout</h1>

<p align="center">
  <strong>Находит рискованные шаблоны. Показывает доказательства. Помогает исправить причину.</strong><br>
  Локальный статический анализатор безопасности на Rust.
</p>

<p align="center">
  <a href="https://github.com/abduforge/FerroScout/actions/workflows/ci.yml"><img src="https://github.com/abduforge/FerroScout/actions/workflows/ci.yml/badge.svg" alt="Rust CI"></a>
  <a href="https://github.com/abduforge/FerroScout/actions/workflows/code-scanning.yml"><img src="https://github.com/abduforge/FerroScout/actions/workflows/code-scanning.yml/badge.svg" alt="FerroScout Code Scanning"></a>
  <a href="https://github.com/abduforge/FerroScout/releases"><img src="https://img.shields.io/github/v/release/abduforge/FerroScout?display_name=tag&sort=semver" alt="Последний релиз"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/abduforge/FerroScout" alt="Лицензия MIT"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust" alt="Rust 1.70 или новее"></a>
  <a href="https://github.com/abduforge/FerroScout/issues"><img src="https://img.shields.io/github/issues/abduforge/FerroScout" alt="Открытые Issues"></a>
</p>

<p align="center">
  <a href="README.md">English version</a> ·
  <a href="https://github.com/abduforge/FerroScout/releases">Релизы</a> ·
  <a href="https://github.com/abduforge/FerroScout/issues">Обсуждение ошибок</a>
</p>

---

FerroScout обходит исходный код и конфигурационные файлы, проверяет их по набору правил безопасности и выводит найденные совпадения с путём к файлу, номером строки, доказательством, уровнем уверенности и советом по исправлению. Также он умеет создавать отчёты **SARIF 2.1.0** для GitHub Code Scanning.

Программа работает локально и пассивно: не запускает проверяемые программы и не изменяет файлы. CLI сам не выполняет сетевых запросов. Необязательный workflow GitHub Actions загружает SARIF-отчёт (пути, номера строк и очищенные фрагменты доказательств) в GitHub Code Scanning.

> **О точности:** FerroScout 0.2.0 — rule-based инструмент для помощи при проверке кода, а не полноценный языковой SAST-анализатор. Он не доказывает возможность эксплуатации и не понимает все межфайловые потоки данных. Считай находки поводом для ручной проверки. Чистый отчёт не гарантирует безопасность.

## Кратко о проекте

| | |
|---|---|
| **Язык** | Rust (stable, edition 2021) |
| **Платформа** | Linux |
| **Анализ** | Локальный, статический, только чтение |
| **Форматы отчёта** | Текст, JSON, SARIF 2.1.0 |
| **Правила** | 10 групп проверок |
| **Лицензия** | MIT |

## Быстрый старт

### Сборка из исходников

Установи стабильный Rust toolchain и выполни:

```bash
git clone https://github.com/abduforge/FerroScout.git
cd FerroScout
cargo generate-lockfile
cargo build --release
```

Бинарный файл появится в `target/release/ferroscout`.

### Установка готового релиза

Архивы для Linux x86_64 и контрольные суммы SHA-256 публикуются на странице [Releases](https://github.com/abduforge/FerroScout/releases). Скачай подходящие `.tar.gz` и `.sha256`, затем выполни:

```bash
sha256sum -c ferroscout-v0.2.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf ferroscout-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
install -Dm755 ferroscout/ferroscout ~/.local/bin/ferroscout
```

### Первый запуск

```bash
./target/release/ferroscout scan ./путь/к/проекту
```

Чтобы запускать программу из любого каталога, скопируй её в директорию из `PATH`:

```bash
install -Dm755 target/release/ferroscout ~/.local/bin/ferroscout
```

## Использование

```bash
# Проверить каталог проекта
ferroscout scan ./project

# Проверить один файл
ferroscout scan ./src/main.rs

# Отчёт в JSON
ferroscout scan ./project --format json

# SARIF для GitHub Code Scanning
ferroscout scan ./project --format sarif > ferroscout.sarif

# Оставить находки Medium и High
ferroscout scan ./project --severity medium

# Исключить каталоги или относительные пути
ferroscout scan ./project --exclude target --exclude fixtures

# Установить ограничение размера файла (максимум 16 МиБ)
ferroscout scan ./project --max-file-size 1048576

# Показать список встроенных правил
ferroscout rules
```

Полная справка: `ferroscout --help`.

### Коды завершения

| Код | Значение |
|---:|---|
| `0` | Выбранных находок нет, контекста достаточно |
| `1` | Найдена одна или несколько проблем |
| `2` | Ошибка сканирования или недостаточно контекста |

Такой интерфейс подходит для скриптов и CI. Сам по себе код `1` не обязан останавливать сборку — это решает workflow.

## Проверки безопасности

| Правило | Область | Что ищет |
|---|---|---|
| `FS-SECRET-001` | Секреты | Похожие на учётные данные присваивания, Bearer-токены и PEM-маркеры приватных ключей |
| `FS-XSS-001` | XSS | Маркер недоверенного ввода рядом с динамическим HTML sink |
| `FS-INJECT-001` | Инъекции | Динамическую сборку SQL и некоторые шаблоны запуска shell-команд |
| `FS-PATH-001` | Path Traversal | Маркеры недоверенного ввода рядом с файловыми операциями |
| `FS-SSRF-001` | SSRF | Пользовательские значения рядом с серверными HTTP-запросами |
| `FS-CORS-001` | CORS | Отражение Origin в файле, где также включены credentials |
| `FS-DESER-001` | Десериализация | Некоторые небезопасные API десериализации |
| `FS-TLS-001` | TLS | Явное отключение проверки сертификатов |
| `FS-DEBUG-001` | Debug | Типичные настройки debug-режима |
| `FS-CRYPTO-001` | Криптография | Некоторые слабые схемы хеширования паролей и небезопасные источники случайности |

### Что содержит находка

Каждый результат содержит ID правила, критичность, уверенность, путь к файлу, номер строки, фрагмент доказательства, объяснение, возможное влияние и рекомендацию. Похожие на секреты значения маскируются.

Правила консервативные и построчные. Например, одного `innerHTML` недостаточно, чтобы объявить XSS: текущее правило также ищет рядом маркер недоверенного ввода и отсутствие маркера санитизации. Это всё ещё эвристика, а не полноценный taint analysis.

## GitHub Code Scanning (SARIF)

FerroScout умеет создавать SARIF 2.1.0:

```bash
ferroscout scan . --format sarif > ferroscout.sarif
```

В репозитории есть workflow `.github/workflows/code-scanning.yml`: он запускает FerroScout при push в `main` и загружает SARIF в GitHub Code Scanning. Чтобы результат появился во вкладке **Security**, функция Code Scanning должна быть доступна и включена в настройках репозитория. Workflow исключает `tests` и `src/rules`, потому что в этих каталогах находятся намеренно уязвимые синтетические примеры для тестирования самого анализатора.

В собственном workflow можно использовать `github/codeql-action/upload-sarif`, выдав задаче разрешение `security-events: write`.

## Область и приватность

- Читает файлы локально; сам CLI не выполняет сетевых запросов.
- Необязательный workflow Code Scanning загружает SARIF-отчёт в GitHub. В нём есть пути, номера строк и фрагменты доказательств; маскирование секретов основано на эвристиках и не даёт гарантии. Перед включением workflow для чувствительных репозиториев проверь его содержимое.
- Не запускает проверяемые программы, скрипты, shell-команды и сборочные процессы.
- Не изменяет и не удаляет файлы.
- Пропускает символические ссылки при обходе каталога и отклоняет симлинк в качестве цели сканирования.
- Пропускает бинарные файлы и файлы больше заданного лимита (по умолчанию 2 МиБ, жёсткий максимум — 16 МиБ).
- Проверяет распространённые расширения исходников и конфигураций, а также отдельные файлы `.env`, `Dockerfile`, `.http` и `.har`.
- По умолчанию исключает типичные каталоги сборки и зависимостей: `.git`, `target`, `node_modules`, `vendor`, `dist`, виртуальные окружения.
- Маскирует значения, похожие на секреты, в доказательствах. Это не повод хранить секреты в репозитории.

## Ограничения

FerroScout 0.2.0 использует регулярные выражения и контекст соседних строк. Он не строит полные AST, не выполняет межпроцедурный или межфайловый taint analysis, не разрешает конфигурацию фреймворков, не обращается к сервисам и не проверяет логику авторизации. Поэтому надёжное обнаружение IDOR не заявляется. Совпадение правила требует проверки, а отсутствие совпадений не доказывает безопасность кода.

## Разработка

```bash
cargo generate-lockfile
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

Используй только синтетические тестовые данные. Не добавляй настоящие пароли, токены, приватные ключи и данные пользователей. Перед pull request прочитай [CONTRIBUTING.md](CONTRIBUTING.md).

## Ссылки

- [История изменений](CHANGELOG.md)
- [Политика безопасности](SECURITY.md)
- [Как внести вклад](CONTRIBUTING.md)
- [Сообщить об ошибке](https://github.com/abduforge/FerroScout/issues/new/choose)
- [Релизы](https://github.com/abduforge/FerroScout/releases)

## Лицензия

MIT. См. [LICENSE](LICENSE).
