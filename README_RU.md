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
  <a href="https://github.com/abduforge/FerroScout/actions/workflows/code-scanning.yml"><img src="https://github.com/abduforge/FerroScout/actions/workflows/code-scanning.yml/badge.svg" alt="Code Scanning"></a>
  <a href="https://img.shields.io/github/v/release/abduforge/FerroScout?display_name=tag&sort=semver"><img src="https://img.shields.io/github/v/release/abduforge/FerroScout?display_name=tag&sort=semver" alt="Последний релиз"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/abduforge/FerroScout" alt="MIT license"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-stable-orange?logo=rust" alt="Stable Rust"></a>
  <a href="https://github.com/abduforge/FerroScout/issues"><img src="https://img.shields.io/github/issues/abduforge/FerroScout" alt="Открытые Issues"></a>
</p>

<p align="center">
  <a href="README.md">English version</a> ·
  <a href="https://github.com/abduforge/FerroScout/releases">Релизы</a> ·
  <a href="https://github.com/abduforge/FerroScout/discussions">Обсуждения</a>
</p>

---

FerroScout проверяет исходный код и конфигурационные файлы по набору правил безопасности. Каждая находка содержит ID правила, критичность, уверенность, путь и номер строки, доказательство, возможное влияние и совет по исправлению.

Сканер работает локально и только читает файлы: он не запускает проверяемые программы и не обращается к удалённым сервисам. Отчёты доступны в форматах text, Markdown, JSON и SARIF 2.1.0.

> **О точности:** FerroScout — небольшой эвристический анализатор, а не полноценный языковой SAST. Совпадение правила — повод для ручной проверки, а не доказательство эксплуатации. Чистый отчёт не гарантирует безопасность.

## Кратко о проекте

| | |
|---|---|
| Язык | Rust, edition 2021 |
| Платформа | Linux |
| Режим | Локальный, пассивный, только чтение |
| Отчёты | Text · Markdown · JSON · SARIF 2.1.0 |
| Группы правил | 10 |
| Лицензия | MIT |

## Быстрый старт

### Сборка из исходников

Установи стабильный Rust toolchain и выполни:

```bash
git clone https://github.com/abduforge/FerroScout.git
cd FerroScout
cargo generate-lockfile
cargo build --release --locked
```

Бинарный файл появится в `target/release/ferroscout`.

### Установка релиза

Архивы Linux x86_64 и SHA-256 публикуются на странице [Releases](https://github.com/abduforge/FerroScout/releases). После скачивания проверь архив:

```bash
sha256sum -c ferroscout-v0.3.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf ferroscout-v0.3.0-x86_64-unknown-linux-gnu.tar.gz
install -Dm755 ferroscout/ferroscout ~/.local/bin/ferroscout
```

Убедись, что `~/.local/bin` есть в `PATH`.

## Использование

```bash
# Проверить каталог проекта
ferroscout scan ./project

# Проверить один файл
ferroscout scan ./src/main.rs

# Сохранить Markdown-отчёт
ferroscout scan ./project --format markdown > ferroscout-report.md

# Создать JSON или SARIF
ferroscout scan ./project --format json > ferroscout-report.json
ferroscout scan ./project --format sarif > ferroscout.sarif

# Оставить находки Medium и High
ferroscout scan ./project --severity medium

# Исключить известное шумное правило (параметр можно повторять)
ferroscout scan ./project --exclude-rule FS-TLS-001

# Исключить каталоги сборки и тестовые данные
ferroscout scan ./project --exclude target --exclude fixtures

# Задать максимальный размер файла (не более 16 МиБ)
ferroscout scan ./project --max-file-size 1048576

# Показать встроенные правила
ferroscout rules
```

Полная справка: `ferroscout --help`.

### Коды завершения

| Код | Значение |
|---:|---|
| `0` | После фильтров находок нет, контекста достаточно |
| `1` | Найдена одна или несколько проблем |
| `2` | Ошибка сканирования или недостаточно контекста |

Это удобно для скриптов и CI. Решение о том, должна ли находка останавливать сборку, принимает workflow.

## Подавление известных исключений

Чтобы скрыть конкретную находку, добавь перед ней комментарий с ID правила и обязательной причиной:

```python
# ferroscout:ignore-next-line FS-TLS-001 -- локальный тестовый сервер использует тестовый сертификат
requests.get(url, verify=False)
```

В JavaScript и Rust используется такой же маркер:

```javascript
// ferroscout:ignore-next-line FS-XSS-001 -- значение очищается обёрткой выше
container.innerHTML = sanitizedValue
```

Поддерживаются комментарии, начинающиеся с `//`, `#`, `/*`, `<!--` или SQL `--`. Пустая причина не принимается. Директива в строковом литерале не сработает. Вместо ID можно указать `*`, но делай так только если исключение действительно относится ко всем правилам на следующей строке.

Отчёт показывает количество подавленных комментариями находок отдельно от результатов, исключённых параметрами командной строки. Исходные файлы не изменяются.

## Встроенные проверки

| Правило | Область | Что ищет |
|---|---|---|
| `FS-SECRET-001` | Секреты | Похожие на учётные данные присваивания, Bearer-токены и маркеры приватных ключей |
| `FS-XSS-001` | XSS | Маркеры недоверенного ввода рядом с динамическими HTML sink |
| `FS-INJECT-001` | Инъекции | Динамическую сборку SQL и некоторые шаблоны shell-команд |
| `FS-PATH-001` | Path Traversal | Маркеры недоверенного ввода рядом с файловыми операциями |
| `FS-SSRF-001` | SSRF | Пользовательские значения рядом с серверными HTTP-запросами |
| `FS-CORS-001` | CORS | Отражение Origin в конфигурациях, где также включены credentials |
| `FS-DESER-001` | Десериализация | Некоторые небезопасные API десериализации |
| `FS-TLS-001` | TLS | Явное отключение проверки сертификатов |
| `FS-DEBUG-001` | Debug | Типичные настройки debug-режима |
| `FS-CRYPTO-001` | Криптография | Некоторые слабые схемы хеширования паролей и небезопасные источники случайности |

Проверки намеренно консервативны и в основном построчные. Они не строят полные деревья синтаксиса и не доказывают, что ввод контролируется атакующим.

## GitHub Code Scanning

FerroScout может создавать SARIF 2.1.0:

```bash
ferroscout scan . --format sarif > ferroscout.sarif
```

Необязательный workflow `.github/workflows/code-scanning.yml` собирает сканер, формирует SARIF и загружает его в GitHub Code Scanning. Workflow исключает `tests` и `src/rules`, где находятся синтетические тестовые примеры и шаблоны правил. Перед включением для чувствительного репозитория проверь workflow: SARIF содержит пути, номера строк и очищенные фрагменты доказательств.

## Приватность и работа с файлами

- CLI читает файлы локально и не выполняет сетевые запросы.
- Не запускает проверяемые программы, скрипты, shell-команды и сборочные процессы.
- Не изменяет и не удаляет проверяемые файлы.
- Пропускает символические ссылки при обходе и отклоняет симлинк в качестве цели сканирования.
- Пропускает бинарные файлы и файлы больше установленного лимита (по умолчанию 2 МиБ, максимум 16 МиБ).
- Распознаёт распространённые расширения исходников и конфигураций, а также отдельные файлы `.env`, `Dockerfile`, `.http` и `.har`.
- По умолчанию пропускает `.git`, `target`, `node_modules`, `vendor`, `dist` и виртуальные окружения.
- Маскирует значения, похожие на секреты, в доказательствах. Маскирование эвристическое; не добавляй секреты в репозиторий.

## Ограничения

FerroScout использует регулярные выражения и контекст соседних строк. Он не выполняет полный AST-анализ, межпроцедурный или межфайловый taint analysis, анализ конфигурации фреймворков, динамические проверки или анализ авторизации. Надёжное обнаружение IDOR не заявляется. Совпадение правила требует контекста, а отсутствие совпадений не доказывает безопасность.

## Разработка

```bash
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

Используй только синтетические тестовые данные. Не добавляй настоящие пароли, токены, приватные ключи и пользовательские данные. Перед pull request прочитай [CONTRIBUTING.md](CONTRIBUTING.md).

## Файлы проекта

- [История изменений](CHANGELOG.md)
- [Политика безопасности](SECURITY.md)
- [Как внести вклад](CONTRIBUTING.md)
- [Поддержка](SUPPORT.md)
- [Сообщить об ошибке](https://github.com/abduforge/FerroScout/issues/new/choose)
- [Обсуждения](https://github.com/abduforge/FerroScout/discussions)

## Лицензия

MIT. См. [LICENSE](LICENSE).
