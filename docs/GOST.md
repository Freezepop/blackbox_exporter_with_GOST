# Поддержка ГОСТ TLS в blackbox_exporter

Основная документация проекта находится в [README.md](../README.md).

Этот репозиторий — форк [Prometheus blackbox_exporter](https://github.com/prometheus/blackbox_exporter), который сохраняет штатную работу HTTP-проб и автоматически повторяет несовместимый TLS handshake через встроенный OpenSSL с ГОСТ-криптографией.

Форк не добавляет в `blackbox.yml` параметр вроде `gost: true`: тип TLS определяется по результату первого handshake. Обычные HTTPS-сайты обслуживает стандартный `crypto/tls` Go, а ГОСТ backend используется только после характерной ошибки несовместимости протокола или cipher suite.

## Состояние этой версии

| Компонент | Версия |
|---|---:|
| blackbox_exporter upstream | 0.28.0, commit `5a059bee8d8ffa4e75947c5055fb0abeefc582e6` |
| Версия форка в бинарнике | `0.28.0-gost-auto` |
| Go | 1.26.4 |
| OpenSSL | 3.4.1 |
| gost-engine | 3.0.3 |
| go-openssl | 1.4.2 + локальные изменения |
| prometheus/common | 0.67.4 + локальное расширение transport API |
| ГОСТ release-платформы | Linux `amd64` и `arm64` |
| Стандартные платформы | Linux, Windows, macOS, DragonFly BSD, FreeBSD, NetBSD и OpenBSD (см. release workflow) |

Версии Go, OpenSSL и gost-engine закреплены в `scripts/build-gost-linux.sh`. Слово «последняя» относится к моменту подготовки текущей ревизии; сборка не подменяет версии автоматически, поэтому обновление получается воспроизводимым.

## Что отличается от оригинального blackbox_exporter

Штатные TCP, ICMP, DNS, gRPC и HTTP/3-пробы не изменены. Изменения относятся к HTTP/HTTPS-пробам без `use_http3: true`.

### Автоматический TLS fallback

Для каждого HTTPS-запроса сначала используется штатный transport blackbox_exporter на Go `crypto/tls`:

1. Если handshake успешен, запрос продолжается без участия OpenSSL.
2. Если сервер отвечает ошибкой совместимости TLS, первый transport закрывает неудачное соединение.
3. Запрос один раз повторяется на новом TCP-соединении через OpenSSL/gost-engine.
4. Ошибка второго backend либо HTTP-ответ возвращается обычной логике blackbox_exporter.

Fallback рассматривается при сообщениях об unsupported protocol/version, неизвестном или отсутствующем cipher suite, `handshake failure` либо `illegal parameter`. Он намеренно **не** запускается для DNS/TCP/timeout-ошибок и распознанных ошибок доверия сертификату или имени хоста.

Успешный переход виден в журнале:

```text
Standard TLS is incompatible; retrying with the GOST backend
```

Для ГОСТ handshake используются TLS 1.0–1.2 и следующие cipher suite:

```text
GOST2012-GOST8912-GOST8912
GOST2001-GOST89-GOST89
GOST2012-KUZNYECHIK-KUZNYECHIK
GOST2012-MAGMA-MAGMA
```

На fallback-пути принудительно используется HTTP/1.1. Обычный путь сохраняет штатные HTTP/1.1, HTTP/2 и TLS 1.0–1.3. HTTP/3 работает только через оригинальный QUIC/Go transport и в ГОСТ fallback не участвует.

### Метрики TLS

OpenSSL-соединение преобразуется в `tls.ConnectionState`, поэтому стандартные метрики blackbox_exporter продолжают работать:

```text
probe_http_ssl 1
probe_tls_version_info{version="TLS 1.2"} 1
probe_tls_cipher_info{cipher="GOST (OpenSSL engine)"} 1
probe_ssl_last_chain_info{...} 1
probe_ssl_earliest_cert_expiry ...
```

Если Go не сможет разобрать алгоритмы конкретного ГОСТ-сертификата, проверку цепочки и hostname всё равно выполнит OpenSSL. В таком случае поля сертификата и метрики срока действия могут отсутствовать, но доступность, версия TLS и cipher останутся доступны.

### Проверка сертификатов

При отсутствии `tls_config.ca` и `tls_config.ca_file` ГОСТ backend ищет системный CA bundle в таком порядке:

1. переменная окружения `SSL_CERT_FILE`;
2. `/etc/pki/tls/certs/ca-bundle.crt` — AlmaLinux/RHEL;
3. `/etc/ssl/certs/ca-certificates.crt` — Debian/Ubuntu.

`insecure_skip_verify: false` остаётся нормальным и рекомендуемым режимом. OpenSSL проверяет цепочку, а затем hostname/SAN.

Поддерживаются inline/file-параметры `ca`, `ca_file`, `cert`, `cert_file`, `key` и `key_file`. Secret Manager references `ca_ref`, `cert_ref` и `key_ref` на ГОСТ fallback пока не поддерживаются. На стандартном Go TLS пути они продолжают работать как в upstream.

### Изменённые и добавленные файлы

| Путь | Назначение |
|---|---|
| `prober/gost_tls.go` | автоматический выбор backend, OpenSSL dialer, TLS/сертификатные метаданные |
| `prober/http.go` | подключение fallback transport и безопасный экспорт метрик сертификата |
| `prober/tls.go` | имена ГОСТ cipher suite в метриках |
| `prober/gost_tls_test.go` | unit-тесты выбора backend |
| `prober/gost_engine_test.go` | локальный integration test ГОСТ TLS 1.0 и 1.2 |
| `third_party/go-openssl` | vendored go-openssl с поддержкой статической линковки и регистрации gost-engine |
| `third_party/prometheus-common` | vendored prometheus/common с опцией пользовательского `DialTLSContext` |
| `scripts/build-gost-linux.sh` | независимая от пакетного менеджера Linux-сборка ГОСТ-бинарника |
| `.github/workflows/ci-fork.yml` | CI стандартной и ГОСТ-сборки |
| `.github/workflows/release-fork.yml` | мультиплатформенные стандартные релизы и Linux ГОСТ-релизы |
| `.github/workflows/upstream-sync.yml` | проверка новых стабильных тегов upstream и создание update PR |
| `.github/workflows/release-after-upstream-sync.yml` | тег и release после merge проверенного sync PR |

В `go.mod` используются локальные `replace` для обоих каталогов `third_party`. Поэтому их необходимо хранить в Git вместе с проектом — без них форк не соберётся.

## Поддерживаемые сборки

Обычная сборка не включает ГОСТ-код и остаётся кроссплатформенной, как upstream. Она использует build tag по умолчанию и `CGO_ENABLED=0` в release workflow.

ГОСТ-вариант сейчас поддерживается на Linux `amd64` и `arm64`. Он требует нативную CGO-сборку, поскольку статически линкует OpenSSL и gost-engine. Windows/macOS-артефакты в релизе являются обычными сборками без ГОСТ: наличие файла для ОС не означает скрытой или непроверенной ГОСТ-поддержки.

## Требования к Linux-машине для ГОСТ-сборки

- Linux x86_64 либо arm64;
- выход в Интернет к `go.dev` и GitHub для первой сборки;
- установленный C/C++ toolchain, CMake, Perl, pkg-config, curl, Git и Python 3;
- несколько гигабайт свободного места;
- рекомендуется не менее 4 CPU.

CryptoPro CSP, лицензия CryptoPro и регистрация на сторонних сервисах не требуются.

## Сборка

На любом совместимом Linux с уже установленными зависимостями:

```bash
chmod +x ./scripts/build-gost-linux.sh
JOBS="$(nproc)" make build-gost
```

Скрипт выполняет следующие действия:

1. скачивает официальный архив закреплённой версии Go и проверяет SHA-256 по API `go.dev`;
2. клонирует закреплённый OpenSSL и собирает статические `libssl.a`/`libcrypto.a`;
3. клонирует gost-engine и собирает его как набор статических библиотек;
4. формирует локальный `pkg-config` файл;
5. запускает целевые unit/integration-тесты;
6. собирает blackbox_exporter с CGO и build tags `gost openssl_static openssl_gost`;
7. проверяет тип бинарника и создаёт SHA-256 файл.

Результат:

```text
dist/blackbox_exporter-gost
dist/blackbox_exporter-gost.sha256
```

Проверка:

```bash
./dist/blackbox_exporter-gost --version
file ./dist/blackbox_exporter-gost
ldd ./dist/blackbox_exporter-gost || true
sha256sum -c ./dist/blackbox_exporter-gost.sha256
```

Для статического ELF `ldd` должен сообщить, что бинарник не является динамически связанным. На целевой машине отдельные OpenSSL/gost-engine библиотеки не нужны.

### Повторная и чистая сборка

Промежуточные файлы хранятся в `.build-gost/<версии>-<архитектура>` и повторно используются. Версии входят в ключ каталога, поэтому изменение Go/OpenSSL/gost-engine не переиспользует несовместимый кэш. Чтобы изменить корневой каталог или степень параллелизма:

```bash
BLACKBOX_GOST_BUILD_DIR=/var/tmp/blackbox-gost-build \
BLACKBOX_GOST_DIST_DIR="$PWD/dist" \
JOBS=8 \
./scripts/build-gost-linux.sh
```

Для полностью чистой сборки удалите только явно выбранный build-каталог, затем снова запустите скрипт:

```bash
rm -rf -- "$PWD/.build-gost"
JOBS="$(nproc)" ./scripts/build-gost-linux.sh
```

`dist/` и `.build-gost/` добавлены в `.gitignore` и не должны коммититься. Бинарники лучше публиковать как Git Release вместе с `.sha256`.

## Автоматические сборки и релизы

В `.github/workflows/ci-fork.yml` два независимых задания:

- `standard` запускает полный `go test ./...` и обычную сборку без тега `gost`;
- `gost` собирает статический Linux ГОСТ-бинарник и запускает интеграционные тесты OpenSSL/gost-engine.

Workflow `.github/workflows/release-fork.yml` запускается по тегу вида `vX.Y.Z-gost.N`. Он создаёт один GitHub Release и прикладывает к нему:

- обычные upstream-совместимые архивы для Linux, Windows, macOS, DragonFly BSD, FreeBSD, NetBSD и OpenBSD;
- ГОСТ-архивы для Linux `amd64` и `arm64` с суффиксом `-gost`;
- отдельные SHA-256 файлы для каждого архива.

Пример выпуска:

```bash
git tag -a v0.28.0-gost.1 -m 'blackbox_exporter 0.28.0 with GOST TLS fallback'
git push origin v0.28.0-gost.1
```

Для ручной проверки workflow можно запустить через вкладку Actions → Fork release → Run workflow. При ручном запуске артефакты собираются и сохраняются в workflow run, но GitHub Release не создаётся.

GitHub-hosted ARM runner должен быть доступен репозиторию. Если GitHub не предоставляет `ubuntu-24.04-arm` для вашего типа репозитория, ARM job нужно перевести на собственный ARM64 runner; подмена его кросс-компиляцией невозможна без отдельного кросс-toolchain для CGO.

## Установка доверенного ГОСТ-УЦ на AlmaLinux 9

Установка backend сама по себе не делает неизвестный УЦ доверенным. Для строгой проверки сертификатов добавьте официальный корневой сертификат в системное хранилище.

Пример для ГОСТ-цепочки Минцифры 2025:

```bash
install -d -m 0700 /root/mincifry-ca/gost-2025
cd /root/mincifry-ca/gost-2025

curl -fL -o root-ca.zip \
  https://gu-st.ru/content/lending/android_russian_trusted_root_ca.zip

unzip -q root-ca.zip -d root

sha256sum root/russian_trusted_root_ca_gost_2025.cer
```

Ожидаемый SHA-256 сертификата:

```text
5b51db721b7c34958ed7432ae917a91297dd37508b2cae4f858ffbac6bc525ef
```

Установка:

```bash
openssl x509 \
  -inform DER \
  -in root/russian_trusted_root_ca_gost_2025.cer \
  -out russian_trusted_root_ca_gost_2025.pem

openssl x509 \
  -in russian_trusted_root_ca_gost_2025.pem \
  -noout -subject -issuer -dates -fingerprint -sha256

install -m 0644 \
  russian_trusted_root_ca_gost_2025.pem \
  /etc/pki/ca-trust/source/anchors/russian_trusted_root_ca_gost_2025.pem

update-ca-trust extract
```

Не используйте `insecure_skip_verify: true` в production вместо установки доверенного корня. Не добавляйте leaf-сертификаты отдельных сайтов в anchors.

## Конфигурация

Специальной ГОСТ-секции нет. Используется обычная конфигурация blackbox_exporter:

```yaml
modules:
  http_2xx:
    prober: http
    timeout: 30s
    http:
      preferred_ip_protocol: ip4
      follow_redirects: true
      enable_http2: true
      tls_config:
        insecure_skip_verify: false
```

Один и тот же модуль можно применять одновременно к стандартным и ГОСТ-сайтам.

Проверка файла:

```bash
./dist/blackbox_exporter-gost \
  --config.file=/etc/prometheus/blackbox.yml \
  --config.check
```

## Тестовый запуск рядом с production

```bash
./dist/blackbox_exporter-gost \
  --config.file=/etc/prometheus/blackbox.yml \
  --web.listen-address=127.0.0.1:19115 \
  --log.level=debug
```

Обычная TLS-цель:

```bash
curl -sS \
  'http://127.0.0.1:19115/probe?module=http_2xx&target=https%3A%2F%2Fexample.com%2F' |
grep -E 'probe_success|probe_http_status_code|probe_tls_version_info|probe_tls_cipher_info'
```

ГОСТ TLS-цель:

```bash
curl -sS \
  'http://127.0.0.1:19115/probe?module=http_2xx&target=https%3A%2F%2Feis.ahml.ru%2F' |
grep -E 'probe_success|probe_http_status_code|probe_http_ssl|probe_tls_version_info|probe_tls_cipher_info'
```

Ожидается `probe_success 1` в обоих случаях. Для обычной цели должен отображаться стандартный cipher, для ГОСТ-цели — ГОСТ cipher и TLS 1.0–1.2.

Расширенная диагностика:

```bash
curl -sS \
  'http://127.0.0.1:19115/probe?module=http_2xx&target=https%3A%2F%2Feis.ahml.ru%2F&debug=true'
```

## Установка как systemd-службы

Рекомендуется не заменять работающий бинарник до параллельного теста. Пример установки:

```bash
install -m 0755 \
  ./dist/blackbox_exporter-gost \
  /usr/local/bin/blackbox_exporter-gost

/usr/local/bin/blackbox_exporter-gost --version
```

Пример `/etc/systemd/system/blackbox_exporter-gost.service`:

```ini
[Unit]
Description=Prometheus Blackbox Exporter with automatic GOST TLS fallback
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=blackbox_exporter
Group=blackbox_exporter
ExecStart=/usr/local/bin/blackbox_exporter-gost \
  --config.file=/etc/prometheus/blackbox.yml \
  --web.listen-address=127.0.0.1:9115 \
  --log.level=info
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

Убедитесь, что пользователь службы может читать конфигурацию, CA bundle и файлы, указанные в `tls_config`:

```bash
systemd-analyze verify /etc/systemd/system/blackbox_exporter-gost.service
systemctl daemon-reload
systemctl enable --now blackbox_exporter-gost.service
systemctl --no-pager --full status blackbox_exporter-gost.service
journalctl -u blackbox_exporter-gost.service -n 100 --no-pager
```

## Обновление форка

Обновление состоит из двух независимых операций: переноса патчей на новую версию blackbox_exporter и планового обновления криптографических компонентов. Не следует просто выполнять `git pull` в production и пересобирать бинарник без тестов.

### Подготовка Git-репозитория

Сохраните официальный Prometheus как `upstream`, а собственный Git-сервер как `origin`:

```bash
git remote rename origin upstream
git remote add origin <URL-ВАШЕГО-РЕПОЗИТОРИЯ>
git fetch --all --tags
```

Закоммитьте текущий форк отдельным коммитом поверх тега upstream:

```bash
git add -A
git status --short
git commit -m 'Add automatic GOST TLS fallback'
git tag -a v0.28.0-gost.1 -m 'blackbox_exporter 0.28.0 with automatic GOST TLS fallback'
git push -u origin HEAD
git push origin v0.28.0-gost.1
```

Не добавляйте `dist/`, `.build-gost/` и старые экспериментальные бинарники.

После первой публикации разрешите GitHub Actions создавать pull request в настройках репозитория: Settings → Actions → General → Workflow permissions → Allow GitHub Actions to create and approve pull requests. Для release workflow нужны права на запись содержимого, уже указанные в YAML.

### Автоматическая проверка upstream

`.github/workflows/upstream-sync.yml` раз в сутки сравнивает `.upstream-version` с последним стабильным тегом Prometheus:

- если новой версии нет, workflow ничего не меняет;
- если тег появился и merge проходит, создаётся ветка `automation/upstream-X.Y.Z` и pull request;
- если возник конфликт, создаётся issue для ручного переноса.

Workflow намеренно не делает auto-merge: изменения transport API, зависимостей и TLS-кода требуют ревью. После merge проверенного PR workflow `release-after-upstream-sync.yml` автоматически создаёт тег `vX.Y.Z-gost.1` и через `workflow_dispatch` запускает обе release-матрицы и публикацию GitHub Release. Явный dispatch нужен потому, что обычный tag push, сделанный встроенным `GITHUB_TOKEN`, сам по себе не порождает следующий workflow run.

### Переход на новую версию blackbox_exporter

Рекомендуемый процесс — отдельная ветка и cherry-pick одного форк-коммита:

```bash
git fetch upstream --tags
git switch -c update/upstream-X.Y.Z vX.Y.Z
git cherry-pick <COMMIT-С-GOST-ПАТЧЕМ>
```

Наиболее вероятные конфликты будут в:

```text
go.mod
go.sum
prober/http.go
prober/tls.go
third_party/prometheus-common/config/http_config.go
```

После разрешения конфликтов обязательно:

1. проверить, не изменился ли API создания HTTP transport в `prometheus/common`;
2. сравнить новую upstream-версию `github.com/prometheus/common` с vendored-копией;
3. перенести `WithDialTLSContextFunc` в vendored-копию той же версии, которую требует новый upstream;
4. проверить логику redirect и ServerName в новом `prober/http.go`;
5. обновить версию blackbox_exporter в `-ldflags` и таблице выше;
6. выполнить чистую сборку и полный набор тестов.

Полезная последовательность после переноса:

```bash
rm -rf -- "$PWD/.build-gost"
JOBS="$(nproc)" ./scripts/build-gost-linux.sh

go test ./...          # если в PATH есть подходящая версия Go
go vet ./...           # дополнительная статическая проверка

./dist/blackbox_exporter-gost --config.file=/etc/prometheus/blackbox.yml --config.check
```

Затем повторите parallel-run тест стандартной и ГОСТ-цели. Только после этого создавайте новый тег, например `vX.Y.Z-gost.1`.

### Обновление Go, OpenSSL или gost-engine

Измените соответствующие значения по умолчанию в начале `scripts/build-gost-linux.sh` либо передайте их как переменные окружения:

```bash
GO_VERSION=... \
OPENSSL_VERSION=... \
GOST_ENGINE_VERSION=... \
JOBS="$(nproc)" \
./scripts/build-gost-linux.sh
```

После изменения версий скрипт автоматически выберет новый versioned build-каталог. Для принудительной полностью чистой сборки можно удалить общий кэш:

```bash
rm -rf -- "$PWD/.build-gost"
JOBS="$(nproc)" ./scripts/build-gost-linux.sh
```

Проверяйте как минимум:

- unit/integration-тесты из build-скрипта;
- обычный TLS 1.2/1.3 сайт;
- реальный ГОСТ TLS 1.2 сайт;
- строгую проверку сертификата;
- redirect между разными hostname;
- `basic_auth`, custom headers и proxy, если они используются в вашей конфигурации;
- отсутствие runtime-зависимостей через `ldd`.

### Обновление production-бинарника

Собирайте бинарник на build-хосте, проверяйте SHA-256 и устанавливайте атомарно через временное имя:

```bash
sha256sum -c blackbox_exporter-gost.sha256

install -m 0755 \
  blackbox_exporter-gost \
  /usr/local/bin/blackbox_exporter-gost.new

/usr/local/bin/blackbox_exporter-gost.new --version
/usr/local/bin/blackbox_exporter-gost.new \
  --config.file=/etc/prometheus/blackbox.yml \
  --config.check

mv -f \
  /usr/local/bin/blackbox_exporter-gost.new \
  /usr/local/bin/blackbox_exporter-gost

systemctl restart blackbox_exporter-gost.service
systemctl --no-pager --full status blackbox_exporter-gost.service
```

Перед обновлением сохраните предыдущий бинарник либо храните версионные файлы и переключайте symlink. Откат должен сводиться к возврату предыдущего проверенного бинарника и перезапуску службы.

## Ограничения и риски

- ГОСТ fallback применяется только к HTTP/HTTPS prober; это не общая замена TLS во всех prober.
- HTTP/3/QUIC с ГОСТ не поддерживается.
- ГОСТ backend использует HTTP/1.1 и TLS не выше 1.2.
- На ГОСТ-цели выполняются два handshake: сначала Go TLS, затем OpenSSL/GOST. Это добавляет одно неуспешное TCP/TLS соединение и небольшую задержку.
- Список текстовых ошибок, запускающих fallback, может потребовать обновления после изменения формулировок ошибок Go.
- `handshake failure` — общий TLS alert, поэтому fallback иногда может запускаться и для не-ГОСТ-сервера. Это не превращает неуспешную проверку в успешную: результат второго backend всё равно должен пройти TLS и HTTP-проверки.
- Secret Manager references `ca_ref`, `cert_ref`, `key_ref` не поддерживаются fallback backend.
- Vendored `go-openssl` и `prometheus/common` являются частью сопровождаемого патча; их нельзя без проверки заменить обычными upstream-модулями.
- Статическая линковка упрощает deployment, но обновление OpenSSL требует выпуска нового бинарника.
- Это независимый форк, не официальный релиз Prometheus и не сертифицированное СКЗИ. Он предназначен для мониторинга доступности, а не для задач, где законодательство требует сертифицированный криптопровайдер.

## Диагностика

### Fallback не запускается

Запустите probe с `debug=true` и посмотрите исходную ошибку Go TLS. Если это новая формулировка ошибки совместимости, её нужно осознанно добавить в `shouldTryGOST()` и покрыть тестом.

### `GOST ciphers are unavailable`

Бинарник собран без тегов `gost openssl_static openssl_gost` либо gost-engine не был статически зарегистрирован. Используйте `scripts/build-gost-linux.sh`/`make build-gost`, а не обычный `go build`.

### `certificate verify failed`

ГОСТ handshake уже работает, но отсутствует нужный корневой УЦ, сервер не передаёт промежуточный сертификат, истёк срок действия либо hostname не совпадает. Не лечите это постоянным `insecure_skip_verify: true`; проверьте цепочку и системный CA bundle.

### Обычный сайт перестал работать

Это не ожидаемое поведение: стандартный backend всегда вызывается первым. Сравните результат с оригинальным blackbox_exporter той же версии, включите `debug=true` и приложите обе трассировки к issue вашего форка.

### Проверка версии и linkage

```bash
blackbox_exporter-gost --version
file "$(command -v blackbox_exporter-gost)"
ldd "$(command -v blackbox_exporter-gost)" || true
```

## Лицензии и происхождение кода

Основной проект распространяется по Apache License 2.0. Vendored-зависимости сохраняют собственные `LICENSE`, `NOTICE` и сведения об авторах. При публикации форка не удаляйте эти файлы и явно указывайте, что проект основан на Prometheus blackbox_exporter, но не является официальным релизом Prometheus.

Ссылки:

- [Prometheus blackbox_exporter](https://github.com/prometheus/blackbox_exporter)
- [OpenSSL](https://github.com/openssl/openssl)
- [gost-engine](https://github.com/gost-engine/engine)
- [tarantool/go-openssl](https://github.com/tarantool/go-openssl)
- [официальная страница сертификатов Госуслуг](https://www.gosuslugi.ru/crt)
