d# 🌐 Domain Controller

Центральная панель управления доменами и reverse-proxy на базе **Nginx + Flask + Let's Encrypt**.

Один внешний IP → много доменов → автоматическая генерация Nginx-конфигов → выпуск SSL-сертификатов одной кнопкой.

---

## Возможности

| Функция | Описание |
|---------|----------|
| **Reverse Proxy** | HTTP и HTTPS проксирование по домену на внутренний IP:порт |
| **Frontend HTTPS** | Автоматический Let's Encrypt для домена |
| **Backend HTTPS** | Поддержка TLS-бэкендов (Proxmox, API и т.д.) |
| **WebSocket** | Поддержка WebSocket (чаты, WebRTC, real-time приложения) |
| **Stream TCP/UDP** | Проксирование TCP и UDP потоков (SIP, RTP, SSH и др.) через Nginx `stream {}` |
| **Веб-панель** | Добавление / редактирование / удаление маршрутов через GUI |
| **Группы** | Тегирование доменов по группам с фильтрацией |
| **Аудит** | Лог всех действий — кто, когда, что изменил |
| **Авторизация** | Логин / пароль для доступа к панели |
| **Nginx sync** | Автогенерация `domain-routes.conf` + `stream-routes.conf` + `nginx -t` + `reload` |
| **Auto-renew** | `certbot.timer` + deploy hook для автопродления сертификатов |
| **Dashboard** | Главная страница с графиками запросов, ошибок, топ доменов/IP |
| **Статистика** | Расширенная страница аналитики: 7 графиков, 8 таблиц, фильтры по времени и домену |
| **JSON-логи** | Nginx пишет access-логи в JSON для парсинга и хранения в PostgreSQL |
| **Dev Mode** | Тестовый запуск без Nginx/Certbot на локальной машине |

---

## Архитектура

```
Внешний IP (напр. 213.230.69.181)
    │
    ├── :80  ──► NAT ──► 10.100.10.250:80  (Nginx http)
    ├── :443 ──► NAT ──► 10.100.10.250:443 (Nginx http)
    └── :5060/udp ──► NAT ──► 10.100.10.250:5060 (Nginx stream)

Контроллер (10.100.10.250):
    ├── Nginx http {}     — HTTP/HTTPS reverse proxy (по домену)
    ├── Nginx stream {}   — TCP/UDP forward (по порту)
    ├── Flask-панель      — веб-интерфейс (порт 5000)
    ├── PostgreSQL        — хранение маршрутов, аудита и статистики
    ├── JSON-логи Nginx   — dc_access.json + dc_stream.json
    ├── Фоновый парсер    — автоматический сбор и очистка логов
    └── Certbot           — выпуск и обновление сертификатов

Примеры HTTP-маршрутов:
    nettech.uz         → 10.100.10.240:80   (HTTP backend)
    shop.nettech.uz    → 10.100.10.241:80   (HTTP backend + WebSocket)
    vm.nettech.uz      → 10.100.10.210:8006 (HTTPS backend, Proxmox)

Примеры Stream-маршрутов:
    :5060/udp          → 10.100.10.220:5060 (FreePBX SIP)
    :5061/tcp          → 10.100.10.220:5061 (SIP TLS)
    :10000-20000/udp   → 10.100.10.220      (RTP media)
```

### База данных — PostgreSQL

В production используется **только PostgreSQL**. SQLite остался в коде как fallback для локальной разработки (`DEV_MODE=1`) и unit-тестов — на сервере он не нужен.

**Конфигурация:**
- `DATABASE_URL=postgresql+psycopg2://dc_user:PASSWORD@127.0.0.1:5432/dc` в `.env`
- SQLAlchemy `pool_size=5, max_overflow=10, pool_pre_ping=True`
- Бэкапы — `pg_dump -Fc` (custom формат, `pg_restore`-friendly) с проверкой через `pg_restore --list`
- `_db_size_bytes()` использует `pg_database_size()` для мониторинга
- Помощники `_hour_bucket_sql()` / `_day_of_week_sql()` / `_hour_of_day_sql()` — для PG используют `to_char()` / `extract('dow')`

**install.sh** автоматически:
1. Ставит `postgresql postgresql-contrib libpq-dev`
2. Создаёт пользователя `dc_user` с автогенерированным паролем (`secrets.token_urlsafe(32)`)
3. Создаёт БД `dc OWNER dc_user`
4. Прописывает `DATABASE_URL` в `.env`
5. `db.create_all()` создаёт схему

**Миграция существующей SQLite-установки на PG:**

Скрипт `deploy/migrate-sqlite-to-pg.py` копирует все таблицы по чанкам, обновляет sequence'ы, проверяет counts 1:1. Использует флаг `DC_NO_BG_THREADS=1`, чтобы фоновый log-парсер не писал в БД во время копирования.

```bash
# 1. Ставим PG (если не стоит): sudo apt install postgresql
sudo systemctl enable --now postgresql
# 2. Создаём юзера и БД (через SQL-файл, чтобы пароль с спецсимволами не мешал)
sudo -u postgres psql <<EOF
CREATE USER dc_user WITH PASSWORD 'GENERATE_RANDOM_HERE';
CREATE DATABASE dc OWNER dc_user ENCODING 'UTF8' TEMPLATE template0;
EOF
# 3. Прописываем DATABASE_URL в .env (но сервис не перезапускаем!)
echo "DATABASE_URL=postgresql+psycopg2://dc_user:PASSWORD@127.0.0.1:5432/dc" | \
    sudo tee -a /opt/domain-controller/.env
# 4. Останавливаем приложение
sudo systemctl stop domain-controller
# 5. Запускаем миграцию (скрипт сам делает ensure_schema в PG, TRUNCATE, копирование, sequences)
sudo python3 /opt/domain-controller/deploy/migrate-sqlite-to-pg.py \
    --sqlite /opt/domain-controller/data.db \
    --pg 'postgresql+psycopg2://dc_user:PASSWORD@127.0.0.1:5432/dc'
# 6. Запускаем и проверяем
sudo systemctl start domain-controller
curl http://127.0.0.1:5000/healthz
sudo /opt/domain-controller/venv/bin/flask --app /opt/domain-controller/app.py doctor
# 7. Если всё ок — архивируем SQLite, чтобы случайно не использовать
sudo mv /opt/domain-controller/data.db /opt/domain-controller/data.db.archive-after-pg-migration
```

Этот переход уже выполнен на проде 10.100.10.250 — все ~340 тысяч строк скопированы без потерь, сервис работает на PG. Архивный SQLite остался в `/opt/domain-controller/data.db.archive-after-pg-migration` (78 МБ).

### Настройки через UI (`/settings`)

Константы, которые раньше были захардкожены в коде, теперь лежат в таблице `app_settings` и редактируются через `/settings` (admin-only). Настройки с in-memory кэшем TTL=60 сек.

Текущий список:
- **Retention (хранение логов)**:
  - `retention_access_logs_days` (default 30)
  - `retention_stream_logs_days` (default 30)
  - `retention_audit_logs_days` (default 365)
  - `retention_parser_errors_days` (default 30)
  - `retention_fail2ban_events_days` (default 30)
- **Security (rate-limit /login)**:
  - `login_max_failures` (default 10)
  - `login_window_sec` (default 600)
  - `login_lockout_sec` (default 600)
- **Intervals**:
  - `backend_health_interval_sec` (default 120)
  - `ssl_warning_threshold_days` (default 14)

Валидация с границами: retention-значения `1..365/1825` дней, rate-limit в разумных диапазонах. Изменения пишутся в `audit_logs` (`settings_update`). В будущем можно расширить список через `SETTING_DEFINITIONS` в коде — UI автоматически подхватит.

### Индексы

Composite индексы на `access_logs (timestamp, status)`, `access_logs (timestamp, server_name)`, `access_logs (timestamp, remote_addr)`, `stream_logs (timestamp, server_port)` — ускоряют `/api/stats/full` в десятки раз на миллионных таблицах. Создаются автоматически в `__table_args__` моделей.

### SQLite в DEV-режиме

При `DEV_MODE=1` (только локальная разработка / unit-тесты) — fallback на SQLite-файл `dev_data.db` рядом с `app.py`. На production-сервере SQLite **не используется** и не должен использоваться. PRAGMA-оптимизации (WAL, cache_size, mmap_size, temp_store) применяются только к SQLite-соединениям через event listener; для PG они автоматически пропускаются.

### Парсер логов и checkpoint

Фоновый поток читает `/var/log/nginx/dc_access.json` и `/var/log/nginx/dc_stream.json` инкрементально. Позиция чтения хранится в отдельной таблице `log_checkpoints` (а не в памяти процесса, как было раньше). Это даёт две гарантии:

- **Рестарт сервиса не вызывает перечитывание** — иначе парсер плодил бы массовые дубликаты в `access_logs` / `stream_logs`.
- **Детектируется ротация logrotate** по смене inode и **truncate** по уменьшению размера — в обоих случаях чтение начинается с нуля корректно.

При первом запуске (checkpoint отсутствует) парсер стартует с **конца файла** — это сознательный выбор, чтобы исторические мегабайты лога не шли в БД как свежие события.

### Очистка старых логов

`_cleanup_old_logs` удаляет записи старше 30 дней порциями по 5 000 строк (`synchronize_session=False`), чтобы не держать write-lock на БД. Отметка последнего запуска тоже лежит в `log_checkpoints` — cleanup не чаще раза в 24 часа, даже если фоновый поток тикает каждые 5 сек.

### Валидация ввода и безопасность

Все значения, попадающие в nginx-конфиг или в argv `certbot`, проходят regex-валидацию в `is_valid_domain` / `is_valid_host` / `is_valid_port` / `is_valid_ssl_path` — это защищает от config-injection (например, `domain="ex.com;}server{..."`) и от argv-injection в `certbot -d`. Порты 22, 25, 53, 5000, 5432, 8080 занесены в `RESERVED_PORTS` и не могут быть выбраны как `listen_port` маршрута.

Параметр `?next=...` на `/login` валидируется `is_safe_next_url` — принимаются только относительные URL (защита от open-redirect фишинга).

Session cookie: `HttpOnly` + `SameSite=Lax`.

### Отказоустойчивость nginx-reload

Если после сохранения маршрута в БД `nginx -t && systemctl reload nginx` упал, приложение автоматически **откатывает транзакцию**: на create — удаляет свежесозданный маршрут; на edit — восстанавливает из snapshot; на letsencrypt — сбрасывает `enable_https` и пути к сертификатам в прежнее состояние. Раньше при такой ошибке БД и nginx-конфиг расходились.

### DEV_MODE использует отдельную БД

В DEV_MODE приложение автоматически переключается на `dev_data.db` (а не на `data.db`). Случайно выставленный `DEV_MODE=1` на продовой машине больше не может забить боевую БД фейковыми записями.

### Безопасность панели

- **CSRF:** все POST-формы защищены самодельной проверкой (без зависимости от `flask-wtf`). Токен хранится в сессии, генерируется через `secrets.token_urlsafe(32)`, прикрепляется к каждой форме через `{{ csrf_token() }}`. Отсутствует или не совпадает → `400`. API-эндпоинты (`/api/*`) только читают — они исключены.
- **Rate-limit на /login:** `10` неудачных попыток за `10 минут` с одного IP → `429` с подсказкой сколько ждать. Счётчик in-memory, per-IP, потокобезопасный.
- **SECRET_KEY guard:** если `DC_PANEL_SECRET` не задан или равен дефолту (`change-me`) — приложение **отказывается стартовать** в non-DEV режиме. `install.sh` автогенерирует секрет через `secrets.token_urlsafe(64)`.
- **Session regenerate at login:** при успешном логине сессия очищается и создаётся заново — защита от session-fixation.
- **Open redirect:** `?next=…` в `/login` валидируется как относительный URL (`is_safe_next_url`).
- **Input validation:** `is_valid_domain` / `is_valid_host` / `is_valid_port` / `is_valid_ssl_path` применяются к любым значениям, попадающим в nginx-конфиг или `certbot -d`. Это закрывает config-injection и argv-injection.
- **Reserved ports:** `{22, 25, 53, 5000, 5432, 8080}` нельзя назначить как `listen_port` маршрута.
- **HTML-ограничения:** `maxlength`, `pattern`, `min`/`max` на полях форм — клиентская защита поверх серверной.
- **Secure cookie:** `HttpOnly` + `SameSite=Lax`. `MAX_CONTENT_LENGTH=1MB` на любой request.
- **/logout — POST-only** (раньше был GET, который можно было триггернуть через `<img>`).
- **Unique constraint на `domain_routes.domain`** — нельзя создать два маршрута с одинаковым доменом.

### Atomic nginx reload

`apply_all_configs()` теперь работает как мини-транзакция:

1. Генерирует новый `domain-routes.conf` и `stream-routes.conf` в памяти.
2. Создаёт `.rollback`-бэкапы действующих конфигов.
3. Атомарно подменяет файлы (`os.replace`, посекторный `fsync`).
4. `nginx -t` — если не прошёл → восстанавливает `.rollback`, поднимает `CalledProcessError`.
5. `systemctl reload nginx` — если не прошёл → восстанавливает и пытается сделать повторный reload на заведомо рабочем конфиге.
6. Удаляет `.rollback`.

В итоге: на диске никогда не остаётся «полу-записанного» или заведомо плохого конфига — если reload провалился, nginx продолжает работать на предыдущей версии.

### Healthcheck `/healthz`

Открытый (без авторизации) endpoint для мониторинга:

```json
{
  "ok": true,
  "checks": {"db": "ok", "parser_age_sec": 4},
  "dev_mode": false
}
```

HTTP `200` — всё хорошо. `503` — если БД не отвечает или парсер не тикал больше 5 минут. В `deploy/domain-panel.conf` `/healthz` явно разрешён для всех IP (`allow all;`).

### Кэш /api/stats/full

`/api/stats/full` — самый тяжёлый эндпоинт (35+ SQL-запросов, фронт дёргает раз в 30 сек на двух страницах). Поверх него лежит **in-process кэш с TTL 10 секунд** (ключ = range + since/until + domain). При параллельных запросах все, кроме первого, получают кэшированный результат мгновенно.

### Logrotate для nginx-логов

`deploy/dc-nginx-logs.logrotate` → `/etc/logrotate.d/dc-nginx-logs`. Ротирует `dc_access.json`/`dc_stream.json` ежедневно, хранит 14 дней, сжимает старые, шлёт `SIGUSR1` nginx'у (с fallback на `SIGHUP`) после ротации. Парсер корректно детектирует смену inode и подхватывает новый файл.

### Role-Based Access Control

Две роли: `admin` (полный доступ) и `viewer` (только чтение). Выражается через:

- Декоратор `@admin_required` — на мутирующих эндпоинтах (`/delete/...`, `/letsencrypt/...`, `/streams/delete/...`, `/users/...`).
- Проверка в теле функции на `/add`, `/edit`, `/streams/add`, `/streams/edit` (GET разрешён viewer'у — посмотреть форму, POST только admin).
- `session["role"]` заполняется при логине из `User.role`.
- Шаблоны: кнопки Edit/Delete/Let's Encrypt/«+ Домен»/«+ Stream» и раздел **Пользователи** скрыты от viewer'ов. У viewer в шапке — бейдж `viewer`.

Управление: через веб — `/users` (admin-only), либо CLI:
```bash
flask create-user bob            # интерактивно + по умолчанию admin
flask set-role bob viewer        # переключить в read-only
```

### API-токены

Stateless-авторизация для curl/cron/мониторинга. Toкен хранится как SHA-256 хэш, raw-значение видно один раз при создании.

```bash
flask token-create admin "grafana-scraper"  # показывает токен
curl -H "Authorization: Bearer <token>" http://panel:8080/api/stats/backends
flask token-list                            # список (без raw)
flask token-revoke 1                        # отозвать по ID
```

`login_required` декоратор автоматически пропускает запросы к `/api/*` либо по session-cookie, либо по Bearer-токену. Вне `/api/*` токены не работают (HTML-UI только через логин).

### Webhook-уведомления (опционально)

Если в `.env` задан `DC_WEBHOOK_URL=https://...`, приложение шлёт POST JSON при событиях: `certbot_failed`, `letsencrypt_nginx_failed`, `backend_down` (на переходе up→down), `ssl_expiring_soon` (при <14 дней, с дедупом per-domain). Payload:
```json
{"event":"backend_down","domain":"vm.nettech.uz","details":"10.103.10.254:443 — timeout","timestamp":"2026-04-23T...","host":"domain-controller"}
```
Доставка в отдельном daemon-thread, ошибки не роняют запрос. Подойдёт для Slack/Telegram/Discord incoming webhooks.

### Backend health-check

Фоновый TCP-ping каждых target_host:target_port раз в 2 минуты. Результат (up/down/error/checked_at) сохраняется в `DomainRoute.last_health_*`. Виджет на dashboard показывает актуальное состояние; `/api/stats/backends` отдаёт JSON; `/metrics` выдаёт `dc_backend_up{domain,target}`. На переходе up→down триггерится webhook.

### SSL expiry мониторинг

`openssl x509 -noout -enddate` на всех `enable_https` маршрутах. Результат кэшируется в памяти на 5 мин. Виджет на dashboard с цветовыми статусами (ok/warning 30д/critical 7д/expired); `/api/stats/ssl` — JSON; `/metrics` — `dc_ssl_days_left{domain}`. При <14 дней шлётся webhook-уведомление (дедуп per-domain).

### Dead-letter для парсера

Битые JSON-строки nginx-лога попадают в таблицу `parser_errors` (до 10 000 записей, самодедуп-лимит) вместо молчаливого пропуска. Видны в `flask doctor` и на `/metrics` (`dc_parser_errors_total`). Автоматически чистятся старше 30 дней.

### Retention

- `access_logs`, `stream_logs` — 30 дней (`_cleanup_old_logs(days=30)`)
- `parser_errors` — 30 дней
- `audit_logs` — **365 дней** (история действий админов хранится дольше)

Cleanup запускается не чаще раза в сутки (отметка в `log_checkpoints.cleanup_last_run`), удаление батчами по 5000 строк без блокировки.

### Prometheus /metrics

Стандартный text-format на `GET /metrics` — без внешних зависимостей (не тянем `prometheus_client`). Метрики: `dc_up`, `dc_uptime_seconds`, `dc_domain_routes_total`, `dc_stream_routes_total`, `dc_users_total`, `dc_api_tokens_total`, `dc_access_logs_total`, `dc_stream_logs_total`, `dc_parser_errors_total`, `dc_db_size_bytes`, `dc_disk_free_bytes`, `dc_parser_checkpoint_age_seconds{source}`, `dc_backend_up{domain,target}`, `dc_ssl_days_left{domain}`, `dc_requests_last_hour_total{status,class}`.

Защита: если в `.env` задан `DC_METRICS_TOKEN`, scraper должен слать `Authorization: Bearer <token>`. Иначе открыт (рассчитано на LAN-only через nginx whitelist).

### Бэкапы

`deploy/backup.sh` + systemd timer `domain-controller-backup.timer` (03:15 UTC ежедневно). Использует `pg_dump -Fc` (custom-формат, сжатый, можно делать селективное восстановление через `pg_restore`). Каждый дамп проверяется через `pg_restore --list` — битый удаляется и скрипт возвращает ненулевой код. Хранится 14 снимков в `/opt/domain-controller/backups/` с правами `700` на директории и `600` на файлах.

Восстановление из дампа:
```bash
sudo systemctl stop domain-controller
# Полный restore (DROP всех таблиц + создание заново + загрузка данных)
sudo -u postgres pg_restore --clean --if-exists -d dc \
    /opt/domain-controller/backups/dc.pg.YYYYMMDD-HHMMSS.dump
sudo systemctl start domain-controller
curl http://127.0.0.1:5000/healthz
```

### Fail2ban

`deploy/fail2ban-dc.jail` + `deploy/fail2ban-dc.filter` ловят HTTP 429 на `/login` в `/var/log/nginx/access.log`. После 5 таких за 10 минут IP блокируется iptables на 1 час. Стандартный `sshd` jail активируется автоматически при установке пакета — это важно для защиты SSH от брутфорса (rate-limit панели его не покрывает).

### Temporary pause jail

Админ может **приостановить** jail на 15 мин / 1 ч / 6 ч / 24 ч — jail автоматически возобновится по истечении.

**Механика:**
- Запись в таблицу `jail_pauses` (jail_name, paused_until, paused_by, reason)
- `fail2ban-client stop <jail>` — jail полностью убирается из fail2ban, iptables-правила этого jail'а удаляются, **все забаненные через него IP снимаются**
- Фоновый поток раз в цикл (5-10 сек) проверяет: если `paused_until < now` → `fail2ban-client start <jail>` + удаляет запись
- Если сервер/fail2ban рестартанёт — наш поток увидит активную запись и снова сделает stop

**Разрешено только для `dc-404-flood` и `domain-controller`.** `sshd` и `dc-manual` слишком критичны для отключения через UI — если очень надо, правим `/etc/fail2ban/jail.d/*.conf` + `systemctl reload fail2ban`.

**UI:** вкладка «Правила» → на каждой карточке jail'а 4 кнопки (15м/1ч/6ч/24ч) + prompt на причину. У приостановленного — жёлтый баннер «Возобновить сейчас». Все операции → audit_logs (`firewall_jail_pause`, `firewall_jail_resume`).

### fail2ban.log парсер + реальная история банов

До этого «История банов» в Firewall показывала только **ручные** ban/unban из audit_logs. Теперь есть полная картина.

**Как работает:**
- Модель `FailbanEvent(timestamp, jail, action, ip)` — действия Ban / Unban / Restore
- Парсер `_parse_fail2ban_log` читает `/var/log/fail2ban.log` инкрементально (тот же механизм что для nginx — checkpoint в `log_checkpoints`, детект ротации по inode)
- Regex: `... fail2ban.actions [PID]: NOTICE [<jail>] Ban|Unban|Restore Ban <IP>`
- Retention 30 дней (как другие логи)
- Индекс `(timestamp, jail)` для быстрых агрегатов по графикам

**Endpoint `/api/firewall/timeline`** теперь агрегирует из `fail2ban_events` — график в Firewall → Обзор показывает **все** баны (ручные и автоматические), а не только ручные.

На первом запуске checkpoint инициализируется в конец файла (`file_size`) — исторические Ban/Unban не копируются в БД, чтобы не было дублей. Только новые события начиная с сегодня.

### Per-domain drill-down

На странице `/statistics` в вкладках **Домены** и **Health** каждая строка таблицы теперь кликабельна. Клик открывает новую вкладку «Детали» (появляется в sidebar с именем домена в бейдже), с детальной статистикой за 24ч:

- 4 big-metric'а: запросов, ошибок (+ error rate), avg time, unique IP
- Timeline запросов по часам
- HTTP-статусы donut
- Топ-10 URI с avg_time
- Топ-10 IP с last_seen

Endpoint `/api/stats/domain/<name>` расширен — теперь возвращает `unique_ips`, `avg_time` для URI и `last_seen` для IP.

### UI-навигация: sidebar + вкладки

Две самые насыщенные страницы — `/firewall` и `/statistics` — переделаны под **левую sidebar с внутренними вкладками**. Все данные грузятся одним AJAX-запросом, переключение между секциями — мгновенное (CSS `display: none/block`), URL-фрагмент `#tab=name` для deep-linking.

**Firewall** — 5 вкладок:
1. **Обзор** — 4 big-metric'а (банов сейчас / total / ботов отбито 24ч / UZ CIDRs) + bar-chart ручных bans/unbans по часам за сутки + последние 5 событий
2. **Правила** — read-only карточки по каждому jail'у с явно указанными **портами**, которые он блокирует (после бага с `domain-controller` где port=8080, стало важно видеть это сразу)
3. **Blocked IP** — с фильтрами: по jail'у, по типу (manual/auto, определяется по audit_logs), по географии (UZ / не-UZ), поиск по IP. Экспорт CSV
4. **Allowlist** — то же что раньше
5. **История** — с фильтрами по action/user + CSV-экспорт

**Statistics** — 8 вкладок:
1. **Обзор** — 8 big-metrics с **дельтами** (Δ% vs предыдущий период) + успех/ошибки bar + timeline + пиковый час + HTTP-статусы
2. **Домены** — таблица Health-score по каждому домену (`100 - error_rate*2 - avg_time_penalty - backend_down_penalty`) + топ доменов + avg response time bar-chart
3. **Трафик** — Throughput timeline МБ/час + распределение размеров ответов + HTTP/HTTPS split + топ URI
4. **Клиенты** — Desktop/Mobile/Bot/API donut + топ User-Agents + топ IP с % и прогресс-барами
5. **География** — UZ vs World (считается по `uz.zone.cache` из 205 CIDR от ipdeny.com), donut + numbers по запросам и уникальным IP
6. **Производительность** — response time distribution + самые медленные запросы + **heatmap активности день недели × час** (видно пиковые часы)
7. **Ошибки** — HTTP-методы donut + **топ-10 IP генерирующих больше всего 4xx/5xx** (обычно сканеры) + проблемные URI + последние ошибки
8. **Stream** — TCP/UDP статистика (как раньше)

### Новые API endpoints для статистики

| Endpoint | Что возвращает |
|---|---|
| `GET /api/stats/comparison?hours=24` | текущий vs предыдущий период, delta_pct |
| `GET /api/stats/heatmap` | matrix 7×24 (день недели × час) за последние 7 дней |
| `GET /api/stats/geography` | UZ vs World по запросам и уникальным IP за 24ч |
| `GET /api/stats/throughput` | байты/час за 24ч |
| `GET /api/stats/response-size` | distribution размеров ответов |
| `GET /api/stats/domain-health` | health-score per domain с учётом backend up/down |
| `GET /api/stats/top-error-ips` | топ-10 IP по количеству 4xx/5xx, с UZ-флагом |
| `GET /api/firewall/timeline` | ручные bans/unbans по часам за 24ч |

Все используют composite-индексы на `access_logs(timestamp, status)` / `(timestamp, server_name)` / `(timestamp, remote_addr)` — быстрые даже на сотнях тысяч строк.

### Fix: access_log в server{}

`access_log` был внутри `location /` — это значит `return 444` от `if ($bad_bot_ua)` в scope `server{}` не логировался. Метрика `bot_blocked_24h` всегда показывала 0. Теперь `access_log` вынесен на уровень `server{}` — все ответы (включая 444) попадают в `dc_access.json`, метрика реально растёт.

### Разница между jail'ами fail2ban

**Важно понимать, как fail2ban блокирует трафик.** Каждый jail в своей конфигурации имеет директиву `port` — и iptables-правило создаётся только для этих портов. IP, забаненный в jail с `port = 8080`, **продолжит открывать сайты** на 80/443 — это не баг, это как устроен fail2ban.

| Jail | Порты | Назначение |
|---|---|---|
| `dc-manual` | **все** (`iptables-allports`) | Ручной бан через UI — полная блокировка IP. **Выбирать по умолчанию** |
| `dc-404-flood` | 80, 443 | Авто-бан за 404-флуд на публичных сайтах |
| `domain-controller` | 8080 | Авто-бан за брутфорс `/login` (только админ-панель) |
| `sshd` | 22 | SSH brute-force |

В UI **`/firewall` → Ручной бан** селектор jail'а по умолчанию выставлен на `dc-manual`. Если хотите **разом отрезать IP от сервера** — выбирайте именно его.

Проверить кого и на каких портах банит iptables:
```bash
sudo iptables -L -n | grep -B1 -A3 'Chain f2b-'
```

### Firewall / страница `/firewall`

Отдельная вкладка для admin'ов, собирает всю защиту под одним capot'ом:

- **Сводка**: сколько IP заблокировано сейчас, сколько всего банов с рестарта fail2ban, сколько ботов отбил nginx за 24 часа (status=444), сколько CIDR в узбекском allowlist.
- **Список активных jail'ов**: имя, текущие/всего банов, параметры `maxretry/findtime/bantime`. Настройки — read-only: управляются через `/etc/fail2ban/*`, из UI не меняются (это осознанно — чтобы нельзя было «кликом» отключить защиту по ошибке).
- **Заблокированные IP**: таблица с кнопкой **Unban**. У каждого IP бейджи: **UZ** (если он в узбекском пуле — подсказка что возможно задет CGNAT-клиент), **private** (RFC1918).
- **Ручной ban**: форма с IP, выбором jail'а и полем «Причина» → запись в `audit_logs`. Защищено от самоблока (свой IP, RFC1918). Узбекские IP требуют **явного подтверждения** через отдельный чекбокс — защита от случайного блока реального клиента.
- **История**: последние 100 действий `firewall_manual_ban` / `firewall_unban` из audit_logs (fail2ban сам историю не хранит, а мы сохраняем в БД).

Авто-обновление каждые 30 сек. CSRF на всех POST. Все ban/unban идут в audit-лог с именем админа.

Под капотом — тонкий subprocess-wrapper над `fail2ban-client` с whitelist'ом аргументов (никакого `shell=True`), timeout 10 сек, regex-валидация имён jail'ов и IP (stdlib `ipaddress`).

### Allowlist доступа к панели

Whitelist IP, которые могут заходить на `:8080`, теперь управляется из БД (таблица `ip_allowlist`) и редактируется через UI на странице **Firewall**. Раньше эти строки правились руками в `/etc/nginx/sites-available/domain-panel.conf`.

**Как работает:**
- `generate_panel_config()` строит весь файл панели из записей БД + стандартных защит (slowloris-таймауты, security headers, rate-limit zones).
- `apply_all_configs()` пишет его атомарно (`.rollback` бэкап + `os.replace` + `nginx -t` + reload + rollback при ошибке), вместе с `domain-routes.conf` и `stream-routes.conf`.
- На первом запуске (пустая таблица) seed кладёт `10.0.0.0/8` + `127.0.0.1/32` — минимум для внутренней сети.

**UI (секция на `/firewall`):**
- Таблица записей с колонкой «Комментарий» и бейджем «вы здесь» у CIDR, покрывающего ваш IP
- Форма добавления: принимает одиночный IP (`1.2.3.4` → `/32`), полный CIDR (`10.0.0.0/8`), IPv6
- Валидация через stdlib `ipaddress.ip_network(..., strict=False)` — принимает host-bits
- Кнопка удаления с защитой от **self-lockout**: если CIDR покрывает ваш IP и нет другого покрывающего — нужно двойное подтверждение
- Защита от «удалить всё»: минимум одна запись должна остаться (иначе `deny all;` закроет всех)
- Все изменения → audit_log: `allowlist_add`, `allowlist_remove`

**Fallback:** если кто-то всё же удалил все записи через SQL напрямую, генератор вставляет `allow 10.0.0.0/8; # fallback` — чтобы не превратить `deny all;` в «заперто на замок».

В форме HTTP-маршрута появился чекбокс **«Bot protection»** (по умолчанию **включен**). Управляет тем, добавлять ли `include /etc/nginx/snippets/bot-protect.conf;` в соответствующий `server{}`. Выключают для публичных сайтов, где могут ходить «странные» легитимные боты (SEO-пауки, Googlebot/YandexBot, собственные скрипты), которые могли бы попасть под нашу регулярку.

На карточке [list.html](templates/list.html) у таких маршрутов появляется серый бейдж **«Bot-protect OFF»** — видно с первого взгляда.

### Ежемесячное обновление UZ CIDR

`deploy/domain-controller-uz-cidrs.timer` + `.service` — запускают `apply-uz-cidrs.sh` 1 числа каждого месяца в 03:45 UTC (± случайные 30 минут). IPdeny выкладывает новый список сетей по стране, а у нас он автоматически подтягивается и обновляет `ignoreip` в `dc-404-flood`. Защита от CGNAT-банов остаётся актуальной без ручного вмешательства.

### Bot-protection для проксируемых доменов

Мягкий фильтр для снижения нагрузки от сканеров (sqlmap, nikto, masscan, zgrab, Censys, Shodan, BinaryEdge и похожие). Два слоя:

**Слой 1 — nginx UA-блок.** Глобальная `map $http_user_agent $bad_bot_ua { ... }` в `/etc/nginx/conf.d/10-bot-protection.conf` + snippet `/etc/nginx/snippets/bot-protect.conf` с `if ($bad_bot_ua) { return 444; }`, подключаемый в каждый `server{}` проксируемых доменов (генерируется автоматически в `generate_nginx_config`). 444 обрывает TCP без ответа — скан уходит быстрее, и мы не тратим body-трафик. Certbot UA не содержит scanner-паттернов, поэтому продление сертификатов не ломается.

**НЕ блокируем**: curl, wget, python-requests, Go-http-client (легитимные клиенты), пустой UA (много реальных скриптов без него). Блокируем только явные pentest-тулзы и recon-сервисы.

**Слой 2 — fail2ban 404-flood.** `deploy/fail2ban-dc-404.{filter,jail}` ловят 50+ четырёхсоток с одного IP за 5 минут в `/var/log/nginx/dc_access.json` (JSON-лог парсится regex'ом `"remote_addr":"<HOST>".*"status":404`). Ban iptables на 1 час.

**UZ allowlist против CGNAT.** `deploy/apply-uz-cidrs.sh` скачивает список IP-пула Узбекистана с [ipdeny.com/ipblocks/data/countries/uz.zone](https://www.ipdeny.com/ipblocks/data/countries/uz.zone) (205 CIDR) и собирает финальный `/etc/fail2ban/jail.d/dc-404-flood.conf` с `ignoreip`, включающим весь UZ. Это защищает от случайных банов реальных клиентов UzTelecom/Beeline/Ucell/Sarkor, которые сидят за CGNAT и делят IP со сканерами. Кэш в `/opt/domain-controller/deploy/uz.zone.cache` — работает и без сети.

Перезапускать вручную после изменения политики: `sudo /opt/domain-controller/deploy/apply-uz-cidrs.sh`.

Проверка:
```bash
# scanner UA — должен оборвать TCP
curl -H 'User-Agent: sqlmap/1.7' https://sub.nettech.uz/
# curl: (92) HTTP/2 stream 1 was not closed cleanly: PROTOCOL_ERROR — ОК

# обычный UA — работает
curl -H 'User-Agent: Mozilla/5.0' https://sub.nettech.uz/login  # → 200

# статус 404-flood jail
sudo fail2ban-client status dc-404-flood
```

### Unit-тесты

28 тестов в `tests/test_app.py` на stdlib `unittest` (без pytest):

```bash
DEV_MODE=1 venv/bin/python -m unittest tests.test_app -v
```

Покрывают: валидаторы (domain/host/port/ssl/next-url), генерацию nginx-конфига, helpers (`_utcnow`, `_safe_int/float`, `_parse_ts`, `_atomic_write`), хэш API-токена, CSRF-защиту, `/healthz`, `/metrics`. Каждый тест изолирован через `drop_all + create_all`.

### Certbot auto-renewal

`certbot.timer` от пакета certbot запускается дважды в день. Deploy-hook `/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh` вызывает `systemctl reload nginx` после успешного продления. Прошедший `certbot renew --dry-run` на проде показал успешное обновление всех 7 сертификатов.

---

## Структура проекта

```
/opt/domain-controller/
├── app.py                       # Flask-приложение (бизнес-логика, модели, роуты)
├── wsgi.py                      # WSGI entry-point (gunicorn / uwsgi)
├── gunicorn.conf.py             # Конфиг gunicorn (workers=1, threads=4, gthread)
├── requirements.txt             # Python-зависимости
├── .env                         # DC_PANEL_SECRET, LETSENCRYPT_EMAIL, DEV_MODE (chmod 600)
├── dev_data.db                  # SQLite только для DEV_MODE (на проде нет — там PostgreSQL)
├── templates/
│   ├── base.html                # Базовый layout + навигация
│   ├── login.html               # Страница входа
│   ├── dashboard.html           # Дашборд (главная) с SSL/backend widgets
│   ├── statistics.html          # Расширенная страница статистики
│   ├── list.html                # Список HTTP-маршрутов
│   ├── form.html                # Форма HTTP-маршрута
│   ├── streams_list.html        # Список TCP/UDP stream-маршрутов
│   ├── stream_form.html         # Форма stream-маршрута
│   ├── logs.html                # Аудит-логи
│   └── users.html               # Управление пользователями и API-токенами (admin only)
├── tests/
│   └── test_app.py              # 28 unit-тестов (stdlib unittest, без pytest)
├── deploy/
│   ├── install.sh               # Автоустановщик для свежего сервера
│   ├── env.example              # Шаблон .env (WEBHOOK_URL, METRICS_TOKEN и т.д.)
│   ├── domain-controller.service            # systemd unit (gunicorn + hardening)
│   ├── domain-controller-backup.service     # oneshot сервис бэкапа БД
│   ├── domain-controller-backup.timer       # ежедневный бэкап 03:15 UTC
│   ├── backup.sh                            # online-snapshot + gzip + rotate 14d
│   ├── domain-panel.conf                    # nginx frontend (whitelist + rate-limit + headers)
│   ├── dc-nginx-logs.logrotate              # logrotate для dc_*.json
│   ├── fail2ban-dc.jail                     # fail2ban jail для 429 на /login
│   └── fail2ban-dc.filter                   # regex для фильтра
└── venv/                        # Python virtual environment
```

---

## Статистика и мониторинг

### Dashboard (`/`)

Главная страница отображает сводку за последние 24 часа:

- **Карточки метрик**: запросы, уникальные IP, ошибки, среднее время ответа
- **Stream-метрики**: сессии, трафик IN/OUT
- **Графики**: запросы по часам, HTTP-статусы (doughnut), топ домены (bar)
- **Таблицы**: топ IP-адресов, последние ошибки
- Автообновление каждые 30 сек

### Страница Статистики (`/statistics`)

Расширенная аналитика с фильтрами:

| Фильтр | Описание |
|--------|----------|
| **Время** | 1ч / 6ч / 24ч / 3 дня / Неделя / Месяц / Кастомный |
| **Домен** | Фильтрация по конкретному домену |

**Виджеты (7 графиков + 8 таблиц):**

- Успешные vs неуспешные запросы (timeline)
- HTTP-статусы (doughnut)
- Методы запросов GET/POST/PUT/DELETE (doughnut)
- HTTP vs HTTPS (doughnut)
- Клиенты: Desktop / Mobile / Bot / API (doughnut)
- Время ответа: < 100ms / 100-500ms / 500ms-1s / > 1s (doughnut)
- Avg/Max время ответа по доменам (bar)
- Топ домены, URI, IP-адресов, User-Agent (таблицы)
- Самые медленные запросы, самые проблемные URI (таблицы)
- Последние ошибки с деталями (таблица)
- Stream TCP/UDP: порт, сессии, байты, duration (таблица)

### Логи Nginx

Приложение автоматически настраивает Nginx на запись логов в JSON-формат:

```
/var/log/nginx/dc_access.json   — HTTP-логи
/var/log/nginx/dc_stream.json   — Stream TCP/UDP-логи
```

Фоновый поток парсит эти файлы каждые **5 секунд** и сохраняет в PostgreSQL.
Срок хранения настраивается через `/settings` (по умолчанию 30 дней для access/stream, 365 для audit).

> **Важно**: Nginx должен иметь права на запись в `/var/log/nginx/`. Это стандартная настройка для большинства дистрибутивов.

### API Endpoints

| Endpoint | Описание |
|----------|----------|
| `GET /api/stats/overview` | Сводка за 24ч |
| `GET /api/stats/timeline?hours=24` | Запросы по часам |
| `GET /api/stats/status-codes` | Распределение HTTP-статусов |
| `GET /api/stats/domains` | Статистика по доменам |
| `GET /api/stats/top-ips?limit=10` | Топ IP-адресов |
| `GET /api/stats/top-uris` | Топ URI |
| `GET /api/stats/errors?limit=15` | Последние ошибки |
| `GET /api/stats/streams` | Stream TCP/UDP статистика |
| `GET /api/stats/full?range=24h` | Полная статистика с фильтром |

Параметр `range`: `1h`, `6h`, `24h`, `3d`, `7d`, `30d` или `custom` с `since=ISO&until=ISO`.
Опционально: `&domain=example.com` для фильтрации по домену.

---

## Быстрый старт (Dev Mode)

Для тестирования на своей машине **без Nginx и Certbot**:

```bash
# 1. Клонирование
git clone https://github.com/dismoilov/DomainController.git
cd DomainController

# 2. Python venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Инициализация БД
DEV_MODE=1 flask --app app.py init-db

# 4. Создание пользователя (введите пароль)
DEV_MODE=1 flask --app app.py create-user admin

# 5. Запуск
DEV_MODE=1 python app.py
```

Панель откроется: **http://127.0.0.1:5000**

В Dev Mode:
- Nginx не вызывается (`nginx -t`, `systemctl reload` — пропускаются)
- Certbot не вызывается (Let's Encrypt имитируется)
- Конфиги пишутся в папку проекта: `dev_domain-routes.conf`, `dev_stream-routes.conf`
- Flask запускается с `debug=True` (в Production — `debug=False`, debugger отключён)

---

## Установка на сервер (Production)

### Быстрый путь (автоматический)

Все шаги ниже собраны в `deploy/install.sh` — идемпотентный скрипт:

```bash
sudo mkdir -p /opt/domain-controller
sudo git clone https://github.com/dismoilov/DomainController.git /opt/domain-controller
cd /opt/domain-controller
sudo ./deploy/install.sh
```

Скрипт делает 9 шагов:
1. Ставит пакеты: `nginx`, `certbot`, `python3-venv`, `logrotate`, `fail2ban`, `openssl`, **`postgresql postgresql-contrib libpq-dev`**
2. Создаёт venv и `pip install -r requirements.txt` (включая `psycopg2-binary`)
3. **PostgreSQL**: создаёт пользователя `dc_user` с автогенерированным паролем (32 байта `secrets.token_urlsafe`), создаёт БД `dc OWNER dc_user`
4. Копирует `deploy/env.example` → `/opt/domain-controller/.env`, автогенерирует `DC_PANEL_SECRET`, подставляет `DATABASE_URL` с настоящим паролем PG
5. Создаёт ACME webroot `/var/www/certbot`
6. Подключает `include /etc/nginx/stream-routes.conf` в `nginx.conf`, кладёт пустые `domain-routes.conf` и `stream-routes.conf`
7. Кладёт `domain-panel.conf` (с allow-листом — отредактировать!), глобальный `bot-protection.conf`, snippet `bot-protect.conf`
8. Устанавливает systemd-юниты (`domain-controller.service`, `domain-controller-backup.{service,timer}`, `domain-controller-uz-cidrs.{service,timer}`), `logrotate.d/dc-nginx-logs`, fail2ban-фильтры/jail'ы; запускает `apply-uz-cidrs.sh` для UZ-allowlist
9. Инициализирует схему БД через `flask init-db`

После установки — действовать по подсказкам скрипта (отредактировать allow-list в nginx, создать пользователя через `flask create-user`, `systemctl enable --now domain-controller`).

### Предпосылки

- **ОС:** Ubuntu 24.04 (или совместимый Debian-based дистрибутив)
- **Внешний IP** с проброшенными портами:
  - `80/tcp → <IP контроллера>:80`
  - `443/tcp → <IP контроллера>:443`
  - Дополнительные порты для stream-маршрутов (SIP, RTP и т.д.)
- **DNS:** A-записи доменов указывают на внешний IP

---

### Ручной путь (по шагам)

### 1. Системные пакеты

```bash
sudo apt update && sudo apt upgrade - y 
```

```bash
sudo apt install -y nginx python3-venv python3-pip certbot logrotate fail2ban openssl \
                    libnginx-mod-stream postgresql postgresql-contrib libpq-dev
sudo rm -f /etc/nginx/sites-enabled/default
```

### 2. ACME webroot

```bash
sudo mkdir -p /var/www/certbot && sudo chmod 755 /var/www/certbot
```

### 3. Клонирование проекта

```bash
sudo mkdir -p /opt/domain-controller
cd /opt/domain-controller
sudo git clone https://github.com/dismoilov/DomainController.git .
sudo chown -R $USER:$USER /opt/domain-controller
```

> **Или вручную:** скопируйте `app.py`, `requirements.txt` и папку `templates/` в `/opt/domain-controller/`.

### 4. Python venv + зависимости

```bash
cd /opt/domain-controller
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Nginx — включить `conf.d` и `stream`

Убедитесь, что в `/etc/nginx/nginx.conf`:

**Внутри блока `http {}`:**
```nginx
include /etc/nginx/conf.d/*.conf;
include /etc/nginx/sites-enabled/*;
```

**Вне блока `http {}` (на верхнем уровне), добавьте:**
```nginx
include /etc/nginx/stream-routes.conf;
```

> ⚠️ Блок `stream {}` **не может** быть внутри `http {}` — это разные контексты Nginx.

Создайте пустые файлы:

```bash
sudo bash -c 'echo "# managed by domain controller" > /etc/nginx/conf.d/domain-routes.conf'
sudo bash -c 'echo "# no stream routes configured yet" > /etc/nginx/stream-routes.conf'
sudo mkdir -p /var/www/certbot
sudo chmod 755 /var/www/certbot
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl restart nginx
sudo systemctl status nginx --no-pager
```

### 6. Инициализация базы данных

```bash
cd /opt/domain-controller
source venv/bin/activate
flask --app app.py init-db
```

### 7. Создание первого пользователя

```bash
flask --app app.py create-user admin
```

Введите и подтвердите пароль.

### 8. systemd-сервис + gunicorn

В продакшене приложение запускается через **gunicorn** (а не встроенный Flask dev-server). Готовые файлы лежат в `deploy/`:

```bash
# .env с секретом (сгенерируйте DC_PANEL_SECRET!)
sudo cp /opt/domain-controller/deploy/env.example /opt/domain-controller/.env
sudo nano /opt/domain-controller/.env  # задать DC_PANEL_SECRET и LETSENCRYPT_EMAIL
sudo chmod 600 /opt/domain-controller/.env

# systemd unit с hardening (PrivateTmp, ProtectSystem=full и т.п.)
sudo cp /opt/domain-controller/deploy/domain-controller.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now domain-controller
sudo systemctl status domain-controller
```

`ExecStart` в unit'е: `gunicorn -c gunicorn.conf.py wsgi:application` (1 worker, 4 threads — подробности в `gunicorn.conf.py`).

> ⚠️ **Почему `User=root`?** Панель пишет в `/etc/nginx/conf.d/`, дергает `nginx -t`, `systemctl reload nginx`, `certbot`. Переход на выделенного пользователя требует sudoers-правил для этих команд и `chown` директорий — сделано не будет без отдельной итерации. Зато systemd-unit включает `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full` + явный `ReadWritePaths` — это сильно сужает blast-radius.

**Генерация `DC_PANEL_SECRET`:**
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```
Без заданного secret приложение откажется стартовать в non-DEV режиме.

### 9. Nginx — frontend для панели

```bash
sudo tee /etc/nginx/sites-available/domain-panel.conf > /dev/null << 'EOF'
server {
    listen 8080;
    server_name _;

    allow 10.100.10.0/24;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
```

```bash
sudo ln -sf /etc/nginx/sites-available/domain-panel.conf /etc/nginx/sites-enabled/domain-panel.conf
sudo nginx -t && sudo systemctl reload nginx
```

Панель доступна: **http://\<IP контроллера\>:8080**

### 10. Firewall (UFW)

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8080/tcp
```

> Если панель должна быть только из локальной сети — **не** пробрасывайте порт `8080` на роутере.

Для stream-маршрутов добавляйте соответствующие порты:
```bash
sudo ufw allow 5060/udp   # SIP
sudo ufw allow 5061/tcp   # SIP TLS
```

---

## Автопродление сертификатов

### Включить certbot.timer

```bash
sudo systemctl enable --now certbot.timer
sudo systemctl status certbot.timer
```

### Deploy hook — автоперезагрузка Nginx

```bash
sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh > /dev/null << 'EOF'
#!/bin/sh
systemctl reload nginx
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

### Проверка

```bash
sudo certbot renew --dry-run
```

---

## Использование панели

### Добавление HTTP-домена

1. Войдите в панель
2. Нажмите **+ Домен**
3. Заполните:
   - **Домен:** `example.com`
   - **Внутренний IP:** `10.100.10.240`
   - **Порт:** `80`
   - **Группа:** `Production` (опционально)
   - **Frontend HTTPS:** включить если нужен SSL
   - **Backend HTTPS:** включить если бэкенд сам работает по TLS
   - **WebSocket:** включить для real-time приложений
4. Нажмите **Создать**
5. Для SSL — нажмите кнопку **Let's Encrypt** в списке маршрутов

### Добавление Stream-маршрута (TCP/UDP)

1. Нажмите **+ Stream** или зайдите в **Stream-порты**
2. Заполните:
   - **Название:** `FreePBX SIP`
   - **Входящий порт:** `5060`
   - **Протокол:** `UDP`
   - **Внутренний IP:** `10.100.10.220`
   - **Внутренний порт:** `5060`
   - **DNS-привязка:** `pbx.nettech.uz` (опционально, для справки)
3. Нажмите **Создать**
4. Добавьте NAT-проброс на роутере: `5060/udp → контроллер:5060`

### Примеры HTTP-маршрутов

| Домен | IP | Порт | Frontend HTTPS | Backend HTTPS | WS | Группа |
|-------|----|------|:-:|:-:|:-:|--------|
| `nettech.uz` | `10.100.10.240` | `80` | ✅ | ❌ | ❌ | NetTech |
| `shop.nettech.uz` | `10.100.10.241` | `80` | ✅ | ❌ | ✅ | Shop |
| `vm.nettech.uz` | `10.100.10.210` | `8006` | ✅ | ✅ | ❌ | Infra |

### Примеры Stream-маршрутов

| Имя | Порт | Протокол | Target | DNS-привязка | Группа |
|-----|------|----------|--------|-------------|--------|
| FreePBX SIP | `5060` | UDP | `10.100.10.220:5060` | `pbx.nettech.uz` | VoIP |
| SIP TLS | `5061` | TCP | `10.100.10.220:5061` | `pbx.nettech.uz` | VoIP |
| SSH Tunnel | `2222` | TCP | `10.100.10.200:22` | — | Infra |

---

## Диагностика

### Проверка HTTP

```bash
curl -v -H "Host: nettech.uz" http://127.0.0.1/
```

### Проверка HTTPS

```bash
curl -vk --resolve nettech.uz:443:127.0.0.1 https://nettech.uz/
```

### Просмотр HTTP-конфига

```bash
sudo cat /etc/nginx/conf.d/domain-routes.conf
```

### Просмотр Stream-конфига

```bash
sudo cat /etc/nginx/stream-routes.conf
```

### Полный merged-конфиг Nginx

```bash
sudo nginx -T
```

### Поиск конфликтов `server_name`

```bash
sudo grep -rn "server_name" /etc/nginx/
```

---

## Обновление существующей установки

```bash
# 1. Бэкап
cp /opt/domain-controller/data.db /opt/domain-controller/data.db.bak
cp /etc/nginx/conf.d/domain-routes.conf /etc/nginx/conf.d/domain-routes.conf.bak

# 2. Обновить файлы (app.py, templates/, requirements.txt)
cd /opt/domain-controller
git pull  # или замените файлы вручную

# 3. Обновить зависимости
source venv/bin/activate
pip install -r requirements.txt

# 4. Перезапуск
sudo systemctl restart domain-controller.service
```

> Новая версия автоматически добавит недостающие колонки и таблицы в БД через `ensure_schema()`.

---

## Переменные окружения

| Переменная | Описание | По умолчанию |
|-----------|----------|-------------|
| `DC_PANEL_SECRET` | Секретный ключ Flask (сессии) | `change-me` |
| `LETSENCRYPT_EMAIL` | Email для Let's Encrypt | `admin@example.com` |
| `DEV_MODE` | Тестовый режим (`1` = включён) | `0` |

---

## Важные правила эксплуатации

### 1. Backend не должен делать redirect на HTTPS

Если TLS завершается на контроллере, бэкенд **не должен** делать `return 301 https://...` — иначе будет бесконечный redirect loop.

### 2. Один домен — один источник конфигурации

Нельзя одновременно держать домен и в панели, и в ручном конфиге (`/etc/nginx/sites-enabled/`). Это вызовет `conflicting server name`.

### 3. Каждому HTTPS-домену — свой сертификат

Сертификат `nettech.uz` **не покроет** `shop.nettech.uz` (если только это не wildcard). Нажимайте **Let's Encrypt** для каждого домена отдельно.

### 4. Stream ≠ HTTP

TCP/UDP stream-маршруты работают **по номеру порта**, а не по доменному имени. Домен в DNS нужен только для удобства (чтобы пользователи набирали `pbx.nettech.uz`, а не IP).

### 5. Удалите default-сайт Nginx

```bash
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

---

## Лицензия

MIT
