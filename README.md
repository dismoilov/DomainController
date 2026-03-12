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
| **JSON-логи** | Nginx пишет access-логи в JSON для парсинга и хранения в SQLite |
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
    ├── SQLite            — хранение маршрутов, аудита и статистики
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

---

## Структура проекта

```
/opt/domain-controller/
├── app.py                  # Flask-приложение
├── requirements.txt        # Python-зависимости
├── data.db                 # SQLite (создаётся автоматически)
├── templates/
│   ├── base.html           # Базовый layout + навигация
│   ├── login.html          # Страница входа
│   ├── dashboard.html      # Дашборд (главная)
│   ├── statistics.html     # Расширенная страница статистики
│   ├── list.html           # Список HTTP-маршрутов
│   ├── form.html           # Форма HTTP-маршрута
│   ├── streams_list.html   # Список TCP/UDP stream-маршрутов
│   ├── stream_form.html    # Форма stream-маршрута
│   └── logs.html           # Аудит-логи
└── venv/                   # Python virtual environment
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

Фоновый поток парсит эти файлы каждые **5 секунд** и сохраняет в SQLite.
Записи старше **7 дней** удаляются автоматически.

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
- Flask запускается с `debug=True`

---

## Установка на сервер (Production)

### Предпосылки

- **ОС:** Ubuntu 24.04 (или совместимый Debian-based дистрибутив)
- **Внешний IP** с проброшенными портами:
  - `80/tcp → <IP контроллера>:80`
  - `443/tcp → <IP контроллера>:443`
  - Дополнительные порты для stream-маршрутов (SIP, RTP и т.д.)
- **DNS:** A-записи доменов указывают на внешний IP

### 1. Системные пакеты

```bash
sudo apt update && sudo apt upgrade - y 
```

```bash
sudo apt install -y nginx python3-venv python3-pip certbot sqlite3 libnginx-mod-stream
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

### 8. systemd-сервис

```bash
sudo tee /etc/systemd/system/domain-controller.service > /dev/null << 'EOF'
[Unit]
Description=Domain Controller Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/domain-controller
Environment="DC_PANEL_SECRET=ЗАМЕНИТЕ_НА_ДЛИННЫЙ_СЛУЧАЙНЫЙ_КЛЮЧ"
Environment="LETSENCRYPT_EMAIL=admin@example.com"
ExecStart=/opt/domain-controller/venv/bin/python app.py
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now domain-controller.service
sudo systemctl status domain-controller.service
```

> ⚠️ **Почему `root`?** Панели нужен доступ к записи в `/etc/nginx/conf.d/`, запуску `nginx -t`, `systemctl reload nginx` и `certbot`. Для production можно вынести эти команды в `sudoers`.

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
