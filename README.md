# 🌐 Domain Controller

Центральная панель управления доменами и reverse-proxy на базе **Nginx + Flask + Let's Encrypt**.

Один внешний IP → много доменов → автоматическая генерация Nginx-конфигов → выпуск SSL-сертификатов одной кнопкой.

---

## Возможности

| Функция | Описание |
|---------|----------|
| **Reverse Proxy** | HTTP и HTTPS проксирование по домену на внутренний IP:порт |
| **Frontend HTTPS** | Автоматический Let's Encrypt для домена |
| **Backend HTTPS** | Поддержка TLS-бэкендов (Proxmox, API и т.д.) |
| **Веб-панель** | Добавление / редактирование / удаление маршрутов через GUI |
| **Группы** | Тегирование доменов по группам с фильтрацией |
| **Аудит** | Лог всех действий — кто, когда, что изменил |
| **Авторизация** | Логин / пароль для доступа к панели |
| **Nginx sync** | Автогенерация `domain-routes.conf` + `nginx -t` + `reload` |
| **Auto-renew** | `certbot.timer` + deploy hook для автопродления сертификатов |

---

## Архитектура

```
Внешний IP (напр. 213.230.69.181)
    │
    ├── :80  ──► NAT ──► 10.100.10.250:80  (Nginx)
    └── :443 ──► NAT ──► 10.100.10.250:443 (Nginx)

Контроллер (10.100.10.250):
    ├── Nginx          — приём и проксирование трафика
    ├── Flask-панель   — веб-интерфейс (порт 5000)
    ├── SQLite         — хранение маршрутов и аудита
    └── Certbot        — выпуск и обновление сертификатов

Примеры маршрутов:
    nettech.uz         → 10.100.10.240:80   (HTTP backend)
    shop.nettech.uz    → 10.100.10.241:80   (HTTP backend)
    vm.nettech.uz      → 10.100.10.210:8006 (HTTPS backend, Proxmox)
```

---

## Структура проекта

```
/opt/domain-controller/
├── app.py               # Flask-приложение
├── requirements.txt     # Python-зависимости
├── data.db              # SQLite (создаётся автоматически)
├── templates/
│   ├── base.html        # Базовый layout
│   ├── login.html       # Страница входа
│   ├── list.html        # Список маршрутов
│   ├── form.html        # Форма добавления/редактирования
│   └── logs.html        # Аудит-логи
└── venv/                # Python virtual environment
```

---

## Предпосылки

- **ОС:** Ubuntu 24.04 (или совместимый Debian-based дистрибутив)
- **Внешний IP** с проброшенными портами:
  - `80/tcp → <IP контроллера>:80`
  - `443/tcp → <IP контроллера>:443`
- **DNS:** A-записи доменов указывают на внешний IP

---

## Установка

### 1. Системные пакеты

```bash
sudo apt update && sudo apt install -y nginx python3-venv python3-pip certbot sqlite3
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

### 5. Nginx — включить `conf.d`

Убедитесь, что в `/etc/nginx/nginx.conf` внутри блока `http {}` есть:

```nginx
include /etc/nginx/conf.d/*.conf;
```

Создайте пустой файл маршрутов:

```bash
sudo bash -c 'echo "# managed by domain controller" > /etc/nginx/conf.d/domain-routes.conf'
sudo nginx -t && sudo systemctl reload nginx
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

### Добавление домена

1. Войдите по адресу `http://<IP>:8080`
2. Нажмите **+ Добавить домен**
3. Заполните:
   - **Домен:** `example.com`
   - **Внутренний IP:** `10.100.10.240`
   - **Порт:** `80`
   - **Группа:** `Production` (опционально)
   - **Frontend HTTPS:** включить если нужен SSL
   - **Backend HTTPS:** включить если бэкенд сам работает по TLS (Proxmox, API)
4. Нажмите **Создать**
5. Для SSL — нажмите кнопку **Let's Encrypt** в списке маршрутов

### Примеры маршрутов

| Домен | IP | Порт | Frontend HTTPS | Backend HTTPS | Группа |
|-------|----|------|:-:|:-:|--------|
| `nettech.uz` | `10.100.10.240` | `80` | ✅ | ❌ | NetTech |
| `shop.nettech.uz` | `10.100.10.241` | `80` | ✅ | ❌ | Shop |
| `vm.nettech.uz` | `10.100.10.210` | `8006` | ✅ | ✅ | Infra |

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

### Просмотр текущего конфига

```bash
sudo cat /etc/nginx/conf.d/domain-routes.conf
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

> Новая версия автоматически добавит недостающие колонки в БД через `ensure_schema()`.

---

## Переменные окружения

| Переменная | Описание | По умолчанию |
|-----------|----------|-------------|
| `DC_PANEL_SECRET` | Секретный ключ Flask (сессии) | `change-me` |
| `LETSENCRYPT_EMAIL` | Email для Let's Encrypt | `admin@example.com` |

---

## Важные правила эксплуатации

### 1. Backend не должен делать redirect на HTTPS

Если TLS завершается на контроллере, бэкенд **не должен** делать `return 301 https://...` — иначе будет бесконечный redirect loop.

### 2. Один домен — один источник конфигурации

Нельзя одновременно держать домен и в панели, и в ручном конфиге (`/etc/nginx/sites-enabled/`). Это вызовет `conflicting server name`.

### 3. Каждому HTTPS-домену — свой сертификат

Сертификат `nettech.uz` **не покроет** `shop.nettech.uz` (если только это не wildcard). Нажимайте **Let's Encrypt** для каждого домена отдельно.

### 4. Удалите default-сайт Nginx

```bash
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

---

## Лицензия

MIT
