import os
import re
import subprocess
import datetime
import threading
import json
import time
import random
import logging
import hmac
import secrets
import hashlib
import ipaddress
import urllib.request
import urllib.error
import functools
from collections import defaultdict
from functools import wraps
from urllib.parse import urlparse

import click
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text, func, event
from sqlalchemy.engine import Engine
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
# DEV_MODE использует отдельную БД, чтобы фейковые данные и эксперименты
# никогда не попали в продовую data.db, даже если кто-то случайно
# выставит DEV_MODE=1 на боевой машине.
# DATABASE_URL в .env побеждает (например, "postgresql+psycopg2://user:pass@host/db").
# Если не задан — fallback на SQLite-файл рядом с app.py. DEV_MODE → dev_data.db.
_db_url = os.environ.get("DATABASE_URL", "").strip()
if not _db_url:
    _DB_FILE = "dev_data.db" if os.environ.get("DEV_MODE", "0") == "1" else "data.db"
    _db_url = "sqlite:///" + os.path.join(BASE_DIR, _DB_FILE)
# SQLAlchemy 2.0 не понимает префикс "postgres://" — нормализуем в "postgresql://".
if _db_url.startswith("postgres://"):
    _db_url = "postgresql+psycopg2://" + _db_url[len("postgres://"):]
app.config["SQLALCHEMY_DATABASE_URI"] = _db_url
# Pool для PG (на SQLite игнорируется). 5 коннекций на 4 воркера + overflow хватит.
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_size": 5,
    "max_overflow": 10,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Dev mode — пропускает nginx/certbot команды, пишет конфиги локально
DEV_MODE = os.environ.get("DEV_MODE", "0") == "1"

# SECRET_KEY guard: в DEV разрешаем дефолт, в проде — обязаны задать через окружение.
# Иначе злоумышленник, зная дефолт, подделает сессионный cookie.
_secret = os.environ.get("DC_PANEL_SECRET", "")
if not _secret:
    if DEV_MODE:
        _secret = "dev-insecure-change-me"
    else:
        raise RuntimeError(
            "DC_PANEL_SECRET must be set to a non-empty value in production. "
            "Generate: python -c 'import secrets; print(secrets.token_urlsafe(64))'"
        )
if _secret in ("change-me", "dev-insecure-change-me") and not DEV_MODE:
    raise RuntimeError("DC_PANEL_SECRET must not be the default/placeholder value")
app.config["SECRET_KEY"] = _secret

# Безопасная сессия: HttpOnly + SameSite=Lax мешают XSS/CSRF-использованию куки.
# Secure не ставим — панель доступна и по http://IP:8080 внутри LAN;
# в проде рекомендуется ходить через https://sub.nettech.uz.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=1024 * 1024,  # 1 МБ — формы не могут быть больше
)

# Email для Let's Encrypt
app.config["LETSENCRYPT_EMAIL"] = os.environ.get("LETSENCRYPT_EMAIL", "admin@example.com")

# Опциональный webhook для уведомлений. Любое HTTP(S) URL, которому мы
# шлём POST с JSON-телом: {"event": "...", "domain": "...", "details": "...",
# "timestamp": "ISO-8601"}. Telegram-боту, Slack-вебхуку и т.п.
app.config["WEBHOOK_URL"] = os.environ.get("DC_WEBHOOK_URL", "").strip()

# Опциональный токен для защиты /metrics. Если задан — Prometheus scraper
# должен слать `Authorization: Bearer <token>`. Если пусто — открыт для LAN.
app.config["METRICS_TOKEN"] = os.environ.get("DC_METRICS_TOKEN", "").strip()

if DEV_MODE:
    NGINX_CONF_PATH = os.path.join(BASE_DIR, "dev_domain-routes.conf")
    STREAM_CONF_PATH = os.path.join(BASE_DIR, "dev_stream-routes.conf")
    ACME_WEBROOT = "/tmp/certbot"
else:
    NGINX_CONF_PATH = "/etc/nginx/conf.d/domain-routes.conf"
    STREAM_CONF_PATH = "/etc/nginx/stream-routes.conf"
    ACME_WEBROOT = "/var/www/certbot"

db = SQLAlchemy(app)

logger = logging.getLogger("domain_controller")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(_h)
    logger.setLevel(logging.INFO)


# ──────────────────────────────────────────────
#  CSRF protection (самодельная, без flask-wtf)
# ──────────────────────────────────────────────

CSRF_SESSION_KEY = "_csrf"
_CSRF_EXEMPT_PATHS = ()  # добавлять сюда нечего: все /api/* сейчас только GET


def csrf_token() -> str:
    """Получить CSRF-токен текущей сессии (создать при отсутствии)."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.after_request
def _no_cache_headers(response):
    """Админ-панель — динамика, никакого кэша.

    Safari по умолчанию агрессивно кэширует HTML с Vary: Cookie и может
    показывать устаревший navbar/dashboard после обновлений шаблонов.
    Статику из CDN (bootstrap, chart.js) это не касается — они с Cache-Control
    от самого CDN.
    """
    ct = response.headers.get("Content-Type", "")
    if ct.startswith("text/html") or ct.startswith("application/json"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.before_request
def _csrf_protect():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    if request.path in _CSRF_EXEMPT_PATHS:
        return None
    # /api/* сейчас только GET; если в будущем появятся POST API — добавлять явно
    if request.path.startswith("/api/"):
        return None
    expected = session.get(CSRF_SESSION_KEY, "")
    submitted = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    if not expected or not submitted or not hmac.compare_digest(expected, submitted):
        logger.warning("CSRF token mismatch from %s on %s %s",
                       request.remote_addr, request.method, request.path)
        abort(400, description="CSRF token missing or invalid")
    return None


# ──────────────────────────────────────────────
#  Brute-force rate-limit на /login (in-memory, per-IP)
#  Не тянем flask-limiter + redis ради простоты развёртывания.
# ──────────────────────────────────────────────

_login_attempts: dict = defaultdict(list)  # ip -> [timestamps неудачных попыток]
_login_attempts_lock = threading.Lock()
LOGIN_WINDOW_SEC = 600        # окно 10 минут
LOGIN_MAX_FAILURES = 10       # больше N неудач за окно = 429
LOGIN_LOCKOUT_SEC = 600       # сколько держать IP в блоке после превышения


def _rate_limit_check(ip: str) -> tuple[bool, int]:
    """Вернуть (allowed, retry_after_sec). Не модифицирует состояние."""
    now = time.time()
    with _login_attempts_lock:
        window = get_setting("login_window_sec", LOGIN_WINDOW_SEC)
        max_fail = get_setting("login_max_failures", LOGIN_MAX_FAILURES)
        lockout = get_setting("login_lockout_sec", LOGIN_LOCKOUT_SEC)
        history = [t for t in _login_attempts.get(ip, []) if now - t < window]
        _login_attempts[ip] = history
        if len(history) >= max_fail:
            oldest = history[0]
            retry = int(lockout - (now - oldest))
            return False, max(retry, 1)
    return True, 0


def _record_login_failure(ip: str):
    with _login_attempts_lock:
        _login_attempts[ip].append(time.time())


def _reset_login_failures(ip: str):
    with _login_attempts_lock:
        _login_attempts.pop(ip, None)


def _client_ip() -> str:
    """Определить IP клиента с учётом nginx X-Forwarded-For."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


# WAL + busy_timeout лечат "database is locked" при параллельной работе
# фонового парсера логов (пишет) и API статистики (читает большие агрегаты).
# cache_size/mmap_size/temp_store ускоряют агрегаты на /api/stats/* (десятки запросов
# подряд на сотнях тысяч строк). synchronous=NORMAL безопасен в паре с WAL.
#
# Для PostgreSQL ничего не делаем — у него свои tuning-знания в postgresql.conf.
@event.listens_for(Engine, "connect")
def _sqlite_pragma(dbapi_connection, _connection_record):
    # Применяем PRAGMA только к SQLite-соединениям. В PG класс Connection
    # не имеет PRAGMA-команд и вызов упадёт.
    try:
        cls_name = type(dbapi_connection).__module__ or ""
        if "sqlite" not in cls_name.lower():
            return
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=-50000")
        cursor.execute("PRAGMA mmap_size=268435456")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.close()
    except Exception:
        pass


def _is_sqlite() -> bool:
    """True если текущая БД — SQLite. Используется для dialect-aware SQL."""
    try:
        return db.engine.dialect.name == "sqlite"
    except Exception:
        return app.config.get("SQLALCHEMY_DATABASE_URI", "").startswith("sqlite")


def _db_size_bytes() -> int:
    """Размер БД в байтах. Для SQLite — размер файла, для PG — pg_database_size."""
    if _is_sqlite():
        path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
        try:
            return os.path.getsize(path) if os.path.exists(path) else 0
        except OSError:
            return 0
    # PostgreSQL: SELECT pg_database_size(current_database())
    try:
        return int(db.session.execute(text("SELECT pg_database_size(current_database())")).scalar() or 0)
    except Exception:
        return 0


def _hour_bucket_sql(col):
    """Функция округления datetime до часа (YYYY-MM-DD HH:00) — dialect-aware.

    SQLite:      strftime('%Y-%m-%d %H:00', col)
    PostgreSQL:  to_char(col, 'YYYY-MM-DD HH24:"00"')
    """
    if _is_sqlite():
        return func.strftime("%Y-%m-%d %H:00", col)
    # Для PG: двойные кавычки экранируют литерал в формате to_char
    return func.to_char(col, "YYYY-MM-DD HH24:\"00\"")


def _day_of_week_sql(col):
    """День недели как число. В SQLite strftime('%w') → 0=Sun..6=Sat,
    в PG extract('dow') тоже 0=Sun..6=Sat — унифицировано."""
    if _is_sqlite():
        return func.strftime("%w", col)
    return func.cast(func.extract("dow", col), db.String)


def _hour_of_day_sql(col):
    """Час дня 0-23."""
    if _is_sqlite():
        return func.strftime("%H", col)
    return func.to_char(col, "HH24")


def _utcnow() -> datetime.datetime:
    """Timezone-aware UTC now, представленная как naive datetime для хранения в SQLite.

    Замена устаревшей datetime.datetime.utcnow() — в Python 3.12+ она выводит
    DeprecationWarning. SQLAlchemy column default использует ссылку на эту функцию,
    поэтому объявлять её надо до описания моделей.
    """
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


# ──────────────────────────────────────────────
#  Пресеты сервисов для stream-маршрутов
# ──────────────────────────────────────────────

SERVICE_PRESETS = {
    "sip":      {"label": "SIP",             "port": 5060,  "protocol": "udp", "desc": "VoIP сигнализация"},
    "sip-tls":  {"label": "SIP-TLS",         "port": 5061,  "protocol": "tcp", "desc": "Шифрованный SIP"},
    "rtp":      {"label": "RTP",             "port": 10000, "protocol": "udp", "desc": "VoIP медиа (аудио/видео)"},
    "ssh":      {"label": "SSH",             "port": 22,    "protocol": "tcp", "desc": "Удалённый доступ SSH"},
    "dns":      {"label": "DNS",             "port": 53,    "protocol": "udp", "desc": "DNS-запросы"},
    "smtp":     {"label": "SMTP",            "port": 25,    "protocol": "tcp", "desc": "Почтовый сервер"},
    "smtps":    {"label": "SMTP TLS",        "port": 587,   "protocol": "tcp", "desc": "Почта с шифрованием"},
    "imap":     {"label": "IMAP",            "port": 143,   "protocol": "tcp", "desc": "Получение почты"},
    "imaps":    {"label": "IMAPS",           "port": 993,   "protocol": "tcp", "desc": "Почта IMAP с SSL"},
    "pop3":     {"label": "POP3",            "port": 110,   "protocol": "tcp", "desc": "Почта POP3"},
    "pop3s":    {"label": "POP3S",           "port": 995,   "protocol": "tcp", "desc": "Почта POP3 с SSL"},
    "rtsp":     {"label": "RTSP",            "port": 554,   "protocol": "tcp", "desc": "Видеонаблюдение/стриминг"},
    "rtmp":     {"label": "RTMP",            "port": 1935,  "protocol": "tcp", "desc": "Live-стриминг"},
    "ftp":      {"label": "FTP",             "port": 21,    "protocol": "tcp", "desc": "Передача файлов"},
    "mqtt":     {"label": "MQTT",            "port": 1883,  "protocol": "tcp", "desc": "IoT сообщения"},
    "mqtts":    {"label": "MQTT TLS",        "port": 8883,  "protocol": "tcp", "desc": "IoT с шифрованием"},
    "rdp":      {"label": "RDP",             "port": 3389,  "protocol": "tcp", "desc": "Удалённый рабочий стол"},
    "vnc":      {"label": "VNC",             "port": 5900,  "protocol": "tcp", "desc": "VNC Remote Desktop"},
    "mysql":    {"label": "MySQL",           "port": 3306,  "protocol": "tcp", "desc": "База данных MySQL"},
    "postgres": {"label": "PostgreSQL",      "port": 5432,  "protocol": "tcp", "desc": "База данных PostgreSQL"},
    "redis":    {"label": "Redis",           "port": 6379,  "protocol": "tcp", "desc": "Кэш/очереди Redis"},
    "openvpn":  {"label": "OpenVPN",         "port": 1194,  "protocol": "udp", "desc": "VPN-подключение"},
    "wireguard":{"label": "WireGuard",       "port": 51820, "protocol": "udp", "desc": "VPN WireGuard"},
    "custom":   {"label": "Другой (Custom)", "port": None,  "protocol": "tcp", "desc": "Произвольный TCP/UDP"},
}


# ──────────────────────────────────────────────
#  Models
# ──────────────────────────────────────────────

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)
    # Роль для RBAC: 'admin' (полный доступ) или 'viewer' (только чтение).
    # По умолчанию admin — бэквард-совместимо с существующими пользователями.
    role = db.Column(db.String(16), nullable=False, default="admin")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class JailPause(db.Model):
    """Временная приостановка jail'а fail2ban.

    Механика: при паузе делаем `fail2ban-client stop <jail>` — jail полностью
    снимается с нагрузки (автобанов не будет, iptables-правила этого jail'а
    удалятся). В `paused_until` записываем время окончания. Фоновый поток
    каждую минуту проверяет: если `paused_until < now` — `fail2ban-client start
    <jail>` и запись удаляется.

    Разрешено паузить только dc-404-flood и domain-controller — sshd и dc-manual
    слишком критичны. На рестарте сервера: fail2ban прочитает свой конфиг и jail
    будет active, но наш фоновый поток увидит активную запись и снова сделает stop.
    """
    __tablename__ = "jail_pauses"

    id = db.Column(db.Integer, primary_key=True)
    jail_name = db.Column(db.String(64), unique=True, nullable=False)
    paused_until = db.Column(db.DateTime, nullable=False)
    paused_by = db.Column(db.String(64), nullable=True)
    reason = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)


class AppSetting(db.Model):
    """Key-value настройки приложения, управляемые через UI /settings.

    Заменяют Python-константы (retention, интервалы, rate-limit пороги) —
    чтобы админ мог менять без правки кода и рестарта.
    """
    __tablename__ = "app_settings"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(1024), nullable=False)
    value_type = db.Column(db.String(16), nullable=False, default="string")  # string|int|bool
    category = db.Column(db.String(32), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)
    updated_by = db.Column(db.String(64), nullable=True)


class FailbanEvent(db.Model):
    """События из /var/log/fail2ban.log (Ban/Unban с IP+jail).

    Даёт реальную историю автобанов (fail2ban сам её не хранит после stop).
    Позиция парсера — в log_checkpoints с ключом "fail2ban_log".
    """
    __tablename__ = "fail2ban_events"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    jail = db.Column(db.String(64), nullable=False, index=True)
    action = db.Column(db.String(16), nullable=False)   # Ban | Unban | Restore
    ip = db.Column(db.String(64), nullable=False)

    __table_args__ = (
        db.Index("ix_fail2ban_events_ts_jail", "timestamp", "jail"),
    )


class IpAllowlist(db.Model):
    """IP/CIDR с разрешённым доступом к панели (nginx :8080 allow-list).

    Перегенерируется в /etc/nginx/sites-available/domain-panel.conf при каждом
    изменении. Таблица не должна оставаться пустой — иначе `deny all;` закроет
    всех. Проверка "не удалять последний" реализована в endpoint'е.
    """
    __tablename__ = "ip_allowlist"

    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(64), unique=True, nullable=False)
    comment = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    created_by = db.Column(db.String(64), nullable=True)


class ApiToken(db.Model):
    """Bearer-токен для автоматизации (curl, Terraform, скрипты).

    Хранится в виде SHA-256 хэша — оригинальный токен показывается только
    при создании через CLI. Потеря = пересоздание.
    """
    __tablename__ = "api_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", lazy=True)

    @staticmethod
    def hash_token(raw: str) -> str:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class DomainRoute(db.Model):
    __tablename__ = "domain_routes"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    target_host = db.Column(db.String(255), nullable=False)
    target_port = db.Column(db.Integer, nullable=False)

    # Кастомные listen-порты (по умолчанию 80/443)
    listen_port = db.Column(db.Integer, default=80, nullable=False)
    listen_port_ssl = db.Column(db.Integer, default=443, nullable=False)

    # HTTPS на фронте (домене)
    enable_https = db.Column(db.Boolean, default=False)
    ssl_cert_path = db.Column(db.String(512), nullable=True)
    ssl_key_path = db.Column(db.String(512), nullable=True)

    # Группа/тег
    group_name = db.Column(db.String(128), nullable=True)

    # HTTPS на backend
    backend_https = db.Column(db.Boolean, default=False)

    # WebSocket поддержка
    enable_websocket = db.Column(db.Boolean, default=False)

    # Логирование запросов
    enable_logging = db.Column(db.Boolean, default=True)

    # Nginx UA-блок сканеров в server{}. True по умолчанию (безопасный дефолт).
    # Выключают, если домен — публичный сайт с легитимными "странными" клиентами
    # (например, Googlebot, Yandex SEO tools или собственные скрипты, которые
    # мог зацепить наш regex).
    enable_bot_protection = db.Column(db.Boolean, default=True, nullable=False)

    # Backend health-check (обновляется фоновым потоком каждые 2 минуты)
    last_health_check = db.Column(db.DateTime, nullable=True)
    last_health_status = db.Column(db.String(16), nullable=True)  # "up" / "down" / None
    last_health_error = db.Column(db.String(255), nullable=True)

    # Связанные stream-маршруты
    stream_routes = db.relationship("StreamRoute", backref="domain_route", lazy=True)

    def __repr__(self):
        return f"<DomainRoute {self.domain} -> {self.target_host}:{self.target_port}>"


class StreamRoute(db.Model):
    """TCP/UDP поток — проксирование через Nginx stream {} модуль."""
    __tablename__ = "stream_routes"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    listen_port = db.Column(db.Integer, unique=True, nullable=False)
    target_host = db.Column(db.String(255), nullable=False)
    target_port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False, default="tcp")   # tcp / udp
    service_type = db.Column(db.String(32), nullable=False, default="custom")  # sip, ssh, dns, custom...
    domain_hint = db.Column(db.String(255), nullable=True)
    group_name = db.Column(db.String(128), nullable=True)

    # Привязка к домену (опционально)
    domain_route_id = db.Column(db.Integer, db.ForeignKey("domain_routes.id"), nullable=True)

    # Логирование
    enable_logging = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<StreamRoute {self.name} :{self.listen_port}/{self.protocol} -> {self.target_host}:{self.target_port}>"


class AccessLog(db.Model):
    """HTTP/HTTPS запросы, собранные из JSON-лога Nginx."""
    __tablename__ = "access_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True)
    remote_addr = db.Column(db.String(45))
    remote_port = db.Column(db.Integer)
    server_name = db.Column(db.String(255), index=True)
    server_port = db.Column(db.Integer)
    method = db.Column(db.String(10))
    uri = db.Column(db.String(2048))
    status = db.Column(db.Integer)
    body_bytes = db.Column(db.Integer)
    request_time = db.Column(db.Float)
    upstream_addr = db.Column(db.String(255))
    upstream_time = db.Column(db.String(64))
    user_agent = db.Column(db.String(512))
    referer = db.Column(db.String(512))
    scheme = db.Column(db.String(10))
    ssl_protocol = db.Column(db.String(32))

    __table_args__ = (
        db.Index("ix_access_logs_ts_status", "timestamp", "status"),
        db.Index("ix_access_logs_ts_server", "timestamp", "server_name"),
        db.Index("ix_access_logs_ts_remote", "timestamp", "remote_addr"),
    )


class StreamAccessLog(db.Model):
    """TCP/UDP сессии, собранные из JSON-лога Nginx stream."""
    __tablename__ = "stream_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True)
    remote_addr = db.Column(db.String(45))
    remote_port = db.Column(db.Integer)
    server_port = db.Column(db.Integer, index=True)
    protocol = db.Column(db.String(10))
    bytes_received = db.Column(db.Integer)
    bytes_sent = db.Column(db.Integer)
    session_time = db.Column(db.Float)
    upstream_addr = db.Column(db.String(255))

    __table_args__ = (
        db.Index("ix_stream_logs_ts_port", "timestamp", "server_port"),
    )
    status = db.Column(db.String(10))


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    username = db.Column(db.String(64), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)


class LogCheckpoint(db.Model):
    """Персистентная позиция парсера в файлах nginx-логов и метки служебных задач.

    Без этой таблицы позиция жила в памяти процесса и терялась при любом рестарте,
    из-за чего парсер перечитывал весь лог и создавал массовые дубли в access_logs/stream_logs.
    """
    __tablename__ = "log_checkpoints"

    key = db.Column(db.String(64), primary_key=True)
    position = db.Column(db.BigInteger, nullable=False, default=0)
    inode = db.Column(db.BigInteger, nullable=False, default=0)
    file_size = db.Column(db.BigInteger, nullable=False, default=0)
    updated_at = db.Column(
        db.DateTime,
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
    )


class ParserError(db.Model):
    """Dead-letter: строки nginx-логов, которые не удалось разобрать.

    Без этой таблицы битые JSON молча пропускались (`json.JSONDecodeError`
    давил парсер), и диагностировать проблему с nginx log_format было нельзя.
    """
    __tablename__ = "parser_errors"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)
    source = db.Column(db.String(32), nullable=False)     # "http_log" | "stream_log"
    line_excerpt = db.Column(db.String(1024), nullable=False)
    error = db.Column(db.String(255), nullable=False)


# ──────────────────────────────────────────────
#  Schema migrations
# ──────────────────────────────────────────────

def ensure_schema():
    """Создать таблицы и добавить недостающие колонки при апгрейде."""
    db.create_all()

    inspector = inspect(db.engine)
    tables = inspector.get_table_names()

    # domain_routes migrations
    if "domain_routes" in tables:
        cols = {c["name"] for c in inspector.get_columns("domain_routes")}
        migrations = []

        if "enable_https" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN enable_https BOOLEAN NOT NULL DEFAULT 0")
        if "ssl_cert_path" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN ssl_cert_path VARCHAR(512)")
        if "ssl_key_path" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN ssl_key_path VARCHAR(512)")
        if "group_name" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN group_name VARCHAR(128)")
        if "backend_https" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN backend_https BOOLEAN NOT NULL DEFAULT 0")
        if "enable_websocket" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN enable_websocket BOOLEAN NOT NULL DEFAULT 0")
        if "listen_port" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN listen_port INTEGER NOT NULL DEFAULT 80")
        if "listen_port_ssl" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN listen_port_ssl INTEGER NOT NULL DEFAULT 443")
        if "enable_logging" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN enable_logging BOOLEAN NOT NULL DEFAULT 1")
        if "last_health_check" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN last_health_check DATETIME")
        if "last_health_status" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN last_health_status VARCHAR(16)")
        if "last_health_error" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN last_health_error VARCHAR(255)")
        if "enable_bot_protection" not in cols:
            migrations.append("ALTER TABLE domain_routes ADD COLUMN enable_bot_protection BOOLEAN NOT NULL DEFAULT 1")

        if migrations:
            with db.engine.begin() as conn:
                for sql in migrations:
                    conn.execute(text(sql))

    # stream_routes migrations
    if "stream_routes" in tables:
        cols = {c["name"] for c in inspector.get_columns("stream_routes")}
        migrations = []

        if "service_type" not in cols:
            migrations.append("ALTER TABLE stream_routes ADD COLUMN service_type VARCHAR(32) NOT NULL DEFAULT 'custom'")
        if "domain_route_id" not in cols:
            migrations.append("ALTER TABLE stream_routes ADD COLUMN domain_route_id INTEGER")
        if "enable_logging" not in cols:
            migrations.append("ALTER TABLE stream_routes ADD COLUMN enable_logging BOOLEAN NOT NULL DEFAULT 1")

        if migrations:
            with db.engine.begin() as conn:
                for sql in migrations:
                    conn.execute(text(sql))

    # users migrations
    if "users" in tables:
        cols = {c["name"] for c in inspector.get_columns("users")}
        if "role" not in cols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'admin'"))

    # Seed IpAllowlist: на первом запуске (если БД пустая) кладём разумный минимум,
    # который покрывает внутреннюю сеть. Без этого nginx-generator создаст
    # domain-panel.conf с пустым allow-списком → "deny all;" закроет всех.
    try:
        if IpAllowlist.query.count() == 0:
            for cidr in ("10.0.0.0/8", "127.0.0.1/32"):
                db.session.add(IpAllowlist(cidr=cidr, comment="seed (внутренняя сеть)", created_by="system"))
            db.session.commit()
            logger.info("IpAllowlist seeded with 10.0.0.0/8 + 127.0.0.1/32")
    except Exception as e:
        logger.warning("IpAllowlist seed failed: %s", e)
        db.session.rollback()

    # Unique-индекс на domain_routes.domain: защищает от случайных дублей.
    # CREATE UNIQUE INDEX IF NOT EXISTS не упадёт, если индекс уже есть.
    # Если в БД уже есть дубликаты — логируем предупреждение вместо падения.
    try:
        with db.engine.begin() as conn:
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_domain_routes_domain "
                "ON domain_routes (domain)"
            ))
    except Exception as e:
        logger.warning("cannot create unique index on domain_routes.domain "
                       "(скорее всего есть дубликаты в БД): %s", e)


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

def frontend_https_ready(route: DomainRoute) -> bool:
    return bool(route.enable_https and route.ssl_cert_path and route.ssl_key_path)


def _try_api_token_auth() -> bool:
    """Проверить Authorization: Bearer <token>. При успехе инжектит user в session-like контекст.

    Использует Flask `g` вместо session (stateless), чтобы не создавать сессионные куки
    для stateless API-вызовов. current_username() и is_admin читают из g.api_user если он есть.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    raw = auth[7:].strip()
    if not raw or len(raw) > 128:
        return False
    token_hash = ApiToken.hash_token(raw)
    tok = ApiToken.query.filter_by(token_hash=token_hash).first()
    if not tok:
        return False
    # Обновляем last_used не чаще раза в минуту — не спамим БД.
    now = _utcnow()
    if not tok.last_used_at or (now - tok.last_used_at).total_seconds() > 60:
        tok.last_used_at = now
        db.session.commit()
    from flask import g
    g.api_user = tok.user
    return True


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" in session:
            return func(*args, **kwargs)
        # API-эндпоинты могут пускать по Bearer-токену.
        if request.path.startswith("/api/") and _try_api_token_auth():
            return func(*args, **kwargs)
        if request.path.startswith("/api/"):
            return jsonify({"error": "unauthorized"}), 401
        return redirect(url_for("login", next=request.path))
    return wrapper


def admin_required(func):
    """POST-маршруты, меняющие конфигурацию, требуют роль admin.

    Работает поверх login_required: проверяет session['role'] или g.api_user.role.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        from flask import g
        role = session.get("role")
        if not role and getattr(g, "api_user", None):
            role = g.api_user.role
        if role != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"error": "admin role required"}), 403
            flash("Действие доступно только администратору", "danger")
            return redirect(url_for("dashboard")), 403
        return func(*args, **kwargs)
    return wrapper


def current_username() -> str:
    from flask import g
    if session.get("username"):
        return session["username"]
    if getattr(g, "api_user", None):
        return f"{g.api_user.username}@api"
    return "system"


def log_action(action: str, domain: str | None = None, details: str | None = None):
    entry = AuditLog(
        username=current_username(),
        action=action,
        domain=domain,
        details=details,
    )
    db.session.add(entry)
    db.session.commit()


# События, при которых триггерим внешний webhook (если настроен).
# Остальные аудит-действия (login, view и т.п.) не шлём — это шум.
_WEBHOOK_EVENTS = {
    "letsencrypt_failed",
    "letsencrypt_nginx_failed",
    "nginx_reload_failed",
    "backend_down",
    "ssl_expiring_soon",
    "parser_error_spike",
}


def _fire_webhook(event: str, domain: str | None = None, details: str | None = None):
    """Не-блокирующая отправка уведомления (отдельный поток).

    Если WEBHOOK_URL не задан или эвент не из списка — просто выходим.
    Ошибки доставки логируем, но не роняем основной request.
    """
    url = app.config.get("WEBHOOK_URL", "")
    if not url or event not in _WEBHOOK_EVENTS:
        return

    payload = json.dumps({
        "event": event,
        "domain": domain,
        "details": details,
        "timestamp": _utcnow().isoformat() + "Z",
        "host": "domain-controller",
    }).encode("utf-8")

    def _send():
        try:
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "DomainController/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status >= 400:
                    logger.warning("webhook %s returned %s", url, resp.status)
        except (urllib.error.URLError, TimeoutError) as e:
            logger.warning("webhook delivery failed: %s", e)
        except Exception:
            logger.exception("webhook unexpected error")

    threading.Thread(target=_send, daemon=True, name="dc-webhook").start()


# ──────────────────────────────────────────────
#  AppSetting — runtime-настройки, UI /settings
# ──────────────────────────────────────────────

_SETTINGS_CACHE: dict = {}
_SETTINGS_CACHE_LOADED_AT: float = 0.0
_SETTINGS_LOCK = threading.Lock()
_SETTINGS_TTL = 60.0  # sec

# Описания настроек — рендерим их на странице /settings. Расширяем по необходимости.
SETTING_DEFINITIONS = [
    # key, type, default, category, description, min, max
    ("retention_access_logs_days",    "int",  30,  "retention",  "Хранение access_logs (HTTP), дней", 1, 365),
    ("retention_stream_logs_days",    "int",  30,  "retention",  "Хранение stream_logs (TCP/UDP), дней", 1, 365),
    ("retention_audit_logs_days",     "int",  365, "retention",  "Хранение audit_logs (действия админов), дней", 30, 1825),
    ("retention_parser_errors_days",  "int",  30,  "retention",  "Хранение parser_errors (битые JSON), дней", 1, 180),
    ("retention_fail2ban_events_days","int",  30,  "retention",  "Хранение fail2ban_events (история банов), дней", 1, 365),

    ("login_max_failures",   "int",  10,  "security",   "Неудачных попыток /login до блока IP", 3, 100),
    ("login_window_sec",     "int",  600, "security",   "Окно подсчёта попыток, сек", 60, 3600),
    ("login_lockout_sec",    "int",  600, "security",   "Длительность блокировки IP после превышения, сек", 60, 86400),

    ("backend_health_interval_sec", "int", 120, "intervals", "Интервал TCP-пинга бэкендов, сек", 30, 3600),
    ("ssl_warning_threshold_days",  "int", 14,  "intervals", "Порог предупреждения об истечении SSL, дней", 1, 90),
]


def _load_settings():
    global _SETTINGS_CACHE, _SETTINGS_CACHE_LOADED_AT
    try:
        rows = AppSetting.query.all()
        _SETTINGS_CACHE = {r.key: (r.value, r.value_type) for r in rows}
    except Exception:
        _SETTINGS_CACHE = {}
    _SETTINGS_CACHE_LOADED_AT = time.time()


def get_setting(key: str, default):
    """Получить значение настройки с in-memory кэшем (TTL 60 сек).

    Если настройка не задана — возвращает default. Тип вычисляется из БД,
    если настройка отсутствует — из Python-типа default'а.
    """
    with _SETTINGS_LOCK:
        if time.time() - _SETTINGS_CACHE_LOADED_AT > _SETTINGS_TTL:
            _load_settings()
        if key not in _SETTINGS_CACHE:
            return default
        val, vtype = _SETTINGS_CACHE[key]
    try:
        if vtype == "int":
            return int(val)
        if vtype == "bool":
            return str(val).lower() in ("true", "1", "yes", "on")
        return val
    except (ValueError, TypeError):
        return default


def set_setting(key: str, value, vtype: str = "string", category=None, description=None):
    rec = AppSetting.query.filter_by(key=key).first()
    if rec:
        rec.value = str(value)
        rec.value_type = vtype
        if category is not None:
            rec.category = category
        if description is not None:
            rec.description = description
        rec.updated_by = current_username()
    else:
        db.session.add(AppSetting(
            key=key, value=str(value), value_type=vtype,
            category=category, description=description,
            updated_by=current_username(),
        ))
    db.session.commit()
    _load_settings()


def ensure_acme_webroot():
    os.makedirs(ACME_WEBROOT, exist_ok=True)


# ──────────────────────────────────────────────
#  Input validation
#  Все значения, которые попадают в nginx-конфиг или в argv certbot,
#  должны пройти эти проверки — иначе возможен config injection.
# ──────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_IPV4_RE = re.compile(r"^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$")
_HOSTNAME_RE = _DOMAIN_RE  # тот же формат
_SSL_PATH_RE = re.compile(r"^/etc/letsencrypt/live/[A-Za-z0-9.\-_]+/(fullchain|privkey|cert|chain)\.pem$")

# Порты, которые нельзя занимать под stream/HTTP-маршруты на контроллере —
# либо они используются системой, либо панелью, либо другими критичными сервисами.
RESERVED_PORTS = {
    22,    # SSH контроллера
    25,    # SMTP (может использоваться mail)
    53,    # DNS (resolver)
    5000,  # Flask-панель, слушает 127.0.0.1
    5432,  # PostgreSQL (на случай если есть)
    8080,  # сама nginx-обёртка панели
}


def is_valid_domain(s: str) -> bool:
    return bool(s) and bool(_DOMAIN_RE.match(s)) and ".." not in s


def is_valid_host(s: str) -> bool:
    if not s:
        return False
    # Если строка выглядит как IP (только цифры и точки) — она обязана пройти
    # IPv4-regex, иначе это мусор типа "256.1.1.1". Hostname-regex для такой
    # строки может ложно пропустить (цифры+дефисы+точки формально валидны).
    if all(c in "0123456789." for c in s):
        return bool(_IPV4_RE.match(s))
    return bool(_HOSTNAME_RE.match(s))


def is_valid_port(n: int, allow_reserved: bool = False) -> bool:
    if not isinstance(n, int):
        return False
    if not (1 <= n <= 65535):
        return False
    if not allow_reserved and n in RESERVED_PORTS:
        return False
    return True


def is_valid_ssl_path(s: str) -> bool:
    return bool(s) and bool(_SSL_PATH_RE.match(s)) and ".." not in s


def is_safe_next_url(target: str) -> bool:
    """Защита от open-redirect: принимаем только относительные URL на ту же панель."""
    if not target:
        return False
    parsed = urlparse(target)
    # схема/хост быть не должны; путь обязан начинаться со /
    return not parsed.scheme and not parsed.netloc and target.startswith("/")


# ──────────────────────────────────────────────
#  Nginx config generation — HTTP (domain-routes)
# ──────────────────────────────────────────────

HTTP_LOG_PATH = "/var/log/nginx/dc_access.json"
STREAM_LOG_PATH = "/var/log/nginx/dc_stream.json"
if DEV_MODE:
    HTTP_LOG_PATH = os.path.join(BASE_DIR, "dev_access.json")
    STREAM_LOG_PATH = os.path.join(BASE_DIR, "dev_stream.json")


def build_log_format_block() -> str:
    """Nginx log_format для JSON-логирования HTTP-запросов."""
    return (
        "\nlog_format dc_json escape=json '{"
        '"time":"$time_iso8601",'
        '"remote_addr":"$remote_addr",'
        '"remote_port":"$remote_port",'
        '"server_name":"$server_name",'
        '"server_port":"$server_port",'
        '"request_method":"$request_method",'
        '"request_uri":"$request_uri",'
        '"status":$status,'
        '"body_bytes_sent":$body_bytes_sent,'
        '"request_time":$request_time,'
        '"upstream_addr":"$upstream_addr",'
        '"upstream_response_time":"$upstream_response_time",'
        '"http_user_agent":"$http_user_agent",'
        '"http_referer":"$http_referer",'
        '"scheme":"$scheme",'
        '"ssl_protocol":"$ssl_protocol"'
        "}';\n\n"
    )


def build_proxy_directives(route: DomainRoute) -> str:
    scheme = "https" if route.backend_https else "http"

    directives = [
        f"proxy_pass {scheme}://{route.target_host}:{route.target_port};",
        "proxy_set_header Host $host;",
        "proxy_set_header X-Real-IP $remote_addr;",
        "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "proxy_set_header X-Forwarded-Proto $scheme;",
        "proxy_set_header X-Forwarded-Host $host;",
        "proxy_set_header X-Forwarded-Port $server_port;",
        "proxy_read_timeout 3600;",
        "proxy_send_timeout 3600;",
    ]

    if route.enable_websocket or route.backend_https:
        directives.extend([
            "proxy_http_version 1.1;",
            "proxy_set_header Upgrade $http_upgrade;",
            'proxy_set_header Connection "upgrade";',
        ])

    if route.backend_https:
        directives.append("proxy_ssl_verify off;")

    return "\n".join(f"        {line}" for line in directives)


def _server_access_log_line(route: DomainRoute) -> str:
    """access_log на уровне server{} — чтобы логировать 444 от bot-protect тоже.

    Раньше access_log был внутри location / — и return 444 от if ($bad_bot_ua)
    в scope server{} не попадал в лог. Метрика bot_blocked_24h была всегда 0.
    Теперь лог пишется на уровне server{} → все ответы (включая 444) в логе.
    """
    if not route.enable_logging:
        return ""
    return f"    access_log {HTTP_LOG_PATH} dc_json;\n"


def _bot_protect_include_for(route: DomainRoute) -> str:
    """Строка include bot-protection snippet'а — только если домен не опт-аутнут.

    В DEV_MODE не подключается (файла на dev-машине нет).
    """
    if DEV_MODE or not route.enable_bot_protection:
        return ""
    return "    include /etc/nginx/snippets/bot-protect.conf;\n\n"


def generate_nginx_config():
    """Сгенерировать domain-routes.conf."""
    ensure_acme_webroot()
    routes = DomainRoute.query.order_by(DomainRoute.domain).all()
    blocks: list[str] = []

    for route in routes:
        server_names = route.domain.strip()
        proxy_block = build_proxy_directives(route)
        https_active = frontend_https_ready(route)
        lp = route.listen_port or 80
        lps = route.listen_port_ssl or 443
        bot_include = _bot_protect_include_for(route)
        access_log_line = _server_access_log_line(route)

        # HTTP server
        if https_active:
            http_block = f"""
# {route.id}: {server_names}:{lp} -> {'https' if route.backend_https else 'http'}://{route.target_host}:{route.target_port}
server {{
    listen {lp};
    server_name {server_names};

{access_log_line}{bot_include}    location ^~ /.well-known/acme-challenge/ {{
        root {ACME_WEBROOT};
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}
"""
        else:
            http_block = f"""
# {route.id}: {server_names}:{lp} -> {'https' if route.backend_https else 'http'}://{route.target_host}:{route.target_port}
server {{
    listen {lp};
    server_name {server_names};

{access_log_line}{bot_include}    location ^~ /.well-known/acme-challenge/ {{
        root {ACME_WEBROOT};
    }}

    location / {{
{proxy_block}
    }}
}}
"""
        blocks.append(http_block)

        # HTTPS server
        if https_active:
            https_block = f"""
server {{
    listen {lps} ssl http2;
    server_name {server_names};

    ssl_certificate {route.ssl_cert_path};
    ssl_certificate_key {route.ssl_key_path};

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_protocols TLSv1.2 TLSv1.3;

{access_log_line}{bot_include}    location / {{
{proxy_block}
    }}
}}
"""
            blocks.append(https_block)

    content = "\n".join(blocks) if blocks else "# no domains configured yet\n"
    return build_log_format_block() + content


# ──────────────────────────────────────────────
#  Nginx config generation — Stream (TCP/UDP)
# ──────────────────────────────────────────────

def generate_stream_config():
    """Сгенерировать stream-routes.conf для TCP/UDP маршрутов.

    Возвращает строку с содержимым конфига (не пишет на диск).
    """
    streams = StreamRoute.query.order_by(StreamRoute.listen_port).all()

    if not streams:
        return "# no stream routes configured yet\n"

    blocks: list[str] = []
    blocks.append("stream {")
    blocks.append(f"""
    log_format dc_stream escape=json '{{'
      '"time":"$time_iso8601",'
      '"remote_addr":"$remote_addr",'
      '"remote_port":"$remote_port",'
      '"server_port":"$server_port",'
      '"protocol":"$protocol",'
      '"bytes_received":$bytes_received,'
      '"bytes_sent":$bytes_sent,'
      '"session_time":"$session_time",'
      '"upstream_addr":"$upstream_addr",'
      '"status":"$status"'
      '}}'
    ;
    access_log {STREAM_LOG_PATH} dc_stream;
""")

    for s in streams:
        proto_flag = " udp" if s.protocol == "udp" else ""
        hint = f"  ({s.domain_hint})" if s.domain_hint else ""
        preset = SERVICE_PRESETS.get(s.service_type, {})
        svc_label = preset.get("label", s.service_type) if preset else s.service_type
        block = f"""
    # [{svc_label}] {s.name}{hint}
    server {{
        listen {s.listen_port}{proto_flag};
        proxy_pass {s.target_host}:{s.target_port};
        proxy_timeout 3600s;
        proxy_connect_timeout 10s;
    }}
"""
        blocks.append(block)

    blocks.append("}")
    return "\n".join(blocks)


PANEL_NGINX_PATH = "/etc/nginx/sites-available/domain-panel.conf"
if DEV_MODE:
    PANEL_NGINX_PATH = os.path.join(BASE_DIR, "dev_domain-panel.conf")


def generate_panel_config() -> str:
    """Собрать /etc/nginx/sites-available/domain-panel.conf из IpAllowlist.

    Возвращает строку (как generate_nginx_config). Записывает её `apply_all_configs`
    атомарно, с rollback на случай `nginx -t` failure.
    """
    # Порядок стабильный (по id) — чтобы diff конфигов между reload'ами был читаемым
    entries = IpAllowlist.query.order_by(IpAllowlist.id).all()
    allow_lines = []
    for e in entries:
        comment = f"    # {e.comment}" if e.comment else ""
        allow_lines.append(f"    allow {e.cidr};{comment}")
    if not allow_lines:
        # На случай если таблица осиротела — fallback чтобы не закрыть всех "deny all"
        allow_lines.append("    allow 10.0.0.0/8;  # fallback (IpAllowlist пустой)")

    allow_block = "\n".join(allow_lines)

    return f"""# Сгенерировано DomainController из таблицы ip_allowlist.
# Ручное редактирование бессмысленно — следующий apply_all_configs перепишет.
# Для добавления IP — через UI: /firewall → секция Allowlist.

limit_req_zone $binary_remote_addr zone=panel_login:5m rate=5r/m;
limit_req_zone $binary_remote_addr zone=panel_general:10m rate=30r/s;

server {{
    listen 8080;
    server_name _;

    # Whitelist — доступ к панели управления.
{allow_block}
    deny all;

    # Анти-Slowloris.
    client_header_timeout  10s;
    client_body_timeout    10s;
    send_timeout           10s;
    keepalive_timeout      30s;

    client_max_body_size   1m;
    client_body_buffer_size 16k;

    # Security headers.
    add_header X-Frame-Options          "DENY"           always;
    add_header X-Content-Type-Options   "nosniff"        always;
    add_header Referrer-Policy          "no-referrer"    always;
    add_header X-XSS-Protection         "1; mode=block"  always;
    add_header Permissions-Policy       "geolocation=(), microphone=(), camera=()" always;

    location = /login {{
        limit_req zone=panel_login burst=3 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout    60s;
        proxy_send_timeout    60s;
    }}

    location = /healthz {{
        allow all;
        proxy_pass http://127.0.0.1:5000/healthz;
        access_log off;
        proxy_read_timeout 5s;
    }}

    location / {{
        limit_req zone=panel_general burst=60 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout    180s;
        proxy_send_timeout    180s;
    }}
}}
"""


def _atomic_write(path: str, content: str):
    """Атомарно записать файл через временный файл + os.replace.

    Гарантирует, что при любом крахе в середине записи на диске остаётся
    либо старая, либо новая версия, но не полу-записанная.
    """
    tmp_path = f"{path}.tmp.{os.getpid()}"
    with open(tmp_path, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def apply_all_configs():
    """Атомарно сгенерировать nginx-конфиги и перезагрузить nginx.

    Алгоритм:
    1. Сгенерировать новые конфиги в памяти (строки).
    2. Сделать `.rollback`-бэкап текущих файлов.
    3. Атомарно записать новые конфиги (tmp → rename).
    4. `nginx -t`. Если не прошёл — восстановить из `.rollback` и поднять ошибку.
    5. `systemctl reload nginx`. Если не прошёл — то же самое.
    6. Удалить `.rollback`-бэкапы.
    """
    # 1. Сгенерировать в память
    new_http = generate_nginx_config()
    new_stream = generate_stream_config()
    new_panel = generate_panel_config()

    if DEV_MODE:
        # В dev-режиме только пишем файлы (рядом с проектом), nginx не трогаем.
        _atomic_write(NGINX_CONF_PATH, new_http)
        _atomic_write(STREAM_CONF_PATH, new_stream)
        _atomic_write(PANEL_NGINX_PATH, new_panel)
        return

    # 2. Бэкапы текущих конфигов
    targets = [
        (NGINX_CONF_PATH, new_http),
        (STREAM_CONF_PATH, new_stream),
        (PANEL_NGINX_PATH, new_panel),
    ]
    rollbacks: list = []  # (path, rollback_path)
    for path, _content in targets:
        rp = path + ".rollback"
        if os.path.exists(path):
            _atomic_write(rp, open(path).read())
            rollbacks.append((path, rp))

    def _restore_from_rollback():
        for path, rp in rollbacks:
            try:
                os.replace(rp, path)
            except OSError as oe:
                logger.error("rollback %s failed: %s", path, oe)

    # 3. Атомарная запись новых конфигов
    try:
        for path, content in targets:
            _atomic_write(path, content)
    except Exception:
        _restore_from_rollback()
        raise

    # 4. Валидация
    try:
        subprocess.run(["nginx", "-t"], check=True, capture_output=True, text=True, timeout=30)
    except subprocess.CalledProcessError as e:
        logger.error("nginx -t failed, rolling back: %s\n%s", e, e.stderr if hasattr(e, "stderr") else "")
        _restore_from_rollback()
        raise
    except subprocess.TimeoutExpired:
        logger.error("nginx -t timed out, rolling back")
        _restore_from_rollback()
        raise subprocess.CalledProcessError(1, ["nginx", "-t"], "timeout")

    # 5. Reload
    try:
        subprocess.run(["systemctl", "reload", "nginx"], check=True, capture_output=True, text=True, timeout=30)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.error("systemctl reload nginx failed, rolling back: %s", e)
        _restore_from_rollback()
        try:
            subprocess.run(["systemctl", "reload", "nginx"], check=False, timeout=30)
        except Exception:
            pass
        raise subprocess.CalledProcessError(
            e.returncode if hasattr(e, "returncode") else 1,
            ["systemctl", "reload", "nginx"],
            str(e),
        )

    # 6. Удалить .rollback
    for _path, rp in rollbacks:
        try:
            os.unlink(rp)
        except FileNotFoundError:
            pass


# ──────────────────────────────────────────────
#  Background log reader
# ──────────────────────────────────────────────

def _safe_int(v, default=0):
    try:
        return int(v) if v not in (None, "", "-") else default
    except (TypeError, ValueError):
        return default


def _safe_float(v, default=0.0):
    try:
        return float(v) if v not in (None, "", "-") else default
    except (TypeError, ValueError):
        return default


def _parse_ts(value):
    if not value:
        return _utcnow()
    try:
        return datetime.datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return _utcnow()


def _read_new_lines(path: str, key: str):
    """Прочитать новые строки из файла, используя персистентный checkpoint.

    Возвращает список строк. Детектирует ротацию (смена inode) и truncate
    (файл стал меньше сохранённой позиции) — в обоих случаях читаем с начала.
    На первом запуске (checkpoint отсутствует) стартуем с конца файла, чтобы
    не перечитывать исторические мегабайты и не создавать дубликаты.
    """
    if not os.path.exists(path):
        return []

    st = os.stat(path)
    cp = db.session.get(LogCheckpoint, key)

    if cp is None:
        cp = LogCheckpoint(key=key, position=st.st_size, inode=st.st_ino, file_size=st.st_size)
        db.session.add(cp)
        db.session.commit()
        return []

    if cp.inode != st.st_ino or st.st_size < cp.position:
        logger.info("log rotation/truncate detected for %s (inode %s→%s, size %s→%s)",
                    path, cp.inode, st.st_ino, cp.position, st.st_size)
        cp.position = 0
        cp.inode = st.st_ino

    with open(path, "r") as f:
        f.seek(cp.position)
        new_lines = f.readlines()
        new_pos = f.tell()

    cp.position = new_pos
    cp.file_size = st.st_size
    return new_lines


def _record_parser_error(source: str, line: str, exc: Exception):
    """Сохранить проблемную строку в dead-letter, если не раздут."""
    # Ограничиваем размер таблицы — не даём ей расти бесконечно на кривом nginx.
    try:
        count = db.session.query(func.count(ParserError.id)).scalar() or 0
        if count >= 10000:
            return
        db.session.add(ParserError(
            source=source,
            line_excerpt=(line or "")[:1024],
            error=f"{type(exc).__name__}: {exc}"[:255],
        ))
    except Exception:
        # Если даже запись в dead-letter упала — молча продолжаем
        db.session.rollback()


def _parse_http_log():
    """Прочитать новые строки из dc_access.json."""
    new_lines = _read_new_lines(HTTP_LOG_PATH, "http_log")
    if not new_lines:
        db.session.commit()
        return

    entries = []
    for line in new_lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError as e:
            _record_parser_error("http_log", line, e)
            continue

        entries.append(AccessLog(
            timestamp=_parse_ts(d.get("time")),
            remote_addr=d.get("remote_addr", ""),
            remote_port=_safe_int(d.get("remote_port")),
            server_name=d.get("server_name", ""),
            server_port=_safe_int(d.get("server_port")),
            method=d.get("request_method", ""),
            uri=(d.get("request_uri") or "")[:2048],
            status=_safe_int(d.get("status")),
            body_bytes=_safe_int(d.get("body_bytes_sent")),
            request_time=_safe_float(d.get("request_time")),
            upstream_addr=d.get("upstream_addr", ""),
            upstream_time=str(d.get("upstream_response_time", "")),
            user_agent=(d.get("http_user_agent") or "")[:512],
            referer=(d.get("http_referer") or "")[:512],
            scheme=d.get("scheme", ""),
            ssl_protocol=d.get("ssl_protocol", ""),
        ))

    if entries:
        db.session.bulk_save_objects(entries)
    db.session.commit()


def _parse_stream_log():
    """Прочитать новые строки из dc_stream.json."""
    new_lines = _read_new_lines(STREAM_LOG_PATH, "stream_log")
    if not new_lines:
        db.session.commit()
        return

    entries = []
    for line in new_lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError as e:
            _record_parser_error("stream_log", line, e)
            continue

        entries.append(StreamAccessLog(
            timestamp=_parse_ts(d.get("time")),
            remote_addr=d.get("remote_addr", ""),
            remote_port=_safe_int(d.get("remote_port")),
            server_port=_safe_int(d.get("server_port")),
            protocol=d.get("protocol", "TCP"),
            bytes_received=_safe_int(d.get("bytes_received")),
            bytes_sent=_safe_int(d.get("bytes_sent")),
            session_time=_safe_float(d.get("session_time")),
            upstream_addr=d.get("upstream_addr", ""),
            status=str(d.get("status", ""))[:10],
        ))

    if entries:
        db.session.bulk_save_objects(entries)
    db.session.commit()


FAIL2BAN_LOG_PATH = "/var/log/fail2ban.log"
_FAIL2BAN_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}),\d+\s+fail2ban\.actions\s+\[\d+\]:\s+"
    r"(?:NOTICE|WARNING)\s+\[([\w.-]+)\]\s+(Ban|Unban|Restore Ban|Found)\s+(\S+)"
)


def _parse_fail2ban_log():
    """Парсит /var/log/fail2ban.log — строит реальную историю банов.

    События Ban/Unban/Restore Ban попадают в таблицу fail2ban_events.
    Позиция чтения — в log_checkpoints по ключу "fail2ban_log" (тот же механизм
    что для nginx-логов: инкрементально, с детектом ротации через inode).
    """
    if DEV_MODE or not os.path.exists(FAIL2BAN_LOG_PATH):
        return

    # Право чтения /var/log/fail2ban.log есть только у root. Наш сервис уже root,
    # так что OSError тут маловероятен — но на всякий случай глушим.
    try:
        new_lines = _read_new_lines(FAIL2BAN_LOG_PATH, "fail2ban_log")
    except OSError as e:
        logger.warning("cannot read %s: %s", FAIL2BAN_LOG_PATH, e)
        db.session.rollback()
        return

    if not new_lines:
        db.session.commit()
        return

    entries = []
    for line in new_lines:
        m = _FAIL2BAN_LINE_RE.match(line)
        if not m:
            continue
        ts_raw, jail, action, ip = m.groups()
        # "Restore Ban" → "Restore" для унификации
        action = action.replace("Restore Ban", "Restore")
        # Fail2ban иногда пишет "Found" — это не бан, а только детект; пропускаем
        if action == "Found":
            continue
        try:
            ts = datetime.datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if not is_valid_ip(ip):
            continue
        entries.append(FailbanEvent(timestamp=ts, jail=jail, action=action, ip=ip))

    if entries:
        db.session.bulk_save_objects(entries)
    db.session.commit()


CLEANUP_CHECKPOINT_KEY = "cleanup_last_run"
CLEANUP_INTERVAL_SECONDS = 24 * 3600
CLEANUP_BATCH_SIZE = 5000


def _delete_old_in_batches(model, cutoff):
    """Удалить старые записи порциями, чтобы не держать write-lock на БД.

    Поле «когда создана запись» — у разных таблиц называется по-разному:
    AccessLog.timestamp, StreamAccessLog.timestamp, но ParserError.created_at,
    AuditLog.created_at. Выбираем подходящее динамически.
    """
    time_col = getattr(model, "timestamp", None) or getattr(model, "created_at", None)
    if time_col is None:
        return 0
    total = 0
    while True:
        ids = [row[0] for row in db.session.query(model.id)
               .filter(time_col < cutoff)
               .limit(CLEANUP_BATCH_SIZE)
               .all()]
        if not ids:
            break
        db.session.query(model).filter(model.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()
        total += len(ids)
        if len(ids) < CLEANUP_BATCH_SIZE:
            break
    return total


def _cleanup_old_logs(days: int | None = None, force: bool = False):
    """Удалить старые записи. Запускается не чаще раза в сутки.

    Сроки хранения берутся из AppSetting (управляются через UI /settings),
    с fallback на дефолты в SETTING_DEFINITIONS.
    """
    cp = db.session.get(LogCheckpoint, CLEANUP_CHECKPOINT_KEY)
    now = _utcnow()
    if not force and cp is not None:
        last_run = datetime.datetime.fromtimestamp(cp.position or 0, tz=datetime.timezone.utc).replace(tzinfo=None)
        if (now - last_run).total_seconds() < CLEANUP_INTERVAL_SECONDS:
            return 0

    access_days = days if days is not None else get_setting("retention_access_logs_days", 30)
    stream_days = get_setting("retention_stream_logs_days", 30)
    audit_days = get_setting("retention_audit_logs_days", 365)
    parser_days = get_setting("retention_parser_errors_days", 30)
    f2b_days = get_setting("retention_fail2ban_events_days", 30)

    removed_http = _delete_old_in_batches(AccessLog, now - datetime.timedelta(days=access_days))
    removed_stream = _delete_old_in_batches(StreamAccessLog, now - datetime.timedelta(days=stream_days))
    removed_parser = _delete_old_in_batches(ParserError, now - datetime.timedelta(days=parser_days))
    removed_f2b = _delete_old_in_batches(FailbanEvent, now - datetime.timedelta(days=f2b_days))

    # Audit — удаляется по created_at, а не timestamp.
    audit_cutoff = now - datetime.timedelta(days=audit_days)
    removed_audit = 0
    while True:
        ids = [row[0] for row in db.session.query(AuditLog.id)
               .filter(AuditLog.created_at < audit_cutoff)
               .limit(CLEANUP_BATCH_SIZE).all()]
        if not ids:
            break
        db.session.query(AuditLog).filter(AuditLog.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()
        removed_audit += len(ids)
        if len(ids) < CLEANUP_BATCH_SIZE:
            break

    if cp is None:
        cp = LogCheckpoint(key=CLEANUP_CHECKPOINT_KEY)
        db.session.add(cp)
    cp.position = int(now.timestamp())
    cp.inode = 0
    cp.file_size = 0
    db.session.commit()

    total = removed_http + removed_stream + removed_parser + removed_audit + removed_f2b
    if total:
        logger.info("cleanup: removed %d access + %d stream + %d parser_errors + %d audit + %d fail2ban (retention: access %dd, audit %dd)",
                    removed_http, removed_stream, removed_parser, removed_audit, removed_f2b,
                    access_days, audit_days)
    return total


def _generate_fake_data():
    """DEV_MODE: генерировать фейковые данные для тестирования дашборда."""
    domains = DomainRoute.query.all()
    streams = StreamRoute.query.all()

    if not domains and not streams:
        return

    now = _utcnow()
    methods = ["GET", "GET", "GET", "POST", "PUT", "DELETE", "HEAD"]
    uris = ["/", "/api/data", "/login", "/static/app.js", "/admin", "/images/logo.png",
            "/api/users", "/products", "/checkout", "/favicon.ico", "/health", "/ws"]
    statuses = [200, 200, 200, 200, 200, 301, 302, 304, 400, 403, 404, 404, 500, 502]
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1",
        "Mozilla/5.0 (Linux; Android 14) Mobile Chrome/120.0",
        "curl/8.4.0", "python-requests/2.31.0", "PostmanRuntime/7.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2) Safari/604.1",
    ]
    ips = [f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(30)]
    ips += [f"10.100.10.{random.randint(1,254)}" for _ in range(5)]

    http_entries = []
    for _ in range(random.randint(15, 40)):
        if not domains:
            break
        route = random.choice(domains)
        ts = now - datetime.timedelta(minutes=random.randint(0, 1440), seconds=random.randint(0, 59))
        http_entries.append(AccessLog(
            timestamp=ts,
            remote_addr=random.choice(ips),
            remote_port=random.randint(30000, 65535),
            server_name=route.domain,
            server_port=route.listen_port or 80,
            method=random.choice(methods),
            uri=random.choice(uris),
            status=random.choice(statuses),
            body_bytes=random.randint(200, 500000),
            request_time=round(random.uniform(0.001, 2.5), 3),
            upstream_addr=f"{route.target_host}:{route.target_port}",
            upstream_time=str(round(random.uniform(0.001, 2.0), 3)),
            user_agent=random.choice(agents),
            referer="",
            scheme=random.choice(["http", "https"]),
            ssl_protocol=random.choice(["TLSv1.3", "TLSv1.2", "-"]),
        ))

    stream_entries = []
    for _ in range(random.randint(5, 15)):
        if not streams:
            break
        s = random.choice(streams)
        ts = now - datetime.timedelta(minutes=random.randint(0, 1440), seconds=random.randint(0, 59))
        stream_entries.append(StreamAccessLog(
            timestamp=ts,
            remote_addr=random.choice(ips),
            remote_port=random.randint(30000, 65535),
            server_port=s.listen_port,
            protocol=s.protocol.upper(),
            bytes_received=random.randint(100, 50000),
            bytes_sent=random.randint(100, 50000),
            session_time=round(random.uniform(0.1, 300.0), 2),
            upstream_addr=f"{s.target_host}:{s.target_port}",
            status=random.choice(["200", "502", "200", "200"]),
        ))

    if http_entries:
        db.session.bulk_save_objects(http_entries)
    if stream_entries:
        db.session.bulk_save_objects(stream_entries)
    db.session.commit()


HEALTH_CHECK_INTERVAL_SECONDS = 120  # раз в 2 минуты
HEALTH_CHECK_TIMEOUT_SECONDS = 3
_last_health_run = 0.0


def _tcp_ping(host: str, port: int, timeout: float = HEALTH_CHECK_TIMEOUT_SECONDS) -> tuple[bool, str]:
    """Простой TCP-connect до backend. Возвращает (ok, error_or_empty)."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except socket.timeout:
        return False, "timeout"
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"[:255]


def _run_backend_health_checks():
    """Пинговать все target_host:target_port маршрутов, апдейтить статусы в БД."""
    global _last_health_run
    now_ts = time.time()
    interval = get_setting("backend_health_interval_sec", HEALTH_CHECK_INTERVAL_SECONDS)
    if now_ts - _last_health_run < interval:
        return
    _last_health_run = now_ts

    routes = DomainRoute.query.all()
    now = _utcnow()
    changed = False
    for r in routes:
        ok, err = _tcp_ping(r.target_host, r.target_port)
        new_status = "up" if ok else "down"
        prev_status = r.last_health_status
        if prev_status != new_status:
            logger.info("backend health change: %s (%s:%s) %s → %s (%s)",
                        r.domain, r.target_host, r.target_port,
                        prev_status or "?", new_status, err or "ok")
            # Сигналим вебхуком только при переходе up→down (чтобы не спамить).
            if new_status == "down" and prev_status == "up":
                _fire_webhook("backend_down", domain=r.domain,
                              details=f"{r.target_host}:{r.target_port} — {err}")
        r.last_health_check = now
        r.last_health_status = new_status
        r.last_health_error = err if not ok else None
        changed = True
    if changed:
        db.session.commit()


SSL_WARNING_THRESHOLD_DAYS = 14
_last_ssl_warning_run = 0.0
_ssl_warned_domains: set = set()


def _check_ssl_expiry_warnings():
    """Раз в сутки проверять все SSL и уведомлять через webhook при <14 дней.

    Каждый домен шлёт warning только один раз, пока не обновится — трек в памяти.
    Сбрасывается при рестарте (не критично).
    """
    global _last_ssl_warning_run
    now_ts = time.time()
    if now_ts - _last_ssl_warning_run < 86400:
        return
    _last_ssl_warning_run = now_ts

    if DEV_MODE:
        return

    routes = DomainRoute.query.filter(DomainRoute.enable_https.is_(True)).all()
    now = _utcnow()
    for r in routes:
        if not r.ssl_cert_path:
            continue
        expires_at = _read_ssl_expiry(r.ssl_cert_path)
        if expires_at is None:
            continue
        days_left = (expires_at - now).days
        threshold = get_setting("ssl_warning_threshold_days", SSL_WARNING_THRESHOLD_DAYS)
        if days_left < threshold and r.domain not in _ssl_warned_domains:
            _fire_webhook("ssl_expiring_soon", domain=r.domain,
                          details=f"expires in {days_left} days ({expires_at.isoformat()})")
            log_action("ssl_expiring_soon", domain=r.domain, details=f"{days_left} days left")
            _ssl_warned_domains.add(r.domain)
        elif days_left >= threshold * 2:
            # После обновления сертификата — сбрасываем warned-флаг.
            _ssl_warned_domains.discard(r.domain)


def start_log_reader():
    """Запустить фоновый поток чтения логов.

    Защита от «тихой смерти» потока: любые исключения логируются со стеком,
    но поток продолжает работать. Раньше здесь стоял `except: pass`,
    из-за чего потеря парсинга могла остаться незамеченной сутками.
    """
    def _worker():
        while True:
            try:
                with app.app_context():
                    if DEV_MODE:
                        try:
                            _generate_fake_data()
                        except Exception:
                            logger.exception("fake data generator failed")
                            db.session.rollback()
                    else:
                        try:
                            _parse_http_log()
                        except Exception:
                            logger.exception("_parse_http_log failed")
                            db.session.rollback()
                        try:
                            _parse_stream_log()
                        except Exception:
                            logger.exception("_parse_stream_log failed")
                            db.session.rollback()
                    try:
                        _cleanup_old_logs(days=30)
                    except Exception:
                        logger.exception("_cleanup_old_logs failed")
                        db.session.rollback()
                    try:
                        _run_backend_health_checks()
                    except Exception:
                        logger.exception("backend health check failed")
                        db.session.rollback()
                    try:
                        _check_ssl_expiry_warnings()
                    except Exception:
                        logger.exception("SSL expiry check failed")
                        db.session.rollback()
                    try:
                        _check_expired_pauses()
                    except Exception:
                        logger.exception("jail pause check failed")
                        db.session.rollback()
                    try:
                        _parse_fail2ban_log()
                    except Exception:
                        logger.exception("fail2ban log parser failed")
                        db.session.rollback()
            except Exception:
                logger.exception("log reader loop crashed")
            time.sleep(10 if DEV_MODE else 5)

    t = threading.Thread(target=_worker, daemon=True, name="dc-log-reader")
    t.start()


# ──────────────────────────────────────────────
#  Stats API endpoints
# ──────────────────────────────────────────────

@app.route("/api/stats/overview")
@login_required
def api_stats_overview():
    """Общая сводка за 24 часа."""
    since = _utcnow() - datetime.timedelta(hours=24)

    total = AccessLog.query.filter(AccessLog.timestamp >= since).count()
    unique_ips = db.session.query(func.count(func.distinct(AccessLog.remote_addr))).filter(
        AccessLog.timestamp >= since).scalar() or 0
    errors = AccessLog.query.filter(AccessLog.timestamp >= since, AccessLog.status >= 400).count()
    avg_time = db.session.query(func.avg(AccessLog.request_time)).filter(
        AccessLog.timestamp >= since).scalar() or 0.0

    total_stream = StreamAccessLog.query.filter(StreamAccessLog.timestamp >= since).count()
    total_bytes_in = db.session.query(func.sum(StreamAccessLog.bytes_received)).filter(
        StreamAccessLog.timestamp >= since).scalar() or 0
    total_bytes_out = db.session.query(func.sum(StreamAccessLog.bytes_sent)).filter(
        StreamAccessLog.timestamp >= since).scalar() or 0

    # Количество доменов и stream
    domain_count = DomainRoute.query.count()
    stream_count = StreamRoute.query.count()

    return jsonify({
        "total_requests": total,
        "unique_ips": unique_ips,
        "errors_4xx_5xx": errors,
        "avg_response_time": round(avg_time, 3),
        "total_stream_sessions": total_stream,
        "stream_bytes_in": total_bytes_in,
        "stream_bytes_out": total_bytes_out,
        "domain_count": domain_count,
        "stream_count": stream_count,
    })


@app.route("/api/stats/timeline")
@login_required
def api_stats_timeline():
    """Запросы по часам за последние N часов."""
    hours = int(request.args.get("hours", 24))
    since = _utcnow() - datetime.timedelta(hours=hours)

    rows = db.session.query(
        _hour_bucket_sql(AccessLog.timestamp).label("hour"),
        func.count().label("cnt"),
    ).filter(
        AccessLog.timestamp >= since
    ).group_by("hour").order_by("hour").all()

    return jsonify({
        "labels": [r.hour for r in rows],
        "data": [r.cnt for r in rows],
    })


@app.route("/api/stats/status-codes")
@login_required
def api_stats_status_codes():
    """Распределение HTTP-статусов за 24ч."""
    since = _utcnow() - datetime.timedelta(hours=24)

    rows = db.session.query(
        AccessLog.status,
        func.count().label("cnt"),
    ).filter(
        AccessLog.timestamp >= since
    ).group_by(AccessLog.status).order_by(func.count().desc()).all()

    return jsonify({
        "labels": [str(r.status) for r in rows],
        "data": [r.cnt for r in rows],
    })


@app.route("/api/stats/domains")
@login_required
def api_stats_domains():
    """Статистика по каждому домену за 24ч."""
    since = _utcnow() - datetime.timedelta(hours=24)

    rows = db.session.query(
        AccessLog.server_name,
        func.count().label("cnt"),
        func.avg(AccessLog.request_time).label("avg_time"),
        func.sum(AccessLog.body_bytes).label("total_bytes"),
    ).filter(
        AccessLog.timestamp >= since
    ).group_by(AccessLog.server_name).order_by(func.count().desc()).all()

    return jsonify([{
        "domain": r.server_name,
        "requests": r.cnt,
        "avg_time": round(r.avg_time or 0, 3),
        "total_bytes": r.total_bytes or 0,
    } for r in rows])


@app.route("/api/stats/top-ips")
@login_required
def api_stats_top_ips():
    """Топ IP-адресов за 24ч."""
    since = _utcnow() - datetime.timedelta(hours=24)
    limit = int(request.args.get("limit", 20))

    rows = db.session.query(
        AccessLog.remote_addr,
        func.count().label("cnt"),
        func.max(AccessLog.timestamp).label("last_seen"),
    ).filter(
        AccessLog.timestamp >= since
    ).group_by(AccessLog.remote_addr).order_by(func.count().desc()).limit(limit).all()

    return jsonify([{
        "ip": r.remote_addr,
        "requests": r.cnt,
        "last_seen": r.last_seen.isoformat() if r.last_seen else "",
    } for r in rows])


@app.route("/api/stats/top-uris")
@login_required
def api_stats_top_uris():
    """Топ URI (опционально по домену) за 24ч."""
    since = _utcnow() - datetime.timedelta(hours=24)
    domain = request.args.get("domain")
    limit = int(request.args.get("limit", 20))

    q = db.session.query(
        AccessLog.uri,
        func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since)

    if domain:
        q = q.filter(AccessLog.server_name == domain)

    rows = q.group_by(AccessLog.uri).order_by(func.count().desc()).limit(limit).all()

    return jsonify([{"uri": r.uri, "requests": r.cnt} for r in rows])


@app.route("/api/stats/errors")
@login_required
def api_stats_errors():
    """Последние ошибки (4xx/5xx)."""
    since = _utcnow() - datetime.timedelta(hours=24)
    limit = int(request.args.get("limit", 50))

    rows = AccessLog.query.filter(
        AccessLog.timestamp >= since,
        AccessLog.status >= 400,
    ).order_by(AccessLog.timestamp.desc()).limit(limit).all()

    return jsonify([{
        "time": r.timestamp.isoformat() if r.timestamp else "",
        "domain": r.server_name,
        "uri": r.uri,
        "status": r.status,
        "ip": r.remote_addr,
        "user_agent": r.user_agent,
    } for r in rows])


@app.route("/api/stats/streams")
@login_required
def api_stats_streams():
    """Статистика по stream-портам за 24ч."""
    since = _utcnow() - datetime.timedelta(hours=24)

    rows = db.session.query(
        StreamAccessLog.server_port,
        func.count().label("cnt"),
        func.sum(StreamAccessLog.bytes_received).label("bytes_in"),
        func.sum(StreamAccessLog.bytes_sent).label("bytes_out"),
        func.avg(StreamAccessLog.session_time).label("avg_session"),
    ).filter(
        StreamAccessLog.timestamp >= since
    ).group_by(StreamAccessLog.server_port).order_by(func.count().desc()).all()

    return jsonify([{
        "port": r.server_port,
        "sessions": r.cnt,
        "bytes_in": r.bytes_in or 0,
        "bytes_out": r.bytes_out or 0,
        "avg_session_time": round(r.avg_session or 0, 2),
    } for r in rows])


def _read_ssl_expiry(cert_path: str) -> datetime.datetime | None:
    """Вернуть notAfter сертификата или None при ошибке."""
    if not cert_path or not os.path.exists(cert_path):
        return None
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        end = out.stdout.strip().replace("notAfter=", "")
        return datetime.datetime.strptime(end, "%b %d %H:%M:%S %Y %Z")
    except Exception:
        return None


# Кэш SSL-статусов — чтобы не дёргать openssl на каждый AJAX-тик dashboard.
_SSL_CACHE: dict = {}
_SSL_CACHE_LOCK = threading.Lock()
_SSL_CACHE_TTL = 300.0  # 5 минут


@app.route("/api/stats/ssl")
@login_required
def api_stats_ssl():
    """Список всех HTTPS-доменов с оставшимися днями до истечения сертификата."""
    now_ts = time.time()
    with _SSL_CACHE_LOCK:
        cached = _SSL_CACHE.get("all")
        if cached and (now_ts - cached[0]) < _SSL_CACHE_TTL:
            return jsonify(cached[1])

    domains = DomainRoute.query.filter(DomainRoute.enable_https.is_(True)).order_by(DomainRoute.domain).all()
    now = _utcnow()
    result = []
    for r in domains:
        expires_at = _read_ssl_expiry(r.ssl_cert_path) if not DEV_MODE else None
        if expires_at is None:
            result.append({
                "domain": r.domain,
                "expires_at": None,
                "days_left": None,
                "status": "unknown",
            })
            continue
        days_left = (expires_at - now).days
        if days_left < 0:
            status = "expired"
        elif days_left < 7:
            status = "critical"
        elif days_left < 30:
            status = "warning"
        else:
            status = "ok"
        result.append({
            "domain": r.domain,
            "expires_at": expires_at.isoformat() + "Z",
            "days_left": days_left,
            "status": status,
        })

    # Сортировка: сначала проблемные (меньше days_left), None в конец.
    result.sort(key=lambda x: (x["days_left"] is None, x["days_left"] if x["days_left"] is not None else 9999))

    with _SSL_CACHE_LOCK:
        _SSL_CACHE["all"] = (now_ts, result)
    return jsonify(result)


@app.route("/api/stats/comparison")
@login_required
def api_stats_comparison():
    """Сравнение периодов: текущие 24ч vs предыдущие 24ч.

    Для каждого ключевого показателя возвращает current/previous/delta_pct.
    Чтобы фронт мог показать стрелки +12% / -5% рядом с big-metric'ами.
    """
    hours = max(1, min(int(request.args.get("hours", 24)), 168))
    now = _utcnow()
    cur_since = now - datetime.timedelta(hours=hours)
    prev_since = now - datetime.timedelta(hours=hours * 2)

    def _metrics(since, until):
        base = AccessLog.query.filter(AccessLog.timestamp >= since, AccessLog.timestamp < until)
        total = base.count()
        errors = base.filter(AccessLog.status >= 400).count()
        avg_time = db.session.query(func.avg(AccessLog.request_time)).filter(
            AccessLog.timestamp >= since, AccessLog.timestamp < until).scalar() or 0
        unique_ips = db.session.query(func.count(func.distinct(AccessLog.remote_addr))).filter(
            AccessLog.timestamp >= since, AccessLog.timestamp < until).scalar() or 0
        bytes_sum = db.session.query(func.sum(AccessLog.body_bytes)).filter(
            AccessLog.timestamp >= since, AccessLog.timestamp < until).scalar() or 0
        return {
            "total": total, "errors": errors,
            "avg_time": round(avg_time, 3),
            "unique_ips": unique_ips,
            "bytes": bytes_sum,
            "error_rate": round(errors / total * 100, 2) if total else 0,
        }

    cur = _metrics(cur_since, now)
    prev = _metrics(prev_since, cur_since)

    def _delta(c, p):
        if not p:
            return None if c == 0 else 100.0
        return round((c - p) / p * 100, 1)

    return jsonify({
        "current": cur,
        "previous": prev,
        "delta_pct": {k: _delta(cur[k], prev[k]) for k in cur},
    })


@app.route("/api/stats/heatmap")
@login_required
def api_stats_heatmap():
    """Матрица 7×24 — активность по дням недели × часам дня, за последние 7 дней.

    SQLite %w = 0 (воскресенье) … 6 (суббота).
    """
    since = _utcnow() - datetime.timedelta(days=7)
    rows = db.session.query(
        _day_of_week_sql(AccessLog.timestamp).label("dow"),
        _hour_of_day_sql(AccessLog.timestamp).label("hour"),
        func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since).group_by("dow", "hour").all()

    # matrix[dow][hour] = count. Преобразуем в понедельник-начало (0=Mon).
    matrix = [[0] * 24 for _ in range(7)]
    for r in rows:
        try:
            # SQLite dow: 0=Sun, сдвигаем к ISO 0=Mon
            sun_based = int(r.dow)
            iso_dow = (sun_based + 6) % 7
            hr = int(r.hour)
            matrix[iso_dow][hr] = r.cnt
        except (ValueError, TypeError):
            continue

    return jsonify({
        "days": ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"],
        "hours": list(range(24)),
        "matrix": matrix,
    })


@app.route("/api/stats/geography")
@login_required
def api_stats_geography():
    """UZ vs World по распределению запросов за 24ч.

    Оптимизировано: сначала GROUP BY remote_addr (уникальных IP обычно сотни),
    затем проверяем каждый уникальный IP через CIDR-список один раз.
    """
    since = _utcnow() - datetime.timedelta(hours=24)
    rows = db.session.query(
        AccessLog.remote_addr,
        func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since).group_by(AccessLog.remote_addr).all()

    uz_requests = 0
    world_requests = 0
    uz_ips = 0
    world_ips = 0
    for r in rows:
        if not r.remote_addr:
            continue
        if is_uz_ip(r.remote_addr):
            uz_requests += r.cnt
            uz_ips += 1
        else:
            world_requests += r.cnt
            world_ips += 1

    return jsonify({
        "requests": {"uz": uz_requests, "world": world_requests},
        "ips":      {"uz": uz_ips, "world": world_ips},
    })


@app.route("/api/stats/throughput")
@login_required
def api_stats_throughput():
    """Трафик (байты) по часам за 24ч."""
    since = _utcnow() - datetime.timedelta(hours=24)
    rows = db.session.query(
        _hour_bucket_sql(AccessLog.timestamp).label("hour"),
        func.sum(AccessLog.body_bytes).label("bytes"),
    ).filter(AccessLog.timestamp >= since).group_by("hour").order_by("hour").all()
    return jsonify({
        "labels": [r.hour[-5:] for r in rows],
        "bytes":  [int(r.bytes or 0) for r in rows],
    })


@app.route("/api/stats/response-size")
@login_required
def api_stats_response_size():
    """Distribution размеров ответов за 24ч."""
    since = _utcnow() - datetime.timedelta(hours=24)
    base = AccessLog.query.filter(AccessLog.timestamp >= since)
    tiny  = base.filter(AccessLog.body_bytes < 10240).count()
    small = base.filter(AccessLog.body_bytes >= 10240, AccessLog.body_bytes < 102400).count()
    med   = base.filter(AccessLog.body_bytes >= 102400, AccessLog.body_bytes < 1048576).count()
    big   = base.filter(AccessLog.body_bytes >= 1048576).count()
    return jsonify({
        "labels": ["< 10 КБ", "10-100 КБ", "100 КБ-1 МБ", "> 1 МБ"],
        "data":   [tiny, small, med, big],
    })


@app.route("/api/stats/domain-health")
@login_required
def api_stats_domain_health():
    """Health-score каждого домена: 0-100, где больше = лучше.

    Формула:
        score = 100 - min(30, error_rate)*2 - min(20, avg_time_ms/100)
    Плюс суммарный backend-статус (up/down из last_health_status).
    """
    since = _utcnow() - datetime.timedelta(hours=24)
    rows = db.session.query(
        AccessLog.server_name,
        func.count().label("total"),
        func.sum(func.cast(AccessLog.status >= 400, db.Integer)).label("errors"),
        func.avg(AccessLog.request_time).label("avg_t"),
    ).filter(
        AccessLog.timestamp >= since,
        AccessLog.server_name != "",
    ).group_by(AccessLog.server_name).order_by(func.count().desc()).all()

    # Backend up/down из БД
    domain_map = {r.domain: r for r in DomainRoute.query.all()}

    result = []
    for r in rows:
        total = r.total or 0
        err = int(r.errors or 0)
        err_rate = (err / total * 100) if total else 0
        avg_ms = (r.avg_t or 0) * 1000
        score = 100 - min(30, err_rate) * 2 - min(20, avg_ms / 100)
        score = max(0, min(100, round(score, 1)))
        route = domain_map.get(r.server_name)
        backend = route.last_health_status if route else None
        if backend == "down":
            score = max(0, score - 30)
        result.append({
            "domain": r.server_name,
            "total": total,
            "error_rate": round(err_rate, 2),
            "avg_ms": round(avg_ms, 1),
            "backend": backend,
            "score": score,
        })
    return jsonify(result)


@app.route("/api/stats/top-error-ips")
@login_required
def api_stats_top_error_ips():
    """Топ 10 IP, которые сгенерировали больше всего 4xx/5xx за 24ч."""
    since = _utcnow() - datetime.timedelta(hours=24)
    rows = db.session.query(
        AccessLog.remote_addr,
        func.count().label("errors"),
    ).filter(
        AccessLog.timestamp >= since,
        AccessLog.status >= 400,
        AccessLog.remote_addr != "",
    ).group_by(AccessLog.remote_addr).order_by(func.count().desc()).limit(10).all()
    return jsonify([{
        "ip": r.remote_addr,
        "errors": r.errors,
        "is_uz": is_uz_ip(r.remote_addr),
    } for r in rows])


@app.route("/api/stats/backends")
@login_required
def api_stats_backends():
    """Статус health-check всех бэкендов (TCP-ping target_host:target_port)."""
    rows = DomainRoute.query.order_by(DomainRoute.domain).all()
    return jsonify([{
        "domain": r.domain,
        "target": f"{r.target_host}:{r.target_port}",
        "status": r.last_health_status,  # "up" / "down" / None
        "error": r.last_health_error,
        "checked_at": r.last_health_check.isoformat() + "Z" if r.last_health_check else None,
    } for r in rows])


@app.route("/api/stats/domain/<domain_name>")
@login_required
def api_stats_domain_detail(domain_name):
    """Детальная статистика одного домена."""
    since = _utcnow() - datetime.timedelta(hours=24)

    # Timeline по часам
    timeline = db.session.query(
        _hour_bucket_sql(AccessLog.timestamp).label("hour"),
        func.count().label("cnt"),
    ).filter(
        AccessLog.timestamp >= since,
        AccessLog.server_name == domain_name,
    ).group_by("hour").order_by("hour").all()

    # Топ URI (с avg_time для drill-down)
    top_uris = db.session.query(
        AccessLog.uri,
        func.count().label("cnt"),
        func.avg(AccessLog.request_time).label("avg_t"),
    ).filter(
        AccessLog.timestamp >= since,
        AccessLog.server_name == domain_name,
    ).group_by(AccessLog.uri).order_by(func.count().desc()).limit(10).all()

    # Топ IP (с last_seen для drill-down)
    top_ips = db.session.query(
        AccessLog.remote_addr,
        func.count().label("cnt"),
        func.max(AccessLog.timestamp).label("last_seen"),
    ).filter(
        AccessLog.timestamp >= since,
        AccessLog.server_name == domain_name,
    ).group_by(AccessLog.remote_addr).order_by(func.count().desc()).limit(10).all()

    # Статусы
    status_dist = db.session.query(
        AccessLog.status,
        func.count().label("cnt"),
    ).filter(
        AccessLog.timestamp >= since,
        AccessLog.server_name == domain_name,
    ).group_by(AccessLog.status).order_by(func.count().desc()).all()

    # Сводка
    total = AccessLog.query.filter(AccessLog.timestamp >= since, AccessLog.server_name == domain_name).count()
    avg_time = db.session.query(func.avg(AccessLog.request_time)).filter(
        AccessLog.timestamp >= since, AccessLog.server_name == domain_name).scalar() or 0
    errors = AccessLog.query.filter(
        AccessLog.timestamp >= since, AccessLog.server_name == domain_name, AccessLog.status >= 400).count()
    unique_ips = db.session.query(func.count(func.distinct(AccessLog.remote_addr))).filter(
        AccessLog.timestamp >= since, AccessLog.server_name == domain_name).scalar() or 0

    return jsonify({
        "domain": domain_name,
        "total_requests": total,
        "total": total,  # alias для UI
        "avg_response_time": round(avg_time, 3),
        "errors": errors,
        "unique_ips": unique_ips,
        "timeline": {"labels": [r.hour for r in timeline], "data": [r.cnt for r in timeline]},
        "top_uris": [{"uri": r.uri, "requests": r.cnt, "avg_time": round(r.avg_t or 0, 3)} for r in top_uris],
        "top_ips": [{
            "ip": r.remote_addr, "requests": r.cnt,
            "last_seen": r.last_seen.isoformat() + "Z" if r.last_seen else None,
        } for r in top_ips],
        "status_codes": {"labels": [str(r.status) for r in status_dist], "data": [r.cnt for r in status_dist]},
        "statuses": {"labels": [str(r.status) for r in status_dist], "data": [r.cnt for r in status_dist]},
    })


def _parse_time_range():
    """Получить since/until из query params."""
    preset = request.args.get("range", "24h")
    now = _utcnow()

    presets = {
        "1h": datetime.timedelta(hours=1),
        "6h": datetime.timedelta(hours=6),
        "24h": datetime.timedelta(hours=24),
        "3d": datetime.timedelta(days=3),
        "7d": datetime.timedelta(days=7),
        "30d": datetime.timedelta(days=30),
    }

    if preset in presets:
        since = now - presets[preset]
        until = now
    else:
        # Custom: since=ISO&until=ISO
        try:
            since = datetime.datetime.fromisoformat(request.args.get("since", ""))
        except (ValueError, TypeError):
            since = now - datetime.timedelta(hours=24)
        try:
            until = datetime.datetime.fromisoformat(request.args.get("until", ""))
        except (ValueError, TypeError):
            until = now

    return since, until


# In-memory кэш для /api/stats/full — тяжёлый эндпоинт (35+ SQL-запросов),
# который фронт дёргает каждые 30 сек. TTL 10 сек: статистика "почти real-time",
# но мы не молотим БД на каждый AJAX-refresh и не душим фоновый парсер.
_STATS_CACHE: dict = {}
_STATS_CACHE_LOCK = threading.Lock()
_STATS_CACHE_TTL = 10.0


@app.route("/api/stats/full")
@login_required
def api_stats_full():
    """Полная статистика с фильтрацией по времени."""
    since, until = _parse_time_range()
    domain_filter = request.args.get("domain")

    cache_key = (request.args.get("range", ""),
                 request.args.get("since", ""),
                 request.args.get("until", ""),
                 domain_filter or "")
    now_ts = time.time()
    with _STATS_CACHE_LOCK:
        cached = _STATS_CACHE.get(cache_key)
        if cached and (now_ts - cached[0]) < _STATS_CACHE_TTL:
            return jsonify(cached[1])

    base_q = AccessLog.query.filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until)
    if domain_filter:
        base_q = base_q.filter(AccessLog.server_name == domain_filter)

    # 1. Overview
    total = base_q.count()
    success = base_q.filter(AccessLog.status < 400).count()
    errors_4xx = base_q.filter(AccessLog.status >= 400, AccessLog.status < 500).count()
    errors_5xx = base_q.filter(AccessLog.status >= 500).count()
    avg_time = db.session.query(func.avg(AccessLog.request_time)).filter(
        AccessLog.timestamp >= since, AccessLog.timestamp <= until).scalar() or 0
    unique_ips = db.session.query(func.count(func.distinct(AccessLog.remote_addr))).filter(
        AccessLog.timestamp >= since, AccessLog.timestamp <= until).scalar() or 0
    total_bytes = db.session.query(func.sum(AccessLog.body_bytes)).filter(
        AccessLog.timestamp >= since, AccessLog.timestamp <= until).scalar() or 0

    # 2. Timeline (auto-bucket по диапазону)
    delta = until - since
    # Бакет — либо час, либо день; выбираем по длине периода
    bucket_by_day = delta.total_seconds() > 604800  # >7 дней → группируем по дням

    def _bucket(col):
        if bucket_by_day:
            if _is_sqlite():
                return func.strftime("%Y-%m-%d", col)
            return func.to_char(col, "YYYY-MM-DD")
        return _hour_bucket_sql(col)

    tl_q = db.session.query(
        _bucket(AccessLog.timestamp).label("bucket"),
        func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until)
    if domain_filter:
        tl_q = tl_q.filter(AccessLog.server_name == domain_filter)
    timeline = tl_q.group_by("bucket").order_by("bucket").all()

    # 3. Success vs errors timeline
    tl_ok = db.session.query(
        _bucket(AccessLog.timestamp).label("bucket"),
        func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until, AccessLog.status < 400)
    if domain_filter:
        tl_ok = tl_ok.filter(AccessLog.server_name == domain_filter)
    tl_ok = tl_ok.group_by("bucket").order_by("bucket").all()

    tl_err = db.session.query(
        _bucket(AccessLog.timestamp).label("bucket"),
        func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until, AccessLog.status >= 400)
    if domain_filter:
        tl_err = tl_err.filter(AccessLog.server_name == domain_filter)
    tl_err = tl_err.group_by("bucket").order_by("bucket").all()

    # 4. Status code distribution
    statuses = db.session.query(
        AccessLog.status, func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until)
    if domain_filter:
        statuses = statuses.filter(AccessLog.server_name == domain_filter)
    statuses = statuses.group_by(AccessLog.status).order_by(func.count().desc()).all()

    # 5. Methods
    methods = db.session.query(
        AccessLog.method, func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until)
    if domain_filter:
        methods = methods.filter(AccessLog.server_name == domain_filter)
    methods = methods.group_by(AccessLog.method).order_by(func.count().desc()).all()

    # 6. Top Domains
    top_domains = db.session.query(
        AccessLog.server_name,
        func.count().label("cnt"),
        func.avg(AccessLog.request_time).label("avg_t"),
        func.sum(AccessLog.body_bytes).label("bytes"),
        func.count(func.nullif(AccessLog.status < 400, False)).label("ok"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until
    ).group_by(AccessLog.server_name).order_by(func.count().desc()).limit(20).all()

    # 7. Top URIs
    top_uris_q = db.session.query(
        AccessLog.uri, func.count().label("cnt"),
        func.avg(AccessLog.request_time).label("avg_t"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until)
    if domain_filter:
        top_uris_q = top_uris_q.filter(AccessLog.server_name == domain_filter)
    top_uris = top_uris_q.group_by(AccessLog.uri).order_by(func.count().desc()).limit(20).all()

    # 8. Top IPs (with %)
    top_ips_q = db.session.query(
        AccessLog.remote_addr,
        func.count().label("cnt"),
        func.max(AccessLog.timestamp).label("last"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until)
    if domain_filter:
        top_ips_q = top_ips_q.filter(AccessLog.server_name == domain_filter)
    top_ips = top_ips_q.group_by(AccessLog.remote_addr).order_by(func.count().desc()).limit(30).all()

    # 9. User-Agent analysis
    ua_q = db.session.query(
        AccessLog.user_agent, func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until)
    if domain_filter:
        ua_q = ua_q.filter(AccessLog.server_name == domain_filter)
    user_agents_raw = ua_q.group_by(AccessLog.user_agent).order_by(func.count().desc()).limit(15).all()

    def _classify_ua(ua: str) -> str:
        ua_lower = ua.lower()
        if any(b in ua_lower for b in ["bot", "spider", "crawl", "slurp", "semrush", "ahref"]):
            return "Bot"
        if any(b in ua_lower for b in ["curl", "wget", "python-requests", "httpie", "postman", "go-http"]):
            return "API/CLI"
        if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
            return "Mobile"
        if any(b in ua_lower for b in ["chrome", "firefox", "safari", "edge", "opera"]):
            return "Desktop"
        return "Other"

    ua_categories = {}
    for ua_row in user_agents_raw:
        cat = _classify_ua(ua_row.user_agent or "")
        ua_categories[cat] = ua_categories.get(cat, 0) + ua_row.cnt

    # 10. Scheme (HTTP vs HTTPS)
    schemes = db.session.query(
        AccessLog.scheme, func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until)
    if domain_filter:
        schemes = schemes.filter(AccessLog.server_name == domain_filter)
    schemes = schemes.group_by(AccessLog.scheme).order_by(func.count().desc()).all()

    # 11. Slowest requests
    slowest_q = AccessLog.query.filter(
        AccessLog.timestamp >= since, AccessLog.timestamp <= until,
    ).order_by(AccessLog.request_time.desc()).limit(15)
    if domain_filter:
        slowest_q = slowest_q.filter(AccessLog.server_name == domain_filter)
    slowest = slowest_q.all()

    # 12. Response time distribution (buckets)
    rt_fast = base_q.filter(AccessLog.request_time < 0.1).count()
    rt_normal = base_q.filter(AccessLog.request_time >= 0.1, AccessLog.request_time < 0.5).count()
    rt_slow = base_q.filter(AccessLog.request_time >= 0.5, AccessLog.request_time < 1.0).count()
    rt_very_slow = base_q.filter(AccessLog.request_time >= 1.0).count()

    # 13. Avg response time by domain
    avg_by_domain = db.session.query(
        AccessLog.server_name,
        func.avg(AccessLog.request_time).label("avg_t"),
        func.max(AccessLog.request_time).label("max_t"),
        func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until
    ).group_by(AccessLog.server_name).order_by(func.avg(AccessLog.request_time).desc()).limit(20).all()

    # 14. Recent errors
    recent_errors_q = AccessLog.query.filter(
        AccessLog.timestamp >= since, AccessLog.timestamp <= until,
        AccessLog.status >= 400,
    ).order_by(AccessLog.timestamp.desc()).limit(30)
    if domain_filter:
        recent_errors_q = recent_errors_q.filter(AccessLog.server_name == domain_filter)
    recent_errors = recent_errors_q.all()

    # 15. Stream stats
    stream_q = db.session.query(
        StreamAccessLog.server_port,
        func.count().label("cnt"),
        func.sum(StreamAccessLog.bytes_received).label("bytes_in"),
        func.sum(StreamAccessLog.bytes_sent).label("bytes_out"),
        func.avg(StreamAccessLog.session_time).label("avg_sess"),
        func.max(StreamAccessLog.session_time).label("max_sess"),
    ).filter(
        StreamAccessLog.timestamp >= since, StreamAccessLog.timestamp <= until,
    ).group_by(StreamAccessLog.server_port).order_by(func.count().desc()).all()

    # 16. Error rate by URI (top failing endpoints)
    error_uris_q = db.session.query(
        AccessLog.uri,
        func.count().label("total"),
        func.sum(func.cast(AccessLog.status >= 400, db.Integer)).label("errors"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until)
    if domain_filter:
        error_uris_q = error_uris_q.filter(AccessLog.server_name == domain_filter)
    error_uris = error_uris_q.group_by(AccessLog.uri).having(
        func.sum(func.cast(AccessLog.status >= 400, db.Integer)) > 0
    ).order_by(func.sum(func.cast(AccessLog.status >= 400, db.Integer)).desc()).limit(15).all()

    payload = {
        "range": {"since": since.isoformat(), "until": until.isoformat()},
        "overview": {
            "total": total, "success": success, "errors_4xx": errors_4xx, "errors_5xx": errors_5xx,
            "avg_response_time": round(avg_time, 3), "unique_ips": unique_ips,
            "total_bytes": total_bytes,
            "error_rate": round((errors_4xx + errors_5xx) / total * 100, 1) if total else 0,
            "success_rate": round(success / total * 100, 1) if total else 0,
        },
        "timeline": {"labels": [r.bucket for r in timeline], "data": [r.cnt for r in timeline]},
        "timeline_ok": {"labels": [r.bucket for r in tl_ok], "data": [r.cnt for r in tl_ok]},
        "timeline_err": {"labels": [r.bucket for r in tl_err], "data": [r.cnt for r in tl_err]},
        "status_codes": {"labels": [str(r.status) for r in statuses], "data": [r.cnt for r in statuses]},
        "methods": {"labels": [r.method for r in methods], "data": [r.cnt for r in methods]},
        "top_domains": [{
            "domain": r.server_name, "requests": r.cnt,
            "avg_time": round(r.avg_t or 0, 3), "bytes": r.bytes or 0,
        } for r in top_domains],
        "top_uris": [{"uri": r.uri, "requests": r.cnt, "avg_time": round(r.avg_t or 0, 3)} for r in top_uris],
        "top_ips": [{
            "ip": r.remote_addr, "requests": r.cnt,
            "pct": round(r.cnt / total * 100, 1) if total else 0,
            "last_seen": r.last.isoformat() if r.last else "",
        } for r in top_ips],
        "user_agents": [{"agent": r.user_agent or "—", "requests": r.cnt} for r in user_agents_raw],
        "ua_categories": {"labels": list(ua_categories.keys()), "data": list(ua_categories.values())},
        "schemes": {"labels": [r.scheme or "—" for r in schemes], "data": [r.cnt for r in schemes]},
        "slowest": [{
            "time": r.timestamp.isoformat() if r.timestamp else "",
            "domain": r.server_name, "uri": r.uri, "method": r.method,
            "status": r.status, "request_time": r.request_time, "ip": r.remote_addr,
        } for r in slowest],
        "response_time_dist": {
            "labels": ["< 100ms", "100-500ms", "500ms-1s", "> 1s"],
            "data": [rt_fast, rt_normal, rt_slow, rt_very_slow],
        },
        "avg_by_domain": [{
            "domain": r.server_name, "avg_time": round(r.avg_t or 0, 3),
            "max_time": round(r.max_t or 0, 3), "requests": r.cnt,
        } for r in avg_by_domain],
        "recent_errors": [{
            "time": r.timestamp.isoformat() if r.timestamp else "",
            "domain": r.server_name, "uri": r.uri, "status": r.status,
            "ip": r.remote_addr, "method": r.method, "user_agent": r.user_agent,
        } for r in recent_errors],
        "streams": [{
            "port": r.server_port, "sessions": r.cnt,
            "bytes_in": r.bytes_in or 0, "bytes_out": r.bytes_out or 0,
            "avg_session": round(r.avg_sess or 0, 2), "max_session": round(r.max_sess or 0, 2),
        } for r in stream_q],
        "error_uris": [{
            "uri": r.uri, "total": r.total, "errors": r.errors,
            "error_rate": round((r.errors or 0) / r.total * 100, 1) if r.total else 0,
        } for r in error_uris],
    }

    with _STATS_CACHE_LOCK:
        _STATS_CACHE[cache_key] = (time.time(), payload)
        # Простая защита от разрастания: выкидываем старые ключи
        if len(_STATS_CACHE) > 32:
            oldest = min(_STATS_CACHE.items(), key=lambda kv: kv[1][0])[0]
            _STATS_CACHE.pop(oldest, None)

    return jsonify(payload)


@app.route("/statistics")
@login_required
def statistics_page():
    """Расширенная страница статистики."""
    domains = DomainRoute.query.order_by(DomainRoute.domain).all()
    streams = StreamRoute.query.order_by(StreamRoute.listen_port).all()
    return render_template("statistics.html", dev_mode=DEV_MODE, domains=domains,
                           streams=streams, service_presets=SERVICE_PRESETS)


# ──────────────────────────────────────────────
#  Request Log Viewer
# ──────────────────────────────────────────────

@app.route("/api/logs/requests")
@login_required
def api_logs_requests():
    """Пагинированный список HTTP-запросов с фильтрами."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = min(per_page, 200)  # cap

    q = AccessLog.query

    # Домен
    domain = request.args.get("domain")
    if domain:
        q = q.filter(AccessLog.server_name == domain)

    # IP
    ip = request.args.get("ip")
    if ip:
        q = q.filter(AccessLog.remote_addr.like(f"%{ip}%"))

    # Метод
    method = request.args.get("method")
    if method:
        q = q.filter(AccessLog.method == method.upper())

    # Статус (точный или диапазон)
    status = request.args.get("status")
    if status:
        if status.endswith("xx"):
            base = int(status[0]) * 100
            q = q.filter(AccessLog.status >= base, AccessLog.status < base + 100)
        else:
            try:
                q = q.filter(AccessLog.status == int(status))
            except ValueError:
                pass

    # URI (поиск подстроки)
    uri = request.args.get("uri")
    if uri:
        q = q.filter(AccessLog.uri.like(f"%{uri}%"))

    # User-Agent (поиск подстроки)
    ua = request.args.get("ua")
    if ua:
        q = q.filter(AccessLog.user_agent.like(f"%{ua}%"))

    # Scheme
    scheme = request.args.get("scheme")
    if scheme:
        q = q.filter(AccessLog.scheme == scheme)

    # Мин. время ответа
    min_time = request.args.get("min_time", type=float)
    if min_time is not None:
        q = q.filter(AccessLog.request_time >= min_time)

    # Макс. время ответа
    max_time = request.args.get("max_time", type=float)
    if max_time is not None:
        q = q.filter(AccessLog.request_time <= max_time)

    # Мин. размер ответа
    min_bytes = request.args.get("min_bytes", type=int)
    if min_bytes is not None:
        q = q.filter(AccessLog.body_bytes >= min_bytes)

    # Время от/до
    since = request.args.get("since")
    if since:
        try:
            q = q.filter(AccessLog.timestamp >= datetime.datetime.fromisoformat(since))
        except (ValueError, TypeError):
            pass

    until = request.args.get("until")
    if until:
        try:
            q = q.filter(AccessLog.timestamp <= datetime.datetime.fromisoformat(until))
        except (ValueError, TypeError):
            pass

    # Сортировка
    sort = request.args.get("sort", "timestamp")
    order = request.args.get("order", "desc")
    sort_col = getattr(AccessLog, sort, AccessLog.timestamp)
    if order == "asc":
        q = q.order_by(sort_col.asc())
    else:
        q = q.order_by(sort_col.desc())

    total = q.count()
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    rows = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
        "data": [{
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else "",
            "ip": r.remote_addr,
            "method": r.method,
            "domain": r.server_name,
            "uri": r.uri,
            "status": r.status,
            "bytes": r.body_bytes,
            "time": r.request_time,
            "upstream": r.upstream_addr,
            "ua": r.user_agent,
            "referer": r.referer,
            "scheme": r.scheme,
            "ssl": r.ssl_protocol,
        } for r in rows],
    })


@app.route("/requests")
@login_required
def requests_page():
    """Страница просмотра запросов."""
    domains = DomainRoute.query.order_by(DomainRoute.domain).all()
    return render_template("requests.html", dev_mode=DEV_MODE, domains=domains)


# ──────────────────────────────────────────────
#  Auth routes
# ──────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        ip = _client_ip()
        allowed, retry = _rate_limit_check(ip)
        if not allowed:
            logger.warning("login rate-limit hit: %s (retry in %ds)", ip, retry)
            flash(f"Слишком много неудачных попыток. Повторите через {retry} сек.", "danger")
            return redirect(url_for("login")), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            _record_login_failure(ip)
            flash("Неверное имя пользователя или пароль", "danger")
            return redirect(url_for("login"))

        _reset_login_failures(ip)
        # Регенерируем сессию, чтобы не подобрать SessionID до логина
        session.clear()
        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role or ("admin" if user.is_admin else "viewer")
        csrf_token()  # гарантируем что свежий токен создан для первой POST-формы
        log_action("login", details=f"User logged in from {ip} as {session['role']}")

        next_url = request.args.get("next")
        if not is_safe_next_url(next_url):
            next_url = url_for("dashboard")
        return redirect(next_url)

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if "user_id" in session:
        log_action("logout", details="User logged out")
    session.clear()
    return redirect(url_for("login"))


# ──────────────────────────────────────────────
#  Domain routes CRUD
# ──────────────────────────────────────────────

@app.route("/")
@login_required
def dashboard():
    """Главная страница — дашборд."""
    return render_template("dashboard.html", dev_mode=DEV_MODE)


_STARTED_AT = _utcnow()


@app.route("/healthz")
def healthz():
    """Healthcheck для мониторинга.

    Не требует авторизации, но раскрывает только безопасные метрики:
    состояние БД, возраст парсера, счётчики маршрутов/логов, uptime.
    Секретов (ключи, пути к сертификатам, пароли) НЕ отдаёт.
    """
    status = {"ok": True, "checks": {}}
    http_code = 200

    try:
        db.session.execute(text("SELECT 1")).scalar()
        status["checks"]["db"] = "ok"
    except Exception as e:
        status["ok"] = False
        status["checks"]["db"] = f"fail: {type(e).__name__}"
        http_code = 503

    try:
        cp_http = db.session.get(LogCheckpoint, "http_log")
        if cp_http and cp_http.updated_at:
            age = (_utcnow() - cp_http.updated_at).total_seconds()
            status["checks"]["parser_age_sec"] = int(age)
            if not DEV_MODE and age > 300:
                status["ok"] = False
                status["checks"]["parser"] = "stale"
                http_code = 503
        else:
            status["checks"]["parser"] = "no checkpoint yet"
    except Exception as e:
        status["checks"]["parser"] = f"fail: {type(e).__name__}"

    try:
        status["counts"] = {
            "domain_routes": DomainRoute.query.count(),
            "stream_routes": StreamRoute.query.count(),
            "access_logs": AccessLog.query.count(),
            "stream_logs": StreamAccessLog.query.count(),
        }
    except Exception:
        pass

    try:
        sz = _db_size_bytes()
        if sz:
            status["db_size_mb"] = round(sz / 1024 / 1024, 1)
    except Exception:
        pass

    try:
        st = os.statvfs(BASE_DIR)
        status["disk_free_mb"] = round((st.f_bavail * st.f_frsize) / 1024 / 1024, 0)
    except Exception:
        pass

    status["uptime_sec"] = int((_utcnow() - _STARTED_AT).total_seconds())
    status["dev_mode"] = DEV_MODE
    return jsonify(status), http_code


def _metrics_escape(s: str) -> str:
    """Экранирование значения лейбла для Prometheus text format."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@app.route("/metrics")
def metrics():
    """Prometheus exposition format.

    Защита: если задан DC_METRICS_TOKEN — требуется Authorization: Bearer <token>.
    Если не задан — open (рассчитано на LAN-only доступ через nginx whitelist).
    """
    token = app.config.get("METRICS_TOKEN", "")
    if token:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not hmac.compare_digest(auth[7:], token):
            return "unauthorized\n", 401, {"Content-Type": "text/plain"}

    lines = []
    out = lines.append

    out("# HELP dc_up Приложение работает")
    out("# TYPE dc_up gauge")
    out("dc_up 1")

    out("# HELP dc_uptime_seconds Время работы процесса с последнего рестарта")
    out("# TYPE dc_uptime_seconds counter")
    out(f"dc_uptime_seconds {int((_utcnow() - _STARTED_AT).total_seconds())}")

    try:
        out("# HELP dc_domain_routes_total Количество HTTP/HTTPS маршрутов")
        out("# TYPE dc_domain_routes_total gauge")
        out(f"dc_domain_routes_total {DomainRoute.query.count()}")

        out("# HELP dc_stream_routes_total Количество TCP/UDP stream-маршрутов")
        out("# TYPE dc_stream_routes_total gauge")
        out(f"dc_stream_routes_total {StreamRoute.query.count()}")

        out("# HELP dc_users_total Количество пользователей панели")
        out("# TYPE dc_users_total gauge")
        out(f"dc_users_total {User.query.count()}")

        out("# HELP dc_api_tokens_total Количество активных API-токенов")
        out("# TYPE dc_api_tokens_total gauge")
        out(f"dc_api_tokens_total {ApiToken.query.count()}")

        out("# HELP dc_access_logs_total Размер таблицы access_logs")
        out("# TYPE dc_access_logs_total gauge")
        out(f"dc_access_logs_total {AccessLog.query.count()}")

        out("# HELP dc_stream_logs_total Размер таблицы stream_logs")
        out("# TYPE dc_stream_logs_total gauge")
        out(f"dc_stream_logs_total {StreamAccessLog.query.count()}")

        out("# HELP dc_parser_errors_total Количество записей dead-letter парсера")
        out("# TYPE dc_parser_errors_total gauge")
        out(f"dc_parser_errors_total {ParserError.query.count()}")
    except Exception:
        pass

    try:
        sz = _db_size_bytes()
        if sz:
            out("# HELP dc_db_size_bytes Размер БД в байтах (SQLite файл или pg_database_size)")
            out("# TYPE dc_db_size_bytes gauge")
            out(f"dc_db_size_bytes {sz}")
    except Exception:
        pass

    try:
        st = os.statvfs(BASE_DIR)
        out("# HELP dc_disk_free_bytes Свободное место на разделе с приложением")
        out("# TYPE dc_disk_free_bytes gauge")
        out(f"dc_disk_free_bytes {st.f_bavail * st.f_frsize}")
    except Exception:
        pass

    # Возраст checkpoint'ов парсера — индикатор здоровья фонового потока
    try:
        out("# HELP dc_parser_checkpoint_age_seconds Секунды с последнего обновления checkpoint")
        out("# TYPE dc_parser_checkpoint_age_seconds gauge")
        for key in ("http_log", "stream_log"):
            cp = db.session.get(LogCheckpoint, key)
            if cp and cp.updated_at:
                age = int((_utcnow() - cp.updated_at).total_seconds())
                out(f'dc_parser_checkpoint_age_seconds{{source="{key}"}} {age}')
    except Exception:
        pass

    # Backend health
    try:
        out("# HELP dc_backend_up 1 если target backend отвечает на TCP, 0 если нет")
        out("# TYPE dc_backend_up gauge")
        for r in DomainRoute.query.all():
            if not r.last_health_status:
                continue
            up = 1 if r.last_health_status == "up" else 0
            dom = _metrics_escape(r.domain)
            target = _metrics_escape(f"{r.target_host}:{r.target_port}")
            out(f'dc_backend_up{{domain="{dom}",target="{target}"}} {up}')
    except Exception:
        pass

    # SSL expiry
    try:
        out("# HELP dc_ssl_days_left Дней до истечения SSL-сертификата")
        out("# TYPE dc_ssl_days_left gauge")
        now = _utcnow()
        for r in DomainRoute.query.filter(DomainRoute.enable_https.is_(True)).all():
            exp = _read_ssl_expiry(r.ssl_cert_path) if not DEV_MODE else None
            if exp is None:
                continue
            days_left = (exp - now).days
            dom = _metrics_escape(r.domain)
            out(f'dc_ssl_days_left{{domain="{dom}"}} {days_left}')
    except Exception:
        pass

    # HTTP-запросы за последний час по статус-классу
    try:
        since = _utcnow() - datetime.timedelta(hours=1)
        rows = db.session.query(AccessLog.status, func.count()).filter(
            AccessLog.timestamp >= since
        ).group_by(AccessLog.status).all()
        if rows:
            out("# HELP dc_requests_last_hour_total Запросы за последний час по статусу")
            out("# TYPE dc_requests_last_hour_total gauge")
            for status, cnt in rows:
                klass = f"{status // 100}xx" if status else "unknown"
                out(f'dc_requests_last_hour_total{{status="{status}",class="{klass}"}} {cnt}')
    except Exception:
        pass

    body = "\n".join(lines) + "\n"
    return body, 200, {"Content-Type": "text/plain; version=0.0.4; charset=utf-8"}


@app.route("/domains")
@login_required
def index():
    from sqlalchemy.orm import selectinload

    group = request.args.get("group")
    # selectinload — отдельный SELECT по списку FK вместо одного большого JOIN.
    # Для one-to-many даёт ровно 2 запроса (домены + все их stream_routes)
    # вместо N+1, и не требует .unique() от cartesian-product.
    query = DomainRoute.query.options(selectinload(DomainRoute.stream_routes))

    if group:
        query = query.filter_by(group_name=group)

    routes = query.order_by(DomainRoute.domain).all()
    groups = db.session.query(DomainRoute.group_name).distinct().all()
    groups = [g[0] for g in groups if g[0]]

    # Все stream-маршруты без привязки к домену (для отдельного блока)
    unlinked_streams = StreamRoute.query.filter_by(domain_route_id=None).order_by(StreamRoute.listen_port).all()

    return render_template(
        "list.html",
        routes=routes,
        groups=groups,
        selected_group=group,
        dev_mode=DEV_MODE,
        unlinked_streams=unlinked_streams,
        service_presets=SERVICE_PRESETS,
    )


def _validate_domain_form():
    """Собрать и провалидировать поля формы домена. Возвращает (dict, error_msg)."""
    domain = request.form.get("domain", "").strip().lower()
    target_host = request.form.get("target_host", "").strip()
    target_port_s = request.form.get("target_port", "").strip()
    group_name = request.form.get("group_name", "").strip() or None

    listen_port_s = request.form.get("listen_port", "80").strip() or "80"
    listen_port_ssl_s = request.form.get("listen_port_ssl", "443").strip() or "443"

    enable_https = request.form.get("enable_https") == "on"
    backend_https = request.form.get("backend_https") == "on"
    enable_websocket = request.form.get("enable_websocket") == "on"
    # Чекбокс: если он вообще в форме отсутствует (=None), трактуем как "включить"
    # только для нового маршрута. Для edit — присутствие "on" означает включить,
    # отсутствие → выключить. В HTML нужно дублировать hidden-поле, чтобы различать.
    enable_bot_protection = request.form.get("enable_bot_protection") == "on"

    ssl_cert_path = request.form.get("ssl_cert_path", "").strip() or None
    ssl_key_path = request.form.get("ssl_key_path", "").strip() or None

    if not domain or not target_host or not target_port_s:
        return None, "Заполните домен, IP и порт"
    if not is_valid_domain(domain):
        return None, "Неверный формат домена (разрешены a-z, 0-9, точка, дефис)"
    if not is_valid_host(target_host):
        return None, "Неверный формат внутреннего хоста (IP или DNS-имя)"
    try:
        port_int = int(target_port_s)
        lp = int(listen_port_s)
        lps = int(listen_port_ssl_s)
    except ValueError:
        return None, "Порты должны быть числами"
    # target_port — может быть любой валидный (бэкенд может слушать на 22/5000 и т.п.)
    if not is_valid_port(port_int, allow_reserved=True):
        return None, "Target-порт должен быть в диапазоне 1-65535"
    # listen-порты — нельзя брать системные/зарезервированные
    if not is_valid_port(lp):
        return None, f"HTTP-порт {lp} недопустим или зарезервирован (системные: {sorted(RESERVED_PORTS)})"
    if not is_valid_port(lps):
        return None, f"HTTPS-порт {lps} недопустим или зарезервирован"
    if ssl_cert_path and not is_valid_ssl_path(ssl_cert_path):
        return None, "Путь к сертификату должен быть вида /etc/letsencrypt/live/<domain>/fullchain.pem"
    if ssl_key_path and not is_valid_ssl_path(ssl_key_path):
        return None, "Путь к ключу должен быть вида /etc/letsencrypt/live/<domain>/privkey.pem"

    return {
        "domain": domain,
        "target_host": target_host,
        "target_port": port_int,
        "listen_port": lp,
        "listen_port_ssl": lps,
        "group_name": group_name,
        "enable_https": enable_https,
        "backend_https": backend_https,
        "enable_websocket": enable_websocket,
        "enable_bot_protection": enable_bot_protection,
        "ssl_cert_path": ssl_cert_path if enable_https else None,
        "ssl_key_path": ssl_key_path if enable_https else None,
    }, None


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        if session.get("role") != "admin":
            flash("Создание маршрутов доступно только администратору", "danger")
            return redirect(url_for("index"))
        data, err = _validate_domain_form()
        if err:
            flash(err, "danger")
            return redirect(url_for("add"))

        route = DomainRoute(**data)
        db.session.add(route)
        db.session.commit()

        try:
            apply_all_configs()
        except subprocess.CalledProcessError as e:
            # Откат, чтобы БД и nginx не разъехались
            db.session.delete(route)
            db.session.commit()
            logger.error("nginx reload failed on create_route %s: %s", data["domain"], e)
            flash(f"Ошибка nginx: {e}. Маршрут не сохранён.", "danger")
            return redirect(url_for("add"))

        log_action(
            "create_route",
            domain=data["domain"],
            details=f"target={data['target_host']}:{data['target_port']}, "
                    f"listen={data['listen_port']}/{data['listen_port_ssl']}, "
                    f"https={data['enable_https']}, backend_https={data['backend_https']}, "
                    f"ws={data['enable_websocket']}",
        )
        flash("Домен добавлен, nginx обновлён", "success")
        return redirect(url_for("index"))

    return render_template("form.html", route=None)


@app.route("/edit/<int:route_id>", methods=["GET", "POST"])
@login_required
def edit(route_id):
    route = DomainRoute.query.get_or_404(route_id)

    if request.method == "POST":
        if session.get("role") != "admin":
            flash("Редактирование маршрутов доступно только администратору", "danger")
            return redirect(url_for("index"))
        data, err = _validate_domain_form()
        if err:
            flash(err, "danger")
            return redirect(url_for("edit", route_id=route.id))

        # Snapshot старых значений — для отката при ошибке nginx
        snapshot = {col: getattr(route, col) for col in (
            "domain", "target_host", "target_port", "listen_port", "listen_port_ssl",
            "group_name", "enable_https", "backend_https", "enable_websocket",
            "enable_bot_protection", "ssl_cert_path", "ssl_key_path",
        )}

        for col, value in data.items():
            setattr(route, col, value)
        db.session.commit()

        try:
            apply_all_configs()
        except subprocess.CalledProcessError as e:
            for col, value in snapshot.items():
                setattr(route, col, value)
            db.session.commit()
            logger.error("nginx reload failed on update_route %s: %s", data["domain"], e)
            flash(f"Ошибка nginx: {e}. Изменения откатаны.", "danger")
            return redirect(url_for("edit", route_id=route.id))

        log_action(
            "update_route",
            domain=data["domain"],
            details=f"target={data['target_host']}:{data['target_port']}, "
                    f"listen={data['listen_port']}/{data['listen_port_ssl']}, "
                    f"https={data['enable_https']}, backend_https={data['backend_https']}, "
                    f"ws={data['enable_websocket']}",
        )
        flash("Маршрут обновлён, nginx обновлён", "success")
        return redirect(url_for("index"))

    return render_template("form.html", route=route)


@app.route("/delete/<int:route_id>", methods=["POST"])
@login_required
@admin_required
def delete(route_id):
    route = DomainRoute.query.get_or_404(route_id)
    domain = route.domain

    # Отвязать stream-маршруты
    for s in route.stream_routes:
        s.domain_route_id = None

    db.session.delete(route)
    db.session.commit()

    try:
        apply_all_configs()
        log_action("delete_route", domain=domain)
        flash("Маршрут удалён, nginx обновлён", "success")
    except subprocess.CalledProcessError as e:
        flash(f"Ошибка nginx: {e}", "danger")

    return redirect(url_for("index"))


@app.route("/letsencrypt/<int:route_id>", methods=["POST"])
@login_required
@admin_required
def letsencrypt(route_id):
    route = DomainRoute.query.get_or_404(route_id)
    domain = route.domain

    # Защита от того, что в БД уже лежит кривое имя (например, от старого
    # билда без валидации) — certbot argv-инъекция не должна пройти.
    if not is_valid_domain(domain):
        flash("Домен в БД имеет недопустимый формат — сначала отредактируйте маршрут", "danger")
        log_action("letsencrypt_rejected", domain=domain, details="invalid domain format")
        return redirect(url_for("index"))

    if DEV_MODE:
        route.enable_https = True
        route.ssl_cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        route.ssl_key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
        db.session.commit()
        # apply_all_configs в DEV_MODE пишет dev_*-routes.conf без nginx -t.
        # Раньше здесь вызывались generate_*_config() напрямую, но после
        # рефакторинга под atomic reload они возвращают строку и файлы не пишутся.
        apply_all_configs()
        flash("DEV MODE: Сертификат имитирован, HTTPS активирован", "warning")
        log_action("letsencrypt_dev", domain=domain, details="dev mode — simulated")
        return redirect(url_for("index"))

    ensure_acme_webroot()

    cmd = [
        "certbot", "certonly", "--webroot",
        "-w", ACME_WEBROOT,
        "-d", domain,
        "--agree-tos",
        "-m", app.config["LETSENCRYPT_EMAIL"],
        "--non-interactive",
        "--keep-until-expiring",
    ]

    try:
        subprocess.run(cmd, check=True, timeout=180)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        flash(f"Ошибка certbot: {e}", "danger")
        log_action("letsencrypt_failed", domain=domain, details=str(e))
        _fire_webhook("letsencrypt_failed", domain=domain, details=str(e))
        return redirect(url_for("index"))

    cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"

    # Запомним прежнее состояние, чтобы откатить флаги при провале apply_all_configs
    prev_state = (route.enable_https, route.ssl_cert_path, route.ssl_key_path)
    route.enable_https = True
    route.ssl_cert_path = cert_path
    route.ssl_key_path = key_path
    db.session.commit()

    try:
        apply_all_configs()
    except subprocess.CalledProcessError as e:
        route.enable_https, route.ssl_cert_path, route.ssl_key_path = prev_state
        db.session.commit()
        logger.error("nginx reload failed after certbot on %s: %s", domain, e)
        log_action("letsencrypt_nginx_failed", domain=domain, details=str(e))
        _fire_webhook("letsencrypt_nginx_failed", domain=domain, details=str(e))
        flash(f"Сертификат получен, но nginx не перезагрузился: {e}. Состояние маршрута откатано.", "danger")
        return redirect(url_for("index"))

    flash("Сертификат выпущен/обновлён, HTTPS активирован", "success")
    log_action("letsencrypt_success", domain=domain, details=cert_path)
    return redirect(url_for("index"))


# ──────────────────────────────────────────────
#  Stream routes CRUD (TCP/UDP)
# ──────────────────────────────────────────────

@app.route("/streams")
@login_required
def streams_index():
    group = request.args.get("group")
    query = StreamRoute.query

    if group:
        query = query.filter_by(group_name=group)

    streams = query.order_by(StreamRoute.listen_port).all()
    groups = db.session.query(StreamRoute.group_name).distinct().all()
    groups = [g[0] for g in groups if g[0]]

    return render_template(
        "streams_list.html",
        streams=streams,
        groups=groups,
        selected_group=group,
        dev_mode=DEV_MODE,
        service_presets=SERVICE_PRESETS,
    )


def _validate_stream_form(existing_stream_id: int | None = None):
    """Собрать и провалидировать поля формы stream-маршрута."""
    name = request.form.get("name", "").strip()
    listen_port_s = request.form.get("listen_port", "").strip()
    target_host = request.form.get("target_host", "").strip()
    target_port_s = request.form.get("target_port", "").strip()
    protocol = request.form.get("protocol", "tcp").strip().lower()
    service_type = request.form.get("service_type", "custom").strip()
    domain_hint = request.form.get("domain_hint", "").strip() or None
    group_name = request.form.get("group_name", "").strip() or None
    domain_route_id_s = request.form.get("domain_route_id", "").strip() or None

    if not name or not listen_port_s or not target_host or not target_port_s:
        return None, "Заполните все обязательные поля"
    if protocol not in ("tcp", "udp"):
        return None, "Протокол должен быть tcp или udp"
    if service_type and service_type not in SERVICE_PRESETS:
        return None, "Неизвестный тип сервиса"
    if domain_hint and not is_valid_domain(domain_hint):
        return None, "Метка DNS — должна быть корректным доменом"
    if not is_valid_host(target_host):
        return None, "Неверный формат внутреннего хоста (IP или DNS-имя)"

    try:
        listen_port_int = int(listen_port_s)
        target_port_int = int(target_port_s)
        domain_route_id = int(domain_route_id_s) if domain_route_id_s else None
    except ValueError:
        return None, "Порты должны быть числами"

    if not is_valid_port(listen_port_int):
        return None, (f"listen-порт {listen_port_int} недопустим или зарезервирован "
                      f"(системные: {sorted(RESERVED_PORTS)})")
    if not is_valid_port(target_port_int, allow_reserved=True):
        return None, "Target-порт должен быть в диапазоне 1-65535"

    q = StreamRoute.query.filter_by(listen_port=listen_port_int)
    if existing_stream_id is not None:
        q = q.filter(StreamRoute.id != existing_stream_id)
    existing = q.first()
    if existing:
        return None, f"Порт {listen_port_int} уже используется маршрутом «{existing.name}»"

    return {
        "name": name,
        "listen_port": listen_port_int,
        "target_host": target_host,
        "target_port": target_port_int,
        "protocol": protocol,
        "service_type": service_type,
        "domain_hint": domain_hint,
        "group_name": group_name,
        "domain_route_id": domain_route_id,
    }, None


@app.route("/streams/add", methods=["GET", "POST"])
@login_required
def streams_add():
    if request.method == "POST":
        if session.get("role") != "admin":
            flash("Создание stream-маршрутов доступно только администратору", "danger")
            return redirect(url_for("streams_index"))
        data, err = _validate_stream_form()
        if err:
            flash(err, "danger")
            return redirect(url_for("streams_add"))

        stream = StreamRoute(**data)
        db.session.add(stream)
        db.session.commit()

        try:
            apply_all_configs()
        except subprocess.CalledProcessError as e:
            db.session.delete(stream)
            db.session.commit()
            logger.error("nginx reload failed on create_stream %s: %s", data["name"], e)
            flash(f"Ошибка nginx: {e}. Маршрут не сохранён.", "danger")
            return redirect(url_for("streams_add"))

        log_action(
            "create_stream",
            domain=data["domain_hint"],
            details=f"[{data['service_type']}] {data['name']}: :{data['listen_port']}/{data['protocol']} "
                    f"-> {data['target_host']}:{data['target_port']}",
        )
        flash("Stream-маршрут добавлен, nginx обновлён", "success")
        return redirect(url_for("streams_index"))

    domains = DomainRoute.query.order_by(DomainRoute.domain).all()
    return render_template("stream_form.html", stream=None, domains=domains, service_presets=SERVICE_PRESETS)


@app.route("/streams/edit/<int:stream_id>", methods=["GET", "POST"])
@login_required
def streams_edit(stream_id):
    stream = StreamRoute.query.get_or_404(stream_id)

    if request.method == "POST":
        if session.get("role") != "admin":
            flash("Редактирование stream-маршрутов доступно только администратору", "danger")
            return redirect(url_for("streams_index"))
        data, err = _validate_stream_form(existing_stream_id=stream.id)
        if err:
            flash(err, "danger")
            return redirect(url_for("streams_edit", stream_id=stream.id))

        snapshot = {col: getattr(stream, col) for col in data.keys()}
        for col, value in data.items():
            setattr(stream, col, value)
        db.session.commit()

        try:
            apply_all_configs()
        except subprocess.CalledProcessError as e:
            for col, value in snapshot.items():
                setattr(stream, col, value)
            db.session.commit()
            logger.error("nginx reload failed on update_stream %s: %s", data["name"], e)
            flash(f"Ошибка nginx: {e}. Изменения откатаны.", "danger")
            return redirect(url_for("streams_edit", stream_id=stream.id))

        log_action(
            "update_stream",
            domain=data["domain_hint"],
            details=f"[{data['service_type']}] {data['name']}: :{data['listen_port']}/{data['protocol']} "
                    f"-> {data['target_host']}:{data['target_port']}",
        )
        flash("Stream-маршрут обновлён, nginx обновлён", "success")
        return redirect(url_for("streams_index"))

    domains = DomainRoute.query.order_by(DomainRoute.domain).all()
    return render_template("stream_form.html", stream=stream, domains=domains, service_presets=SERVICE_PRESETS)


@app.route("/streams/delete/<int:stream_id>", methods=["POST"])
@login_required
@admin_required
def streams_delete(stream_id):
    stream = StreamRoute.query.get_or_404(stream_id)
    name = stream.name
    domain_hint = stream.domain_hint

    db.session.delete(stream)
    db.session.commit()

    try:
        apply_all_configs()
        log_action("delete_stream", domain=domain_hint, details=f"Удалён: {name}")
        flash("Stream-маршрут удалён, nginx обновлён", "success")
    except subprocess.CalledProcessError as e:
        flash(f"Ошибка nginx: {e}", "danger")

    return redirect(url_for("streams_index"))


# ──────────────────────────────────────────────
#  API: service presets (for JS)
# ──────────────────────────────────────────────

@app.route("/api/presets")
@login_required
def api_presets():
    from flask import jsonify
    return jsonify(SERVICE_PRESETS)


# ──────────────────────────────────────────────
#  Audit logs
# ──────────────────────────────────────────────

@app.route("/logs")
@login_required
def logs():
    logs_q = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(300).all()
    return render_template("logs.html", logs=logs_q)


# ──────────────────────────────────────────────
#  Firewall (fail2ban) — admin only
# ──────────────────────────────────────────────

# Имя jail'а: буквы/цифры/дефис/подчёркивание. Защита от shell-injection
# в subprocess fail2ban-client.
_JAIL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def is_valid_ip(raw: str) -> bool:
    """IPv4/IPv6 validation через stdlib ipaddress. Без ведущих пробелов."""
    if not raw or raw != raw.strip():
        return False
    try:
        ipaddress.ip_address(raw)
        return True
    except ValueError:
        return False


def _load_uz_cidrs_cache() -> list:
    """Загрузить CIDR-список Узбекистана из кэша apply-uz-cidrs.sh."""
    cache_paths = [
        os.path.join(BASE_DIR, "deploy", "uz.zone.cache"),
        "/opt/domain-controller/deploy/uz.zone.cache",
    ]
    networks = []
    for p in cache_paths:
        if os.path.exists(p):
            try:
                with open(p) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        try:
                            networks.append(ipaddress.ip_network(line, strict=False))
                        except ValueError:
                            continue
                break
            except OSError:
                continue
    return networks


# Кэш UZ-сетей в памяти. Перечитывается раз в 10 минут (на случай обновления timer'ом).
_UZ_CIDRS: list = []
_UZ_CIDRS_LOADED_AT: float = 0.0
_UZ_CIDRS_LOCK = threading.Lock()


def _get_uz_cidrs() -> list:
    global _UZ_CIDRS, _UZ_CIDRS_LOADED_AT
    now = time.time()
    with _UZ_CIDRS_LOCK:
        if not _UZ_CIDRS or (now - _UZ_CIDRS_LOADED_AT) > 600:
            _UZ_CIDRS = _load_uz_cidrs_cache()
            _UZ_CIDRS_LOADED_AT = now
        return _UZ_CIDRS


def is_uz_ip(raw: str) -> bool:
    """True если IP принадлежит одному из CIDR Узбекистана (по нашему кэшу)."""
    if not is_valid_ip(raw):
        return False
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    for net in _get_uz_cidrs():
        if addr in net:
            return True
    return False


def is_rfc1918_ip(raw: str) -> bool:
    """Частные адреса (10/8, 172.16/12, 192.168/16, 127/8)."""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


# ──────────────────────────────────────────────
#  GeoIP — lookup по IP через DB-IP free city .mmdb (формат MaxMind).
#
#  База обновляется ежемесячно отдельным скриптом deploy/update-geoip.sh.
#  На проде путь /var/lib/dc-geoip/dbip-city-lite.mmdb (≈130 МБ).
#  Если базы нет — geoip_lookup() возвращает None, остальной код работает.
#
#  Reader использует mmap → файл не грузится целиком в RAM, страницы по запросу.
# ──────────────────────────────────────────────

_DEFAULT_GEOIP_PATH = "/var/lib/dc-geoip/dbip-city-lite.mmdb"
if DEV_MODE:
    _DEFAULT_GEOIP_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "data", "geoip", "dbip-city-lite.mmdb",
    )
DC_GEOIP_DB = os.environ.get("DC_GEOIP_DB", _DEFAULT_GEOIP_PATH)

_geoip_reader = None
_geoip_init_lock = threading.Lock()
_geoip_init_attempted = False


def _get_geoip_reader():
    """Ленивая инициализация. Если файла нет / либа не установлена → возвращаем None
    и помечаем _geoip_init_attempted, чтобы не пытаться повторно при каждом lookup."""
    global _geoip_reader, _geoip_init_attempted
    if _geoip_init_attempted:
        return _geoip_reader
    with _geoip_init_lock:
        if _geoip_init_attempted:
            return _geoip_reader
        _geoip_init_attempted = True
        if not os.path.exists(DC_GEOIP_DB):
            logger.info("GeoIP DB не найдена по пути %s — geoip_lookup отключён", DC_GEOIP_DB)
            return None
        try:
            import maxminddb  # noqa: WPS433 (lazy import — опциональная зависимость)
            _geoip_reader = maxminddb.open_database(DC_GEOIP_DB, mode=maxminddb.MODE_MMAP)
            logger.info("GeoIP DB загружена: %s", DC_GEOIP_DB)
        except Exception as e:
            logger.warning("GeoIP DB load failed: %s", e)
        return _geoip_reader


@functools.lru_cache(maxsize=5000)
def geoip_lookup(ip: str):
    """Поиск IP в GeoIP-базе.

    Возвращает dict {country_code, country_name, country_name_ru, city, latitude, longitude}
    или None, если: IP пустой/частный, базы нет, lookup не удался.

    Вызывается из API-обработчиков; кэшируется LRU чтобы не дёргать mmdb десятки раз
    на один и тот же IP в одном response.
    """
    if not ip or is_rfc1918_ip(ip):
        return None
    reader = _get_geoip_reader()
    if reader is None:
        return None
    try:
        rec = reader.get(ip)
    except (ValueError, Exception):  # ValueError при невалидном IP-формате
        return None
    if not rec:
        return None
    country = rec.get("country") or {}
    city = rec.get("city") or {}
    loc = rec.get("location") or {}
    cnames = country.get("names") or {}
    cnames_ru = cnames.get("ru") or cnames.get("en") or ""
    return {
        "country_code": (country.get("iso_code") or "").upper(),
        "country_name": cnames.get("en") or "",
        "country_name_ru": cnames_ru,
        "city": (city.get("names") or {}).get("en") or "",
        "latitude": loc.get("latitude"),
        "longitude": loc.get("longitude"),
    }


def _fail2ban_call(args: list, timeout: int = 10) -> tuple:
    """Вызов fail2ban-client. Args — whitelisted список (никакой shell).

    Возвращает (returncode, stdout, stderr). При timeout/отсутствии fail2ban
    вернёт (-1, "", err_msg) вместо броска — вызывающий код умеет с этим жить.
    """
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return -1, "", "invalid args type"
    cmd = ["fail2ban-client", *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "fail2ban-client timeout"
    except FileNotFoundError:
        return -1, "", "fail2ban-client not installed"
    except Exception as e:
        return -1, "", f"{type(e).__name__}: {e}"


def fail2ban_list_jails() -> list:
    """Список активных jail'ов."""
    rc, out, _ = _fail2ban_call(["status"])
    if rc != 0:
        return []
    # Формат: "Jail list:\tdc-404-flood, domain-controller, sshd"
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("`- Jail list:") or line.startswith("Jail list:"):
            tail = line.split(":", 1)[1].strip()
            return [j.strip() for j in tail.split(",") if j.strip()]
    return []


def _parse_fail2ban_jail_status(text: str) -> dict:
    """Разобрать вывод `fail2ban-client status <jail>` в dict."""
    info = {"currently_failed": 0, "total_failed": 0, "currently_banned": 0,
            "total_banned": 0, "banned_ips": []}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("|- Currently failed:") or line.startswith("|  |- Currently failed:"):
            try:
                info["currently_failed"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("|  `- Total failed:") or line.startswith("|  |- Total failed:"):
            try:
                info["total_failed"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("|- Currently banned:") or line.startswith("   |- Currently banned:"):
            try:
                info["currently_banned"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("|- Total banned:") or line.startswith("   |- Total banned:"):
            try:
                info["total_banned"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("`- Banned IP list:") or line.startswith("   `- Banned IP list:"):
            tail = line.split(":", 1)[1].strip()
            info["banned_ips"] = [ip for ip in tail.split() if is_valid_ip(ip)]
    return info


def fail2ban_jail_info(name: str) -> dict:
    """Детали jail'а. Валидирует имя перед вызовом fail2ban-client."""
    if not _JAIL_NAME_RE.match(name or ""):
        return {}
    rc, out, _ = _fail2ban_call(["status", name])
    if rc != 0:
        return {}
    return _parse_fail2ban_jail_status(out)


def fail2ban_banned_ips(name: str) -> list:
    info = fail2ban_jail_info(name)
    return info.get("banned_ips", [])


def fail2ban_unban(name: str, ip: str) -> tuple:
    """Разблокировать IP в указанном jail'е. Возвращает (ok, message)."""
    if not _JAIL_NAME_RE.match(name or ""):
        return False, "invalid jail name"
    if not is_valid_ip(ip):
        return False, "invalid ip"
    rc, out, err = _fail2ban_call(["set", name, "unbanip", ip])
    if rc == 0:
        return True, out.strip() or "unbanned"
    return False, err.strip() or f"rc={rc}"


def fail2ban_manual_ban(name: str, ip: str) -> tuple:
    if not _JAIL_NAME_RE.match(name or ""):
        return False, "invalid jail name"
    if not is_valid_ip(ip):
        return False, "invalid ip"
    rc, out, err = _fail2ban_call(["set", name, "banip", ip])
    if rc == 0:
        return True, out.strip() or "banned"
    return False, err.strip() or f"rc={rc}"


def fail2ban_config(name: str) -> dict:
    """Получить параметры jail'а (findtime, maxretry, bantime)."""
    if not _JAIL_NAME_RE.match(name or ""):
        return {}
    result = {}
    for attr in ("findtime", "maxretry", "bantime"):
        rc, out, _ = _fail2ban_call(["get", name, attr])
        if rc == 0:
            result[attr] = out.strip()
    return result


@app.route("/firewall")
@login_required
@admin_required
def firewall_page():
    """Страница Firewall: jails, banned IPs, ручной ban/unban, статистика."""
    return render_template("firewall.html")


@app.route("/api/firewall/overview")
@login_required
def api_firewall_overview():
    jails = fail2ban_list_jails()
    # Если есть активные паузы, но самого jail'а нет в live-списке (он остановлен),
    # всё равно покажем его в UI — чтобы было видно "paused" состояние.
    paused_map = {p.jail_name: p for p in JailPause.query.all()}
    for paused_name in paused_map.keys():
        if paused_name not in jails and paused_name in PAUSABLE_JAILS:
            jails.append(paused_name)

    jails_data = []
    total_currently_banned = 0
    total_banned = 0
    for j in jails:
        info = fail2ban_jail_info(j)
        cfg = fail2ban_config(j)
        paused = paused_map.get(j)
        jails_data.append({
            "name": j,
            "currently_banned": info.get("currently_banned", 0),
            "total_banned": info.get("total_banned", 0),
            "currently_failed": info.get("currently_failed", 0),
            "config": cfg,
            "pausable": j in PAUSABLE_JAILS,
            "paused_until": paused.paused_until.isoformat() + "Z" if paused else None,
            "paused_by": paused.paused_by if paused else None,
            "paused_reason": paused.reason if paused else None,
        })
        total_currently_banned += info.get("currently_banned", 0)
        total_banned += info.get("total_banned", 0)

    # Подсчёт 444-ответов в логе за сутки — метрика активности UA-блока
    bot_blocked_24h = 0
    try:
        since = _utcnow() - datetime.timedelta(hours=24)
        bot_blocked_24h = db.session.query(func.count(AccessLog.id)).filter(
            AccessLog.timestamp >= since,
            AccessLog.status == 444,
        ).scalar() or 0
    except Exception:
        pass

    return jsonify({
        "jails": jails_data,
        "total_currently_banned": total_currently_banned,
        "total_banned_since_start": total_banned,
        "bot_blocked_24h": int(bot_blocked_24h),
        "uz_cidrs_count": len(_get_uz_cidrs()),
    })


@app.route("/api/firewall/banned")
@login_required
def api_firewall_banned():
    """Список всех заблокированных IP по всем jail'ам."""
    jails = fail2ban_list_jails()
    result = []
    for j in jails:
        for ip in fail2ban_banned_ips(j):
            result.append({
                "ip": ip,
                "jail": j,
                "is_uz": is_uz_ip(ip),
                "is_private": is_rfc1918_ip(ip),
                "geo": geoip_lookup(ip),
            })
    return jsonify(result)


_BOTS_RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 24 * 7}


@app.route("/api/firewall/bots")
@login_required
def api_firewall_bots():
    """Детальная статистика по 444-ответам (отбитые боты).

    Возвращает всё необходимое для UI-вкладки /firewall#tab=bots:
      - summary: total, unique_ips, unique_domains, unique_uas
      - timeline: bucket-по-часам (для графика)
      - top_ips: топ-20 IP с first/last seen + флагами (is_uz, is_banned)
      - top_domains: топ-10 доменов
      - top_user_agents: топ-20 UA (усечённо до 120 симв)
      - recent: последние N запросов (полный detail)

    Всё ограничено одним окном (?range=1h|6h|24h|7d, default 24h) и,
    опционально, ?domain=nettech.uz для drill-down.
    """
    rng = request.args.get("range", "24h")
    hours = _BOTS_RANGE_HOURS.get(rng, 24)
    try:
        limit = min(max(int(request.args.get("limit", 100)), 10), 500)
    except ValueError:
        limit = 100
    domain_filter = (request.args.get("domain") or "").strip().lower()

    since = _utcnow() - datetime.timedelta(hours=hours)
    base_q = AccessLog.query.filter(
        AccessLog.status == 444,
        AccessLog.timestamp >= since,
    )
    if domain_filter and is_valid_domain(domain_filter):
        base_q = base_q.filter(AccessLog.server_name == domain_filter)

    # Используем подзапрос-alias для переиспользования фильтра в aggregations
    base_subq = base_q.with_entities(
        AccessLog.id, AccessLog.timestamp, AccessLog.remote_addr,
        AccessLog.server_name, AccessLog.method, AccessLog.uri,
        AccessLog.user_agent, AccessLog.referer,
    ).subquery()

    # Summary
    total = db.session.query(func.count()).select_from(base_subq).scalar() or 0
    unique_ips = db.session.query(func.count(func.distinct(base_subq.c.remote_addr))).scalar() or 0
    unique_domains = db.session.query(func.count(func.distinct(base_subq.c.server_name))).scalar() or 0
    unique_uas = db.session.query(func.count(func.distinct(base_subq.c.user_agent))).scalar() or 0

    # Timeline (по часам)
    tl_rows = db.session.query(
        _hour_bucket_sql(base_subq.c.timestamp).label("hour"),
        func.count().label("cnt"),
    ).group_by("hour").order_by("hour").all()
    timeline = [{"hour": r.hour, "count": int(r.cnt)} for r in tl_rows]

    # Top IPs (20)
    top_ip_rows = db.session.query(
        base_subq.c.remote_addr.label("ip"),
        func.count().label("cnt"),
        func.min(base_subq.c.timestamp).label("first_seen"),
        func.max(base_subq.c.timestamp).label("last_seen"),
    ).group_by(base_subq.c.remote_addr).order_by(func.count().desc()).limit(20).all()

    banned_set = set()
    try:
        for j in fail2ban_list_jails():
            for ip in fail2ban_banned_ips(j):
                banned_set.add(ip)
    except Exception:
        pass

    top_ips = [{
        "ip": r.ip,
        "count": int(r.cnt),
        "first_seen": r.first_seen.isoformat() + "Z" if r.first_seen else None,
        "last_seen": r.last_seen.isoformat() + "Z" if r.last_seen else None,
        "is_uz": is_uz_ip(r.ip or ""),
        "is_private": is_rfc1918_ip(r.ip or ""),
        "is_banned": (r.ip or "") in banned_set,
        "geo": geoip_lookup(r.ip or ""),
    } for r in top_ip_rows]

    # Top domains (10)
    top_domain_rows = db.session.query(
        base_subq.c.server_name.label("domain"),
        func.count().label("cnt"),
    ).group_by(base_subq.c.server_name).order_by(func.count().desc()).limit(10).all()
    top_domains = [{"domain": r.domain or "—", "count": int(r.cnt)} for r in top_domain_rows]

    # Top User-Agents (20) — склеиваем короткие группы, UA обрезаем для отображения
    top_ua_rows = db.session.query(
        base_subq.c.user_agent.label("ua"),
        func.count().label("cnt"),
    ).group_by(base_subq.c.user_agent).order_by(func.count().desc()).limit(20).all()
    top_user_agents = [{
        "user_agent": (r.ua or "—")[:240],
        "count": int(r.cnt),
    } for r in top_ua_rows]

    # Recent requests (limit)
    recent_rows = db.session.query(
        base_subq.c.timestamp, base_subq.c.remote_addr, base_subq.c.server_name,
        base_subq.c.method, base_subq.c.uri, base_subq.c.user_agent, base_subq.c.referer,
    ).order_by(base_subq.c.timestamp.desc()).limit(limit).all()
    recent = [{
        "timestamp": r.timestamp.isoformat() + "Z" if r.timestamp else None,
        "ip": r.remote_addr,
        "domain": r.server_name,
        "method": r.method,
        "uri": (r.uri or "")[:500],
        "user_agent": (r.user_agent or "")[:240],
        "referer": (r.referer or "")[:240],
        "is_uz": is_uz_ip(r.remote_addr or ""),
        "is_banned": (r.remote_addr or "") in banned_set,
        "geo": geoip_lookup(r.remote_addr or ""),
    } for r in recent_rows]

    return jsonify({
        "range": rng,
        "domain_filter": domain_filter or None,
        "summary": {
            "total": int(total),
            "unique_ips": int(unique_ips),
            "unique_domains": int(unique_domains),
            "unique_user_agents": int(unique_uas),
        },
        "timeline": timeline,
        "top_ips": top_ips,
        "top_domains": top_domains,
        "top_user_agents": top_user_agents,
        "recent": recent,
    })


def _blocked_ban_targets() -> set:
    """Адреса, которые никогда нельзя забанить через UI.

    Включает: IP клиента, выполняющего действие; localhost; UZ-пул; RFC1918.
    Это защита от self-lockout и от блока "своих".
    """
    blocked = set()
    try:
        blocked.add(_client_ip())
    except Exception:
        pass
    return blocked


@app.route("/api/firewall/unban", methods=["POST"])
@login_required
@admin_required
def api_firewall_unban():
    # JSON-POST с пустым телом: request.json = None → .get() → AttributeError.
    # Поэтому get_json(silent=True) с явным fallback на {}.
    if request.is_json:
        data = request.get_json(silent=True) or {}
        ip = (data.get("ip") or "").strip()
        jail = (data.get("jail") or "").strip()
    else:
        ip = (request.form.get("ip") or "").strip()
        jail = (request.form.get("jail") or "").strip()
    if not is_valid_ip(ip):
        return jsonify({"ok": False, "error": "invalid ip"}), 400
    if not _JAIL_NAME_RE.match(jail):
        return jsonify({"ok": False, "error": "invalid jail"}), 400
    ok, msg = fail2ban_unban(jail, ip)
    log_action("firewall_unban", details=f"jail={jail} ip={ip} result={msg}")
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/firewall/ban", methods=["POST"])
@login_required
@admin_required
def api_firewall_ban():
    ip = (request.form.get("ip") or "").strip()
    jail = (request.form.get("jail") or "").strip()
    reason = (request.form.get("reason") or "").strip()[:255]
    if not is_valid_ip(ip):
        return jsonify({"ok": False, "error": "invalid ip"}), 400
    if not _JAIL_NAME_RE.match(jail):
        return jsonify({"ok": False, "error": "invalid jail"}), 400

    # Защита от самоблока и от блока своих
    if ip in _blocked_ban_targets():
        return jsonify({"ok": False, "error": "нельзя забанить ваш собственный IP"}), 400
    if is_rfc1918_ip(ip):
        return jsonify({"ok": False, "error": "нельзя забанить частный IP (RFC1918/localhost)"}), 400
    # Форс-подтверждение для UZ: клиент должен передать confirm_uz=1
    confirm_uz = request.form.get("confirm_uz") == "1"
    if is_uz_ip(ip) and not confirm_uz:
        return jsonify({
            "ok": False,
            "error": "ip_is_uz",
            "hint": "IP принадлежит узбекскому пулу. Повторите запрос с confirm_uz=1",
        }), 409

    ok, msg = fail2ban_manual_ban(jail, ip)
    log_action("firewall_manual_ban", details=f"jail={jail} ip={ip} reason={reason} result={msg}")
    return jsonify({"ok": ok, "message": msg})


def _ip_in_allowlist(ip: str, entries: list) -> bool:
    """True если IP попадает хотя бы в один CIDR из allowlist."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for e in entries:
        try:
            if addr in ipaddress.ip_network(e.cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


# Паузить разрешено только эти jail'ы — sshd и dc-manual оставляем неприкосновенными,
# чтобы админ по ошибке не отключил защиту SSH или ручные баны.
PAUSABLE_JAILS = {"dc-404-flood", "domain-controller"}

# Максимум 24 часа — верхняя граница паузы. Дольше — уже осознанное отключение
# в /etc/fail2ban/jail.d/*.conf (enabled=false) + reload.
MAX_PAUSE_SECONDS = 24 * 3600


def _pause_jail(jail_name: str, duration_sec: int, reason: str) -> tuple:
    """Внести паузу в БД и сделать stop в fail2ban. Возвращает (ok, message)."""
    if jail_name not in PAUSABLE_JAILS:
        return False, f"jail {jail_name} не разрешён к паузе (критичная защита)"
    if not (60 <= duration_sec <= MAX_PAUSE_SECONDS):
        return False, f"длительность должна быть 1 мин - {MAX_PAUSE_SECONDS // 3600} ч"
    paused_until = _utcnow() + datetime.timedelta(seconds=duration_sec)

    # Обновить или создать запись
    existing = JailPause.query.filter_by(jail_name=jail_name).first()
    if existing:
        existing.paused_until = paused_until
        existing.paused_by = current_username()
        existing.reason = (reason or "")[:255]
    else:
        db.session.add(JailPause(
            jail_name=jail_name,
            paused_until=paused_until,
            paused_by=current_username(),
            reason=(reason or "")[:255],
        ))
    db.session.commit()

    rc, out, err = _fail2ban_call(["stop", jail_name])
    if rc != 0:
        # stop может вернуть ненулевой код если jail уже остановлен — это OK
        logger.warning("fail2ban stop %s: rc=%s stderr=%s", jail_name, rc, err)
    return True, f"jail {jail_name} приостановлен до {paused_until.isoformat()}Z"


def _resume_jail(jail_name: str) -> tuple:
    """Снять паузу: fail2ban-client start + удалить запись JailPause."""
    if jail_name not in PAUSABLE_JAILS:
        return False, "nothing to resume"
    rec = JailPause.query.filter_by(jail_name=jail_name).first()
    if rec:
        db.session.delete(rec)
        db.session.commit()
    rc, out, err = _fail2ban_call(["start", jail_name])
    if rc != 0:
        # start вернёт error если уже запущен — это OK
        logger.info("fail2ban start %s: rc=%s stderr=%s", jail_name, rc, err)
    return True, f"jail {jail_name} возобновлён"


def _check_expired_pauses():
    """Фоновый чекер: если какой-то paused_until истёк — resume."""
    now = _utcnow()
    expired = JailPause.query.filter(JailPause.paused_until <= now).all()
    for rec in expired:
        jail = rec.jail_name
        logger.info("pause expired for %s, resuming", jail)
        db.session.delete(rec)
        db.session.commit()
        _fail2ban_call(["start", jail])

    # Реинвокация stop для действующих пауз — на случай если fail2ban рестартовал
    # за это время и сам перезапустил jail.
    active = JailPause.query.filter(JailPause.paused_until > now).all()
    for rec in active:
        # Это неблокирующая гигиена, не требует успеха
        _fail2ban_call(["stop", rec.jail_name])


@app.route("/api/firewall/jails/<jail_name>/pause", methods=["POST"])
@login_required
@admin_required
def api_firewall_pause(jail_name):
    if not _JAIL_NAME_RE.match(jail_name or ""):
        return jsonify({"ok": False, "error": "invalid jail name"}), 400
    try:
        duration = int(request.form.get("duration_sec", "3600"))
    except ValueError:
        return jsonify({"ok": False, "error": "invalid duration"}), 400
    reason = (request.form.get("reason") or "").strip()
    ok, msg = _pause_jail(jail_name, duration, reason)
    if ok:
        log_action("firewall_jail_pause",
                   details=f"jail={jail_name} duration_sec={duration} reason={reason}")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/api/firewall/jails/<jail_name>/resume", methods=["POST"])
@login_required
@admin_required
def api_firewall_resume(jail_name):
    if not _JAIL_NAME_RE.match(jail_name or ""):
        return jsonify({"ok": False, "error": "invalid jail name"}), 400
    ok, msg = _resume_jail(jail_name)
    log_action("firewall_jail_resume", details=f"jail={jail_name}")
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/firewall/allowlist", methods=["GET"])
@login_required
def api_firewall_allowlist_list():
    entries = IpAllowlist.query.order_by(IpAllowlist.id).all()
    client_ip = _client_ip()
    return jsonify([{
        "id": e.id,
        "cidr": e.cidr,
        "comment": e.comment,
        "created_at": e.created_at.isoformat() + "Z" if e.created_at else None,
        "created_by": e.created_by,
        "covers_current_admin": _ip_in_allowlist(client_ip, [e]),
    } for e in entries])


@app.route("/api/firewall/allowlist/add", methods=["POST"])
@login_required
@admin_required
def api_firewall_allowlist_add():
    cidr_raw = (request.form.get("cidr") or "").strip()
    comment = (request.form.get("comment") or "").strip()[:255] or None

    # Валидация через stdlib: принимает и одиночные IP, и полные CIDR.
    try:
        net = ipaddress.ip_network(cidr_raw, strict=False)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "неверный CIDR/IP"}), 400

    # Нормализуем представление: "10.0.0.5" → "10.0.0.5/32", "10.0.0.0/24" → "10.0.0.0/24"
    cidr = str(net)

    if IpAllowlist.query.filter_by(cidr=cidr).first():
        return jsonify({"ok": False, "error": f"{cidr} уже в списке"}), 409

    entry = IpAllowlist(cidr=cidr, comment=comment, created_by=current_username())
    db.session.add(entry)
    db.session.commit()

    try:
        apply_all_configs()
    except subprocess.CalledProcessError as e:
        db.session.delete(entry)
        db.session.commit()
        logger.error("apply_all_configs failed on allowlist_add %s: %s", cidr, e)
        return jsonify({"ok": False, "error": f"nginx reload упал: {e}"}), 500

    log_action("allowlist_add", details=f"cidr={cidr} comment={comment or ''}")
    return jsonify({"ok": True, "id": entry.id, "cidr": cidr})


@app.route("/api/firewall/allowlist/<int:entry_id>/delete", methods=["POST"])
@login_required
@admin_required
def api_firewall_allowlist_delete(entry_id):
    entry = db.session.get(IpAllowlist, entry_id)
    if not entry:
        return jsonify({"ok": False, "error": "не найдено"}), 404

    # Защита от полного опустошения — хотя бы 1 запись должна остаться
    if IpAllowlist.query.count() <= 1:
        return jsonify({
            "ok": False,
            "error": "нельзя удалить последнюю запись — панель станет недоступна"
        }), 400

    # Self-lockout: проверяем не покрывает ли эта запись текущего админа.
    # Если да — требуем явное подтверждение confirm_self=1 через query string.
    client_ip = _client_ip()
    confirm = request.form.get("confirm_self") == "1"
    if _ip_in_allowlist(client_ip, [entry]) and not confirm:
        # Проверяем: не покроет ли админа какой-то ДРУГОЙ CIDR из allowlist
        others = IpAllowlist.query.filter(IpAllowlist.id != entry.id).all()
        if not _ip_in_allowlist(client_ip, others):
            return jsonify({
                "ok": False,
                "error": "self_lockout",
                "hint": (f"Этот CIDR ({entry.cidr}) покрывает ваш IP ({client_ip}), "
                         "и без него вы потеряете доступ к панели. "
                         "Повторите запрос с confirm_self=1 для подтверждения."),
            }), 409

    cidr = entry.cidr
    comment = entry.comment or ""
    db.session.delete(entry)
    db.session.commit()

    try:
        apply_all_configs()
    except subprocess.CalledProcessError as e:
        # Откатываем БД
        db.session.add(IpAllowlist(cidr=cidr, comment=comment, created_by=entry.created_by))
        db.session.commit()
        logger.error("apply_all_configs failed on allowlist_delete %s: %s", cidr, e)
        return jsonify({"ok": False, "error": f"nginx reload упал, запись восстановлена: {e}"}), 500

    log_action("allowlist_remove", details=f"cidr={cidr}")
    return jsonify({"ok": True})


@app.route("/api/firewall/timeline")
@login_required
def api_firewall_timeline():
    """Все bans/unbans (manual + auto) по часам за последние 24 часа.

    Источник — таблица fail2ban_events, наполняемая парсером /var/log/fail2ban.log.
    Ранее использовались audit_logs, но там только ручные события.
    """
    since = _utcnow() - datetime.timedelta(hours=24)

    # Auto/manual различаем через audit_logs: если для ts+ip есть firewall_manual_ban
    # — это ручной. Остальное — автомат. Но для графика просто: ban vs unban.
    rows = db.session.query(
        _hour_bucket_sql(FailbanEvent.timestamp).label("hour"),
        FailbanEvent.action,
        func.count().label("cnt"),
    ).filter(
        FailbanEvent.timestamp >= since,
    ).group_by("hour", FailbanEvent.action).order_by("hour").all()

    now = _utcnow().replace(minute=0, second=0, microsecond=0)
    labels = []
    for i in range(23, -1, -1):
        labels.append((now - datetime.timedelta(hours=i)).strftime("%Y-%m-%d %H:00"))
    bans_by_hour = {lbl: 0 for lbl in labels}
    unbans_by_hour = {lbl: 0 for lbl in labels}
    for r in rows:
        if r.hour in bans_by_hour:
            if r.action in ("Ban", "Restore"):
                bans_by_hour[r.hour] = r.cnt
            elif r.action == "Unban":
                unbans_by_hour[r.hour] = r.cnt

    return jsonify({
        "labels": [lbl[-5:] for lbl in labels],
        "bans":   [bans_by_hour[l] for l in labels],
        "unbans": [unbans_by_hour[l] for l in labels],
    })


@app.route("/api/firewall/history")
@login_required
def api_firewall_history():
    """Последние 100 ban/unban событий из audit_logs."""
    rows = AuditLog.query.filter(
        AuditLog.action.like("firewall_%")
    ).order_by(AuditLog.created_at.desc()).limit(100).all()
    return jsonify([{
        "time": r.created_at.isoformat() + "Z" if r.created_at else None,
        "user": r.username,
        "action": r.action,
        "details": r.details,
    } for r in rows])


# ──────────────────────────────────────────────
#  App settings UI (admin only)
# ──────────────────────────────────────────────

@app.route("/settings")
@login_required
@admin_required
def settings_page():
    # Строим форму из SETTING_DEFINITIONS
    current = {k: get_setting(k, default) for k, _t, default, _c, _d, *_ in SETTING_DEFINITIONS}
    # Группируем по категориям для красивого layout
    by_category: dict = {}
    for key, vtype, default, category, desc, *bounds in SETTING_DEFINITIONS:
        by_category.setdefault(category, []).append({
            "key": key, "vtype": vtype, "default": default, "category": category,
            "desc": desc, "current": current[key],
            "min_val": bounds[0] if len(bounds) > 0 else None,
            "max_val": bounds[1] if len(bounds) > 1 else None,
        })
    category_titles = {
        "retention": "📦 Хранение логов (retention)",
        "security":  "🔐 Безопасность (rate-limit логина)",
        "intervals": "⏱ Интервалы фоновых задач",
    }
    return render_template("settings.html",
                           by_category=by_category,
                           category_titles=category_titles)


@app.route("/api/settings/update", methods=["POST"])
@login_required
@admin_required
def api_settings_update():
    """Batch update всех настроек из формы /settings."""
    # Список валидных ключей + типы + границы
    definitions = {d[0]: d for d in SETTING_DEFINITIONS}
    changed = []
    errors = []
    for key, form_val in request.form.items():
        if key == "csrf_token" or key not in definitions:
            continue
        _k, vtype, default, category, desc, *bounds = definitions[key]
        raw = form_val.strip()
        if vtype == "int":
            try:
                v = int(raw)
            except ValueError:
                errors.append(f"{key}: '{raw}' не число")
                continue
            if bounds:
                lo, hi = bounds[0], bounds[1]
                if not (lo <= v <= hi):
                    errors.append(f"{key}: {v} вне диапазона [{lo}, {hi}]")
                    continue
            stored = str(v)
        elif vtype == "bool":
            stored = "true" if raw.lower() in ("true", "1", "yes", "on") else "false"
        else:
            if len(raw) > 1024:
                errors.append(f"{key}: слишком длинно (>1024 символов)")
                continue
            stored = raw
        if str(get_setting(key, default)) != stored:
            set_setting(key, stored, vtype=vtype, category=category, description=desc)
            changed.append(key)

    if errors:
        flash("Ошибки: " + "; ".join(errors), "danger")
    elif changed:
        log_action("settings_update", details=f"changed={','.join(changed)}")
        flash(f"Обновлено настроек: {len(changed)} ({', '.join(changed)})", "success")
    else:
        flash("Нет изменений", "info")
    return redirect(url_for("settings_page"))


# ──────────────────────────────────────────────
#  Users & tokens management UI (admin only)
# ──────────────────────────────────────────────

@app.route("/users")
@login_required
@admin_required
def users_index():
    users_list = User.query.order_by(User.id).all()
    tokens_list = ApiToken.query.order_by(ApiToken.id.desc()).all()
    return render_template(
        "users.html",
        users=users_list,
        tokens=tokens_list,
        new_token=session.pop("_new_token", None),
        new_token_name=session.pop("_new_token_name", None),
    )


@app.route("/users/create", methods=["POST"])
@login_required
@admin_required
def users_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "viewer").strip()

    if not username or not password:
        flash("Логин и пароль обязательны", "danger")
        return redirect(url_for("users_index"))
    if not re.match(r"^[A-Za-z0-9._-]{2,64}$", username):
        flash("Логин: 2-64 символа, [A-Za-z0-9._-]", "danger")
        return redirect(url_for("users_index"))
    if len(password) < 8:
        flash("Пароль должен быть не короче 8 символов", "danger")
        return redirect(url_for("users_index"))
    if role not in ("admin", "viewer"):
        flash("Недопустимая роль", "danger")
        return redirect(url_for("users_index"))
    if User.query.filter_by(username=username).first():
        flash("Пользователь с таким логином уже существует", "danger")
        return redirect(url_for("users_index"))

    u = User(username=username, role=role, is_admin=(role == "admin"))
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    log_action("create_user", details=f"{username} ({role})")
    flash(f"Пользователь «{username}» создан ({role})", "success")
    return redirect(url_for("users_index"))


@app.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@admin_required
def users_set_role(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("Пользователь не найден", "danger")
        return redirect(url_for("users_index"))
    if user.username == session.get("username"):
        flash("Нельзя менять собственную роль — войдите под другим admin", "danger")
        return redirect(url_for("users_index"))
    role = request.form.get("role", "").strip()
    if role not in ("admin", "viewer"):
        flash("Недопустимая роль", "danger")
        return redirect(url_for("users_index"))
    user.role = role
    user.is_admin = (role == "admin")
    db.session.commit()
    log_action("set_role", details=f"{user.username} → {role}")
    flash(f"Роль {user.username}: {role}", "success")
    return redirect(url_for("users_index"))


@app.route("/users/<int:user_id>/password", methods=["POST"])
@login_required
@admin_required
def users_set_password(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("Пользователь не найден", "danger")
        return redirect(url_for("users_index"))
    password = request.form.get("password", "").strip()
    if len(password) < 8:
        flash("Пароль должен быть не короче 8 символов", "danger")
        return redirect(url_for("users_index"))
    user.set_password(password)
    db.session.commit()
    log_action("reset_password", details=user.username)
    flash(f"Пароль {user.username} обновлён", "success")
    return redirect(url_for("users_index"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def users_delete(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("Пользователь не найден", "danger")
        return redirect(url_for("users_index"))
    if user.username == session.get("username"):
        flash("Нельзя удалить собственный аккаунт", "danger")
        return redirect(url_for("users_index"))
    # Удалим и все его API-токены
    ApiToken.query.filter_by(user_id=user.id).delete()
    username = user.username
    db.session.delete(user)
    db.session.commit()
    log_action("delete_user", details=username)
    flash(f"Пользователь «{username}» удалён (вместе с его токенами)", "success")
    return redirect(url_for("users_index"))


@app.route("/users/<int:user_id>/tokens/create", methods=["POST"])
@login_required
@admin_required
def tokens_create(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("Пользователь не найден", "danger")
        return redirect(url_for("users_index"))
    name = request.form.get("name", "").strip()
    if not name or len(name) > 64:
        flash("Название токена: 1-64 символа", "danger")
        return redirect(url_for("users_index"))
    raw = secrets.token_urlsafe(32)
    tok = ApiToken(user_id=user.id, name=name, token_hash=ApiToken.hash_token(raw))
    db.session.add(tok)
    db.session.commit()
    log_action("create_token", details=f"{user.username}: {name}")
    # Показываем raw только один раз — через session flash
    session["_new_token"] = raw
    session["_new_token_name"] = f"{user.username}: {name}"
    flash("Токен создан — сохраните его прямо сейчас, он больше не будет показан", "warning")
    return redirect(url_for("users_index"))


@app.route("/tokens/<int:token_id>/revoke", methods=["POST"])
@login_required
@admin_required
def tokens_revoke(token_id):
    tok = db.session.get(ApiToken, token_id)
    if not tok:
        flash("Токен не найден", "danger")
        return redirect(url_for("users_index"))
    u = tok.user.username if tok.user else "?"
    name = tok.name
    db.session.delete(tok)
    db.session.commit()
    log_action("revoke_token", details=f"{u}: {name}")
    flash(f"Токен «{name}» у {u} отозван", "success")
    return redirect(url_for("users_index"))


# ──────────────────────────────────────────────
#  CLI commands
# ──────────────────────────────────────────────

@app.cli.command("init-db")
def init_db_command():
    ensure_schema()
    print("База данных инициализирована.")


@app.cli.command("create-user")
@click.argument("username")
def create_user_command(username):
    ensure_schema()
    password = click.prompt("Пароль", hide_input=True, confirmation_prompt=True)

    if User.query.filter_by(username=username).first():
        print("Пользователь с таким именем уже существует")
        return

    user = User(username=username, is_admin=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print(f"Пользователь {username} создан")


@app.cli.command("apply-configs")
def apply_configs_command():
    """Пересобрать nginx-конфиги из БД и сделать reload.

    Пригодится после обновления шаблонов генератора (например, когда добавили
    bot-protect include) — без этого старые конфиги продолжают крутиться.
    """
    ensure_schema()
    try:
        apply_all_configs()
        print("nginx-конфиги пересобраны и reload прошёл")
    except Exception as e:
        print(f"FAIL: {e}")
        import sys
        sys.exit(1)


@app.cli.command("doctor")
def doctor_command():
    """Диагностика состояния приложения.

    Проверяет БД, парсер логов, nginx-конфиги, сертификаты, место на диске.
    Возвращает код 0 если всё здорово, 1 если есть проблемы.
    """
    ensure_schema()
    problems = 0
    ok = 0

    def _ok(msg):
        nonlocal ok
        ok += 1
        print(f"  ✓ {msg}")

    def _warn(msg):
        nonlocal problems
        problems += 1
        print(f"  ✗ {msg}")

    print("=" * 60)
    print("DomainController doctor")
    print("=" * 60)

    print("\n[БД]")
    try:
        total_domains = DomainRoute.query.count()
        total_streams = StreamRoute.query.count()
        total_access = AccessLog.query.count()
        total_stream_logs = StreamAccessLog.query.count()
        size_mb = _db_size_bytes() / 1024 / 1024
        engine_name = db.engine.dialect.name
        _ok(f"[{engine_name}] домены={total_domains}, stream={total_streams}, access_logs={total_access}, "
            f"stream_logs={total_stream_logs}, size={size_mb:.1f} МБ")
        if _is_sqlite():
            mode = db.session.execute(text("PRAGMA journal_mode")).scalar()
            if str(mode).lower() == "wal":
                _ok("journal_mode=WAL")
            else:
                _warn(f"journal_mode={mode} (ожидается WAL)")
        else:
            _ok("PostgreSQL — PRAGMA неприменимы")
    except Exception as e:
        _warn(f"БД недоступна: {e}")

    print("\n[Парсер логов]")
    for key, path in (("http_log", HTTP_LOG_PATH), ("stream_log", STREAM_LOG_PATH)):
        cp = db.session.get(LogCheckpoint, key)
        if cp is None:
            _warn(f"{key}: нет checkpoint — парсер ещё не запускался")
            continue
        age = (_utcnow() - cp.updated_at).total_seconds() if cp.updated_at else -1
        if os.path.exists(path):
            file_size = os.path.getsize(path)
            behind = max(0, file_size - cp.position)
            if age > 300:
                _warn(f"{key}: checkpoint устарел на {age:.0f} сек (возможно парсер упал)")
            else:
                _ok(f"{key}: position={cp.position}, file_size={file_size}, "
                    f"behind={behind} байт, age={age:.0f}s")
        else:
            _warn(f"{key}: файл {path} не существует")

    print("\n[Nginx конфиги]")
    for label, path in (("domain-routes", NGINX_CONF_PATH), ("stream-routes", STREAM_CONF_PATH)):
        if os.path.exists(path):
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            _ok(f"{label}: {path} ({mtime:%Y-%m-%d %H:%M})")
        else:
            _warn(f"{label}: {path} не существует")
        rollback = path + ".rollback"
        if os.path.exists(rollback):
            _warn(f"{label}: найден {rollback} — возможно reload упал без restore")

    print("\n[SSL сертификаты]")
    if not DEV_MODE:
        try:
            ssl_domains = DomainRoute.query.filter(DomainRoute.enable_https.is_(True)).all()
            for r in ssl_domains:
                cert = r.ssl_cert_path
                if not cert or not os.path.exists(cert):
                    _warn(f"{r.domain}: ssl_cert_path не существует ({cert})")
                    continue
                try:
                    out = subprocess.run(
                        ["openssl", "x509", "-in", cert, "-noout", "-enddate"],
                        capture_output=True, text=True, check=True, timeout=5,
                    )
                    end = out.stdout.strip().replace("notAfter=", "")
                    end_dt = datetime.datetime.strptime(end, "%b %d %H:%M:%S %Y %Z")
                    days_left = (end_dt - _utcnow()).days
                    if days_left < 7:
                        _warn(f"{r.domain}: сертификат истечёт через {days_left} дней")
                    elif days_left < 30:
                        print(f"  ⚠ {r.domain}: сертификат истечёт через {days_left} дней")
                        ok += 1
                    else:
                        _ok(f"{r.domain}: ssl валиден ещё {days_left} дней")
                except Exception as e:
                    _warn(f"{r.domain}: не удалось прочитать сертификат ({e})")
        except Exception as e:
            _warn(f"проверка SSL: {e}")
    else:
        print("  (DEV_MODE — проверка сертификатов пропущена)")

    print("\n[Диск]")
    try:
        st = os.statvfs(BASE_DIR)
        free_gb = (st.f_bavail * st.f_frsize) / 1024 / 1024 / 1024
        total_gb = (st.f_blocks * st.f_frsize) / 1024 / 1024 / 1024
        if free_gb < 1:
            _warn(f"свободно всего {free_gb:.1f} ГБ из {total_gb:.1f} ГБ")
        elif free_gb < 5:
            print(f"  ⚠ свободно {free_gb:.1f} ГБ из {total_gb:.1f} ГБ")
            ok += 1
        else:
            _ok(f"свободно {free_gb:.1f} ГБ из {total_gb:.1f} ГБ")
    except Exception as e:
        _warn(f"statvfs: {e}")

    print("\n[Конфигурация]")
    if app.config["SECRET_KEY"] in ("change-me", "dev-insecure-change-me"):
        if DEV_MODE:
            print("  ⚠ DC_PANEL_SECRET = дефолтный (DEV_MODE)")
        else:
            _warn("DC_PANEL_SECRET = дефолтный (!) — небезопасно для production")
    else:
        _ok(f"DC_PANEL_SECRET задан ({len(app.config['SECRET_KEY'])} символов)")

    print("\n" + "=" * 60)
    print(f"Итог: {ok} OK, {problems} проблем")
    print("=" * 60)
    import sys
    sys.exit(0 if problems == 0 else 1)


@app.cli.command("export-config")
@click.option("--output", "-o", default="-", help="Путь к файлу или - для stdout")
def export_config_command(output):
    """Экспорт маршрутов и пользователей в JSON для переноса на другой узел.

    Секретные данные (password_hash) включаются — файл можно использовать
    только для миграции на доверенный узел. Не публиковать!
    """
    ensure_schema()
    data = {
        "version": 1,
        "exported_at": _utcnow().isoformat() + "Z",
        "domain_routes": [
            {c.name: getattr(r, c.name) for c in r.__table__.columns}
            for r in DomainRoute.query.order_by(DomainRoute.id).all()
        ],
        "stream_routes": [
            {c.name: getattr(r, c.name) for c in r.__table__.columns}
            for r in StreamRoute.query.order_by(StreamRoute.id).all()
        ],
        "users": [
            {"username": u.username, "password_hash": u.password_hash, "is_admin": u.is_admin}
            for u in User.query.order_by(User.id).all()
        ],
    }
    payload = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    if output == "-":
        print(payload)
    else:
        with open(output, "w") as f:
            f.write(payload)
        os.chmod(output, 0o600)
        print(f"экспортировано: {output} (chmod 600)")


@app.cli.command("import-config")
@click.argument("input_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--skip-users", is_flag=True, help="Не импортировать пользователей")
@click.option("--replace", is_flag=True, help="Удалить текущие маршруты перед импортом")
def import_config_command(input_path, skip_users, replace):
    """Импорт JSON, сгенерированного export-config. Дубликаты пропускаются.

    nginx-конфиг после импорта НЕ перегенерируется автоматически — перезапустите
    сервис или зайдите в админку и сделайте любое действие, триггерящее reload.
    """
    ensure_schema()
    with open(input_path) as f:
        data = json.load(f)

    if data.get("version") != 1:
        raise click.ClickException(f"Неизвестная версия: {data.get('version')}")

    if replace:
        click.confirm("Удалить все существующие маршруты и импортировать заново?", abort=True)
        StreamRoute.query.delete()
        DomainRoute.query.delete()
        db.session.commit()

    existing_domains = {r.domain for r in DomainRoute.query.all()}
    existing_ports = {r.listen_port for r in StreamRoute.query.all()}
    added_d = skipped_d = added_s = skipped_s = 0

    for d in data.get("domain_routes", []):
        if d.get("domain") in existing_domains:
            skipped_d += 1
            continue
        d.pop("id", None)
        if not is_valid_domain(d.get("domain", "")):
            click.echo(f"  ✗ пропускаю невалидный домен: {d.get('domain')}")
            skipped_d += 1
            continue
        db.session.add(DomainRoute(**d))
        added_d += 1

    for s in data.get("stream_routes", []):
        if s.get("listen_port") in existing_ports:
            skipped_s += 1
            continue
        s.pop("id", None)
        db.session.add(StreamRoute(**s))
        added_s += 1

    added_u = 0
    if not skip_users:
        existing_u = {u.username for u in User.query.all()}
        for u in data.get("users", []):
            if u["username"] in existing_u:
                continue
            db.session.add(User(
                username=u["username"],
                password_hash=u["password_hash"],
                is_admin=u.get("is_admin", True),
            ))
            added_u += 1

    db.session.commit()
    print(f"Импорт: +{added_d} доменов ({skipped_d} пропущено), "
          f"+{added_s} streams ({skipped_s} пропущено), +{added_u} пользователей")
    print("Перезапустите сервис или сделайте любое изменение в UI для применения nginx-конфигов.")


@app.cli.command("set-role")
@click.argument("username")
@click.argument("role", type=click.Choice(["admin", "viewer"]))
def set_role_command(username, role):
    """Изменить роль пользователя (admin | viewer)."""
    ensure_schema()
    user = User.query.filter_by(username=username).first()
    if not user:
        raise click.ClickException(f"Пользователь {username} не найден")
    user.role = role
    user.is_admin = (role == "admin")
    db.session.commit()
    print(f"{username}: role={role}")


@app.cli.command("token-create")
@click.argument("username")
@click.argument("name")
def token_create_command(username, name):
    """Сгенерировать API-токен для пользователя. Токен показывается ОДИН РАЗ."""
    ensure_schema()
    user = User.query.filter_by(username=username).first()
    if not user:
        raise click.ClickException(f"Пользователь {username} не найден")
    raw = secrets.token_urlsafe(32)
    tok = ApiToken(user_id=user.id, name=name, token_hash=ApiToken.hash_token(raw))
    db.session.add(tok)
    db.session.commit()
    print(f"Создан токен '{name}' для {username} (role={user.role})")
    print()
    print(f"  {raw}")
    print()
    print("СОХРАНИТЕ этот токен сейчас — он больше НЕ БУДЕТ показан.")
    print("Использование: curl -H 'Authorization: Bearer <token>' https://panel/api/healthz")


@app.cli.command("token-list")
def token_list_command():
    """Показать все API-токены (без сами raw-значений)."""
    ensure_schema()
    tokens = ApiToken.query.all()
    if not tokens:
        print("Нет токенов")
        return
    for t in tokens:
        u = t.user.username if t.user else "?"
        last = t.last_used_at.isoformat() + "Z" if t.last_used_at else "never"
        print(f"#{t.id} [{u}] {t.name} — created {t.created_at.isoformat()}Z, last_used {last}")


@app.cli.command("token-revoke")
@click.argument("token_id", type=int)
def token_revoke_command(token_id):
    """Удалить API-токен по ID (см. token-list)."""
    ensure_schema()
    tok = db.session.get(ApiToken, token_id)
    if not tok:
        raise click.ClickException("токен не найден")
    db.session.delete(tok)
    db.session.commit()
    print(f"токен #{token_id} удалён")


with app.app_context():
    ensure_schema()
    # DC_NO_BG_THREADS=1 — отключает фоновый log-reader. Используется migrate-sqlite-to-pg.py
    # чтобы parser/cleanup не писали в БД во время копирования таблиц.
    if os.environ.get("DC_NO_BG_THREADS", "0") != "1":
        start_log_reader()

if __name__ == "__main__":
    if DEV_MODE:
        print("=" * 50)
        print("  🚧 DEV MODE — nginx/certbot пропускаются")
        print(f"  📄 HTTP config:   {NGINX_CONF_PATH}")
        print(f"  📄 Stream config: {STREAM_CONF_PATH}")
        print("  📊 Dashboard:     http://127.0.0.1:5000")
        print("=" * 50)
    app.run(host="127.0.0.1", port=5000, debug=DEV_MODE)
