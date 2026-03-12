import os
import subprocess
import datetime
import threading
import json
import time
import random
from functools import wraps

import click
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text, func
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "data.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("DC_PANEL_SECRET", "change-me")

# Email для Let's Encrypt
app.config["LETSENCRYPT_EMAIL"] = os.environ.get("LETSENCRYPT_EMAIL", "admin@example.com")

# Dev mode — пропускает nginx/certbot команды, пишет конфиги локально
DEV_MODE = os.environ.get("DEV_MODE", "0") == "1"

if DEV_MODE:
    NGINX_CONF_PATH = os.path.join(BASE_DIR, "dev_domain-routes.conf")
    STREAM_CONF_PATH = os.path.join(BASE_DIR, "dev_stream-routes.conf")
    ACME_WEBROOT = "/tmp/certbot"
else:
    NGINX_CONF_PATH = "/etc/nginx/conf.d/domain-routes.conf"
    STREAM_CONF_PATH = "/etc/nginx/stream-routes.conf"
    ACME_WEBROOT = "/var/www/certbot"

db = SQLAlchemy(app)


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

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class DomainRoute(db.Model):
    __tablename__ = "domain_routes"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
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
    status = db.Column(db.String(10))


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    username = db.Column(db.String(64), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)


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


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

def frontend_https_ready(route: DomainRoute) -> bool:
    return bool(route.enable_https and route.ssl_cert_path and route.ssl_key_path)


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return func(*args, **kwargs)
    return wrapper


def current_username() -> str:
    return session.get("username", "system")


def log_action(action: str, domain: str | None = None, details: str | None = None):
    entry = AuditLog(
        username=current_username(),
        action=action,
        domain=domain,
        details=details,
    )
    db.session.add(entry)
    db.session.commit()


def ensure_acme_webroot():
    os.makedirs(ACME_WEBROOT, exist_ok=True)


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

    directives = []
    if route.enable_logging:
        directives.append(f"access_log {HTTP_LOG_PATH} dc_json;")
    directives.extend([
        f"proxy_pass {scheme}://{route.target_host}:{route.target_port};",
        "proxy_set_header Host $host;",
        "proxy_set_header X-Real-IP $remote_addr;",
        "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "proxy_set_header X-Forwarded-Proto $scheme;",
        "proxy_set_header X-Forwarded-Host $host;",
        "proxy_set_header X-Forwarded-Port $server_port;",
        "proxy_read_timeout 3600;",
        "proxy_send_timeout 3600;",
    ])

    if route.enable_websocket or route.backend_https:
        directives.extend([
            "proxy_http_version 1.1;",
            "proxy_set_header Upgrade $http_upgrade;",
            'proxy_set_header Connection "upgrade";',
        ])

    if route.backend_https:
        directives.append("proxy_ssl_verify off;")

    return "\n".join(f"        {line}" for line in directives)


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

        # HTTP server
        if https_active:
            http_block = f"""
# {route.id}: {server_names}:{lp} -> {'https' if route.backend_https else 'http'}://{route.target_host}:{route.target_port}
server {{
    listen {lp};
    server_name {server_names};

    location ^~ /.well-known/acme-challenge/ {{
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

    location ^~ /.well-known/acme-challenge/ {{
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

    location / {{
{proxy_block}
    }}
}}
"""
            blocks.append(https_block)

    content = "\n".join(blocks) if blocks else "# no domains configured yet\n"
    content = build_log_format_block() + content


    with open(NGINX_CONF_PATH, "w") as f:
        f.write(content)


# ──────────────────────────────────────────────
#  Nginx config generation — Stream (TCP/UDP)
# ──────────────────────────────────────────────

def generate_stream_config():
    """Сгенерировать stream-routes.conf для TCP/UDP маршрутов."""
    streams = StreamRoute.query.order_by(StreamRoute.listen_port).all()

    if not streams:
        content = "# no stream routes configured yet\n"
    else:
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
        content = "\n".join(blocks)

    with open(STREAM_CONF_PATH, "w") as f:
        f.write(content)


def reload_nginx():
    """Проверить конфигурацию и перезагрузить Nginx. В DEV_MODE — пропускается."""
    if DEV_MODE:
        return
    subprocess.run(["nginx", "-t"], check=True)
    subprocess.run(["systemctl", "reload", "nginx"], check=True)


def apply_all_configs():
    """Сгенерировать все конфиги и перезагрузить Nginx."""
    generate_nginx_config()
    generate_stream_config()
    reload_nginx()


# ──────────────────────────────────────────────
#  Background log reader
# ──────────────────────────────────────────────

_http_log_pos = 0
_stream_log_pos = 0


def _parse_http_log():
    """Прочитать новые строки из dc_access.json."""
    global _http_log_pos

    if not os.path.exists(HTTP_LOG_PATH):
        return

    with open(HTTP_LOG_PATH, "r") as f:
        f.seek(_http_log_pos)
        new_lines = f.readlines()
        _http_log_pos = f.tell()

    if not new_lines:
        return

    entries = []
    for line in new_lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue

        try:
            ts = datetime.datetime.fromisoformat(d.get("time", "").replace("+00:00", "+00:00"))
        except (ValueError, TypeError):
            ts = datetime.datetime.utcnow()

        entries.append(AccessLog(
            timestamp=ts,
            remote_addr=d.get("remote_addr", ""),
            remote_port=int(d.get("remote_port", 0) or 0),
            server_name=d.get("server_name", ""),
            server_port=int(d.get("server_port", 0) or 0),
            method=d.get("request_method", ""),
            uri=d.get("request_uri", "")[:2048],
            status=int(d.get("status", 0) or 0),
            body_bytes=int(d.get("body_bytes_sent", 0) or 0),
            request_time=float(d.get("request_time", 0) or 0),
            upstream_addr=d.get("upstream_addr", ""),
            upstream_time=str(d.get("upstream_response_time", "")),
            user_agent=d.get("http_user_agent", "")[:512],
            referer=d.get("http_referer", "")[:512],
            scheme=d.get("scheme", ""),
            ssl_protocol=d.get("ssl_protocol", ""),
        ))

    if entries:
        db.session.bulk_save_objects(entries)
        db.session.commit()


def _parse_stream_log():
    """Прочитать новые строки из dc_stream.json."""
    global _stream_log_pos

    if not os.path.exists(STREAM_LOG_PATH):
        return

    with open(STREAM_LOG_PATH, "r") as f:
        f.seek(_stream_log_pos)
        new_lines = f.readlines()
        _stream_log_pos = f.tell()

    if not new_lines:
        return

    entries = []
    for line in new_lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue

        try:
            ts = datetime.datetime.fromisoformat(d.get("time", ""))
        except (ValueError, TypeError):
            ts = datetime.datetime.utcnow()

        sess_time = d.get("session_time", "0")
        try:
            sess_time = float(sess_time)
        except (ValueError, TypeError):
            sess_time = 0.0

        entries.append(StreamAccessLog(
            timestamp=ts,
            remote_addr=d.get("remote_addr", ""),
            remote_port=int(d.get("remote_port", 0) or 0),
            server_port=int(d.get("server_port", 0) or 0),
            protocol=d.get("protocol", "TCP"),
            bytes_received=int(d.get("bytes_received", 0) or 0),
            bytes_sent=int(d.get("bytes_sent", 0) or 0),
            session_time=sess_time,
            upstream_addr=d.get("upstream_addr", ""),
            status=d.get("status", ""),
        ))

    if entries:
        db.session.bulk_save_objects(entries)
        db.session.commit()


def _cleanup_old_logs(days: int = 30):
    """Удалить записи старше N дней."""
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    AccessLog.query.filter(AccessLog.timestamp < cutoff).delete()
    StreamAccessLog.query.filter(StreamAccessLog.timestamp < cutoff).delete()
    db.session.commit()


def _generate_fake_data():
    """DEV_MODE: генерировать фейковые данные для тестирования дашборда."""
    domains = DomainRoute.query.all()
    streams = StreamRoute.query.all()

    if not domains and not streams:
        return

    now = datetime.datetime.utcnow()
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


def start_log_reader():
    """Запустить фоновый поток чтения логов."""
    def _worker():
        while True:
            try:
                with app.app_context():
                    if DEV_MODE:
                        _generate_fake_data()
                    else:
                        _parse_http_log()
                        _parse_stream_log()
                    _cleanup_old_logs(days=30)
            except Exception:
                pass
            time.sleep(10 if DEV_MODE else 5)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


# ──────────────────────────────────────────────
#  Stats API endpoints
# ──────────────────────────────────────────────

@app.route("/api/stats/overview")
@login_required
def api_stats_overview():
    """Общая сводка за 24 часа."""
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=24)

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
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)

    rows = db.session.query(
        func.strftime("%Y-%m-%d %H:00", AccessLog.timestamp).label("hour"),
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
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=24)

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
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=24)

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
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
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
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
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
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
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
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=24)

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


@app.route("/api/stats/domain/<domain_name>")
@login_required
def api_stats_domain_detail(domain_name):
    """Детальная статистика одного домена."""
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=24)

    # Timeline по часам
    timeline = db.session.query(
        func.strftime("%Y-%m-%d %H:00", AccessLog.timestamp).label("hour"),
        func.count().label("cnt"),
    ).filter(
        AccessLog.timestamp >= since,
        AccessLog.server_name == domain_name,
    ).group_by("hour").order_by("hour").all()

    # Топ URI
    top_uris = db.session.query(
        AccessLog.uri,
        func.count().label("cnt"),
    ).filter(
        AccessLog.timestamp >= since,
        AccessLog.server_name == domain_name,
    ).group_by(AccessLog.uri).order_by(func.count().desc()).limit(10).all()

    # Топ IP
    top_ips = db.session.query(
        AccessLog.remote_addr,
        func.count().label("cnt"),
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

    return jsonify({
        "domain": domain_name,
        "total_requests": total,
        "avg_response_time": round(avg_time, 3),
        "errors": errors,
        "timeline": {"labels": [r.hour for r in timeline], "data": [r.cnt for r in timeline]},
        "top_uris": [{"uri": r.uri, "requests": r.cnt} for r in top_uris],
        "top_ips": [{"ip": r.remote_addr, "requests": r.cnt} for r in top_ips],
        "status_codes": {"labels": [str(r.status) for r in status_dist], "data": [r.cnt for r in status_dist]},
    })


def _parse_time_range():
    """Получить since/until из query params."""
    preset = request.args.get("range", "24h")
    now = datetime.datetime.utcnow()

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


@app.route("/api/stats/full")
@login_required
def api_stats_full():
    """Полная статистика с фильтрацией по времени."""
    since, until = _parse_time_range()
    domain_filter = request.args.get("domain")

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
    if delta.total_seconds() <= 86400:
        fmt = "%Y-%m-%d %H:00"
    elif delta.total_seconds() <= 604800:
        fmt = "%Y-%m-%d %H:00"
    else:
        fmt = "%Y-%m-%d"

    tl_q = db.session.query(
        func.strftime(fmt, AccessLog.timestamp).label("bucket"),
        func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until)
    if domain_filter:
        tl_q = tl_q.filter(AccessLog.server_name == domain_filter)
    timeline = tl_q.group_by("bucket").order_by("bucket").all()

    # 3. Success vs errors timeline
    tl_ok = db.session.query(
        func.strftime(fmt, AccessLog.timestamp).label("bucket"),
        func.count().label("cnt"),
    ).filter(AccessLog.timestamp >= since, AccessLog.timestamp <= until, AccessLog.status < 400)
    if domain_filter:
        tl_ok = tl_ok.filter(AccessLog.server_name == domain_filter)
    tl_ok = tl_ok.group_by("bucket").order_by("bucket").all()

    tl_err = db.session.query(
        func.strftime(fmt, AccessLog.timestamp).label("bucket"),
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

    return jsonify({
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
    })


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
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash("Неверное имя пользователя или пароль", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user.id
        session["username"] = user.username
        log_action("login", details="User logged in")

        next_url = request.args.get("next") or url_for("dashboard")
        return redirect(next_url)

    return render_template("login.html")


@app.route("/logout")
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


@app.route("/domains")
@login_required
def index():
    group = request.args.get("group")
    query = DomainRoute.query

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


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        target_host = request.form.get("target_host", "").strip()
        target_port = request.form.get("target_port", "").strip()
        group_name = request.form.get("group_name", "").strip() or None

        listen_port = request.form.get("listen_port", "80").strip()
        listen_port_ssl = request.form.get("listen_port_ssl", "443").strip()

        enable_https = request.form.get("enable_https") == "on"
        backend_https = request.form.get("backend_https") == "on"
        enable_websocket = request.form.get("enable_websocket") == "on"

        ssl_cert_path = request.form.get("ssl_cert_path", "").strip() or None
        ssl_key_path = request.form.get("ssl_key_path", "").strip() or None

        if not domain or not target_host or not target_port:
            flash("Заполните домен, IP и порт", "danger")
            return redirect(url_for("add"))

        try:
            port_int = int(target_port)
            lp = int(listen_port) if listen_port else 80
            lps = int(listen_port_ssl) if listen_port_ssl else 443
        except ValueError:
            flash("Порты должны быть числами", "danger")
            return redirect(url_for("add"))

        route = DomainRoute(
            domain=domain,
            target_host=target_host,
            target_port=port_int,
            listen_port=lp,
            listen_port_ssl=lps,
            group_name=group_name,
            enable_https=enable_https,
            backend_https=backend_https,
            enable_websocket=enable_websocket,
            ssl_cert_path=ssl_cert_path if enable_https else None,
            ssl_key_path=ssl_key_path if enable_https else None,
        )

        db.session.add(route)
        db.session.commit()

        try:
            apply_all_configs()
            log_action(
                "create_route",
                domain=domain,
                details=f"target={target_host}:{port_int}, listen={lp}/{lps}, https={enable_https}, backend_https={backend_https}, ws={enable_websocket}",
            )
            flash("Домен добавлен, nginx обновлён", "success")
        except subprocess.CalledProcessError as e:
            flash(f"Ошибка nginx: {e}", "danger")

        return redirect(url_for("index"))

    return render_template("form.html", route=None)


@app.route("/edit/<int:route_id>", methods=["GET", "POST"])
@login_required
def edit(route_id):
    route = DomainRoute.query.get_or_404(route_id)

    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        target_host = request.form.get("target_host", "").strip()
        target_port = request.form.get("target_port", "").strip()
        group_name = request.form.get("group_name", "").strip() or None

        listen_port = request.form.get("listen_port", "80").strip()
        listen_port_ssl = request.form.get("listen_port_ssl", "443").strip()

        enable_https = request.form.get("enable_https") == "on"
        backend_https = request.form.get("backend_https") == "on"
        enable_websocket = request.form.get("enable_websocket") == "on"

        ssl_cert_path = request.form.get("ssl_cert_path", "").strip() or None
        ssl_key_path = request.form.get("ssl_key_path", "").strip() or None

        if not domain or not target_host or not target_port:
            flash("Заполните домен, IP и порт", "danger")
            return redirect(url_for("edit", route_id=route.id))

        try:
            port_int = int(target_port)
            lp = int(listen_port) if listen_port else 80
            lps = int(listen_port_ssl) if listen_port_ssl else 443
        except ValueError:
            flash("Порты должны быть числами", "danger")
            return redirect(url_for("edit", route_id=route.id))

        route.domain = domain
        route.target_host = target_host
        route.target_port = port_int
        route.listen_port = lp
        route.listen_port_ssl = lps
        route.group_name = group_name
        route.enable_https = enable_https
        route.backend_https = backend_https
        route.enable_websocket = enable_websocket
        route.ssl_cert_path = ssl_cert_path if enable_https else None
        route.ssl_key_path = ssl_key_path if enable_https else None

        db.session.commit()

        try:
            apply_all_configs()
            log_action(
                "update_route",
                domain=domain,
                details=f"target={target_host}:{port_int}, listen={lp}/{lps}, https={enable_https}, backend_https={backend_https}, ws={enable_websocket}",
            )
            flash("Маршрут обновлён, nginx обновлён", "success")
        except subprocess.CalledProcessError as e:
            flash(f"Ошибка nginx: {e}", "danger")

        return redirect(url_for("index"))

    return render_template("form.html", route=route)


@app.route("/delete/<int:route_id>", methods=["POST"])
@login_required
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
def letsencrypt(route_id):
    route = DomainRoute.query.get_or_404(route_id)
    domain = route.domain

    if DEV_MODE:
        route.enable_https = True
        route.ssl_cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        route.ssl_key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
        db.session.commit()
        generate_nginx_config()
        generate_stream_config()
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
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        flash(f"Ошибка certbot: {e}", "danger")
        log_action("letsencrypt_failed", domain=domain, details=str(e))
        return redirect(url_for("index"))

    cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"

    route.enable_https = True
    route.ssl_cert_path = cert_path
    route.ssl_key_path = key_path
    db.session.commit()

    try:
        apply_all_configs()
        flash("Сертификат выпущен/обновлён, HTTPS активирован", "success")
        log_action("letsencrypt_success", domain=domain, details=cert_path)
    except subprocess.CalledProcessError as e:
        flash(f"Ошибка nginx после certbot: {e}", "danger")

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


@app.route("/streams/add", methods=["GET", "POST"])
@login_required
def streams_add():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        listen_port = request.form.get("listen_port", "").strip()
        target_host = request.form.get("target_host", "").strip()
        target_port = request.form.get("target_port", "").strip()
        protocol = request.form.get("protocol", "tcp").strip()
        service_type = request.form.get("service_type", "custom").strip()
        domain_hint = request.form.get("domain_hint", "").strip() or None
        group_name = request.form.get("group_name", "").strip() or None
        domain_route_id = request.form.get("domain_route_id", "").strip() or None

        if not name or not listen_port or not target_host or not target_port:
            flash("Заполните все обязательные поля", "danger")
            return redirect(url_for("streams_add"))

        if protocol not in ("tcp", "udp"):
            flash("Протокол должен быть tcp или udp", "danger")
            return redirect(url_for("streams_add"))

        try:
            listen_port_int = int(listen_port)
            target_port_int = int(target_port)
            domain_route_id = int(domain_route_id) if domain_route_id else None
        except ValueError:
            flash("Порты должны быть числами", "danger")
            return redirect(url_for("streams_add"))

        existing = StreamRoute.query.filter_by(listen_port=listen_port_int).first()
        if existing:
            flash(f"Порт {listen_port_int} уже используется маршрутом «{existing.name}»", "danger")
            return redirect(url_for("streams_add"))

        stream = StreamRoute(
            name=name,
            listen_port=listen_port_int,
            target_host=target_host,
            target_port=target_port_int,
            protocol=protocol,
            service_type=service_type,
            domain_hint=domain_hint,
            group_name=group_name,
            domain_route_id=domain_route_id,
        )

        db.session.add(stream)
        db.session.commit()

        try:
            apply_all_configs()
            log_action(
                "create_stream",
                domain=domain_hint,
                details=f"[{service_type}] {name}: :{listen_port_int}/{protocol} -> {target_host}:{target_port_int}",
            )
            flash("Stream-маршрут добавлен, nginx обновлён", "success")
        except subprocess.CalledProcessError as e:
            flash(f"Ошибка nginx: {e}", "danger")

        return redirect(url_for("streams_index"))

    domains = DomainRoute.query.order_by(DomainRoute.domain).all()
    return render_template("stream_form.html", stream=None, domains=domains, service_presets=SERVICE_PRESETS)


@app.route("/streams/edit/<int:stream_id>", methods=["GET", "POST"])
@login_required
def streams_edit(stream_id):
    stream = StreamRoute.query.get_or_404(stream_id)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        listen_port = request.form.get("listen_port", "").strip()
        target_host = request.form.get("target_host", "").strip()
        target_port = request.form.get("target_port", "").strip()
        protocol = request.form.get("protocol", "tcp").strip()
        service_type = request.form.get("service_type", "custom").strip()
        domain_hint = request.form.get("domain_hint", "").strip() or None
        group_name = request.form.get("group_name", "").strip() or None
        domain_route_id = request.form.get("domain_route_id", "").strip() or None

        if not name or not listen_port or not target_host or not target_port:
            flash("Заполните все обязательные поля", "danger")
            return redirect(url_for("streams_edit", stream_id=stream.id))

        if protocol not in ("tcp", "udp"):
            flash("Протокол должен быть tcp или udp", "danger")
            return redirect(url_for("streams_edit", stream_id=stream.id))

        try:
            listen_port_int = int(listen_port)
            target_port_int = int(target_port)
            domain_route_id = int(domain_route_id) if domain_route_id else None
        except ValueError:
            flash("Порты должны быть числами", "danger")
            return redirect(url_for("streams_edit", stream_id=stream.id))

        existing = StreamRoute.query.filter(
            StreamRoute.listen_port == listen_port_int,
            StreamRoute.id != stream.id
        ).first()
        if existing:
            flash(f"Порт {listen_port_int} уже используется маршрутом «{existing.name}»", "danger")
            return redirect(url_for("streams_edit", stream_id=stream.id))

        stream.name = name
        stream.listen_port = listen_port_int
        stream.target_host = target_host
        stream.target_port = target_port_int
        stream.protocol = protocol
        stream.service_type = service_type
        stream.domain_hint = domain_hint
        stream.group_name = group_name
        stream.domain_route_id = domain_route_id

        db.session.commit()

        try:
            apply_all_configs()
            log_action(
                "update_stream",
                domain=domain_hint,
                details=f"[{service_type}] {name}: :{listen_port_int}/{protocol} -> {target_host}:{target_port_int}",
            )
            flash("Stream-маршрут обновлён, nginx обновлён", "success")
        except subprocess.CalledProcessError as e:
            flash(f"Ошибка nginx: {e}", "danger")

        return redirect(url_for("streams_index"))

    domains = DomainRoute.query.order_by(DomainRoute.domain).all()
    return render_template("stream_form.html", stream=stream, domains=domains, service_presets=SERVICE_PRESETS)


@app.route("/streams/delete/<int:stream_id>", methods=["POST"])
@login_required
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


with app.app_context():
    ensure_schema()
    start_log_reader()

if __name__ == "__main__":
    if DEV_MODE:
        print("=" * 50)
        print("  🚧 DEV MODE — nginx/certbot пропускаются")
        print(f"  📄 HTTP config:   {NGINX_CONF_PATH}")
        print(f"  📄 Stream config: {STREAM_CONF_PATH}")
        print("  📊 Dashboard:     http://127.0.0.1:5000")
        print("=" * 50)
    app.run(host="127.0.0.1", port=5000, debug=True)
