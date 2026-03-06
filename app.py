import os
import subprocess
import datetime
from functools import wraps

import click
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
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

    def __repr__(self):
        return f"<StreamRoute {self.name} :{self.listen_port}/{self.protocol} -> {self.target_host}:{self.target_port}>"


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
#  Auth routes
# ──────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

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

        next_url = request.args.get("next") or url_for("index")
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

if __name__ == "__main__":
    if DEV_MODE:
        print("=" * 50)
        print("  🚧 DEV MODE — nginx/certbot пропускаются")
        print(f"  📄 HTTP config:   {NGINX_CONF_PATH}")
        print(f"  📄 Stream config: {STREAM_CONF_PATH}")
        print("=" * 50)
    app.run(host="127.0.0.1", port=5000, debug=DEV_MODE)
