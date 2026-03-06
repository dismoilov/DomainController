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

NGINX_CONF_PATH = "/etc/nginx/conf.d/domain-routes.conf"
ACME_WEBROOT = "/var/www/certbot"

db = SQLAlchemy(app)


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
    domain = db.Column(db.String(255), unique=True, nullable=False)
    target_host = db.Column(db.String(255), nullable=False)
    target_port = db.Column(db.Integer, nullable=False)

    # HTTPS на фронте (домене)
    enable_https = db.Column(db.Boolean, default=False)
    ssl_cert_path = db.Column(db.String(512), nullable=True)
    ssl_key_path = db.Column(db.String(512), nullable=True)

    # Группа/тег
    group_name = db.Column(db.String(128), nullable=True)

    # HTTPS на backend
    backend_https = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<DomainRoute {self.domain} -> {self.target_host}:{self.target_port}>"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    username = db.Column(db.String(64), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)


def ensure_schema():
    """Создать таблицы и добавить недостающие колонки при апгрейде старых версий."""
    db.create_all()

    inspector = inspect(db.engine)
    tables = inspector.get_table_names()

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

        if migrations:
            with db.engine.begin() as conn:
                for sql in migrations:
                    conn.execute(text(sql))


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

    if route.backend_https:
        directives.extend([
            "proxy_http_version 1.1;",
            "proxy_ssl_verify off;",
            "proxy_set_header Upgrade $http_upgrade;",
            'proxy_set_header Connection "upgrade";',
        ])

    return "\n".join(f"        {line}" for line in directives)


def generate_nginx_config():
    """Сгенерировать domain-routes.conf и перезагрузить nginx."""
    ensure_acme_webroot()
    routes = DomainRoute.query.order_by(DomainRoute.domain).all()
    blocks: list[str] = []

    for route in routes:
        server_names = route.domain.strip()
        proxy_block = build_proxy_directives(route)
        https_active = frontend_https_ready(route)

        # HTTP server
        if https_active:
            http_block = f"""
# {route.id}: {server_names} -> {'https' if route.backend_https else 'http'}://{route.target_host}:{route.target_port}
server {{
    listen 80;
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
# {route.id}: {server_names} -> {'https' if route.backend_https else 'http'}://{route.target_host}:{route.target_port}
server {{
    listen 80;
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
    listen 443 ssl http2;
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

    subprocess.run(["nginx", "-t"], check=True)
    subprocess.run(["systemctl", "reload", "nginx"], check=True)


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

    return render_template("list.html", routes=routes, groups=groups, selected_group=group)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        target_host = request.form.get("target_host", "").strip()
        target_port = request.form.get("target_port", "").strip()
        group_name = request.form.get("group_name", "").strip() or None

        enable_https = request.form.get("enable_https") == "on"
        backend_https = request.form.get("backend_https") == "on"

        ssl_cert_path = request.form.get("ssl_cert_path", "").strip() or None
        ssl_key_path = request.form.get("ssl_key_path", "").strip() or None

        if not domain or not target_host or not target_port:
            flash("Заполните домен, IP и порт", "danger")
            return redirect(url_for("add"))

        try:
            port_int = int(target_port)
        except ValueError:
            flash("Порт должен быть числом", "danger")
            return redirect(url_for("add"))

        existing = DomainRoute.query.filter_by(domain=domain).first()
        if existing:
            flash("Такой домен уже существует", "danger")
            return redirect(url_for("add"))

        route = DomainRoute(
            domain=domain,
            target_host=target_host,
            target_port=port_int,
            group_name=group_name,
            enable_https=enable_https,
            backend_https=backend_https,
            ssl_cert_path=ssl_cert_path if enable_https else None,
            ssl_key_path=ssl_key_path if enable_https else None,
        )

        db.session.add(route)
        db.session.commit()

        try:
            generate_nginx_config()
            log_action(
                "create_route",
                domain=domain,
                details=f"target={target_host}:{port_int}, frontend_https={enable_https}, backend_https={backend_https}",
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

        enable_https = request.form.get("enable_https") == "on"
        backend_https = request.form.get("backend_https") == "on"

        ssl_cert_path = request.form.get("ssl_cert_path", "").strip() or None
        ssl_key_path = request.form.get("ssl_key_path", "").strip() or None

        if not domain or not target_host or not target_port:
            flash("Заполните домен, IP и порт", "danger")
            return redirect(url_for("edit", route_id=route.id))

        try:
            port_int = int(target_port)
        except ValueError:
            flash("Порт должен быть числом", "danger")
            return redirect(url_for("edit", route_id=route.id))

        existing = DomainRoute.query.filter(
            DomainRoute.domain == domain,
            DomainRoute.id != route.id
        ).first()
        if existing:
            flash("Другой маршрут уже использует этот домен", "danger")
            return redirect(url_for("edit", route_id=route.id))

        route.domain = domain
        route.target_host = target_host
        route.target_port = port_int
        route.group_name = group_name
        route.enable_https = enable_https
        route.backend_https = backend_https
        route.ssl_cert_path = ssl_cert_path if enable_https else None
        route.ssl_key_path = ssl_key_path if enable_https else None

        db.session.commit()

        try:
            generate_nginx_config()
            log_action(
                "update_route",
                domain=domain,
                details=f"target={target_host}:{port_int}, frontend_https={enable_https}, backend_https={backend_https}",
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

    db.session.delete(route)
    db.session.commit()

    try:
        generate_nginx_config()
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
        generate_nginx_config()
        flash("Сертификат выпущен/обновлён, HTTPS активирован", "success")
        log_action("letsencrypt_success", domain=domain, details=cert_path)
    except subprocess.CalledProcessError as e:
        flash(f"Ошибка nginx после certbot: {e}", "danger")

    return redirect(url_for("index"))


@app.route("/logs")
@login_required
def logs():
    logs_q = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(300).all()
    return render_template("logs.html", logs=logs_q)


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
    app.run(host="127.0.0.1", port=5000)
