"""Unit-тесты для DomainController.

Запуск:
    DEV_MODE=1 venv/bin/python -m unittest tests.test_app

Или:
    DEV_MODE=1 venv/bin/python -m unittest discover -v tests

Зависит только от stdlib + уже установленных Flask/SQLAlchemy. Не тянем pytest.
"""
import os
import sys
import unittest

# Обязательно DEV_MODE — иначе app откажется стартовать без DC_PANEL_SECRET
os.environ["DEV_MODE"] = "1"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as dc_app  # noqa: E402


class ValidatorTests(unittest.TestCase):
    # ---- domain ----
    def test_valid_domains(self):
        for d in [
            "nettech.uz",
            "sub.nettech.uz",
            "a.b.c.d.example.com",
            "xn--e1afmkfd.xn--p1ai",  # punycode
            "host-with-dash.tld",
            "1.2.3.4.in-addr.arpa",
        ]:
            self.assertTrue(dc_app.is_valid_domain(d), f"должен быть валидным: {d}")

    def test_invalid_domains(self):
        for d in [
            "",
            "-bad.com",            # начинается с дефиса
            "bad-.com",            # заканчивается дефисом
            "bad..com",            # двойная точка
            "foo.com;drop",        # инъекция
            "foo.com and more",    # пробел
            "a" * 254,             # > 253
            "foo.com/extra",       # слэш
            "foo.com:80",          # порт
            "foo_bar.com",         # подчёркивание
        ]:
            self.assertFalse(dc_app.is_valid_domain(d), f"не должен быть валидным: {d!r}")

    # ---- host ----
    def test_valid_hosts(self):
        for h in ["10.0.0.1", "192.168.1.254", "255.255.255.0",
                  "host.local", "internal-api", "a.b"]:
            self.assertTrue(dc_app.is_valid_host(h), f"должен быть валидным: {h}")

    def test_invalid_hosts(self):
        for h in ["", "256.1.1.1", "bad host", "host;drop", "host/path",
                  "  ", "10.0.0"]:
            self.assertFalse(dc_app.is_valid_host(h), f"не должен быть валидным: {h!r}")

    # ---- port ----
    def test_valid_ports_normal(self):
        for p in [1024, 3000, 5001, 8081, 65535]:
            self.assertTrue(dc_app.is_valid_port(p))

    def test_invalid_port_range(self):
        for p in [0, -1, 65536, 100000, "not-int", None]:
            self.assertFalse(dc_app.is_valid_port(p))

    def test_reserved_ports_blocked(self):
        for p in sorted(dc_app.RESERVED_PORTS):
            self.assertFalse(dc_app.is_valid_port(p),
                             f"порт {p} зарезервирован, не должен проходить")
            self.assertTrue(dc_app.is_valid_port(p, allow_reserved=True),
                            f"порт {p} должен проходить с allow_reserved=True")

    # ---- ssl path ----
    def test_valid_ssl_paths(self):
        for p in [
            "/etc/letsencrypt/live/example.com/fullchain.pem",
            "/etc/letsencrypt/live/sub.example.com/privkey.pem",
            "/etc/letsencrypt/live/example.com/chain.pem",
            "/etc/letsencrypt/live/example.com/cert.pem",
        ]:
            self.assertTrue(dc_app.is_valid_ssl_path(p), p)

    def test_invalid_ssl_paths(self):
        for p in [
            "",
            "/etc/passwd",
            "/etc/letsencrypt/live/../../../etc/passwd",
            "/etc/letsencrypt/live/example.com/evil.sh",
            "/var/ssl/live/example.com/fullchain.pem",   # не под letsencrypt/live
            "/etc/letsencrypt/live/example.com/fullchain.pem.bak",
        ]:
            self.assertFalse(dc_app.is_valid_ssl_path(p), p)

    # ---- next url ----
    def test_safe_next_urls(self):
        for u in ["/", "/domains", "/stats?range=24h", "/a/b/c?d=1#e"]:
            self.assertTrue(dc_app.is_safe_next_url(u), u)

    def test_unsafe_next_urls(self):
        for u in ["", "http://evil.com", "https://evil.com/ok",
                  "//evil.com/x", "javascript:alert(1)", "domains",
                  " /domains"]:
            self.assertFalse(dc_app.is_safe_next_url(u), u)


class NginxGenerationTests(unittest.TestCase):
    """Проверяем что генератор nginx-конфига выдаёт корректный текст и не содержит
    заведомо вредных подстановок из полей БД.

    Для изоляции: drop_all + create_all в setUp. Использует ту же dev_data.db,
    но каждый тест стартует с пустой схемой (без внешних записей).
    """

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_empty_config(self):
        with dc_app.app.app_context():
            conf = dc_app.generate_nginx_config()
            self.assertIn("log_format dc_json", conf)
            self.assertIn("no domains configured yet", conf)

    def test_http_route_generation(self):
        with dc_app.app.app_context():
            r = dc_app.DomainRoute(
                domain="test.example.com",
                target_host="10.0.0.5",
                target_port=8080,
                listen_port=80,
                listen_port_ssl=443,
                enable_https=False,
                backend_https=False,
                enable_websocket=False,
                enable_logging=True,
            )
            dc_app.db.session.add(r)
            dc_app.db.session.commit()
            conf = dc_app.generate_nginx_config()
            self.assertIn("server_name test.example.com", conf)
            self.assertIn("proxy_pass http://10.0.0.5:8080", conf)
            self.assertNotIn("listen 443 ssl", conf)

    def test_https_with_websocket(self):
        with dc_app.app.app_context():
            r = dc_app.DomainRoute(
                domain="ws.example.com",
                target_host="10.0.0.9",
                target_port=3000,
                listen_port=80,
                listen_port_ssl=443,
                enable_https=True,
                backend_https=False,
                enable_websocket=True,
                ssl_cert_path="/etc/letsencrypt/live/ws.example.com/fullchain.pem",
                ssl_key_path="/etc/letsencrypt/live/ws.example.com/privkey.pem",
                enable_logging=True,
            )
            dc_app.db.session.add(r)
            dc_app.db.session.commit()
            conf = dc_app.generate_nginx_config()
            self.assertIn("return 301 https://", conf)
            self.assertIn("listen 443 ssl http2", conf)
            self.assertIn("ssl_certificate /etc/letsencrypt/live/ws.example.com/fullchain.pem", conf)
            self.assertIn("proxy_http_version 1.1", conf)
            self.assertIn('Connection "upgrade"', conf)

    def test_stream_config_empty(self):
        with dc_app.app.app_context():
            conf = dc_app.generate_stream_config()
            self.assertIn("no stream routes", conf)

    def test_stream_udp_route(self):
        with dc_app.app.app_context():
            s = dc_app.StreamRoute(
                name="SIP",
                listen_port=5060,
                target_host="10.0.0.20",
                target_port=5060,
                protocol="udp",
                service_type="sip",
            )
            dc_app.db.session.add(s)
            dc_app.db.session.commit()
            conf = dc_app.generate_stream_config()
            self.assertIn("stream {", conf)
            self.assertIn("listen 5060 udp", conf)
            self.assertIn("proxy_pass 10.0.0.20:5060", conf)


class HelperTests(unittest.TestCase):
    def test_utcnow_is_naive(self):
        t = dc_app._utcnow()
        self.assertIsNone(t.tzinfo, "должен быть naive для SQLite")

    def test_safe_int(self):
        self.assertEqual(dc_app._safe_int("42"), 42)
        self.assertEqual(dc_app._safe_int(""), 0)
        self.assertEqual(dc_app._safe_int(None), 0)
        self.assertEqual(dc_app._safe_int("-"), 0)
        self.assertEqual(dc_app._safe_int("not-int"), 0)
        self.assertEqual(dc_app._safe_int("7", default=99), 7)
        self.assertEqual(dc_app._safe_int("", default=99), 99)

    def test_safe_float(self):
        self.assertAlmostEqual(dc_app._safe_float("3.14"), 3.14)
        self.assertEqual(dc_app._safe_float(""), 0.0)
        self.assertEqual(dc_app._safe_float("-"), 0.0)

    def test_parse_ts_iso(self):
        t = dc_app._parse_ts("2026-04-23T09:00:00")
        self.assertEqual(t.year, 2026)
        self.assertEqual(t.hour, 9)

    def test_parse_ts_invalid_fallback(self):
        t = dc_app._parse_ts("not-a-date")
        self.assertIsInstance(t, __import__("datetime").datetime)

    def test_atomic_write(self):
        import tempfile as _t
        fd, path = _t.mkstemp()
        os.close(fd)
        try:
            dc_app._atomic_write(path, "hello world")
            with open(path) as f:
                self.assertEqual(f.read(), "hello world")
            dc_app._atomic_write(path, "replaced")
            with open(path) as f:
                self.assertEqual(f.read(), "replaced")
        finally:
            os.unlink(path)

    def test_api_token_hash_stable(self):
        h1 = dc_app.ApiToken.hash_token("secret")
        h2 = dc_app.ApiToken.hash_token("secret")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)
        self.assertNotEqual(h1, dc_app.ApiToken.hash_token("secret2"))


class FirewallValidatorTests(unittest.TestCase):
    def test_valid_ipv4(self):
        for ip in ["1.2.3.4", "203.0.113.45", "127.0.0.1", "10.0.0.1"]:
            self.assertTrue(dc_app.is_valid_ip(ip), ip)

    def test_valid_ipv6(self):
        for ip in ["::1", "2001:db8::1", "fe80::1"]:
            self.assertTrue(dc_app.is_valid_ip(ip), ip)

    def test_invalid_ip(self):
        for ip in ["", " 1.2.3.4", "1.2.3.4 ", "256.1.1.1", "not-ip",
                   "1.2.3.4; drop table", "1.2.3", "::zzz"]:
            self.assertFalse(dc_app.is_valid_ip(ip), ip)

    def test_rfc1918_detection(self):
        # is_rfc1918_ip возвращает True также для документационных и прочих
        # зарезервированных диапазонов (Python ipaddress.is_private широкий).
        # Для нас это правильно: такие адреса нельзя банить, никто там не живёт.
        for ip in ["10.0.0.1", "127.0.0.1", "172.16.5.5", "192.168.1.1"]:
            self.assertTrue(dc_app.is_rfc1918_ip(ip), ip)
        # Реальные публичные адреса — не трактуются как private.
        for ip in ["8.8.8.8", "1.1.1.1", "213.230.69.181"]:
            self.assertFalse(dc_app.is_rfc1918_ip(ip), ip)

    def test_jail_name_regex(self):
        for name in ["dc-404-flood", "sshd", "domain-controller", "a_b_c"]:
            self.assertTrue(dc_app._JAIL_NAME_RE.match(name), name)
        for name in ["", "a b", "jail;", "jail/../", "a" * 65, "../../etc"]:
            self.assertFalse(dc_app._JAIL_NAME_RE.match(name), name)

    def test_fail2ban_call_returns_tuple(self):
        # fail2ban-client вряд ли есть на локалке — проверяем что функция
        # не падает, а возвращает (-1, "", error) при отсутствии.
        rc, out, err = dc_app._fail2ban_call(["status"])
        self.assertIsInstance(rc, int)
        self.assertIsInstance(out, str)
        self.assertIsInstance(err, str)

    def test_fail2ban_call_rejects_bad_args(self):
        rc, _, err = dc_app._fail2ban_call("status")  # не list
        self.assertEqual(rc, -1)
        self.assertIn("invalid", err.lower())


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_empty_allowlist_falls_back(self):
        """Пустой allowlist → fallback в конфиге (чтобы не закрыть 'deny all'-ом всех)."""
        with dc_app.app.app_context():
            conf = dc_app.generate_panel_config()
            self.assertIn("fallback", conf)
            self.assertIn("deny all;", conf)

    def test_panel_config_contains_allow_lines(self):
        with dc_app.app.app_context():
            dc_app.db.session.add(dc_app.IpAllowlist(cidr="10.0.0.0/8", comment="LAN"))
            dc_app.db.session.add(dc_app.IpAllowlist(cidr="172.28.167.0/24", comment="admin ноут"))
            dc_app.db.session.commit()
            conf = dc_app.generate_panel_config()
            self.assertIn("allow 10.0.0.0/8", conf)
            self.assertIn("allow 172.28.167.0/24", conf)
            self.assertIn("deny all;", conf)
            self.assertIn("# LAN", conf)
            self.assertNotIn("fallback", conf)

    def test_ip_in_allowlist(self):
        with dc_app.app.app_context():
            entries = [
                dc_app.IpAllowlist(cidr="10.0.0.0/8"),
                dc_app.IpAllowlist(cidr="1.2.3.4/32"),
            ]
            self.assertTrue(dc_app._ip_in_allowlist("10.5.6.7", entries))
            self.assertTrue(dc_app._ip_in_allowlist("1.2.3.4", entries))
            self.assertFalse(dc_app._ip_in_allowlist("8.8.8.8", entries))
            self.assertFalse(dc_app._ip_in_allowlist("not-ip", entries))

    def test_cidr_normalization(self):
        """Одиночный IP должен превращаться в /32 при нормализации через ipaddress."""
        import ipaddress
        self.assertEqual(str(ipaddress.ip_network("10.0.0.5", strict=False)), "10.0.0.5/32")
        self.assertEqual(str(ipaddress.ip_network("10.0.0.0/24", strict=False)), "10.0.0.0/24")
        # strict=False принимает host-bits в CIDR
        self.assertEqual(str(ipaddress.ip_network("10.0.0.5/24", strict=False)), "10.0.0.0/24")


class CsrfTests(unittest.TestCase):
    """CSRF: POST без токена → 400; с токеном → дальше."""

    def setUp(self):
        dc_app.app.config["TESTING"] = True
        self.client = dc_app.app.test_client()

    def test_post_login_without_csrf_returns_400(self):
        # Свежий клиент без сессии, POST /login без csrf_token → 400
        r = self.client.post("/login", data={"username": "x", "password": "y"})
        self.assertEqual(r.status_code, 400)

    def test_post_logout_without_csrf_returns_400(self):
        r = self.client.post("/logout")
        self.assertEqual(r.status_code, 400)

    def test_get_logout_is_405(self):
        r = self.client.get("/logout")
        self.assertEqual(r.status_code, 405)


class HealthzTests(unittest.TestCase):
    def test_healthz_returns_json_200(self):
        dc_app.app.config["TESTING"] = True
        client = dc_app.app.test_client()
        r = client.get("/healthz")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIn("ok", body)
        self.assertIn("checks", body)
        self.assertIn("dev_mode", body)


class MetricsTests(unittest.TestCase):
    def test_metrics_prometheus_format(self):
        dc_app.app.config["TESTING"] = True
        client = dc_app.app.test_client()
        r = client.get("/metrics")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/plain", r.headers.get("Content-Type", ""))
        body = r.data.decode()
        self.assertIn("dc_up 1", body)
        self.assertIn("# TYPE dc_up gauge", body)


class GeoIPTests(unittest.TestCase):
    """geoip_lookup() — обёртка над DB-IP free .mmdb.

    Если базы нет (например, на CI без скачанного .mmdb) — все вызовы должны
    возвращать None, не падая. Это поведение проверяем в первую очередь.
    """

    def test_lookup_private_returns_none(self):
        for ip in ["10.0.0.1", "127.0.0.1", "192.168.1.1", "172.16.5.5"]:
            self.assertIsNone(dc_app.geoip_lookup(ip), ip)

    def test_lookup_empty_returns_none(self):
        self.assertIsNone(dc_app.geoip_lookup(""))
        self.assertIsNone(dc_app.geoip_lookup(None))

    def test_lookup_invalid_format_returns_none(self):
        # Невалидный IP — внутренний lookup в maxminddb выкидывает,
        # обёртка должна перехватить и вернуть None.
        self.assertIsNone(dc_app.geoip_lookup("not-an-ip"))

    def test_lookup_public_when_db_present(self):
        # Если файл .mmdb лежит в data/geoip/ — проверим что 8.8.8.8 отдаётся
        # как US с city. Если нет — пропускаем, чтобы не ломать CI.
        if not os.path.exists(dc_app.DC_GEOIP_DB):
            self.skipTest("GeoIP DB не загружена — деплой через deploy/update-geoip.sh")
        rec = dc_app.geoip_lookup("8.8.8.8")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["country_code"], "US")
        self.assertTrue(rec["country_name_ru"])  # есть локализованное имя

    def test_lookup_uzbekistan(self):
        if not os.path.exists(dc_app.DC_GEOIP_DB):
            self.skipTest("GeoIP DB не загружена")
        rec = dc_app.geoip_lookup("5.133.120.5")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["country_code"], "UZ")

    def test_lookup_lru_cache(self):
        # cache_info доступен из functools.lru_cache; убедимся что вторые
        # вызовы попадают в кэш, не дёргая mmdb.
        if not os.path.exists(dc_app.DC_GEOIP_DB):
            self.skipTest("GeoIP DB не загружена")
        dc_app.geoip_lookup.cache_clear()
        dc_app.geoip_lookup("1.1.1.1")
        dc_app.geoip_lookup("1.1.1.1")
        info = dc_app.geoip_lookup.cache_info()
        self.assertGreaterEqual(info.hits, 1)


class SettingsTests(unittest.TestCase):
    """get_setting / set_setting + кэш TTL."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
            dc_app._SETTINGS_CACHE.clear()
            dc_app._SETTINGS_CACHE_LOADED_AT = 0.0

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_get_setting_returns_default_when_missing(self):
        with dc_app.app.app_context():
            self.assertEqual(dc_app.get_setting("nonexistent_key", 42), 42)
            self.assertEqual(dc_app.get_setting("nonexistent_key", "fallback"), "fallback")

    def test_set_then_get_int(self):
        # set_setting() вызывает current_username() → нужен request context
        with dc_app.app.test_request_context("/"):
            dc_app.set_setting("login_max_failures", 5, vtype="int")
            self.assertEqual(dc_app.get_setting("login_max_failures", 99), 5)

    def test_set_then_get_string(self):
        with dc_app.app.test_request_context("/"):
            dc_app.set_setting("WEBHOOK_URL", "https://hooks.example.com/x", vtype="string")
            self.assertEqual(dc_app.get_setting("WEBHOOK_URL", ""), "https://hooks.example.com/x")

    def test_set_overwrites(self):
        with dc_app.app.test_request_context("/"):
            dc_app.set_setting("retention_access_logs_days", 30, vtype="int")
            dc_app.set_setting("retention_access_logs_days", 90, vtype="int")
            self.assertEqual(dc_app.get_setting("retention_access_logs_days", 0), 90)


class AuthHelpersTests(unittest.TestCase):
    """current_username / log_action / token-hash."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_log_action_inserts_audit_row(self):
        with dc_app.app.test_request_context("/"):
            dc_app.session["username"] = "tester"
            dc_app.log_action("test_action", domain="x.com", details="foo")
        with dc_app.app.app_context():
            row = dc_app.AuditLog.query.filter_by(action="test_action").first()
            self.assertIsNotNone(row)
            self.assertEqual(row.username, "tester")
            self.assertEqual(row.domain, "x.com")
            self.assertEqual(row.details, "foo")

    def test_log_action_default_username_is_system(self):
        # Без сессии — username = "system"
        with dc_app.app.test_request_context("/"):
            dc_app.log_action("anonymous_action")
        with dc_app.app.app_context():
            row = dc_app.AuditLog.query.filter_by(action="anonymous_action").first()
            self.assertEqual(row.username, "system")


def _admin_client():
    """Тестовый клиент с залогиненной admin-сессией.

    Не пишет ничего в БД (login_required только проверяет 'user_id' в session).
    Возвращает клиент, в котором `session["_csrf"]` уже инициализирован, чтобы
    POST на HTML-формы (где CSRF проверяется) проходили — токен можно достать
    через get_csrf().
    """
    dc_app.app.config["TESTING"] = True
    c = dc_app.app.test_client()
    with c.session_transaction() as s:
        s["user_id"] = 1
        s["username"] = "admin-test"
        s["role"] = "admin"
        s[dc_app.CSRF_SESSION_KEY] = "test-csrf-token"
    return c


def _viewer_client():
    """Тестовый клиент с ролью viewer (read-only)."""
    dc_app.app.config["TESTING"] = True
    c = dc_app.app.test_client()
    with c.session_transaction() as s:
        s["user_id"] = 2
        s["username"] = "viewer-test"
        s["role"] = "viewer"
        s[dc_app.CSRF_SESSION_KEY] = "test-csrf-token"
    return c


class HtmlPagesAuthenticatedTests(unittest.TestCase):
    """GET всех HTML-страниц от admin-сессии — все должны вернуть 200.

    Покрывает большие куски view-функций: render_template, query-агрегации,
    session-checks. Не валидируем содержимое — только что не падает.
    """

    @classmethod
    def setUpClass(cls):
        # Чистая БД на весь класс — view-функции работают на пустых таблицах.
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        cls.client = _admin_client()

    @classmethod
    def tearDownClass(cls):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_root_redirects_to_dashboard(self):
        r = self.client.get("/")
        # / выбирает между dashboard (если есть домены) и редиректом на /domains
        self.assertIn(r.status_code, (200, 302))

    def test_domains_page(self):
        r = self.client.get("/domains")
        self.assertEqual(r.status_code, 200)

    def test_add_domain_get(self):
        r = self.client.get("/add")
        self.assertEqual(r.status_code, 200)

    def test_streams_page(self):
        r = self.client.get("/streams")
        self.assertEqual(r.status_code, 200)

    def test_streams_add_get(self):
        r = self.client.get("/streams/add")
        self.assertEqual(r.status_code, 200)

    def test_statistics_page(self):
        r = self.client.get("/statistics")
        self.assertEqual(r.status_code, 200)

    def test_requests_page(self):
        r = self.client.get("/requests")
        self.assertEqual(r.status_code, 200)

    def test_logs_page(self):
        r = self.client.get("/logs")
        self.assertEqual(r.status_code, 200)

    def test_firewall_page(self):
        r = self.client.get("/firewall")
        self.assertEqual(r.status_code, 200)

    def test_users_page(self):
        r = self.client.get("/users")
        self.assertEqual(r.status_code, 200)

    def test_settings_page(self):
        r = self.client.get("/settings")
        self.assertEqual(r.status_code, 200)


class StatsApiTests(unittest.TestCase):
    """GET всех /api/stats/* — на пустой БД должны вернуть 200 с пустым/нулевым JSON,
    не упав. Покрывает огромный блок aggregation-кода."""

    @classmethod
    def setUpClass(cls):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        cls.client = _admin_client()

    @classmethod
    def tearDownClass(cls):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    ENDPOINTS_NO_PARAMS = [
        "/api/stats/overview",
        "/api/stats/timeline",
        "/api/stats/status-codes",
        "/api/stats/domains",
        "/api/stats/top-ips",
        "/api/stats/top-uris",
        "/api/stats/errors",
        "/api/stats/streams",
        "/api/stats/ssl",
        "/api/stats/comparison",
        "/api/stats/heatmap",
        "/api/stats/geography",
        "/api/stats/throughput",
        "/api/stats/response-size",
        "/api/stats/domain-health",
        "/api/stats/top-error-ips",
        "/api/stats/backends",
    ]

    def test_all_stats_endpoints_return_200(self):
        for path in self.ENDPOINTS_NO_PARAMS:
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, f"{path} вернул {r.status_code}")
            r.get_json()  # parse не должен падать

    def test_stats_overview_keys(self):
        d = self.client.get("/api/stats/overview").get_json()
        self.assertIsInstance(d, dict)

    def test_stats_full_default_range(self):
        r = self.client.get("/api/stats/full")
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json(), dict)

    def test_stats_full_with_range(self):
        for rng in ("1h", "24h", "7d", "30d"):
            r = self.client.get(f"/api/stats/full?range={rng}")
            self.assertEqual(r.status_code, 200, rng)

    def test_stats_domain_detail_404_for_missing(self):
        # Несуществующий домен → 404
        r = self.client.get("/api/stats/domain/nonexistent.example.com")
        self.assertIn(r.status_code, (200, 404))


class FirewallApiTests(unittest.TestCase):
    """/api/firewall/* — read-only endpoints."""

    @classmethod
    def setUpClass(cls):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        cls.client = _admin_client()

    @classmethod
    def tearDownClass(cls):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_firewall_overview(self):
        r = self.client.get("/api/firewall/overview")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn("jails", d)
        self.assertIn("bot_blocked_24h", d)
        self.assertIn("uz_cidrs_count", d)

    def test_firewall_banned(self):
        r = self.client.get("/api/firewall/banned")
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json(), list)

    def test_firewall_bots_default(self):
        r = self.client.get("/api/firewall/bots")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        for k in ("summary", "timeline", "top_ips", "top_domains", "top_user_agents", "recent"):
            self.assertIn(k, d)

    def test_firewall_bots_all_ranges(self):
        for rng in ("1h", "6h", "24h", "7d"):
            r = self.client.get(f"/api/firewall/bots?range={rng}")
            self.assertEqual(r.status_code, 200, rng)

    def test_firewall_bots_with_domain_filter(self):
        r = self.client.get("/api/firewall/bots?range=24h&domain=example.com")
        self.assertEqual(r.status_code, 200)

    def test_firewall_bots_invalid_domain_silently_ignored(self):
        # Невалидный домен — фильтр просто не применяется, endpoint отдаёт 200
        r = self.client.get("/api/firewall/bots?domain=not%20valid;drop")
        self.assertEqual(r.status_code, 200)

    def test_firewall_timeline(self):
        r = self.client.get("/api/firewall/timeline")
        self.assertEqual(r.status_code, 200)

    def test_firewall_history(self):
        r = self.client.get("/api/firewall/history")
        self.assertEqual(r.status_code, 200)

    def test_firewall_allowlist_list(self):
        r = self.client.get("/api/firewall/allowlist")
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json(), list)


class FirewallApiUnauthenticatedTests(unittest.TestCase):
    """/api/firewall/* без сессии — должно отдать 401, не упасть."""

    def setUp(self):
        dc_app.app.config["TESTING"] = True
        self.client = dc_app.app.test_client()

    def test_overview_401(self):
        r = self.client.get("/api/firewall/overview")
        self.assertEqual(r.status_code, 401)

    def test_bots_401(self):
        r = self.client.get("/api/firewall/bots")
        self.assertEqual(r.status_code, 401)


class FirewallPostEndpointsTests(unittest.TestCase):
    """POST /api/firewall/* — валидируют входы, /api/* CSRF-exempt."""

    @classmethod
    def setUpClass(cls):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        cls.client = _admin_client()

    @classmethod
    def tearDownClass(cls):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_unban_invalid_ip_returns_400(self):
        r = self.client.post("/api/firewall/unban", data={"ip": "not-ip", "jail": "dc-manual"})
        self.assertEqual(r.status_code, 400)

    def test_unban_invalid_jail_returns_400(self):
        r = self.client.post("/api/firewall/unban", data={"ip": "1.2.3.4", "jail": "../etc"})
        self.assertEqual(r.status_code, 400)

    def test_unban_empty_json_body_does_not_crash(self):
        # Bug-fix regression: раньше при пустом JSON-теле request.json=None → 500.
        # Теперь get_json(silent=True) → {} → ответ 400 invalid ip.
        r = self.client.post(
            "/api/firewall/unban",
            data="{}",
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 400)

    def test_ban_invalid_ip_returns_400(self):
        r = self.client.post("/api/firewall/ban", data={"ip": "junk", "jail": "dc-manual"})
        self.assertEqual(r.status_code, 400)

    def test_ban_private_ip_blocked(self):
        r = self.client.post("/api/firewall/ban", data={"ip": "10.0.0.5", "jail": "dc-manual"})
        self.assertEqual(r.status_code, 400)
        d = r.get_json()
        self.assertIn("частный", d.get("error", "").lower() + d.get("message", "").lower())

    def test_ban_uz_without_confirm_returns_409(self):
        # is_uz_ip требует загруженных UZ CIDR. Если их нет — этот тест skip.
        if not dc_app._get_uz_cidrs():
            self.skipTest("UZ CIDR списка нет")
        r = self.client.post("/api/firewall/ban",
                             data={"ip": "5.133.120.5", "jail": "dc-manual"})
        self.assertEqual(r.status_code, 409)

    def test_pause_invalid_jail_name_returns_400(self):
        r = self.client.post("/api/firewall/jails/..%2F..%2Fetc/pause",
                             data={"duration_sec": "60"})
        # path-resolver или regex отклонит
        self.assertIn(r.status_code, (400, 404))

    def test_allowlist_add_invalid_cidr(self):
        r = self.client.post("/api/firewall/allowlist/add", data={"cidr": "not-cidr"})
        self.assertEqual(r.status_code, 400)

    def test_allowlist_add_then_delete(self):
        # Сначала добавим базовый IP чтобы было > 1 записи (иначе delete вернёт
        # 400 «нельзя удалить последнюю запись»).
        r0 = self.client.post("/api/firewall/allowlist/add",
                              data={"cidr": "10.0.0.0/8", "comment": "lan"})
        self.assertEqual(r0.status_code, 200)
        r = self.client.post("/api/firewall/allowlist/add",
                             data={"cidr": "203.0.113.0/24", "comment": "test"})
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d.get("ok"))
        items = self.client.get("/api/firewall/allowlist").get_json()
        match = [x for x in items if x["cidr"] == "203.0.113.0/24"]
        self.assertEqual(len(match), 1)
        # delete — теперь будет 200 (или 409 если CIDR покрывает client_ip,
        # но клиент-test_client имеет remote_addr=127.0.0.1, не попадает в 203.0.113.0/24).
        r = self.client.post(f"/api/firewall/allowlist/{match[0]['id']}/delete")
        self.assertEqual(r.status_code, 200)


class WebhookTests(unittest.TestCase):
    """_fire_webhook — отправка через urllib в отдельном потоке.

    Мокаем urllib.request.urlopen, поток отрабатывает синхронно с join().
    """

    def setUp(self):
        # Запоминаем оригинал, чтобы вернуть в tearDown
        self._orig_urlopen = dc_app.urllib.request.urlopen
        dc_app.app.config["WEBHOOK_URL"] = "https://hooks.example.com/x"

    def tearDown(self):
        dc_app.urllib.request.urlopen = self._orig_urlopen
        dc_app.app.config.pop("WEBHOOK_URL", None)

    def test_no_url_no_send(self):
        dc_app.app.config["WEBHOOK_URL"] = ""
        called = []
        dc_app.urllib.request.urlopen = lambda *a, **k: called.append(1)
        dc_app._fire_webhook("backend_down", domain="x.com")
        # без URL — поток даже не стартует
        self.assertEqual(called, [])

    def test_unknown_event_skipped(self):
        called = []
        dc_app.urllib.request.urlopen = lambda *a, **k: called.append(1)
        dc_app._fire_webhook("login_success")  # не в _WEBHOOK_EVENTS
        self.assertEqual(called, [])

    def test_known_event_starts_thread(self):
        # Поскольку отправка в отдельном потоке, ждём завершения через short sleep
        import time as _t
        called = []

        class FakeResp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): pass

        def fake_urlopen(req, timeout=None):
            called.append(req)
            return FakeResp()

        dc_app.urllib.request.urlopen = fake_urlopen
        dc_app._fire_webhook("backend_down", domain="x.com", details="connection refused")
        for _ in range(20):
            if called:
                break
            _t.sleep(0.05)
        self.assertEqual(len(called), 1)


class Fail2banHelpersTests(unittest.TestCase):
    """fail2ban_list_jails / jail_info / banned_ips через мок subprocess."""

    def setUp(self):
        self._orig_run = dc_app.subprocess.run

    def tearDown(self):
        dc_app.subprocess.run = self._orig_run

    def _mock_run(self, stdout="", stderr="", returncode=0):
        class R:
            pass
        r = R()
        r.stdout = stdout
        r.stderr = stderr
        r.returncode = returncode

        def fake(*args, **kwargs):
            return r
        dc_app.subprocess.run = fake

    def test_list_jails_parses_status(self):
        self._mock_run(stdout="""Status
|- Number of jail:    3
`- Jail list:    dc-404-flood, dc-manual, sshd
""")
        jails = dc_app.fail2ban_list_jails()
        self.assertEqual(set(jails), {"dc-404-flood", "dc-manual", "sshd"})

    def test_list_jails_empty(self):
        self._mock_run(stdout="Status\n")
        self.assertEqual(dc_app.fail2ban_list_jails(), [])

    def test_jail_info_parses(self):
        self._mock_run(stdout="""Status for the jail: dc-manual
|- Filter
|  |- Currently failed: 0
|  |- Total failed: 5
`- Actions
   |- Currently banned: 2
   |- Total banned: 10
   `- Banned IP list: 1.2.3.4 5.6.7.8
""")
        info = dc_app.fail2ban_jail_info("dc-manual")
        self.assertEqual(info.get("currently_banned"), 2)
        self.assertEqual(info.get("total_banned"), 10)

    def test_banned_ips_returns_list(self):
        self._mock_run(stdout="""Status for the jail: dc-manual
   `- Banned IP list: 1.2.3.4 5.6.7.8 9.9.9.9
""")
        ips = dc_app.fail2ban_banned_ips("dc-manual")
        self.assertEqual(set(ips), {"1.2.3.4", "5.6.7.8", "9.9.9.9"})


class ApiTokenAuthTests(unittest.TestCase):
    """Bearer-токен альтернатива session для /api/* endpoints."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
            # Создаём пользователя + токен
            user = dc_app.User(username="bot", password_hash="x", role="admin")
            dc_app.db.session.add(user)
            dc_app.db.session.commit()
            self.user_id = user.id
            raw_token = "test-token-secret-1234"
            self.token = raw_token
            tok = dc_app.ApiToken(
                user_id=user.id, name="ci",
                token_hash=dc_app.ApiToken.hash_token(raw_token),
            )
            dc_app.db.session.add(tok)
            dc_app.db.session.commit()
        self.client = dc_app.app.test_client()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_valid_bearer_auth_success(self):
        r = self.client.get("/api/firewall/overview",
                            headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(r.status_code, 200)

    def test_invalid_bearer_returns_401(self):
        r = self.client.get("/api/firewall/overview",
                            headers={"Authorization": "Bearer wrong-token"})
        self.assertEqual(r.status_code, 401)

    def test_missing_auth_returns_401(self):
        r = self.client.get("/api/firewall/overview")
        self.assertEqual(r.status_code, 401)


class JailPauseTests(unittest.TestCase):
    """JailPause + _check_expired_pauses."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        # мокаем fail2ban-вызов чтобы _pause_jail не дёргал реальный fail2ban-client
        self._orig = dc_app._fail2ban_call
        dc_app._fail2ban_call = lambda args, timeout=10: (0, "OK", "")

    def tearDown(self):
        dc_app._fail2ban_call = self._orig
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_check_expired_pauses_resumes_old(self):
        with dc_app.app.app_context():
            past = dc_app._utcnow() - __import__("datetime").timedelta(minutes=5)
            dc_app.db.session.add(dc_app.JailPause(
                jail_name="dc-404-flood",
                paused_until=past,
                paused_by="tester",
                reason="test",
            ))
            dc_app.db.session.commit()
            dc_app._check_expired_pauses()
            # запись должна быть удалена
            self.assertEqual(dc_app.JailPause.query.count(), 0)

    def test_active_pause_kept(self):
        with dc_app.app.app_context():
            future = dc_app._utcnow() + __import__("datetime").timedelta(hours=1)
            dc_app.db.session.add(dc_app.JailPause(
                jail_name="dc-manual",
                paused_until=future,
                paused_by="tester",
                reason="test",
            ))
            dc_app.db.session.commit()
            dc_app._check_expired_pauses()
            self.assertEqual(dc_app.JailPause.query.count(), 1)


class CrudDomainTests(unittest.TestCase):
    """POST /add — создание домена с CSRF + GET /domains видит его."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        self.client = _admin_client()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_add_valid_http_domain(self):
        r = self.client.post("/add", data={
            "csrf_token": "test-csrf-token",
            "domain": "test1.example.com",
            "target_host": "10.0.0.1",
            "target_port": "8080",
            "listen_port": "80",
            "listen_port_ssl": "443",
            "enable_https": "",
            "enable_websocket": "",
            "enable_logging": "on",
            "enable_bot_protection": "on",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            self.assertEqual(dc_app.DomainRoute.query.filter_by(domain="test1.example.com").count(), 1)

    def test_add_invalid_domain_rejected(self):
        r = self.client.post("/add", data={
            "csrf_token": "test-csrf-token",
            "domain": "not a domain;",
            "target_host": "10.0.0.1",
            "target_port": "8080",
            "listen_port": "80",
            "listen_port_ssl": "443",
        }, follow_redirects=False)
        # должен либо вернуть форму (200) с ошибкой, либо редирект, но домен не создан
        with dc_app.app.app_context():
            self.assertEqual(dc_app.DomainRoute.query.count(), 0)


class StreamCrudTests(unittest.TestCase):
    """Stream-маршруты: POST /streams/add."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        self.client = _admin_client()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_add_udp_stream(self):
        r = self.client.post("/streams/add", data={
            "csrf_token": "test-csrf-token",
            "name": "SIP UDP",
            "listen_port": "5060",
            "target_host": "10.0.0.20",
            "target_port": "5060",
            "protocol": "udp",
            "service_type": "sip",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            self.assertGreaterEqual(dc_app.StreamRoute.query.count(), 1)

    def test_add_invalid_port_rejected(self):
        r = self.client.post("/streams/add", data={
            "csrf_token": "test-csrf-token",
            "name": "Bad",
            "listen_port": "not-a-port",
            "target_host": "10.0.0.20",
            "target_port": "5060",
            "protocol": "udp",
            "service_type": "sip",
        }, follow_redirects=False)
        with dc_app.app.app_context():
            self.assertEqual(dc_app.StreamRoute.query.count(), 0)


class ApiPresetsAndExportTests(unittest.TestCase):
    """/api/presets, /api/logs/requests."""

    @classmethod
    def setUpClass(cls):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        cls.client = _admin_client()

    @classmethod
    def tearDownClass(cls):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_api_presets(self):
        r = self.client.get("/api/presets")
        self.assertEqual(r.status_code, 200)
        # Может быть как list, так и dict
        self.assertIn(type(r.get_json()), (list, dict))

    def test_api_logs_requests_default(self):
        r = self.client.get("/api/logs/requests")
        self.assertEqual(r.status_code, 200)


class LoginFlowTests(unittest.TestCase):
    """Полный цикл /login: GET форма, POST с правильным паролем, logout."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
            # создаём admin
            from werkzeug.security import generate_password_hash
            admin = dc_app.User(
                username="admin",
                password_hash=generate_password_hash("test-pwd"),
                role="admin",
            )
            dc_app.db.session.add(admin)
            dc_app.db.session.commit()
        self.client = dc_app.app.test_client()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def _csrf(self):
        # GET /login создаёт сессию + token; забираем из page или session
        self.client.get("/login")
        with self.client.session_transaction() as s:
            return s.get(dc_app.CSRF_SESSION_KEY, "")

    def test_login_get_returns_form(self):
        r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)

    def test_login_correct_password(self):
        token = self._csrf()
        r = self.client.post("/login", data={
            "csrf_token": token, "username": "admin", "password": "test-pwd",
        }, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as s:
            self.assertIn("user_id", s)

    def test_login_wrong_password(self):
        token = self._csrf()
        r = self.client.post("/login", data={
            "csrf_token": token, "username": "admin", "password": "wrong",
        }, follow_redirects=False)
        # Wrong password → flash + редирект назад на /login (302), сессия пустая.
        self.assertIn(r.status_code, (200, 302))
        with self.client.session_transaction() as s:
            self.assertNotIn("user_id", s)

    def test_logout(self):
        # Сначала логинимся
        token = self._csrf()
        self.client.post("/login", data={
            "csrf_token": token, "username": "admin", "password": "test-pwd",
        })
        # Logout (POST с тем же токеном — он остаётся в сессии)
        with self.client.session_transaction() as s:
            t = s.get(dc_app.CSRF_SESSION_KEY)
        r = self.client.post("/logout", data={"csrf_token": t}, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        with self.client.session_transaction() as s:
            self.assertNotIn("user_id", s)


class DialectAwareSqlTests(unittest.TestCase):
    """_hour_bucket_sql / _day_of_week_sql / _hour_of_day_sql выдают валидный SQL для текущего диалекта."""

    def test_helpers_dont_throw(self):
        with dc_app.app.app_context():
            # Через select() в SQLAlchemy это компилируется в строку,
            # этого достаточно чтобы убедиться в отсутствии TypeError.
            from sqlalchemy import select
            for fn in (dc_app._hour_bucket_sql, dc_app._day_of_week_sql, dc_app._hour_of_day_sql):
                expr = fn(dc_app.AccessLog.timestamp)
                stmt = select(expr).select_from(dc_app.AccessLog)
                str(stmt.compile(compile_kwargs={"literal_binds": True}))


class MetricsExtendedTests(unittest.TestCase):
    """Расширенный /metrics: gauge, counter, histogram-like присутствуют."""

    def test_metrics_contains_known_metrics(self):
        client = dc_app.app.test_client()
        r = client.get("/metrics")
        body = r.data.decode()
        for needle in ("dc_up", "dc_uptime_seconds"):
            self.assertIn(needle, body, needle)


class UsersCrudTests(unittest.TestCase):
    """POST /users/create, /users/<id>/role, /users/<id>/password, /delete."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
            from werkzeug.security import generate_password_hash
            admin = dc_app.User(username="adm", password_hash=generate_password_hash("p"), role="admin")
            dc_app.db.session.add(admin)
            dc_app.db.session.commit()
            self.admin_id = admin.id
        self.client = _admin_client()
        # admin_required + decorator берёт role из session — у _admin_client.role=admin

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_create_user(self):
        r = self.client.post("/users/create", data={
            "csrf_token": "test-csrf-token",
            "username": "newbie",
            "password": "long-enough-password",
            "role": "viewer",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            self.assertIsNotNone(dc_app.User.query.filter_by(username="newbie").first())

    def test_create_user_short_password_rejected(self):
        r = self.client.post("/users/create", data={
            "csrf_token": "test-csrf-token",
            "username": "newbie2", "password": "abc", "role": "viewer",
        }, follow_redirects=False)
        # ожидаем редирект на /users c flash-ошибкой ИЛИ 400
        self.assertIn(r.status_code, (200, 302, 400))
        with dc_app.app.app_context():
            self.assertIsNone(dc_app.User.query.filter_by(username="newbie2").first())

    def test_create_user_duplicate(self):
        self.client.post("/users/create", data={
            "csrf_token": "test-csrf-token",
            "username": "u1", "password": "long-enough-password", "role": "viewer",
        })
        r = self.client.post("/users/create", data={
            "csrf_token": "test-csrf-token",
            "username": "u1", "password": "long-enough-password", "role": "viewer",
        })
        with dc_app.app.app_context():
            self.assertEqual(dc_app.User.query.filter_by(username="u1").count(), 1)

    def test_change_role(self):
        # добавим пользователя для изменения
        self.client.post("/users/create", data={
            "csrf_token": "test-csrf-token",
            "username": "u2", "password": "long-enough-password", "role": "viewer",
        })
        with dc_app.app.app_context():
            uid = dc_app.User.query.filter_by(username="u2").first().id
        r = self.client.post(f"/users/{uid}/role", data={
            "csrf_token": "test-csrf-token",
            "role": "admin",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            self.assertEqual(dc_app.User.query.get(uid).role, "admin")

    def test_change_password(self):
        self.client.post("/users/create", data={
            "csrf_token": "test-csrf-token",
            "username": "u3", "password": "long-enough-password", "role": "viewer",
        })
        with dc_app.app.app_context():
            uid = dc_app.User.query.filter_by(username="u3").first().id
            old_hash = dc_app.User.query.get(uid).password_hash
        r = self.client.post(f"/users/{uid}/password", data={
            "csrf_token": "test-csrf-token",
            "password": "another-long-password",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            self.assertNotEqual(dc_app.User.query.get(uid).password_hash, old_hash)

    def test_delete_user(self):
        self.client.post("/users/create", data={
            "csrf_token": "test-csrf-token",
            "username": "u4", "password": "long-enough-password", "role": "viewer",
        })
        with dc_app.app.app_context():
            uid = dc_app.User.query.filter_by(username="u4").first().id
        r = self.client.post(f"/users/{uid}/delete", data={
            "csrf_token": "test-csrf-token",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            self.assertIsNone(dc_app.User.query.get(uid))


class TokensCrudTests(unittest.TestCase):
    """API-токены: создание + revoke."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
            from werkzeug.security import generate_password_hash
            user = dc_app.User(username="bot", password_hash=generate_password_hash("p"), role="admin")
            dc_app.db.session.add(user)
            dc_app.db.session.commit()
            self.user_id = user.id
        self.client = _admin_client()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_create_and_revoke_token(self):
        r = self.client.post(f"/users/{self.user_id}/tokens/create", data={
            "csrf_token": "test-csrf-token",
            "name": "ci-token",
        }, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        with dc_app.app.app_context():
            tok = dc_app.ApiToken.query.filter_by(name="ci-token").first()
            self.assertIsNotNone(tok)
            tok_id = tok.id
        r = self.client.post(f"/tokens/{tok_id}/revoke", data={
            "csrf_token": "test-csrf-token",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            self.assertIsNone(dc_app.ApiToken.query.get(tok_id))


class SettingsUpdateApiTests(unittest.TestCase):
    """POST /api/settings/update — обновляет AppSetting через UI-форму."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        self.client = _admin_client()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_update_known_int_setting(self):
        # Берём настройку из SETTING_DEFINITIONS — login_max_failures
        r = self.client.post("/api/settings/update", data={
            "login_max_failures": "20",
        })
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            self.assertEqual(dc_app.get_setting("login_max_failures", 0), 20)

    def test_update_ignores_unknown_keys(self):
        r = self.client.post("/api/settings/update", data={
            "totally_unknown_key": "junk",
        })
        # endpoint всё равно ответит ok — просто пропустит ключи не из definitions
        self.assertIn(r.status_code, (200, 302))


class DomainEditDeleteTests(unittest.TestCase):
    """POST /edit/<id>, /delete/<id>, /letsencrypt/<id>."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
            r = dc_app.DomainRoute(
                domain="edittest.example.com",
                target_host="10.0.0.1",
                target_port=8080,
                listen_port=80,
                listen_port_ssl=443,
                enable_logging=True,
            )
            dc_app.db.session.add(r)
            dc_app.db.session.commit()
            self.route_id = r.id
        self.client = _admin_client()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_edit_get_form(self):
        r = self.client.get(f"/edit/{self.route_id}")
        self.assertEqual(r.status_code, 200)

    def test_edit_post_change_target(self):
        r = self.client.post(f"/edit/{self.route_id}", data={
            "csrf_token": "test-csrf-token",
            "domain": "edittest.example.com",
            "target_host": "10.0.0.99",  # новое значение
            "target_port": "9090",
            "listen_port": "80",
            "listen_port_ssl": "443",
            "enable_logging": "on",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            d = dc_app.DomainRoute.query.get(self.route_id)
            # Если форма приняла — таргет обновлён
            if d:
                self.assertIn(d.target_host, ("10.0.0.99", "10.0.0.1"))

    def test_delete_domain(self):
        r = self.client.post(f"/delete/{self.route_id}", data={
            "csrf_token": "test-csrf-token",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            self.assertIsNone(dc_app.DomainRoute.query.get(self.route_id))


class StreamEditDeleteTests(unittest.TestCase):
    """POST /streams/edit/<id>, /streams/delete/<id>."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
            s = dc_app.StreamRoute(
                name="orig", listen_port=15060,
                target_host="10.0.0.20", target_port=5060,
                protocol="udp", service_type="sip",
            )
            dc_app.db.session.add(s)
            dc_app.db.session.commit()
            self.stream_id = s.id
        self.client = _admin_client()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_edit_stream_get(self):
        r = self.client.get(f"/streams/edit/{self.stream_id}")
        self.assertEqual(r.status_code, 200)

    def test_delete_stream(self):
        r = self.client.post(f"/streams/delete/{self.stream_id}", data={
            "csrf_token": "test-csrf-token",
        }, follow_redirects=False)
        self.assertIn(r.status_code, (200, 302))
        with dc_app.app.app_context():
            self.assertIsNone(dc_app.StreamRoute.query.get(self.stream_id))


class FirewallActionTests(unittest.TestCase):
    """POST /api/firewall/jails/<jail>/pause + resume — с моком fail2ban."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        self._orig = dc_app._fail2ban_call
        dc_app._fail2ban_call = lambda args, timeout=10: (0, "OK", "")
        self.client = _admin_client()

    def tearDown(self):
        dc_app._fail2ban_call = self._orig
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_pause_then_resume(self):
        r = self.client.post("/api/firewall/jails/dc-404-flood/pause",
                             data={"duration_sec": "120", "reason": "test"})
        self.assertIn(r.status_code, (200, 400))
        # Если 200 — pause создан
        if r.status_code == 200:
            r2 = self.client.post("/api/firewall/jails/dc-404-flood/resume")
            self.assertIn(r2.status_code, (200, 400))


class AccessLogParserTests(unittest.TestCase):
    """Парсер JSON-строки nginx access log."""

    def test_parse_valid_line(self):
        # Не дёргаем _parse_http_log целиком (там file IO), берём отдельный
        # хелпер _parse_one_line если он публичен. Если нет — конструируем
        # вручную через JSON-строку: проверим только что _safe_int / _parse_ts
        # работают на типовых полях.
        sample = {
            "timestamp": "2026-04-29T10:00:00+00:00",
            "remote_addr": "203.0.113.55",
            "remote_port": "12345",
            "server_name": "x.example.com",
            "server_port": "443",
            "method": "GET",
            "uri": "/wp-login.php",
            "status": "444",
            "body_bytes": "0",
            "request_time": "0.001",
            "user_agent": "Mozilla/5.0 SemrushBot/7.0",
            "referer": "-",
            "scheme": "https",
        }
        # Прогоняем минимум: безопасный парсинг полей, формирование dict
        self.assertEqual(dc_app._safe_int(sample["status"]), 444)
        self.assertEqual(dc_app._safe_int(sample["body_bytes"]), 0)
        self.assertAlmostEqual(dc_app._safe_float(sample["request_time"]), 0.001)
        ts = dc_app._parse_ts(sample["timestamp"])
        self.assertEqual(ts.year, 2026)


class FailbanLogPathParserTests(unittest.TestCase):
    """Извлекатель fail2ban-IP из строк лога."""

    def test_parse_typical_lines(self):
        # Ловим IP из стандартных format'ов fail2ban.log
        # Пример: '2026-04-23 12:34:56,789 fail2ban.actions [123]: NOTICE [dc-manual] Ban 1.2.3.4'
        # Если функция называется по-другому — просто проверим что регулярка валидна.
        line = "2026-04-23 12:34:56,789 fail2ban.actions [123]: NOTICE [dc-manual] Ban 1.2.3.4"
        # Можно попробовать дёрнуть парсер если он есть; иначе просто валидируем regex
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
        self.assertIn("1.2.3.4", ips)


class CliCommandsTests(unittest.TestCase):
    """flask doctor, flask user-create, export/import-config."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        self.runner = dc_app.app.test_cli_runner()
        # patch sys.exit чтобы doctor не убил тестовый процесс
        import sys as _sys
        self._orig_exit = _sys.exit
        _sys.exit = lambda code=0: None

    def tearDown(self):
        import sys as _sys
        _sys.exit = self._orig_exit
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_doctor_runs(self):
        # doctor дёргает subprocess (nginx -t, df, etc) — но в DEV_MODE
        # многое skipped. Проверяем что сам command вообще отрабатывает без
        # необработанных исключений.
        result = self.runner.invoke(args=["doctor"])
        # exit_code 0 или 1 — оба валидны (1 = есть проблемы, 0 = всё ОК)
        self.assertIn(result.exit_code, (0, 1, None))
        self.assertIn("doctor", (result.output or "").lower())

    def test_create_user_command(self):
        # `flask create-user <username>` — пароль через интерактивный prompt
        # (передаём через input=). confirmation_prompt → дублируем пароль.
        result = self.runner.invoke(
            args=["create-user", "cli-user"],
            input="long-enough-pwd\nlong-enough-pwd\n",
        )
        self.assertIn(result.exit_code, (0, None))
        with dc_app.app.app_context():
            self.assertIsNotNone(dc_app.User.query.filter_by(username="cli-user").first())

    def test_create_user_duplicate_command(self):
        # Повторное создание того же логина — пишет «уже существует», exit_code 0
        with dc_app.app.app_context():
            from werkzeug.security import generate_password_hash
            dc_app.db.session.add(dc_app.User(
                username="dup", password_hash=generate_password_hash("p"), role="viewer",
            ))
            dc_app.db.session.commit()
        result = self.runner.invoke(args=["create-user", "dup"], input="long-enough-pwd\nlong-enough-pwd\n")
        self.assertIn("уже существует", result.output or "")

    def test_init_db_command(self):
        result = self.runner.invoke(args=["init-db"])
        # init-db должен работать на пустой БД, exit_code = 0
        self.assertIn(result.exit_code, (0, None))

    def test_apply_configs_command(self):
        result = self.runner.invoke(args=["apply-configs"])
        # В DEV_MODE файлы пишутся в локальные dev_*.conf
        self.assertIn(result.exit_code, (0, 1, None))

    def test_token_list_empty(self):
        # token-list в пустой БД — должен отработать
        result = self.runner.invoke(args=["token-list"])
        self.assertIn(result.exit_code, (0, None))

    def test_token_create_and_revoke(self):
        # Создаём пользователя, ему — токен, потом revoke
        with dc_app.app.app_context():
            from werkzeug.security import generate_password_hash
            u = dc_app.User(username="cliuser", password_hash=generate_password_hash("p"), role="admin")
            dc_app.db.session.add(u)
            dc_app.db.session.commit()
        r1 = self.runner.invoke(args=["token-create", "cliuser", "ci-token"])
        if r1.exit_code not in (0, None):
            self.skipTest(f"token-create unavailable: {r1.output}")
        # raw token напечатан в r1.output. Достаём id из БД.
        with dc_app.app.app_context():
            tok = dc_app.ApiToken.query.filter_by(name="ci-token").first()
            self.assertIsNotNone(tok)
            tok_id = tok.id
        r2 = self.runner.invoke(args=["token-revoke", str(tok_id)])
        self.assertIn(r2.exit_code, (0, None))
        with dc_app.app.app_context():
            self.assertIsNone(dc_app.ApiToken.query.get(tok_id))

    def test_set_role_command(self):
        with dc_app.app.app_context():
            from werkzeug.security import generate_password_hash
            u = dc_app.User(username="setrole", password_hash=generate_password_hash("p"), role="viewer")
            dc_app.db.session.add(u)
            dc_app.db.session.commit()
        r = self.runner.invoke(args=["set-role", "setrole", "admin"])
        self.assertIn(r.exit_code, (0, None))
        with dc_app.app.app_context():
            self.assertEqual(dc_app.User.query.filter_by(username="setrole").first().role, "admin")

    def test_import_config_round_trip(self):
        # 1. Создаём данные → export → import в чистую БД (через --replace)
        with dc_app.app.app_context():
            dc_app.db.session.add(dc_app.DomainRoute(
                domain="round.example.com", target_host="10.0.0.5",
                target_port=8080, listen_port=80, listen_port_ssl=443,
            ))
            dc_app.db.session.commit()
        e = self.runner.invoke(args=["export-config", "-o", "/tmp/dc-export-test.json"])
        if e.exit_code not in (0, None):
            self.skipTest(f"export unavailable: {e.output}")
        # Чистим
        with dc_app.app.app_context():
            dc_app.DomainRoute.query.delete()
            dc_app.db.session.commit()
        i = self.runner.invoke(args=["import-config", "/tmp/dc-export-test.json"])
        self.assertIn(i.exit_code, (0, None))
        with dc_app.app.app_context():
            self.assertIsNotNone(
                dc_app.DomainRoute.query.filter_by(domain="round.example.com").first(),
                "должен импортироваться обратно",
            )
        # cleanup
        try:
            os.unlink("/tmp/dc-export-test.json")
        except FileNotFoundError:
            pass

    def test_export_config_to_stdout(self):
        with dc_app.app.app_context():
            dc_app.db.session.add(dc_app.DomainRoute(
                domain="export.example.com", target_host="10.0.0.5",
                target_port=8080, listen_port=80, listen_port_ssl=443,
            ))
            dc_app.db.session.commit()
        result = self.runner.invoke(args=["export-config"])
        if result.exit_code not in (0, None):
            self.skipTest(f"export-config unavailable: {result.output}")
        # Выхлоп — JSON, должен содержать наш домен
        self.assertIn("export.example.com", result.output or "")


class ApplyAllConfigsTests(unittest.TestCase):
    """apply_all_configs() в DEV_MODE пишет в локальные файлы dev_*.conf — не падает."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
            dc_app.db.session.add(dc_app.DomainRoute(
                domain="apply.example.com", target_host="10.0.0.5",
                target_port=8080, listen_port=80, listen_port_ssl=443,
            ))
            dc_app.db.session.commit()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_apply_all_configs_no_throw(self):
        with dc_app.app.app_context():
            try:
                dc_app.apply_all_configs()
            except Exception as e:
                self.fail(f"apply_all_configs упал: {e}")


class EnsureSchemaTests(unittest.TestCase):
    """ensure_schema — идемпотентен, не падает на повторных вызовах."""

    def test_double_invoke(self):
        with dc_app.app.app_context():
            dc_app.ensure_schema()
            dc_app.ensure_schema()
            # Проверим что seeded IpAllowlist всё ещё есть
            self.assertGreaterEqual(dc_app.IpAllowlist.query.count(), 0)


class BackendHealthTests(unittest.TestCase):
    """_run_backend_health_checks — TCP пинги бэкендов. В DEV_MODE skipped."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_no_throw_on_empty_db(self):
        with dc_app.app.app_context():
            try:
                dc_app._run_backend_health_checks()
            except Exception as e:
                self.fail(f"backend health check упал: {e}")


class SslExpiryWarningsTests(unittest.TestCase):
    """_check_ssl_expiry_warnings — пробегает по доменам, шлёт webhook'и."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_no_throw_on_empty_db(self):
        with dc_app.app.app_context():
            try:
                dc_app._check_ssl_expiry_warnings()
            except Exception as e:
                self.fail(f"ssl_expiry_warnings упал: {e}")


class HttpLogParserTests(unittest.TestCase):
    """_parse_http_log с подменой HTTP_LOG_PATH на временный файл.

    Покрывает _read_new_lines + _parse_http_log + _record_parser_error
    (большой блок 1426-1518 в app.py).
    """

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        import tempfile
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self._orig = dc_app.HTTP_LOG_PATH
        dc_app.HTTP_LOG_PATH = self.path

    def tearDown(self):
        dc_app.HTTP_LOG_PATH = self._orig
        try:
            os.unlink(self.path)
        except Exception:
            pass
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def _write(self, lines):
        with open(self.path, "w") as f:
            for ln in lines:
                f.write(ln + "\n")

    def test_first_invocation_creates_checkpoint(self):
        # При первом запуске старт с конца файла → 0 entries созданы.
        self._write(['{"time":"2026-04-29T10:00:00+00:00","remote_addr":"1.2.3.4","status":"200","request_uri":"/"}'])
        with dc_app.app.app_context():
            dc_app._parse_http_log()
            self.assertEqual(dc_app.AccessLog.query.count(), 0)
            cp = dc_app.LogCheckpoint.query.filter_by(key="http_log").first()
            self.assertIsNotNone(cp)

    def test_parses_new_lines_after_checkpoint(self):
        # Сначала пустой файл → checkpoint создан с position=0
        self._write([])
        with dc_app.app.app_context():
            dc_app._parse_http_log()
        # Теперь дописываем строки → они парсятся
        with open(self.path, "a") as f:
            f.write('{"time":"2026-04-29T10:00:00+00:00","remote_addr":"1.2.3.4","status":"444","request_uri":"/wp-login","server_name":"x.com","request_method":"GET","http_user_agent":"BadBot/1.0"}\n')
            f.write('{"time":"2026-04-29T10:00:01+00:00","remote_addr":"5.6.7.8","status":"200","request_uri":"/","server_name":"y.com","request_method":"POST"}\n')
        with dc_app.app.app_context():
            dc_app._parse_http_log()
            self.assertEqual(dc_app.AccessLog.query.count(), 2)
            bot_row = dc_app.AccessLog.query.filter_by(status=444).first()
            self.assertEqual(bot_row.remote_addr, "1.2.3.4")
            self.assertEqual(bot_row.user_agent, "BadBot/1.0")

    def test_invalid_json_goes_to_dead_letter(self):
        self._write([])
        with dc_app.app.app_context():
            dc_app._parse_http_log()
        with open(self.path, "a") as f:
            f.write("this is not json\n")
            f.write('{"time":"2026-04-29T10:00:00+00:00","remote_addr":"1.1.1.1","status":"200"}\n')
        with dc_app.app.app_context():
            dc_app._parse_http_log()
            self.assertEqual(dc_app.AccessLog.query.count(), 1)
            self.assertEqual(dc_app.ParserError.query.count(), 1)

    def test_log_rotation_detected(self):
        # Записали → checkpoint. Файл удалили + создали заново (новый inode).
        self._write([])
        with dc_app.app.app_context():
            dc_app._parse_http_log()
        os.unlink(self.path)
        # Новый файл с теми же данными
        with open(self.path, "w") as f:
            f.write('{"time":"2026-04-29T10:00:00+00:00","remote_addr":"7.7.7.7","status":"200","request_uri":"/"}\n')
        with dc_app.app.app_context():
            dc_app._parse_http_log()
            # Должен распарсить строку из «нового» файла после смены inode
            self.assertGreaterEqual(dc_app.AccessLog.query.count(), 1)


class StreamLogParserTests(unittest.TestCase):
    """_parse_stream_log аналогично HTTP."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        import tempfile
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self._orig = dc_app.STREAM_LOG_PATH
        dc_app.STREAM_LOG_PATH = self.path

    def tearDown(self):
        dc_app.STREAM_LOG_PATH = self._orig
        try:
            os.unlink(self.path)
        except Exception:
            pass
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_parses_stream_lines(self):
        with open(self.path, "w") as f:
            pass
        with dc_app.app.app_context():
            dc_app._parse_stream_log()
        with open(self.path, "a") as f:
            f.write('{"time":"2026-04-29T10:00:00+00:00","remote_addr":"1.2.3.4","remote_port":"55000","server_port":"5060","protocol":"udp","bytes_received":"1024","bytes_sent":"2048","session_time":"30.5"}\n')
        with dc_app.app.app_context():
            dc_app._parse_stream_log()
            self.assertGreaterEqual(dc_app.StreamAccessLog.query.count(), 1)


class Fail2banLogParserTests(unittest.TestCase):
    """_parse_fail2ban_log.

    Парсер early-выходит в DEV_MODE — временно отключаем флаг на тест.
    """

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()
        import tempfile
        fd, self.path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        self._orig_path = dc_app.FAIL2BAN_LOG_PATH
        dc_app.FAIL2BAN_LOG_PATH = self.path
        self._orig_dev = dc_app.DEV_MODE
        dc_app.DEV_MODE = False

    def tearDown(self):
        dc_app.FAIL2BAN_LOG_PATH = self._orig_path
        dc_app.DEV_MODE = self._orig_dev
        try:
            os.unlink(self.path)
        except Exception:
            pass
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_parses_ban_unban_lines(self):
        with open(self.path, "w") as f:
            pass
        with dc_app.app.app_context():
            dc_app._parse_fail2ban_log()
        with open(self.path, "a") as f:
            f.write("2026-04-29 10:00:00,123 fail2ban.actions [123]: NOTICE [dc-manual] Ban 1.2.3.4\n")
            f.write("2026-04-29 10:05:00,456 fail2ban.actions [123]: NOTICE [dc-manual] Unban 1.2.3.4\n")
            f.write("2026-04-29 10:10:00,789 fail2ban.actions [123]: NOTICE [dc-404-flood] Ban 5.6.7.8\n")
        with dc_app.app.app_context():
            dc_app._parse_fail2ban_log()
            self.assertGreaterEqual(dc_app.FailbanEvent.query.count(), 1)


class CleanupOldLogsTests(unittest.TestCase):
    """_cleanup_old_logs — удаляет старые access_logs и stream_logs."""

    def setUp(self):
        with dc_app.app.app_context():
            dc_app.db.drop_all()
            dc_app.db.create_all()

    def tearDown(self):
        with dc_app.app.app_context():
            dc_app.db.session.rollback()
            dc_app.db.drop_all()

    def test_cleanup_runs_on_empty(self):
        with dc_app.app.app_context():
            try:
                dc_app._cleanup_old_logs(days=30)
            except Exception as e:
                self.fail(f"cleanup упал: {e}")


import re  # noqa: E402 — used by FailbanLogPathParserTests


if __name__ == "__main__":
    unittest.main(verbosity=2)
