"""Gunicorn config для DomainController.

ВАЖНО: workers=1 обязательно. Причины:
- Фоновый парсер nginx JSON-логов (start_log_reader) должен быть в одном
  процессе — иначе форки начнут параллельно читать те же файлы и писать
  в БД дубли (LogCheckpoint сериализован per-process, не per-host).
- In-memory rate-limit /login и SSL-кэш живут в одном процессе.
- Админ-панель не требует большой конкурентности: threads=4 достаточно.
"""

bind = "127.0.0.1:5000"
workers = 1
threads = 4
worker_class = "gthread"

# Достаточно на certbot (до 3 мин) + ручные тяжёлые API-запросы.
timeout = 240
graceful_timeout = 30
keepalive = 5

# Логи в stdout/stderr — systemd сам пишет в journal.
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)sms'

# preload=False: хотим, чтобы threading.Thread парсера стартовал в воркере.
preload_app = False

# Перезапуск воркера раз в N запросов — защита от утечек в долгоживущих процессах.
max_requests = 10000
max_requests_jitter = 500

proc_name = "domain-controller"
