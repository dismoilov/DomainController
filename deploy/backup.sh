#!/usr/bin/env bash
# Ежедневный бэкап PostgreSQL-базы DomainController через pg_dump (custom формат).
#
# Параметры подключения берутся из DATABASE_URL в /opt/domain-controller/.env.
# Каждый дамп проверяется через `pg_restore --list` — битый удаляется и скрипт
# возвращает ненулевой код (увидит systemd → notify on failure если настроен).
#
# Хранится 14 снимков, старше — удаляются.
#
# Вызывается через systemd timer (deploy/domain-controller-backup.timer).

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/domain-controller}"
BACKUP_DIR="${BACKUP_DIR:-$INSTALL_DIR/backups}"
ENV_FILE="${ENV_FILE:-$INSTALL_DIR/.env}"
KEEP_DAYS="${KEEP_DAYS:-14}"

log() { printf '[backup %s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "FAIL: $*"; exit 1; }

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

[[ -f "$ENV_FILE" ]] || die "Не найден $ENV_FILE"
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

[[ -n "${DATABASE_URL:-}" ]] || die "DATABASE_URL не задан в .env"
[[ "$DATABASE_URL" == postgres* ]] || die "Поддерживается только PostgreSQL (DATABASE_URL должен начинаться с 'postgres...')"

# pg_dump не понимает sqlalchemy-префикс +psycopg2 — обрезаем
clean_url="${DATABASE_URL/postgresql+psycopg2:/postgresql:}"
clean_url="${clean_url/postgres+psycopg2:/postgresql:}"

stamp=$(date -u +%Y%m%d-%H%M%S)
final="$BACKUP_DIR/dc.pg.$stamp.dump"

log "pg_dump → $final"
# -Fc = custom format, сжатый, селективное восстановление через pg_restore
pg_dump "$clean_url" -Fc -f "$final"
chmod 600 "$final"

log "проверяю целостность (pg_restore --list)"
if ! pg_restore --list "$final" >/dev/null 2>&1; then
    rm -f "$final"
    die "pg_restore --list упал — дамп битый"
fi
log "готово: $(du -h "$final" | cut -f1) — $final"

# Ротация
find "$BACKUP_DIR" -maxdepth 1 -name 'dc.pg.*.dump' -type f -mtime +"$KEEP_DAYS" -print -delete || true
count=$(find "$BACKUP_DIR" -maxdepth 1 -name 'dc.pg.*.dump' -type f | wc -l)
log "в $BACKUP_DIR сейчас $count бэкапов (keep $KEEP_DAYS дней)"
