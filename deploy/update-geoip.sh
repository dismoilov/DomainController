#!/usr/bin/env bash
# Скачивает свежую копию DB-IP city-lite (~60 MB сжатая, ~130 MB после распаковки).
# База обновляется издателем ежемесячно — есть смысл запускать раз в неделю
# через systemd-таймер (или cron) и перезагружать domain-controller, чтобы
# подхватить актуальную базу.
#
# DB-IP free лицензия: CC BY 4.0 (нужно указывать атрибут «IP Geolocation by DB-IP»).
#
# Использование:
#   sudo /opt/domain-controller/deploy/update-geoip.sh
#   sudo systemctl restart domain-controller   # чтобы reader перечитал mmdb
#
# Пути:
#   GEOIP_DIR  — где живёт mmdb (default /var/lib/dc-geoip)
#   STAGE_DIR  — куда качаем перед атомарным переносом (default GEOIP_DIR/.stage)

set -euo pipefail

GEOIP_DIR="${GEOIP_DIR:-/var/lib/dc-geoip}"
STAGE_DIR="$GEOIP_DIR/.stage"
TARGET="$GEOIP_DIR/dbip-city-lite.mmdb"

log() { printf '[geoip-update %s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "FAIL: $*"; exit 1; }

mkdir -p "$GEOIP_DIR" "$STAGE_DIR"
chmod 755 "$GEOIP_DIR"

# DB-IP публикует файлы по шаблону YYYY-MM. Берём текущий месяц,
# fallback к предыдущему (если новый ещё не загружен).
ym_now=$(date -u +%Y-%m)
ym_prev=$(date -u -d 'last month' +%Y-%m 2>/dev/null || date -u -v-1m +%Y-%m)

for ym in "$ym_now" "$ym_prev"; do
    url="https://download.db-ip.com/free/dbip-city-lite-${ym}.mmdb.gz"
    log "пробую $url"
    if curl -fsSL --connect-timeout 15 -o "$STAGE_DIR/db.mmdb.gz" "$url"; then
        log "скачано $(du -h "$STAGE_DIR/db.mmdb.gz" | cut -f1)"
        break
    fi
    rm -f "$STAGE_DIR/db.mmdb.gz"
done

[[ -s "$STAGE_DIR/db.mmdb.gz" ]] || die "не удалось скачать ни одну версию DB-IP"

gunzip -f "$STAGE_DIR/db.mmdb.gz"
[[ -s "$STAGE_DIR/db.mmdb" ]] || die "распаковка пустая"

# Минимальная sanity-проверка: первый байт mmdb-файла — известная сигнатура
# в маркере «.mmdb» в самом конце файла. Проверим, что есть метадата-маркер.
if ! tail -c 16384 "$STAGE_DIR/db.mmdb" | grep -aq '\xab\xcd\xefMaxMind.com'; then
    die "файл не похож на .mmdb (нет маркера metadata)"
fi

# Атомарная замена через rename
mv -f "$STAGE_DIR/db.mmdb" "$TARGET"
chmod 644 "$TARGET"
chown root:root "$TARGET"
rm -rf "$STAGE_DIR"

log "готово: $(du -h "$TARGET" | cut -f1) — $TARGET"
log "следующий шаг: systemctl restart domain-controller (чтобы перечитать)"
