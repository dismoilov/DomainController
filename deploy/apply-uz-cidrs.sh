#!/usr/bin/env bash
# Собирает финальный /etc/fail2ban/jail.d/dc-404-flood.conf с ignoreip,
# включающим весь IP-пул Узбекистана (защита от CGNAT-банов).
#
# Источник: https://www.ipdeny.com/ipblocks/data/countries/uz.zone — публичный
# список CIDR по country-code, обновляется ipdeny автоматически.
#
# Идемпотентный: можно запускать повторно. При сбое сети использует
# закэшированный список из /opt/domain-controller/deploy/uz.zone.cache.
# Если кэша тоже нет — ставит jail без UZ-списка (только RFC1918 allowlist).
#
# Использование:
#   sudo /opt/domain-controller/deploy/apply-uz-cidrs.sh

set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/opt/domain-controller/deploy}"
CACHE="${CACHE:-$DEPLOY_DIR/uz.zone.cache}"
TEMPLATE="${TEMPLATE:-$DEPLOY_DIR/fail2ban-dc-404.jail}"
JAIL_OUT="${JAIL_OUT:-/etc/fail2ban/jail.d/dc-404-flood.conf}"
SOURCE_URL="${SOURCE_URL:-https://www.ipdeny.com/ipblocks/data/countries/uz.zone}"

log() { printf '[apply-uz-cidrs %s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "FAIL: $*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Запускайте через sudo."
[[ -f "$TEMPLATE" ]] || die "Нет шаблона jail: $TEMPLATE"

log "качаю UZ CIDRs из $SOURCE_URL"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

if curl -fsSL --max-time 30 -o "$tmp" "$SOURCE_URL" 2>/dev/null; then
    # Валидация: каждая строка должна быть CIDR (простой sanity).
    if grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' "$tmp"; then
        count=$(wc -l < "$tmp" | tr -d ' ')
        cp "$tmp" "$CACHE"
        log "скачал $count CIDR, закэшировал в $CACHE"
    else
        log "ответ ipdeny невалиден (не похож на список CIDR)"
        rm -f "$tmp"
    fi
else
    log "не смог скачать (сеть?); пробую кэш"
fi

uz_list=""
if [[ -s "$CACHE" ]]; then
    # Один CIDR на строке, объединяем пробелами для ignoreip
    uz_list=$(tr '\n' ' ' < "$CACHE" | sed 's/ $//')
    count=$(wc -l < "$CACHE" | tr -d ' ')
    log "беру UZ-пул из кэша: $count CIDR"
else
    log "WARNING: UZ-пула нет (ни из сети, ни из кэша); ignoreip будет только RFC1918"
fi

# Берём шаблон, расширяем строку ignoreip
tmp_jail=$(mktemp)
if [[ -n "$uz_list" ]]; then
    awk -v uz="$uz_list" '
        /^ignoreip[[:space:]]*=/ { print $0, uz; next }
        { print }
    ' "$TEMPLATE" > "$tmp_jail"
else
    cp "$TEMPLATE" "$tmp_jail"
fi

# Атомарная замена
install -m 644 -o root -g root "$tmp_jail" "$JAIL_OUT"
rm -f "$tmp_jail"

log "установлен $JAIL_OUT"

# Проверка и reload fail2ban, если он запущен
if systemctl is-active --quiet fail2ban; then
    log "проверяю конфиг и перезагружаю fail2ban..."
    if fail2ban-client reload 2>&1; then
        log "fail2ban reloaded"
    else
        log "WARNING: fail2ban-client reload упал, пробую restart"
        systemctl restart fail2ban
    fi
else
    log "fail2ban не запущен — пропускаю reload"
fi

log "готово"
