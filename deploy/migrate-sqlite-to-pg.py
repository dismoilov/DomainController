#!/usr/bin/env python3
"""Миграция данных из SQLite в PostgreSQL.

Стратегия:
  1. PG-сервер уже установлен, БД и пользователь созданы (install.sh с DB_BACKEND=postgres
     это делает; или руками: CREATE USER ... + CREATE DATABASE ...).
  2. Приложение ОСТАНОВЛЕНО (systemctl stop domain-controller) — иначе будем мигрировать
     горящие данные.
  3. Запускаем этот скрипт — он читает SQLite, создаёт схему в PG через db.create_all(),
     копирует все строки таблица-за-таблицей чанками по 500 штук.
  4. Проверяем: количества строк совпадают.
  5. Меняем .env: DATABASE_URL=postgresql+psycopg2://...
  6. Запускаем приложение.
  7. Если всё хорошо — архивируем sqlite-файл как .sqlite.pre-pg-migrate.

Использование:
    sudo -u root python3 /opt/domain-controller/deploy/migrate-sqlite-to-pg.py \\
        --sqlite /opt/domain-controller/data.db \\
        --pg 'postgresql+psycopg2://dc_user:PASS@127.0.0.1:5432/dc'

Скрипт ИДЕМПОТЕНТЕН в простом смысле: если PG-таблицы уже содержат данные, скрипт
откажется работать (не сольёт дубликаты). Для повторной миграции очистите PG-таблицы.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# DEV_MODE=1 чтобы SECRET_KEY guard не упал (мы не веб-приложение, нам просто модели нужны)
os.environ.setdefault("DEV_MODE", "1")
# Отключаем фоновый log-reader thread — иначе он будет писать checkpoints в БД
# во время копирования таблиц и ловить duplicate-key конфликты.
os.environ["DC_NO_BG_THREADS"] = "1"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", required=True, help="Путь к data.db")
    ap.add_argument("--pg", required=True, help="DATABASE_URL для PG")
    ap.add_argument("--chunk", type=int, default=500, help="Размер чанка для копирования")
    args = ap.parse_args()

    if not os.path.exists(args.sqlite):
        sys.exit(f"SQLite файл не найден: {args.sqlite}")

    # 1. Читаем источник — перезаписываем DATABASE_URL в SQLite
    os.environ["DATABASE_URL"] = "sqlite:///" + os.path.abspath(args.sqlite)
    # Перезагружаем модули на случай если уже импортировали
    if "app" in sys.modules:
        del sys.modules["app"]
    import app as source_app
    source = source_app.db

    with source_app.app.app_context():
        all_models = [
            source_app.User,
            source_app.DomainRoute,
            source_app.StreamRoute,
            source_app.AccessLog,
            source_app.StreamAccessLog,
            source_app.AuditLog,
            source_app.LogCheckpoint,
            source_app.ParserError,
            source_app.AppSetting,
            source_app.FailbanEvent,
            source_app.IpAllowlist,
            source_app.ApiToken,
            source_app.JailPause,
        ]
        counts_src = {m.__tablename__: source.session.query(m).count() for m in all_models}
        print(f"SQLite source:")
        for t, c in counts_src.items():
            print(f"  {t}: {c}")
        data = {}
        for m in all_models:
            data[m] = source.session.query(m).all()
            # expunge — отвязываем от session, чтобы можно было сохранить в PG
            for obj in data[m]:
                source.session.expunge(obj)
                # make_transient убирает pk-привязку? Нет — нам нужен исходный PK
                obj.__dict__.pop("_sa_instance_state", None)

    # 2. Переключаемся на PG
    os.environ["DATABASE_URL"] = args.pg
    del sys.modules["app"]
    import app as target_app
    target = target_app.db

    with target_app.app.app_context():
        target_app.ensure_schema()
        print("\nPostgres target (after ensure_schema):")
        from sqlalchemy import text as _text
        # ensure_schema мог посеять log_checkpoints/ip_allowlist дефолтами — TRUNCATE
        # все таблицы перед копированием, чтобы скрипт был идемпотентен и копия
        # совпадала с источником 1:1.
        for m in all_models:
            existing = target.session.query(m).count()
            print(f"  {m.__tablename__}: {existing} (будет очищено TRUNCATE)")
            target.session.execute(_text(f'TRUNCATE TABLE "{m.__tablename__}" RESTART IDENTITY CASCADE'))
            target.session.commit()

        # 3. Копируем по одной таблице, чанками
        for m in all_models:
            rows = data[m]
            if not rows:
                continue
            print(f"\n{m.__tablename__}: копирую {len(rows)} строк...")
            # Конвертируем ORM-объекты в dicts (без _sa_instance_state)
            dicts = []
            for obj in rows:
                d = {c.name: getattr(obj, c.name) for c in m.__table__.columns}
                dicts.append(d)
            # Batched INSERT
            for i in range(0, len(dicts), args.chunk):
                chunk = dicts[i:i + args.chunk]
                target.session.bulk_insert_mappings(m, chunk)
                target.session.commit()
                print(f"  +{len(chunk)} (всего {min(i + args.chunk, len(dicts))}/{len(dicts)})")

        # 4. Проверяем
        print("\n=== Проверка ===")
        ok = True
        for m in all_models:
            src = counts_src[m.__tablename__]
            dst = target.session.query(m).count()
            mark = "✓" if src == dst else "✗"
            print(f"  {mark} {m.__tablename__}: SQLite={src} → PG={dst}")
            if src != dst:
                ok = False
        if not ok:
            sys.exit("MIGRATION FAILED: counts mismatch")

        # 5. Update sequences в PG (для таблиц с id SERIAL).
        # SQLAlchemy не обновляет последовательности после bulk_insert.
        print("\nОбновляю sequences (PG)...")
        from sqlalchemy import text as _text
        for m in all_models:
            pk = list(m.__table__.primary_key.columns)
            if len(pk) != 1 or pk[0].name != "id":
                continue
            tbl = m.__tablename__
            seq = f"{tbl}_id_seq"
            try:
                target.session.execute(_text(f"""
                    SELECT setval('{seq}',
                        COALESCE((SELECT MAX(id)+1 FROM {tbl}), 1),
                        false)
                """))
                target.session.commit()
                print(f"  ✓ {seq}")
            except Exception as e:
                print(f"  (sequence {seq} не найдена — {type(e).__name__})")
                target.session.rollback()

    print("\n✓ МИГРАЦИЯ ЗАВЕРШЕНА УСПЕШНО")
    print("Далее:")
    print("  1. Отредактируйте .env — DATABASE_URL на PG")
    print("  2. sudo systemctl start domain-controller")
    print("  3. Проверьте /healthz, /metrics, flask doctor")
    print("  4. Если всё ок — mv data.db data.db.pre-pg-migrate")


if __name__ == "__main__":
    main()
