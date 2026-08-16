#!/usr/bin/env python3
"""Сборка SQLite-базы из выгрузки Государственного реестра сертифицированных СЗИ ФСТЭК.

Исходник — CSV с reestr.fstec.ru/reg3 (11 колонок, UTF-8).
Результат — SQLite с FTS5-индексом, нормализованными датами, распознанным
типом средства, классом защиты и статусом сертификата.

Использование:
    python scripts/build_db.py --csv data/reg3.csv --db data/szi.sqlite \
        --snapshot-date 2026-08-16
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
from datetime import date
from pathlib import Path

# --------------------------------------------------------------------------
# Классификация средств
# --------------------------------------------------------------------------

# Тип средства по обозначениям ФСТЭК. Порядок важен: первое совпадение выигрывает,
# поэтому более специфичные шаблоны идут раньше общих.
TOOL_TYPES: list[tuple[str, str, str]] = [
    # (код, человекочитаемое название, regexp)
    ("SAVZ", "Средство антивирусной защиты", r"САВЗ|антивирус"),
    ("SOV", "Система обнаружения вторжений", r"\bСОВ\b|обнаружени\w* вторжен"),
    ("ME", "Межсетевой экран", r"\bМЭ\b|межсетев\w* экран"),
    ("SDZ", "Средство доверенной загрузки", r"\bСДЗ\b|доверенной загрузки"),
    ("SKN", "Средство контроля съёмных носителей", r"\bСКН\b|съёмных машинных носителей|съемных машинных носителей"),
    ("SZI_NSD", "СЗИ от несанкционированного доступа",
     r"\bНСД\b|\bСВТ\b|несанкционированн\w+ доступ|разграничени\w* доступа"),
    ("SKZI", "Средство криптографической защиты", r"\bСКЗИ\b|криптограф|шифрован"),
    ("OS", "Операционная система", r"операционн\w* систем"),
    ("DBMS", "Система управления базами данных", r"\bСУБД\b|управления базами данных"),
    ("VIRT", "Средство виртуализации", r"виртуализац|гипервизор"),
    ("SIEM", "Управление событиями безопасности (SIEM)", r"\bSIEM\b|управления событиями"),
    ("PEMIN", "Защита от ПЭМИН", r"ПЭМИН|помехоподавля|генератор\w* шума"),
    ("ACOUSTIC", "Защита речевой информации",
     r"акустическ|акустоэлектр|виброакустич|громкоговорител|микрофон|речевой информации"),
    ("SCAN", "Средство анализа защищённости", r"анализа защищённости|анализа защищенности|сканер безопасности"),
    ("BACKUP", "Резервное копирование", r"резервного копирования|восстановлени\w* данных"),
]

# Привязка типа средства к каноническим методам противодействия ПТСЗИ.
# Коды соответствуют ptszi_controls.code в CyberRisk.
PTSZI_CONTROL_MAP: dict[str, list[str]] = {
    "SAVZ": ["A"],
    "SOV": ["IDS"],
    "ME": ["FW", "DZ"],
    "SDZ": ["L", "AD"],
    "SKN": ["L"],
    "SZI_NSD": ["L", "AD"],
    "SKZI": ["TE", "DS"],
    "OS": ["AD"],
    "DBMS": ["AD"],
    "VIRT": ["AD"],
    "SCAN": ["AD"],
    "SIEM": ["IDS", "AD"],
    "BACKUP": ["R"],
    # PEMIN намеренно не отображается: защита от побочных излучений
    # выходит за рамки 11 методов ПТСЗИ.
}

# Класс защиты: «четвёртого класса защиты», «РД СВТ(3)», «ИТ.МЭ.А4.ПЗ».
CLASS_WORDS = {
    "первого": 1, "второго": 2, "третьего": 3,
    "четвёртого": 4, "четвертого": 4, "пятого": 5, "шестого": 6,
}


def detect_tool_types(name: str, docs: str) -> tuple[str | None, str | None, list[str]]:
    """Определяет типы средства.

    Одно средство нередко сертифицировано сразу по нескольким профилям защиты:
    например, Dallas Lock проходит и как СЗИ от НСД, и как СОВ, и как МЭ.
    Поэтому возвращаем все совпавшие типы, а основным считаем тот, что виден
    в названии — название описывает суть средства, а перечень документов лишь
    перечисляет профили, которым оно удовлетворяет.

    Возвращает (основной тип, его название, все типы).
    """
    all_types: list[str] = []
    for code, _title, pattern in TOOL_TYPES:
        if re.search(pattern, f"{name} {docs}", re.IGNORECASE):
            all_types.append(code)

    # Основной тип: сперва ищем в названии, и только потом — в документах.
    for code, title, pattern in TOOL_TYPES:
        if re.search(pattern, name, re.IGNORECASE):
            return code, title, all_types
    for code, title, pattern in TOOL_TYPES:
        if code in all_types:
            return code, title, all_types
    return None, None, all_types


def detect_protection_class(docs: str) -> int | None:
    """Извлекает класс защиты (1–6). Меньше — выше требования."""
    if not docs:
        return None

    # «... четвёртого класса защиты»
    for word, value in CLASS_WORDS.items():
        if re.search(rf"{word}\s+класса", docs, re.IGNORECASE):
            return value

    # «ИТ.МЭ.А4.ПЗ», «ИТ.СОВ.С4.ПЗ» — цифра после буквы типа
    m = re.search(r"ИТ\.[А-Я]+\.[А-Я](\d)\.ПЗ", docs)
    if m:
        return int(m.group(1))

    # «РД СВТ(3)», «РД МЭ(4)» — но НЕ «РД НДВ(4)»: там уровень контроля
    # недекларированных возможностей, а не класс защиты.
    m = re.search(r"РД\s+(?!НДВ)[А-Я]+\((\d)\)", docs)
    if m:
        return int(m.group(1))

    return None


def detect_ndv_level(docs: str) -> int | None:
    """Уровень контроля отсутствия недекларированных возможностей (РД НДВ)."""
    m = re.search(r"РД\s+НДВ\((\d)\)", docs or "")
    return int(m.group(1)) if m else None


def normalize_date(value: str) -> str | None:
    """Приводит дату к ISO. В выгрузке встречается и ISO, и ДД.ММ.ГГГГ."""
    value = (value or "").strip()
    if not value:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return value
    m = re.fullmatch(r"(\d{2})\.(\d{2})\.(\d{4})", value)
    if m:
        return f"{m.group(3)}-{m.group(2)}-{m.group(1)}"
    return None


def parse_validity(value: str, today: str) -> tuple[str | None, str, int]:
    """Разбирает поле «Срок действия сертификата».

    Кроме дат оно содержит два особых состояния: «Бессрочно» (действует без
    ограничения срока) и «Действие сертификата приостановлено». Без их
    различения бессрочные сертификаты ошибочно считались бы недействующими.

    Возвращает (дата ISO или None, вид срока, признак действительности).
    """
    raw = (value or "").strip()

    if re.match(r"бессрочн", raw, re.IGNORECASE):
        return None, "perpetual", 1
    if re.search(r"приостановлен", raw, re.IGNORECASE):
        return None, "suspended", 0

    iso = normalize_date(raw)
    if iso:
        return iso, "dated", 1 if iso >= today else 0
    return None, "unknown", 0


def clean(value: str | None) -> str | None:
    """Схлопывает пробелы, пустую строку превращает в NULL."""
    if value is None:
        return None
    value = re.sub(r"\s+", " ", value).strip()
    return value or None


# --------------------------------------------------------------------------
# Схема
# --------------------------------------------------------------------------

SCHEMA = """
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS certificate_controls;
DROP TABLE IF EXISTS metadata;
DROP TABLE IF EXISTS certificates_fts;

CREATE TABLE certificates (
    rowid              INTEGER PRIMARY KEY,
    certificate_number TEXT NOT NULL,
    registered_at      TEXT,
    valid_until        TEXT,
    name               TEXT NOT NULL,
    requirements       TEXT,
    scheme             TEXT,
    laboratory         TEXT,
    certification_body TEXT,
    applicant          TEXT,
    applicant_details  TEXT,
    support_until      TEXT,
    tool_type          TEXT,
    tool_type_name     TEXT,
    protection_class   INTEGER,
    ndv_level          INTEGER,
    -- dated | perpetual | suspended | unknown
    validity_kind      TEXT NOT NULL DEFAULT 'unknown',
    is_active          INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_certificates_type   ON certificates(tool_type);
CREATE INDEX idx_certificates_active ON certificates(is_active);
CREATE INDEX idx_certificates_valid  ON certificates(valid_until);
CREATE INDEX idx_certificates_class  ON certificates(protection_class);

-- Связь сертификата с методами противодействия ПТСЗИ (A, FW, IDS, ...).
CREATE TABLE certificate_controls (
    certificate_rowid INTEGER NOT NULL REFERENCES certificates(rowid) ON DELETE CASCADE,
    control_code      TEXT NOT NULL,
    PRIMARY KEY (certificate_rowid, control_code)
);

CREATE INDEX idx_certificate_controls_code ON certificate_controls(control_code);

CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE VIRTUAL TABLE certificates_fts USING fts5(
    name,
    applicant,
    requirements,
    content='certificates',
    content_rowid='rowid',
    tokenize="unicode61 remove_diacritics 2"
);
"""


def build(csv_path: Path, db_path: Path, snapshot_date: str) -> dict:
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8", errors="replace")))
    if not rows:
        raise SystemExit("исходный CSV пуст")

    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)

    today = date.today().isoformat()
    stats = {
        "snapshot_date": snapshot_date,
        "total": 0,
        "active": 0,
        "expired": 0,
        "by_type": {},
        "by_control": {},
        "by_validity": {},
        "with_protection_class": 0,
    }

    for i, row in enumerate(rows, start=1):
        name = clean(row.get("Наименование средства (шифр)")) or ""
        if not name:
            continue

        docs = clean(row.get("Наименования документов, требованиям которых соответствует средство")) or ""
        valid_until, validity_kind, is_active = parse_validity(
            row.get("Срок действия сертификата", ""), today
        )
        tool_type, tool_type_name, all_types = detect_tool_types(name, docs)
        protection_class = detect_protection_class(docs)

        conn.execute(
            """INSERT INTO certificates (
                   rowid, certificate_number, registered_at, valid_until, name,
                   requirements, scheme, laboratory, certification_body,
                   applicant, applicant_details, support_until,
                   tool_type, tool_type_name, protection_class, ndv_level,
                   validity_kind, is_active
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                i,
                clean(row.get("№ сертификата")) or "",
                normalize_date(row.get("Дата внесения в реестр", "")),
                valid_until,
                name,
                docs,
                clean(row.get("Схема сертификации")),
                clean(row.get("Испытательная лаборатория")),
                clean(row.get("Орган по сертификации")),
                clean(row.get("Заявитель")),
                clean(row.get("Реквизиты заявителя (индекс, адрес, телефон)")),
                normalize_date(row.get("Информация об окончании срока технической поддержки, полученная от заявителя", "")),
                tool_type,
                tool_type_name,
                protection_class,
                detect_ndv_level(docs),
                validity_kind,
                is_active,
            ),
        )

        # Средство закрывает методы всех профилей, по которым сертифицировано.
        controls = {c for t in all_types for c in PTSZI_CONTROL_MAP.get(t, [])}
        for control in sorted(controls):
            conn.execute(
                "INSERT OR IGNORE INTO certificate_controls (certificate_rowid, control_code) VALUES (?,?)",
                (i, control),
            )
            if is_active:
                stats["by_control"][control] = stats["by_control"].get(control, 0) + 1

        stats["total"] += 1
        stats["active" if is_active else "expired"] += 1
        stats["by_validity"][validity_kind] = stats["by_validity"].get(validity_kind, 0) + 1
        if protection_class:
            stats["with_protection_class"] += 1
        if tool_type:
            stats["by_type"][tool_type] = stats["by_type"].get(tool_type, 0) + 1

    conn.execute(
        "INSERT INTO certificates_fts(rowid, name, applicant, requirements) "
        "SELECT rowid, name, COALESCE(applicant,''), COALESCE(requirements,'') FROM certificates"
    )

    for key, value in (
        ("source", "https://reestr.fstec.ru/reg3"),
        ("snapshot_date", snapshot_date),
        ("total", str(stats["total"])),
        ("active", str(stats["active"])),
        ("schema_version", "1"),
    ):
        conn.execute("INSERT INTO metadata (key, value) VALUES (?,?)", (key, value))

    conn.commit()
    conn.execute("VACUUM")
    conn.close()
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=Path("data/reg3.csv"))
    parser.add_argument("--db", type=Path, default=Path("data/szi.sqlite"))
    parser.add_argument("--stats", type=Path, default=Path("data/stats.json"))
    parser.add_argument("--snapshot-date", default=date.today().isoformat())
    args = parser.parse_args()

    if not args.csv.exists():
        print(f"не найден исходник: {args.csv}", file=sys.stderr)
        return 1

    stats = build(args.csv, args.db, args.snapshot_date)
    args.stats.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"собрано: {args.db} ({args.db.stat().st_size / 1024:.0f} КБ)")
    print(f"  всего сертификатов : {stats['total']}")
    print(f"  действующих        : {stats['active']}")
    print(f"  с классом защиты   : {stats['with_protection_class']}")
    print(f"  по методам ПТСЗИ   : {stats['by_control']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
