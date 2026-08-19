#!/usr/bin/env python3
"""Подмешивает курируемые цены в собранную базу реестра.

Реестр ФСТЭК цен не содержит и содержать не может — это перечень сертификатов,
а не прайс-лист. Поэтому цены ведутся отдельным файлом `data/prices.csv`,
который правится руками и версионируется в git.

Шаг вынесен из build_db.py намеренно: база пересобирается из реестра
автоматически, и всё, что дописано внутрь неё, при следующей пересборке
исчезло бы. Отдельный шаг переживает пересборку.

Каждая цена обязана нести источник: URL, тип источника и дату сбора.
Строки без источника отбрасываются — цена без происхождения бесполезна
для работы, которую нужно защищать.

Использование:
    python scripts/merge_prices.py --csv data/prices.csv --db data/szi.sqlite
"""

from __future__ import annotations

import argparse
import csv
import re
import sqlite3
import sys
from datetime import date
from pathlib import Path

SCHEMA = """
DROP TABLE IF EXISTS product_prices;
DROP TABLE IF EXISTS certificate_prices;

CREATE TABLE product_prices (
    id            INTEGER PRIMARY KEY,
    product_name  TEXT NOT NULL,
    vendor        TEXT,
    price_min     REAL,
    price_max     REAL,
    currency      TEXT NOT NULL DEFAULT 'RUB',
    -- per_node | per_server | perpetual | yearly | appliance | bundle | unknown
    license_model TEXT NOT NULL DEFAULT 'unknown',
    source_url    TEXT,
    -- vendor | reseller | procurement | NOT_FOUND
    source_type   TEXT NOT NULL,
    collected_at  TEXT NOT NULL,
    note          TEXT
);

CREATE INDEX idx_product_prices_vendor ON product_prices(vendor);
CREATE INDEX idx_product_prices_source ON product_prices(source_type);

-- Связь цены с позициями реестра. Один продукт обычно имеет несколько
-- сертификатов (разные версии и исполнения), поэтому связь многие-ко-многим.
CREATE TABLE certificate_prices (
    certificate_rowid INTEGER NOT NULL,
    price_id          INTEGER NOT NULL REFERENCES product_prices(id) ON DELETE CASCADE,
    PRIMARY KEY (certificate_rowid, price_id)
);

CREATE INDEX idx_certificate_prices_price ON certificate_prices(price_id);
"""

# Слова, по которым нельзя связывать: они есть почти в каждом наименовании
# реестра и дали бы ложные совпадения.
STOP_WORDS = {
    "программное", "изделие", "программно", "аппаратный", "комплекс", "средство",
    "система", "защиты", "информации", "версия", "для", "от", "несанкционированного",
    "доступа", "специальное", "обеспечение", "средств", "шлюз", "модуль",
    # Аббревиатуры, которыми продукт называют в прайсах, но не в реестре:
    # там пишут полную форму («программно-аппаратный комплекс» вместо «ПАК»).
    "пак", "апкш", "сзи", "нсд", "скзи", "апк",
}


def normalize(text: str) -> str:
    """Убирает кавычки и лишние пробелы, приводит к нижнему регистру."""
    text = re.sub(r"[«»\"'`]", " ", text or "")
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def significant_tokens(name: str) -> list[str]:
    """Оставляет только различающие слова наименования продукта.

    Скобочные вставки отбрасываются: в прайсах пишут «... Application Firewall
    (PT AF)», а в реестре аббревиатуры нет, и по ней ничего не найдётся.

    Пунктуация по краям слова снимается — иначе «Шлюз.» из «С-Терра Шлюз.
    Версия 4.3» не совпадёт со стоп-словом «шлюз» и уйдёт в поиск как
    значимое слово, которого в реестре в таком виде нет.
    """
    name = re.sub(r"\([^)]*\)", " ", name or "")
    tokens = re.findall(r"[\w.\-]+", normalize(name))
    tokens = [t.strip(".-") for t in tokens]
    return [t for t in tokens if t and t not in STOP_WORDS and len(t) > 1]


def match_certificates(conn: sqlite3.Connection, product_name: str) -> list[int]:
    """Ищет позиции реестра, относящиеся к продукту.

    Совпадением считается наличие всех значимых слов названия продукта
    в наименовании средства. Порядок слов не важен: в реестре встречается
    и «Dallas Lock 8.0-K», и «система защиты ... Dallas Lock 8.0-K».
    """
    tokens = significant_tokens(product_name)
    if not tokens:
        return []

    matched: list[int] = []
    for rowid, name in conn.execute("SELECT rowid, name FROM certificates"):
        haystack = normalize(name)
        if all(token in haystack for token in tokens):
            matched.append(rowid)
    return matched


def parse_price(raw: str) -> float | None:
    raw = (raw or "").strip().replace(" ", "").replace(" ", "").replace(",", ".")
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def merge(csv_path: Path, db_path: Path, collected_at: str) -> dict:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)

    stats = {"rows": 0, "with_price": 0, "not_found": 0, "skipped": 0, "linked": 0, "unmatched": []}

    with csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=";")
        for row in reader:
            name = (row.get("product_name") or "").strip()
            if not name:
                continue

            stats["rows"] += 1
            source_type = (row.get("source_type") or "").strip() or "NOT_FOUND"
            price_min = parse_price(row.get("price_min", ""))
            price_max = parse_price(row.get("price_max", ""))

            # Цена без источника недопустима: её происхождение нечем подтвердить.
            source_url = (row.get("source_url") or "").strip()
            if price_min is not None and not source_url:
                print(f"  ПРОПУЩЕНО (цена без источника): {name}", file=sys.stderr)
                stats["skipped"] += 1
                continue

            if price_min is None:
                stats["not_found"] += 1
                source_type = "NOT_FOUND"
            else:
                stats["with_price"] += 1
                if price_max is None:
                    price_max = price_min

            cur = conn.execute(
                """INSERT INTO product_prices (
                       product_name, vendor, price_min, price_max, currency,
                       license_model, source_url, source_type, collected_at, note
                   ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    name,
                    (row.get("vendor") or "").strip() or None,
                    price_min,
                    price_max,
                    (row.get("currency") or "RUB").strip() or "RUB",
                    (row.get("license_model") or "unknown").strip() or "unknown",
                    source_url or None,
                    source_type,
                    collected_at,
                    (row.get("note") or "").strip() or None,
                ),
            )
            price_id = cur.lastrowid

            links = match_certificates(conn, name)
            for rowid in links:
                conn.execute(
                    "INSERT OR IGNORE INTO certificate_prices (certificate_rowid, price_id) VALUES (?,?)",
                    (rowid, price_id),
                )
            stats["linked"] += len(links)
            if not links:
                stats["unmatched"].append(name)

    conn.commit()
    conn.close()
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=Path("data/prices.csv"))
    parser.add_argument("--db", type=Path, default=Path("data/szi.sqlite"))
    parser.add_argument("--collected-at", default=date.today().isoformat())
    args = parser.parse_args()

    if not args.csv.exists():
        print(f"файл цен не найден: {args.csv}", file=sys.stderr)
        return 1
    if not args.db.exists():
        print(f"база не найдена: {args.db} — сначала запустите build_db.py", file=sys.stderr)
        return 1

    stats = merge(args.csv, args.db, args.collected_at)

    print(f"строк в файле цен : {stats['rows']}")
    print(f"  с ценой         : {stats['with_price']}")
    print(f"  без цены        : {stats['not_found']}")
    print(f"  отброшено       : {stats['skipped']}")
    print(f"связей с реестром : {stats['linked']}")
    if stats["unmatched"]:
        print(f"не сопоставлено с реестром ({len(stats['unmatched'])}):")
        for name in stats["unmatched"]:
            print(f"  - {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
