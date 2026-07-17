#!/usr/bin/env python3
"""
sru_parse.py - Parse Windows SRUM database (SRUDB.dat) on Linux.

SRUM = System Resource Usage Monitor. SRUDB.dat is an ESE/JetBlue database
(same format as NTFS $Extend, Windows Search, etc). This tool uses the
pure-Python `dissect.esedb` library, so it does not need libesedb compiled
on Linux - no native ESE build dependency.

Usage:
    python3 sru_parse.py SRUDB.dat -o output_dir
    python3 sru_parse.py SRUDB.dat --list

Dependency:
    pip install dissect.esedb --break-system-packages
"""

import argparse
import csv
import re
import struct
import sys
from datetime import datetime, timedelta
from pathlib import Path

from dissect.esedb import EseDB
from dissect.esedb.c_esedb import JET_coltyp

# Known SRUM table GUIDs -> friendly names (informational only, not required to parse)
KNOWN_TABLES = {
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "AppResourceUseInfo",
    "{DD6636C4-8929-4683-974E-22C046A43763}": "NetworkConnectivityUsage",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "NetworkDataUsage",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": "EnergyUsage",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "AppTimelineProvider",
    "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}": "EnergyUsageLT",
    "{5C8CF1C7-7257-4F13-B223-970EF5939312}": "Push Notification",
}

OLE_EPOCH = datetime(1899, 12, 30)


def ole_date_to_dt(value):
    """Convert an ESE DateTime column value to an ISO datetime string.

    dissect.esedb reads JET_coltyp.DateTime as a raw int64 (see its c_esedb.py comment),
    because interpretation differs per database. Verified against real SRUDB.dat: SRUM
    stores it as an OLE Automation date (double, days since 1899-12-30), with the double's
    bit pattern carried in the int64 - not a plain Windows FILETIME.
    """
    if not value:
        return ""
    try:
        days = struct.unpack("<d", struct.pack("<q", value))[0]
        return (OLE_EPOCH + timedelta(days=days)).isoformat()
    except (OverflowError, OSError, struct.error):
        return f"raw:{value}"


FILETIME_EPOCH = datetime(1601, 1, 1)
# Verified against real SRUDB.dat: these columns hold a plain Windows FILETIME (100ns since
# 1601-01-01) stored as a LongLong/Currency column, NOT the JET DateTime type used by TimeStamp.
FILETIME_NAME_COLS = {"StartTime", "EndTime", "ConnectStartTime"}


def filetime_to_dt(value):
    """Convert a plain Windows FILETIME int to an ISO datetime string."""
    if not value:
        return ""
    try:
        return (FILETIME_EPOCH + timedelta(microseconds=value / 10)).isoformat()
    except (OverflowError, OSError):
        return f"raw:{value}"


def sid_from_bytes(buf):
    """Decode a binary Windows SID into its S-1-5-... string form."""
    try:
        revision = buf[0]
        sub_count = buf[1]
        authority = int.from_bytes(buf[2:8], "big")
        subs = struct.unpack(f"<{sub_count}I", buf[8 : 8 + 4 * sub_count])
        return "S-%d-%d-%s" % (revision, authority, "-".join(str(s) for s in subs))
    except (IndexError, struct.error):
        return buf.hex()


def build_id_map(db):
    """Build {IdIndex: resolved_string} from SruDbIdMapTable (maps AppId/UserId -> real values)."""
    id_map = {}
    try:
        table = db.table("SruDbIdMapTable")
    except KeyError:
        return id_map

    for record in table.records():
        row = record.as_dict()
        idx = row.get("IdIndex")
        idtype = row.get("IdType")
        blob = row.get("IdBlob")
        if idx is None or blob is None:
            continue
        if idtype == 3:  # SID
            id_map[idx] = sid_from_bytes(bytes(blob))
        else:  # string (app path etc), stored UTF-16LE
            try:
                id_map[idx] = (
                    bytes(blob).decode("utf-16-le", errors="replace").rstrip("\x00")
                )
            except Exception:
                id_map[idx] = bytes(blob).hex()
    return id_map


def sanitize(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def dump_table(table, id_map, out_path):
    columns = table.column_names
    datetime_cols = {c for c in columns if table.column(c).type == JET_coltyp.DateTime}
    filetime_cols = {c for c in columns if c in FILETIME_NAME_COLS}
    resolve_cols = {c for c in columns if c in ("AppId", "UserId")}

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        count = 0
        for record in table.records():
            row = record.as_dict()
            out_row = []
            for col in columns:
                val = row.get(col)
                if val is None:
                    out_row.append("")
                elif col in resolve_cols and isinstance(val, int) and val in id_map:
                    out_row.append(id_map[val])
                elif col in datetime_cols and isinstance(val, int):
                    out_row.append(ole_date_to_dt(val))
                elif col in filetime_cols and isinstance(val, int):
                    out_row.append(filetime_to_dt(val))
                elif isinstance(val, (bytes, bytearray, memoryview)):
                    out_row.append(bytes(val).hex())
                else:
                    out_row.append(val)
            writer.writerow(out_row)
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(
        description="Parse a Windows SRUM database (SRUDB.dat) into CSV files."
    )
    parser.add_argument("srudb", help="Path to SRUDB.dat")
    parser.add_argument(
        "-o",
        "--output",
        default="sru_output",
        help="Output directory for CSVs (default: sru_output)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Only list tables found in the database, no CSV output",
    )
    args = parser.parse_args()

    src = Path(args.srudb)
    if not src.is_file():
        print(f"error: file not found: {src}", file=sys.stderr)
        return 1

    with open(src, "rb") as fh:
        try:
            db = EseDB(fh)
        except Exception as e:
            print(
                f"error: failed to parse '{src}' as an ESE database: {e}",
                file=sys.stderr,
            )
            return 1

        tables = [t for t in db.tables() if not t.name.startswith("MSys")]

        if args.list:
            for t in tables:
                friendly = KNOWN_TABLES.get(t.name, "")
                label = f" ({friendly})" if friendly else ""
                print(f"{t.name}{label} - {len(t.column_names)} columns")
            return 0

        id_map = build_id_map(db)
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)

        used_paths = set()
        for t in tables:
            friendly = KNOWN_TABLES.get(t.name, t.name)
            out_path = out_dir / f"{sanitize(friendly)}.csv"
            if out_path in used_paths:
                # Duplicate table name in catalog (seen in real SRUM files) - disambiguate by root page.
                out_path = out_dir / f"{sanitize(friendly)}_{t.root_page}.csv"
            used_paths.add(out_path)
            try:
                n = dump_table(t, id_map, out_path)
                print(f"{t.name} -> {out_path} ({n} rows)")
            except Exception as e:
                print(f"warning: failed on table '{t.name}': {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
