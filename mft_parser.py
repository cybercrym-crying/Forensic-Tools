#!/usr/bin/env python3
"""
mft_parser.py - Parses a raw NTFS $MFT file and outputs CSV.

Input must be a RAW extracted $MFT (e.g. via FTK Imager, KAPE, icat,
or `fls`/`tsk`). This script does not read a live NTFS volume.

Usage:
    python3 mft_parser.py <path_to_mft> <output.csv>
"""

import argparse
import csv
import mmap
import struct
from datetime import datetime, timedelta, timezone

FILE_SIGNATURE = b"FILE"

ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF

FILE_NAME_NAMESPACE = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32 & DOS"}

FIELDNAMES = [
    "record_num",
    "seq_number",
    "in_use",
    "is_directory",
    "file_name",
    "namespace",
    "parent_mft",
    "parent_seq",
    "si_created",
    "si_modified",
    "si_mft_modified",
    "si_accessed",
    "fn_created",
    "fn_modified",
    "fn_mft_modified",
    "fn_accessed",
    "logical_size",
    "has_data_attr",
    "data_resident",
    "resident_data",  # printable ASCII; non-printable bytes shown as \xNN
    "all_names",
]


def filetime_to_dt(filetime):
    """Convert Windows FILETIME (100ns ticks since 1601-01-01) to UTC datetime."""
    if not filetime:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=filetime / 10
        )
    except (OverflowError, OSError, ValueError):
        return None


def apply_fixup(record, sector_size=512):
    """Restore sector end-bytes replaced by the Update Sequence Array (NTFS fixup)."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count == 0 or usa_offset + usa_count * 2 > len(record):
        return record
    record = bytearray(record)
    for i in range(1, usa_count):
        sector_end = i * sector_size - 2
        if sector_end + 2 > len(record):
            break
        replacement = record[usa_offset + i * 2 : usa_offset + i * 2 + 2]
        record[sector_end : sector_end + 2] = replacement
    return bytes(record)


def bytes_to_readable(data):
    """Render bytes as printable ASCII for CSV-safe display.

    NUL bytes dropped entirely (not escaped) — UTF-16LE text like
    'M\\x00a\\x00i\\x00n\\x00' becomes readable 'Main' this way, and
    dropping a byte can never break CSV output. Other non-printable
    bytes still escaped as \\xNN since they carry real binary meaning
    and can't be safely dropped without losing structure.
    """
    out = []
    for b in data:
        if b == 0:
            continue
        elif 32 <= b <= 126:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def parse_record(raw, record_num):
    if len(raw) < 48 or raw[0:4] != FILE_SIGNATURE:
        return None
    raw = apply_fixup(raw)

    seq_number = struct.unpack_from("<H", raw, 16)[0]
    attr_offset = struct.unpack_from("<H", raw, 20)[0]
    flags = struct.unpack_from("<H", raw, 22)[0]
    used_size = struct.unpack_from("<I", raw, 24)[0]

    in_use = bool(flags & 0x01)
    is_directory = bool(flags & 0x02)

    si = {}
    file_names = []
    has_data = False
    data_resident = None
    data_size = None
    resident_data = None

    offset = attr_offset
    while offset + 8 <= len(raw) and offset < used_size:
        attr_type = struct.unpack_from("<I", raw, offset)[0]
        if attr_type in (ATTR_END, 0):
            break
        attr_len = struct.unpack_from("<I", raw, offset + 4)[0]
        if attr_len == 0 or offset + attr_len > len(raw):
            break
        non_resident = raw[offset + 8]

        if attr_type == ATTR_STANDARD_INFORMATION and not non_resident:
            content_offset = struct.unpack_from("<H", raw, offset + 20)[0]
            base = offset + content_offset
            crtime, mtime, ctime, atime = struct.unpack_from("<QQQQ", raw, base)
            si = {
                "si_created": filetime_to_dt(crtime),
                "si_modified": filetime_to_dt(mtime),
                "si_mft_modified": filetime_to_dt(ctime),
                "si_accessed": filetime_to_dt(atime),
            }

        elif attr_type == ATTR_FILE_NAME and not non_resident:
            content_offset = struct.unpack_from("<H", raw, offset + 20)[0]
            base = offset + content_offset
            parent_ref = struct.unpack_from("<Q", raw, base)[0]
            crtime, mtime, ctime, atime = struct.unpack_from("<QQQQ", raw, base + 8)
            alloc_sz, real_sz = struct.unpack_from("<QQ", raw, base + 40)
            name_len = raw[base + 64]
            namespace = raw[base + 65]
            name_bytes = raw[base + 66 : base + 66 + name_len * 2]
            name = name_bytes.decode("utf-16-le", errors="replace")
            file_names.append(
                {
                    "fn_name": name,
                    "fn_namespace": FILE_NAME_NAMESPACE.get(namespace, str(namespace)),
                    "fn_parent_mft": parent_ref & 0xFFFFFFFFFFFF,
                    "fn_parent_seq": (parent_ref >> 48) & 0xFFFF,
                    "fn_created": filetime_to_dt(crtime),
                    "fn_modified": filetime_to_dt(mtime),
                    "fn_mft_modified": filetime_to_dt(ctime),
                    "fn_accessed": filetime_to_dt(atime),
                    "fn_logical_size": real_sz,
                    "fn_allocated_size": alloc_sz,
                }
            )

        elif attr_type == ATTR_DATA:
            name_len_attr = raw[offset + 9]
            if name_len_attr == 0:  # unnamed $DATA = main file content stream
                has_data = True
                data_resident = not bool(non_resident)
                if not non_resident:
                    data_size = struct.unpack_from("<I", raw, offset + 16)[0]
                    content_offset = struct.unpack_from("<H", raw, offset + 20)[0]
                    resident_data = bytes_to_readable(
                        raw[
                            offset
                            + content_offset : offset
                            + content_offset
                            + data_size
                        ]
                    )
                else:
                    data_size = struct.unpack_from("<Q", raw, offset + 48)[0]

        offset += attr_len

    # Prefer a Win32/POSIX name over a short DOS 8.3 alias for the main row
    best_fn = next((fn for fn in file_names if fn["fn_namespace"] != "DOS"), None)
    if best_fn is None and file_names:
        best_fn = file_names[0]

    return {
        "record_num": record_num,
        "seq_number": seq_number,
        "in_use": in_use,
        "is_directory": is_directory,
        "file_name": best_fn["fn_name"] if best_fn else "",
        "namespace": best_fn["fn_namespace"] if best_fn else "",
        "parent_mft": best_fn["fn_parent_mft"] if best_fn else "",
        "parent_seq": best_fn["fn_parent_seq"] if best_fn else "",
        "si_created": si.get("si_created"),
        "si_modified": si.get("si_modified"),
        "si_mft_modified": si.get("si_mft_modified"),
        "si_accessed": si.get("si_accessed"),
        "fn_created": best_fn["fn_created"] if best_fn else None,
        "fn_modified": best_fn["fn_modified"] if best_fn else None,
        "fn_mft_modified": best_fn["fn_mft_modified"] if best_fn else None,
        "fn_accessed": best_fn["fn_accessed"] if best_fn else None,
        # $DATA's own size is authoritative; $FILE_NAME's size fields are
        # only updated periodically by Windows and are often stale.
        "logical_size": (
            data_size if has_data else (best_fn["fn_logical_size"] if best_fn else None)
        ),
        "has_data_attr": has_data,
        "data_resident": data_resident,
        "resident_data": resident_data,
        "all_names": " | ".join(
            f"{fn['fn_name']} ({fn['fn_namespace']})" for fn in file_names
        ),
    }


def detect_record_size(mm, filesize):
    if filesize >= 32 and mm[0:4] == FILE_SIGNATURE:
        alloc = struct.unpack_from("<I", mm, 28)[0]
        if alloc in (512, 1024, 2048, 4096):
            return alloc
    return 1024


def main():
    ap = argparse.ArgumentParser(description="Parse a raw NTFS $MFT file into CSV")
    ap.add_argument("mft_path", help="Path to raw extracted $MFT file")
    ap.add_argument("output_csv", help="Path to output CSV file")
    args = ap.parse_args()

    with open(args.mft_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        filesize = len(mm)
        record_size = detect_record_size(mm, filesize)

        scanned = parsed = 0
        with open(args.output_csv, "w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=FIELDNAMES)
            writer.writeheader()

            record_num = 0
            offset = 0
            while offset + record_size <= filesize:
                raw = mm[offset : offset + record_size]
                scanned += 1
                if raw[0:4] == FILE_SIGNATURE:
                    try:
                        row = parse_record(raw, record_num)
                    except (struct.error, IndexError):
                        row = None
                    if row:
                        writer.writerow(row)
                        parsed += 1
                offset += record_size
                record_num += 1
        mm.close()

    print(
        f"Record size {record_size} byte. Scan {scanned} slot, parsed {parsed} valid FILE record -> {args.output_csv}"
    )


if __name__ == "__main__":
    main()
