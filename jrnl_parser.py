#!/usr/bin/env python3
"""
usnj_parser.py - Parses a raw NTFS $UsnJrnl:$J (USN Journal) stream into CSV.

Input must be the RAW extracted $J alternate data stream (e.g. via
`fsutil usn readjournal`, KAPE, FTK Imager $UsnJrnl:$J export, or
similar). This script does not read a live NTFS volume.

Only USN_RECORD_V2 (standard NTFS) is decoded; V3 (ReFS 128-bit file
IDs) records are skipped.

Usage:
    python3 usnj_parser.py <path_to_J> <output.csv>
"""

import argparse
import csv
import mmap
import struct
from datetime import datetime, timedelta, timezone

REASON_FLAGS = [
    (0x00000001, "DATA_OVERWRITE"),
    (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"),
    (0x00000020, "NAMED_DATA_EXTEND"),
    (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"),
    (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"),
    (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"),
    (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"),
    (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"),
    (0x00200000, "STREAM_CHANGE"),
    (0x00400000, "TRANSACTED_CHANGE"),
    (0x00800000, "INTEGRITY_CHANGE"),
    (0x80000000, "CLOSE"),
]

FIELDNAMES = [
    "usn",
    "timestamp",
    "file_mft_num",
    "file_seq",
    "parent_mft_num",
    "parent_seq",
    "reason",
    "file_attributes",
    "source_info",
    "file_name",
    "record_length",
]


def filetime_to_dt(filetime):
    if not filetime:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=filetime / 10
        )
    except (OverflowError, OSError, ValueError):
        return None


def decode_reason(reason):
    return "|".join(name for bit, name in REASON_FLAGS if reason & bit)


def parse_record(raw):
    """Parse one USN_RECORD_V2. `raw` must be exactly record_length bytes."""
    record_length = struct.unpack_from("<I", raw, 0)[0]
    major_version = struct.unpack_from("<H", raw, 4)[0]
    if major_version != 2:
        return None  # V3 (ReFS) not handled

    file_ref = struct.unpack_from("<Q", raw, 8)[0]
    parent_ref = struct.unpack_from("<Q", raw, 16)[0]
    usn = struct.unpack_from("<q", raw, 24)[0]
    timestamp = struct.unpack_from("<q", raw, 32)[0]
    reason = struct.unpack_from("<I", raw, 40)[0]
    source_info = struct.unpack_from("<I", raw, 44)[0]
    file_attributes = struct.unpack_from("<I", raw, 52)[0]
    name_len = struct.unpack_from("<H", raw, 56)[0]
    name_offset = struct.unpack_from("<H", raw, 58)[0]

    if name_offset + name_len > len(raw):
        return None
    name_bytes = raw[name_offset : name_offset + name_len]
    filename = name_bytes.decode("utf-16-le", errors="replace")

    return {
        "usn": usn,
        "timestamp": filetime_to_dt(timestamp),
        "file_mft_num": file_ref & 0xFFFFFFFFFFFF,
        "file_seq": (file_ref >> 48) & 0xFFFF,
        "parent_mft_num": parent_ref & 0xFFFFFFFFFFFF,
        "parent_seq": (parent_ref >> 48) & 0xFFFF,
        "reason": decode_reason(reason),
        "file_attributes": file_attributes,
        "source_info": source_info,
        "file_name": filename,
        "record_length": record_length,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Parse a raw NTFS $UsnJrnl:$J stream into CSV"
    )
    ap.add_argument("j_path", help="Path to raw extracted $J stream")
    ap.add_argument("output_csv", help="Path to output CSV file")
    args = ap.parse_args()

    with open(args.j_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        filesize = len(mm)

        parsed = skipped = 0
        with open(args.output_csv, "w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=FIELDNAMES)
            writer.writeheader()

            offset = 0
            while offset + 60 <= filesize:
                # Fast-skip a whole zero-filled 4096-byte page (sparse padding).
                if mm[offset : offset + 4] == b"\x00\x00\x00\x00":
                    page_end = (offset // 4096 + 1) * 4096
                    if page_end <= filesize and mm[offset:page_end] == b"\x00" * (
                        page_end - offset
                    ):
                        offset = page_end
                        continue

                record_length = struct.unpack_from("<I", mm, offset)[0]
                major_version, minor_version = struct.unpack_from("<HH", mm, offset + 4)

                # Require a plausible RecordLength AND a real USN_RECORD version
                # (MajorVersion 2 or 3, MinorVersion 0) before trusting this as a
                # record boundary. Without this check, garbage bytes inside a
                # corrupted/misaligned region can look like a valid RecordLength
                # and cause the scan to jump into the middle of the next real
                # record, silently dropping it.
                valid_header = (
                    60 <= record_length <= filesize - offset
                    and major_version in (2, 3)
                    and minor_version == 0
                )
                if not valid_header:
                    # Step 1 byte, not 8: a corrupted or truncated region is not
                    # guaranteed to be a multiple of 8 bytes long, and stepping
                    # by 8 can permanently skip past the true start of the next
                    # real record.
                    offset += 1
                    skipped += 1
                    continue

                try:
                    row = (
                        parse_record(mm[offset : offset + record_length])
                        if major_version == 2
                        else None
                    )
                except (struct.error, IndexError):
                    row = None

                if row:
                    writer.writerow(row)
                    parsed += 1
                offset += record_length
        mm.close()

    print(
        f"Parsed {parsed} USN record, skip {skipped} invalid/padding slot -> {args.output_csv}"
    )


if __name__ == "__main__":
    main()
