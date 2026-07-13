#!/usr/bin/env python3
"""
logfile_parser.py - Parses a raw NTFS $LogFile transaction log into CSV.

Input must be the RAW extracted $LogFile (e.g. via KAPE, FTK Imager,
icat). This script does not read a live NTFS volume.

CONFIDENCE NOTE (read before relying on this for casework):
  $LogFile has no official Microsoft specification. Everything below is
  reconstructed from community DFIR research, not from documentation
  Microsoft publishes. Two parts of this script have different
  confidence levels:

  - PAGE level (RCRD/RSTR/CHKD signature, page-size auto-detect, the
    NTFS multi-sector-transfer "fixup" mechanism) -- HIGH confidence.
    This mirrors the same fixup convention used by $MFT, which is
    well established.

  - RECORD level (the fields inside each page: ClientPreviousLsn,
    RedoOperation/UndoOperation codes, TargetVcn/TargetLcn, etc.) --
    MODERATE confidence. The field names match what tools such as
    Eric Zimmerman's LogFileParser expose, but Windows 8+ introduced a
    restructured log record format (v2) that may not match the
    classic (XP-7, v1) layout implemented here byte-for-byte.

  Recommendation: spot-check this script's output for a few records
  against a hex editor or an established tool (e.g. LogFileParser,
  libfsntfs) before citing it in a report. Treat the opcode names as
  a reference, not ground truth.

Usage:
    python3 logfile_parser.py <path_to_LogFile> <output.csv>
"""

import argparse
import csv
import mmap
import struct

PAGE_SIGNATURES = (b"RCRD", b"RSTR", b"CHKD")
CANDIDATE_PAGE_SIZES = [4096, 8192, 16384, 2048]

# Best-effort redo/undo operation code names (community research, not an
# official Microsoft list -- treat as reference).
OPERATION_NAMES = {
    0x00: "Noop",
    0x01: "CompensationlogRecord",
    0x02: "InitializeFileRecordSegment",
    0x03: "DeallocateFileRecordSegment",
    0x04: "WriteEndOfFileRecordSegment",
    0x05: "CreateAttribute",
    0x06: "DeleteAttribute",
    0x07: "UpdateResidentValue",
    0x08: "UpdateNonresidentValue",
    0x09: "UpdateMappingPairs",
    0x0A: "DeleteDirtyClusters",
    0x0B: "SetNewAttributeSizes",
    0x0C: "AddIndexEntryRoot",
    0x0D: "DeleteIndexEntryRoot",
    0x0E: "AddIndexEntryAllocation",
    0x0F: "DeleteIndexEntryAllocation",
    0x10: "WriteEndOfIndexBuffer",
    0x11: "SetIndexEntryVcnRoot",
    0x12: "SetIndexEntryVcnAllocation",
    0x13: "UpdateFileNameRoot",
    0x14: "UpdateFileNameAllocation",
    0x15: "SetBitsInNonresidentBitMap",
    0x16: "ClearBitsInNonresidentBitMap",
    0x17: "HotFix",
    0x18: "EndTopLevelAction",
    0x19: "PrepareTransaction",
    0x1A: "CommitTransaction",
    0x1B: "ForgetTransaction",
    0x1C: "OpenNonresidentAttribute",
    0x1D: "OpenAttributeTableDump",
    0x1E: "AttributeNamesDump",
    0x1F: "DirtyPageTableDump",
    0x20: "TransactionTableDump",
    0x21: "UpdateRecordDataRoot",
}

RECORD_TYPE_NAMES = {1: "ClientRecord", 2: "CheckpointRecord"}

FIELDNAMES = [
    "page_offset",
    "page_position",
    "page_count",
    "record_offset",
    "client_previous_lsn",
    "client_undo_next_lsn",
    "client_data_length",
    "client_seq_number",
    "client_index",
    "record_type",
    "record_type_name",
    "transaction_id",
    "flags",
    "redo_op",
    "redo_op_name",
    "undo_op",
    "undo_op_name",
    "redo_offset",
    "redo_length",
    "undo_offset",
    "undo_length",
    "target_attribute",
    "lcns_to_follow",
    "record_offset_in_mft",
    "attribute_offset",
    "mft_cluster_index",
    "target_vcn",
    "target_lcns",
    "redo_data_hex",
    "undo_data_hex",
]

MAX_PAYLOAD_HEX_BYTES = 128  # truncate large redo/undo payloads in CSV


def apply_fixup(page, sector_size=512):
    """Restore sector end-bytes replaced by the Update Sequence Array."""
    usa_offset, usa_count = struct.unpack_from("<HH", page, 4)
    if usa_count == 0 or usa_offset + usa_count * 2 > len(page):
        return page
    page = bytearray(page)
    for i in range(1, usa_count):
        sector_end = i * sector_size - 2
        if sector_end + 2 > len(page):
            break
        replacement = page[usa_offset + i * 2 : usa_offset + i * 2 + 2]
        page[sector_end : sector_end + 2] = replacement
    return bytes(page)


def detect_page_size(mm, filesize, sample_size=8 * 1024 * 1024):
    """Infer RCRD/RSTR page size empirically: try common sizes, keep the
    one with the most periodic signature hits. More robust than trusting
    a specific restart-area field offset we're not fully confident in."""
    sample_end = min(filesize, sample_size)
    best_size, best_hits = CANDIDATE_PAGE_SIZES[0], -1
    for size in CANDIDATE_PAGE_SIZES:
        hits = 0
        offset = 0
        while offset + 4 <= sample_end:
            if mm[offset : offset + 4] in PAGE_SIGNATURES:
                hits += 1
            offset += size
        if hits > best_hits:
            best_hits, best_size = hits, size
    return best_size, best_hits


def parse_records_in_page(page, page_offset):
    """Iterate best-effort log records inside one fixed-up RCRD page."""
    usa_offset, usa_count = struct.unpack_from("<HH", page, 4)
    next_record_offset = struct.unpack_from("<H", page, 24)[0]
    page_count, page_position = struct.unpack_from("<HH", page, 20)

    record_start = usa_offset + usa_count * 2
    record_start = (record_start + 7) // 8 * 8  # 8-byte align

    end = next_record_offset
    if end <= record_start or end > len(page):
        end = len(page)  # header field unreliable/absent -> scan to page end

    rows = []
    offset = record_start
    while offset + 40 <= end:
        client_prev_lsn, client_undo_next_lsn = struct.unpack_from("<QQ", page, offset)
        client_data_length = struct.unpack_from("<I", page, offset + 16)[0]
        client_seq_number, client_index = struct.unpack_from("<HH", page, offset + 20)
        record_type = struct.unpack_from("<I", page, offset + 24)[0]
        transaction_id = struct.unpack_from("<I", page, offset + 28)[0]
        flags = struct.unpack_from("<H", page, offset + 32)[0]

        if client_data_length == 0:
            break  # padding / end of used area in this page

        record_total_len = 40 + client_data_length
        if offset + record_total_len > end:
            break  # doesn't fit -> treat rest of page as padding/unreliable

        row = {
            "page_offset": page_offset,
            "page_position": page_position,
            "page_count": page_count,
            "record_offset": page_offset + offset,
            "client_previous_lsn": client_prev_lsn,
            "client_undo_next_lsn": client_undo_next_lsn,
            "client_data_length": client_data_length,
            "client_seq_number": client_seq_number,
            "client_index": client_index,
            "record_type": record_type,
            "record_type_name": RECORD_TYPE_NAMES.get(
                record_type, f"UNKNOWN(0x{record_type:x})"
            ),
            "transaction_id": transaction_id,
            "flags": flags,
        }

        cd_base = offset + 40
        if client_data_length >= 24:
            (
                redo_op,
                undo_op,
                redo_off,
                redo_len,
                undo_off,
                undo_len,
                target_attr,
                lcns_to_follow,
                rec_off_mft,
                attr_off,
                mft_cluster_idx,
                _pad,
            ) = struct.unpack_from("<HHHHHHHHHHHH", page, cd_base)
            row.update(
                {
                    "redo_op": redo_op,
                    "redo_op_name": OPERATION_NAMES.get(
                        redo_op, f"UNKNOWN(0x{redo_op:x})"
                    ),
                    "undo_op": undo_op,
                    "undo_op_name": OPERATION_NAMES.get(
                        undo_op, f"UNKNOWN(0x{undo_op:x})"
                    ),
                    "redo_offset": redo_off,
                    "redo_length": redo_len,
                    "undo_offset": undo_off,
                    "undo_length": undo_len,
                    "target_attribute": target_attr,
                    "lcns_to_follow": lcns_to_follow,
                    "record_offset_in_mft": rec_off_mft,
                    "attribute_offset": attr_off,
                    "mft_cluster_index": mft_cluster_idx,
                }
            )

            vcn_base = cd_base + 24
            if client_data_length >= 32:
                target_vcn = struct.unpack_from("<q", page, vcn_base)[0]
                row["target_vcn"] = target_vcn

                lcns = []
                lcn_base = vcn_base + 8
                for i in range(min(lcns_to_follow, 32)):  # sanity cap
                    lcn_off = lcn_base + i * 8
                    if lcn_off + 8 > offset + record_total_len:
                        break
                    lcns.append(struct.unpack_from("<q", page, lcn_off)[0])
                row["target_lcns"] = "|".join(str(v) for v in lcns)

                data_base = lcn_base + len(lcns) * 8
                if (
                    redo_len
                    and data_base + redo_off + redo_len <= offset + record_total_len
                ):
                    redo_bytes = page[
                        data_base
                        + 0 : data_base
                        + 0
                        + min(redo_len, MAX_PAYLOAD_HEX_BYTES)
                    ]
                    row["redo_data_hex"] = redo_bytes.hex()
                if undo_len:
                    undo_start = data_base + redo_len
                    if undo_start + undo_len <= offset + record_total_len:
                        undo_bytes = page[
                            undo_start : undo_start
                            + min(undo_len, MAX_PAYLOAD_HEX_BYTES)
                        ]
                        row["undo_data_hex"] = undo_bytes.hex()

        rows.append(row)
        offset += (record_total_len + 7) // 8 * 8  # next record, 8-byte aligned

    return rows


def main():
    ap = argparse.ArgumentParser(
        description="Parse a raw NTFS $LogFile into CSV (best-effort, see script docstring)"
    )
    ap.add_argument("logfile_path", help="Path to raw extracted $LogFile")
    ap.add_argument("output_csv", help="Path to output CSV file")
    args = ap.parse_args()

    with open(args.logfile_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        filesize = len(mm)
        page_size, hits = detect_page_size(mm, filesize)

        pages_rcrd = pages_other = records = errors = 0
        with open(args.output_csv, "w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=FIELDNAMES)
            writer.writeheader()

            offset = 0
            while offset + page_size <= filesize:
                sig = mm[offset : offset + 4]
                if sig == b"RCRD":
                    page = apply_fixup(mm[offset : offset + page_size])
                    try:
                        rows = parse_records_in_page(page, offset)
                        for row in rows:
                            writer.writerow(row)
                        records += len(rows)
                        pages_rcrd += 1
                    except (struct.error, IndexError):
                        errors += 1
                elif sig in PAGE_SIGNATURES:
                    pages_other += 1
                offset += page_size
        mm.close()

    print(
        f"Page size {page_size} byte (detected via {hits} signature hit sample). "
        f"RCRD page {pages_rcrd}, other page {pages_other}, record parsed {records}, "
        f"page error {errors} -> {args.output_csv}"
    )


if __name__ == "__main__":
    main()
