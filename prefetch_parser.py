#!/usr/bin/env python3
"""
Windows Prefetch (.pf) Parser & Analyzer - Pure Python, no external
dependencies. Inspired by Eric Zimmerman's PECmd, with additional detail
and export options.

Supported Prefetch format versions:
  17 - Windows XP / 2003
  23 - Windows Vista / 7
  26 - Windows 8 / 8.1
  30 - Windows 10 (all builds, both FileInformation variants)
  31 - Windows 11

Features:
  - Automatic MAM/Xpress-Huffman decompression (pure Python, spec-accurate,
    handles multi-block >64KB streams per official MS-XCA pseudocode)
  - Executable name, run count, all 8 last-run timestamps
  - Volume information: device path, serial number, creation time
  - Directory strings referenced per volume (v23+)
  - Accessed files list, cross-referenced with NTFS $MFT file reference
    (entry number + sequence number) per file, where available (v23+)
  - Cross-validation warnings (e.g. metrics count vs filename count mismatch)
  - Console (human-readable), JSON, and CSV output (summary + timeline,
    single-file or batch across a whole Prefetch folder)
  - Forensic traceability: input file is opened read-only and its
    original atime is restored best-effort after read; SHA-256 of the
    input file, extraction timestamp (UTC), tool version, and git commit
    (if available) are recorded on every parsed record and in every
    output format

Usage:
  python3 prefetch_parser.py file1.pf [file2.pf ...]
  python3 prefetch_parser.py file1.pf [file2.pf ...] --csv ./out_folder
  python3 prefetch_parser.py --dir /path/to/Prefetch/folder
  python3 prefetch_parser.py --dir /path/to/Prefetch/folder --csv ./out
  python3 prefetch_parser.py file1.pf --json
  python3 prefetch_parser.py file1.pf --full        (show all accessed files/dirs, not just a preview)
"""

import struct
import sys
import os
import csv
import json
import hashlib
import subprocess
import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict

# ---------------------------------------------------------------------------
# 0. Tool metadata / forensic traceability
# ---------------------------------------------------------------------------
# Bump TOOL_VERSION whenever parsing logic changes. Record the exact
# TOOL_VERSION + git commit used for a given case in your case notes -
# this is what lets you answer "which exact code produced this output"
# under cross-examination.
TOOL_VERSION = "1.1.0"


def _get_tool_git_commit() -> Optional[str]:
    """Best-effort short git commit hash of this script's repo. Returns
    None (never raises) if this isn't a git checkout, git isn't
    installed, or the lookup fails for any reason - callers must not
    depend on this being present."""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=script_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# 1. Xpress Huffman Decompressor (MS-XCA) - unchanged, spec-accurate
# ---------------------------------------------------------------------------
class HuffmanDecodeError(Exception):
    pass


MAX_BITS = 15
TABLE_SIZE = 1 << MAX_BITS  # 32768
BLOCK_SIZE = 65536


def _build_decode_table(code_lengths):
    table = [None] * TABLE_SIZE
    current_entry = 0
    for bit_length in range(1, MAX_BITS + 1):
        for symbol in range(512):
            if code_lengths[symbol] == bit_length:
                entry_count = 1 << (MAX_BITS - bit_length)
                for _ in range(entry_count):
                    if current_entry >= TABLE_SIZE:
                        raise HuffmanDecodeError(
                            "Invalid compressed data (table overflow)"
                        )
                    table[current_entry] = (symbol, bit_length)
                    current_entry += 1
    return table


def _read16(data, pos):
    if pos + 2 <= len(data):
        return struct.unpack_from("<H", data, pos)[0]
    elif pos + 1 == len(data):
        return data[pos]
    else:
        return 0


def xpress_decompress(data, uncompressed_size):
    out = bytearray()
    pos = 0

    while len(out) < uncompressed_size:
        if pos + 256 > len(data):
            if len(out) >= uncompressed_size:
                break
            raise HuffmanDecodeError(
                f"Not enough remaining data for a new Huffman table "
                f"(pos={pos}, len(data)={len(data)}, out={len(out)}/{uncompressed_size})"
            )

        code_lengths = [0] * 512
        for i in range(256):
            b = data[pos + i]
            code_lengths[2 * i] = b & 0x0F
            code_lengths[2 * i + 1] = (b >> 4) & 0x0F

        table = _build_decode_table(code_lengths)
        current_position = pos + 256

        next_bits = _read16(data, current_position)
        current_position += 2
        next_bits <<= 16
        next_bits |= _read16(data, current_position)
        current_position += 2
        next_bits &= 0xFFFFFFFF

        extra_bit_count = 16
        block_end = len(out) + BLOCK_SIZE

        while len(out) < block_end and len(out) < uncompressed_size:
            next15 = (next_bits >> (32 - 15)) & 0x7FFF
            entry = table[next15]

            if entry is None:
                raise HuffmanDecodeError("Invalid Huffman code during decode")

            symbol, sym_bit_length = entry
            next_bits = (next_bits << sym_bit_length) & 0xFFFFFFFF
            extra_bit_count -= sym_bit_length

            if extra_bit_count < 0:
                w = _read16(data, current_position)
                next_bits |= (w << (-extra_bit_count)) & 0xFFFFFFFF
                next_bits &= 0xFFFFFFFF
                extra_bit_count += 16
                current_position += 2

            if symbol < 256:
                out.append(symbol)
                continue

            if (
                symbol == 256
                and current_position >= len(data)
                and len(out) >= uncompressed_size
            ):
                return bytes(out[:uncompressed_size])

            sym = symbol - 256
            match_length = sym % 16
            match_offset_bit_length = sym // 16

            if match_length == 15:
                if current_position >= len(data):
                    raise HuffmanDecodeError(
                        "Out of data while reading match length extension"
                    )
                match_length = data[current_position]
                current_position += 1

                if match_length == 255:
                    match_length = _read16(data, current_position)
                    current_position += 2
                    if match_length < 15:
                        raise HuffmanDecodeError("Invalid match length extension (<15)")
                    match_length -= 15
                match_length += 15

            match_length += 3

            if match_offset_bit_length:
                match_offset = (
                    next_bits >> (32 - match_offset_bit_length)
                ) & 0xFFFFFFFF
            else:
                match_offset = 0

            match_offset += 1 << match_offset_bit_length
            next_bits = (next_bits << match_offset_bit_length) & 0xFFFFFFFF
            extra_bit_count -= match_offset_bit_length

            if extra_bit_count < 0:
                w = _read16(data, current_position)
                next_bits |= (w << (-extra_bit_count)) & 0xFFFFFFFF
                next_bits &= 0xFFFFFFFF
                extra_bit_count += 16
                current_position += 2

            if match_offset > len(out) or match_offset == 0:
                raise HuffmanDecodeError(
                    f"Invalid match offset: {match_offset} (output length={len(out)})"
                )

            src = len(out) - match_offset
            for i in range(match_length):
                if len(out) >= uncompressed_size:
                    break
                out.append(out[src + i])

        pos = current_position

    return bytes(out[:uncompressed_size])


# ---------------------------------------------------------------------------
# 2. MAM Container Decompression
# ---------------------------------------------------------------------------
def decompress_mam(raw: bytes) -> bytes:
    if raw[:3] != b"MAM":
        return raw

    flag = raw[3]
    uncompressed_size = struct.unpack_from("<I", raw, 4)[0]
    payload = raw[8:]

    if flag != 0x04:
        raise ValueError(f"Unknown MAM compression format: flag=0x{flag:02x}")

    try:
        return xpress_decompress(payload, uncompressed_size)
    except HuffmanDecodeError as e:
        raise ValueError(f"Failed to decompress Xpress Huffman: {e}")


# ---------------------------------------------------------------------------
# 3. Data Structures
# ---------------------------------------------------------------------------
VERSION_OS_MAP = {
    17: "Windows XP / Server 2003",
    23: "Windows Vista / Server 2008 / Windows 7",
    26: "Windows 8 / 8.1",
    30: "Windows 10",
    31: "Windows 11",
}


@dataclass
class VolumeInfo:
    device_path: str = ""
    creation_time: Optional[str] = None
    serial_number: Optional[str] = None
    directories: List[str] = field(default_factory=list)
    directory_count: int = 0
    file_reference_count: int = 0


@dataclass
class AccessedFile:
    path: str = ""
    mft_entry: Optional[int] = None
    mft_sequence: Optional[int] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class PrefetchData:
    file_path: str = ""
    sha256: str = ""
    extraction_timestamp: str = ""
    tool_version: str = ""
    tool_git_commit: Optional[str] = None
    format_version: int = 0
    os_guess: str = ""
    signature: str = ""
    executable_name: str = ""
    prefetch_hash: str = ""
    file_size: int = 0
    run_count: int = 0
    last_run_times: List[str] = field(default_factory=list)
    volumes: List[VolumeInfo] = field(default_factory=list)
    accessed_files: List[AccessedFile] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# 4. Helpers
# ---------------------------------------------------------------------------
def read_utf16_str(data: bytes, offset: int, max_chars: int = 260) -> str:
    end = offset
    limit = min(len(data), offset + max_chars * 2)
    while end + 1 < limit:
        if data[end] == 0 and data[end + 1] == 0:
            break
        end += 2
    try:
        return data[offset:end].decode("utf-16-le", errors="replace")
    except Exception:
        return ""


def filetime_to_datetime(filetime: int) -> Optional[str]:
    if not filetime:
        return None
    try:
        epoch_diff = 116444736000000000  # 1601-01-01 -> 1970-01-01, in 100ns units
        unix_ts = (filetime - epoch_diff) / 10_000_000
        if unix_ts < 0 or unix_ts > 32503680000:
            return None
        return datetime.datetime.fromtimestamp(
            unix_ts, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None


def decode_file_reference(ref: int):
    """
    NTFS FILE_REFERENCE: low 48 bits = MFT entry number,
    high 16 bits = sequence number. Returns (None, None) if unset.
    """
    if not ref:
        return None, None
    mft_entry = ref & 0xFFFFFFFFFFFF
    mft_sequence = (ref >> 48) & 0xFFFF
    return mft_entry, mft_sequence


# ---------------------------------------------------------------------------
# 5. Main SCCA Parser
# ---------------------------------------------------------------------------
class PrefetchParser:
    def parse_file(self, file_path: str) -> PrefetchData:
        # Snapshot original stat before touching the file at all. Opening
        # a file for read can itself update NTFS Last Accessed Time (atime)
        # depending on filesystem/OS settings; we restore it afterward on
        # a best-effort basis. Note this is a courtesy, not a guarantee -
        # working from a write-blocked image/mount is the only real
        # guarantee of evidence integrity.
        orig_stat = None
        try:
            orig_stat = os.stat(file_path)
        except OSError:
            pass

        with open(file_path, "rb") as f:
            raw_input = f.read()

        if orig_stat is not None:
            try:
                os.utime(file_path, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns))
            except OSError:
                pass  # e.g. read-only evidence mount - atime was never touched

        input_sha256 = hashlib.sha256(raw_input).hexdigest()
        extraction_ts = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

        raw = decompress_mam(raw_input)

        if len(raw) < 0x54 or raw[4:8] != b"SCCA":
            raise ValueError("Signature 'SCCA' not found - not a valid Prefetch file")

        pf = PrefetchData(file_path=file_path)
        pf.sha256 = input_sha256
        pf.extraction_timestamp = extraction_ts
        pf.tool_version = TOOL_VERSION
        pf.tool_git_commit = _get_tool_git_commit()
        pf.file_size = len(raw)
        pf.signature = "SCCA"

        version = struct.unpack_from("<I", raw, 0)[0]
        pf.format_version = version
        pf.os_guess = VERSION_OS_MAP.get(version, "Unknown")

        pf.executable_name = read_utf16_str(raw, 0x10, 29).rstrip("\x00")

        phash = struct.unpack_from("<I", raw, 0x4C)[0]
        pf.prefetch_hash = f"0x{phash:08X}"

        # All FileInformation offsets below are relative to base=0x54
        # (start of FileInformation struct, right after the 84-byte file
        # header), per the libscca specification:
        # https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
        base = 0x54

        if version == 17:
            self._parse_common(
                raw,
                pf,
                base,
                last_run_rel=36,
                run_count_rel=60,
                num_run_times=1,
                vol_entry_size=40,
                metrics_entry_size=20,
                has_file_reference=False,
                has_directories=False,
            )
        elif version == 23:
            self._parse_common(
                raw,
                pf,
                base,
                last_run_rel=44,
                run_count_rel=68,
                num_run_times=1,
                vol_entry_size=104,
                metrics_entry_size=32,
                has_file_reference=True,
                has_directories=True,
            )
        elif version == 26:
            self._parse_common(
                raw,
                pf,
                base,
                last_run_rel=44,
                run_count_rel=124,
                num_run_times=8,
                vol_entry_size=104,
                metrics_entry_size=32,
                has_file_reference=True,
                has_directories=True,
            )
        elif version in (30, 31):
            # Windows 10/11: two FileInformation variants exist (212 vs 220
            # bytes). Detected via the Section A (metrics array) offset,
            # which is fixed at 0x130 (variant 1) or 0x128 (variant 2).
            sec_a_off = struct.unpack_from("<I", raw, base)[0]
            run_count_rel = 116 if sec_a_off == 0x128 else 124
            self._parse_common(
                raw,
                pf,
                base,
                last_run_rel=44,
                run_count_rel=run_count_rel,
                num_run_times=8,
                vol_entry_size=96,
                metrics_entry_size=32,
                has_file_reference=True,
                has_directories=True,
            )
        else:
            raise ValueError(f"Unsupported Prefetch format version: {version}")

        return pf

    def _parse_common(
        self,
        raw,
        pf,
        base,
        last_run_rel,
        run_count_rel,
        num_run_times,
        vol_entry_size,
        metrics_entry_size,
        has_file_reference,
        has_directories,
    ):
        sec_a_off, sec_a_cnt = struct.unpack_from("<II", raw, base + 0)
        sec_c_off, sec_c_len = struct.unpack_from("<II", raw, base + 16)
        sec_d_off, sec_d_cnt, sec_d_len = struct.unpack_from("<III", raw, base + 24)

        last_run_off = base + last_run_rel
        run_count_off = base + run_count_rel

        run_times = []
        for i in range(num_run_times):
            off = last_run_off + i * 8
            if off + 8 > len(raw):
                break
            ft = struct.unpack_from("<Q", raw, off)[0]
            ts = filetime_to_datetime(ft)
            if ts:
                run_times.append(ts)
        pf.last_run_times = run_times

        if run_count_off + 4 <= len(raw):
            pf.run_count = struct.unpack_from("<I", raw, run_count_off)[0]

        filenames = self._parse_filename_strings(raw, sec_c_off, sec_c_len)
        file_refs = self._parse_file_references(
            raw, sec_a_off, sec_a_cnt, metrics_entry_size, has_file_reference
        )

        if file_refs and len(file_refs) != len(filenames):
            pf.warnings.append(
                f"Metrics entry count ({len(file_refs)}) does not match "
                f"filename count ({len(filenames)}); file references may "
                f"not align 1:1 with all accessed files."
            )

        for idx, name in enumerate(filenames):
            ref = file_refs[idx] if idx < len(file_refs) else None
            mft_entry, mft_seq = decode_file_reference(ref) if ref else (None, None)
            pf.accessed_files.append(
                AccessedFile(path=name, mft_entry=mft_entry, mft_sequence=mft_seq)
            )

        self._parse_volumes(
            raw, sec_d_off, sec_d_cnt, vol_entry_size, has_directories, pf
        )

    def _parse_filename_strings(self, raw, offset, length) -> List[str]:
        if offset == 0 or length == 0 or offset + length > len(raw):
            return []
        block = raw[offset : offset + length]
        strings = []
        start = 0
        i = 0
        while i + 1 < len(block):
            if block[i] == 0 and block[i + 1] == 0:
                if i > start:
                    s = block[start:i].decode("utf-16-le", errors="replace")
                    if s:
                        strings.append(s)
                start = i + 2
            i += 2
        return strings

    def _parse_file_references(
        self, raw, offset, count, entry_size, has_file_reference
    ):
        """
        Returns a list of raw 8-byte NTFS FILE_REFERENCE values (one per
        file metrics array entry, same order as the filenames block), or
        an empty list if this version doesn't carry file references or
        the section is out of bounds.
        """
        if not has_file_reference or offset == 0 or count == 0:
            return []
        refs = []
        for i in range(count):
            entry_off = offset + i * entry_size
            if entry_off + entry_size > len(raw):
                break
            try:
                # File reference is the trailing 8 bytes of the 32-byte
                # metrics entry (offset +24), confirmed against known-good
                # samples cross-checked with libscca.
                ref = struct.unpack_from("<Q", raw, entry_off + 24)[0]
                refs.append(ref)
            except struct.error:
                break
        return refs

    def _parse_volumes(self, raw, offset, count, entry_size, has_directories, pf):
        for i in range(count):
            entry_off = offset + i * entry_size
            if entry_off + entry_size > len(raw):
                break
            try:
                dev_path_off, dev_path_len = struct.unpack_from("<II", raw, entry_off)
                creation_ft = struct.unpack_from("<Q", raw, entry_off + 8)[0]
                serial = struct.unpack_from("<I", raw, entry_off + 16)[0]

                vol = VolumeInfo()
                if dev_path_off and dev_path_len:
                    abs_off = offset + dev_path_off
                    vol.device_path = read_utf16_str(raw, abs_off, dev_path_len)
                vol.creation_time = filetime_to_datetime(creation_ft)
                vol.serial_number = f"0x{serial:08X}"

                if has_directories and entry_off + 36 <= len(raw):
                    try:
                        file_ref_size = struct.unpack_from("<I", raw, entry_off + 24)[0]
                        dir_str_off = struct.unpack_from("<I", raw, entry_off + 28)[0]
                        num_dirs = struct.unpack_from("<I", raw, entry_off + 32)[0]
                        vol.file_reference_count = (
                            file_ref_size // 8 if file_ref_size else 0
                        )

                        dirs = []
                        if dir_str_off and num_dirs and num_dirs < 100000:
                            pos = offset + dir_str_off
                            for _ in range(num_dirs):
                                if pos + 2 > len(raw):
                                    break
                                numchars = struct.unpack_from("<H", raw, pos)[0]
                                pos += 2
                                if pos + numchars * 2 > len(raw):
                                    break
                                s = raw[pos : pos + numchars * 2].decode(
                                    "utf-16-le", errors="replace"
                                )
                                pos += numchars * 2 + 2  # skip string + null terminator
                                dirs.append(s)
                        vol.directories = dirs
                        vol.directory_count = len(dirs)
                    except struct.error:
                        pass

                pf.volumes.append(vol)
            except struct.error:
                break


# ---------------------------------------------------------------------------
# 6. Output formatting: console, JSON, CSV
# ---------------------------------------------------------------------------
def print_human(pf: PrefetchData, full: bool = False):
    print("=" * 78)
    print(f"File              : {pf.file_path}")
    print(f"SHA-256 (input)   : {pf.sha256}")
    print(f"Extracted         : {pf.extraction_timestamp}")
    print(
        f"Tool Version      : {pf.tool_version}"
        + (f" (git {pf.tool_git_commit})" if pf.tool_git_commit else "")
    )
    print(f"Format Version    : {pf.format_version} ({pf.os_guess})")
    print(f"Executable Name   : {pf.executable_name}")
    print(f"Prefetch Hash     : {pf.prefetch_hash}")
    print(f"Run Count         : {pf.run_count}")
    print(
        f"Last Run Times    : {', '.join(pf.last_run_times) if pf.last_run_times else '-'}"
    )

    print(f"Volume Count      : {len(pf.volumes)}")
    for v in pf.volumes:
        print(
            f"  - {v.device_path} (serial={v.serial_number}, created={v.creation_time})"
        )
        if v.directory_count:
            print(
                f"      Directories referenced: {v.directory_count}"
                f"{' (NTFS file refs: ' + str(v.file_reference_count) + ')' if v.file_reference_count else ''}"
            )
            shown = v.directories if full else v.directories[:10]
            for d in shown:
                print(f"        - {d}")
            if not full and len(v.directories) > 10:
                print(
                    f"        ... and {len(v.directories) - 10} more (use --full to show all)"
                )

    print(f"Accessed Files    : {len(pf.accessed_files)}")
    shown_files = pf.accessed_files if full else pf.accessed_files[:15]
    for af in shown_files:
        ref_str = ""
        if af.mft_entry is not None:
            ref_str = f"  [MFT entry={af.mft_entry}, seq={af.mft_sequence}]"
        print(f"  - {af.path}{ref_str}")
    if not full and len(pf.accessed_files) > 15:
        print(f"  ... and {len(pf.accessed_files) - 15} more (use --full to show all)")

    if pf.warnings:
        print("Warnings:")
        for w in pf.warnings:
            print(f"  ! {w}")
    print()


def write_csv_summary(results: List[PrefetchData], out_path: str):
    fieldnames = [
        "SourceFile",
        "SHA256",
        "ExtractionTimestamp",
        "ToolVersion",
        "ToolGitCommit",
        "FormatVersion",
        "OSGuess",
        "ExecutableName",
        "PrefetchHash",
        "RunCount",
        "LastRunTime1",
        "LastRunTime2",
        "LastRunTime3",
        "LastRunTime4",
        "LastRunTime5",
        "LastRunTime6",
        "LastRunTime7",
        "LastRunTime8",
        "VolumeCount",
        "VolumeDevicePaths",
        "VolumeSerials",
        "VolumeCreationTimes",
        "DirectoryCount",
        "AccessedFileCount",
        "Warnings",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for pf in results:
            row = {
                "SourceFile": pf.file_path,
                "SHA256": pf.sha256,
                "ExtractionTimestamp": pf.extraction_timestamp,
                "ToolVersion": pf.tool_version,
                "ToolGitCommit": pf.tool_git_commit or "",
                "FormatVersion": pf.format_version,
                "OSGuess": pf.os_guess,
                "ExecutableName": pf.executable_name,
                "PrefetchHash": pf.prefetch_hash,
                "RunCount": pf.run_count,
                "VolumeCount": len(pf.volumes),
                "VolumeDevicePaths": " | ".join(v.device_path for v in pf.volumes),
                "VolumeSerials": " | ".join(v.serial_number or "" for v in pf.volumes),
                "VolumeCreationTimes": " | ".join(
                    v.creation_time or "" for v in pf.volumes
                ),
                "DirectoryCount": sum(v.directory_count for v in pf.volumes),
                "AccessedFileCount": len(pf.accessed_files),
                "Warnings": " | ".join(pf.warnings),
            }
            for i in range(8):
                row[f"LastRunTime{i+1}"] = (
                    pf.last_run_times[i] if i < len(pf.last_run_times) else ""
                )
            writer.writerow(row)


def write_csv_timeline(results: List[PrefetchData], out_path: str):
    rows = []
    for pf in results:
        for ts in pf.last_run_times:
            rows.append(
                {
                    "Timestamp": ts,
                    "ExecutableName": pf.executable_name,
                    "PrefetchHash": pf.prefetch_hash,
                    "RunCount": pf.run_count,
                    "SourceFile": pf.file_path,
                    "SHA256": pf.sha256,
                    "ToolVersion": pf.tool_version,
                }
            )
    rows.sort(key=lambda r: r["Timestamp"], reverse=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Timestamp",
                "ExecutableName",
                "PrefetchHash",
                "RunCount",
                "SourceFile",
                "SHA256",
                "ToolVersion",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def write_csv_accessed_files(results: List[PrefetchData], out_path: str):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "SourceFile",
                "ExecutableName",
                "AccessedFilePath",
                "MFTEntry",
                "MFTSequence",
                "SHA256",
                "ToolVersion",
            ],
        )
        writer.writeheader()
        for pf in results:
            for af in pf.accessed_files:
                writer.writerow(
                    {
                        "SourceFile": pf.file_path,
                        "ExecutableName": pf.executable_name,
                        "AccessedFilePath": af.path,
                        "MFTEntry": af.mft_entry if af.mft_entry is not None else "",
                        "MFTSequence": (
                            af.mft_sequence if af.mft_sequence is not None else ""
                        ),
                        "SHA256": pf.sha256,
                        "ToolVersion": pf.tool_version,
                    }
                )


# ---------------------------------------------------------------------------
# 7. CLI
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    args = sys.argv[1:]
    as_json = "--json" in args
    full = "--full" in args
    for flag in ("--json", "--full"):
        if flag in args:
            args.remove(flag)

    csv_dir = None
    if "--csv" in args:
        idx = args.index("--csv")
        if idx + 1 >= len(args):
            print("Error: --csv requires an output folder path.")
            sys.exit(1)
        csv_dir = args[idx + 1]
        del args[idx : idx + 2]

    targets = []
    if args and args[0] == "--dir":
        if len(args) < 2:
            print("Error: --dir requires a folder path.")
            sys.exit(1)
        folder = args[1]
        for fname in sorted(os.listdir(folder)):
            if fname.lower().endswith(".pf"):
                targets.append(os.path.join(folder, fname))
    else:
        targets = args

    if not targets:
        print("No .pf files to process.")
        sys.exit(1)

    parser = PrefetchParser()
    parsed_ok: List[PrefetchData] = []
    json_results = []

    for path in targets:
        try:
            pf = parser.parse_file(path)
            parsed_ok.append(pf)
            json_results.append(pf.to_dict())
            if not as_json and not csv_dir:
                print_human(pf, full=full)
        except Exception as e:
            err = {"file_path": path, "error": str(e)}
            json_results.append(err)
            if not as_json:
                print(f"[FAILED] {path}: {e}")

    if as_json:
        print(json.dumps(json_results, indent=2, ensure_ascii=False))

    if csv_dir:
        os.makedirs(csv_dir, exist_ok=True)
        summary_path = os.path.join(csv_dir, "Prefetch_Summary.csv")
        timeline_path = os.path.join(csv_dir, "Prefetch_Timeline.csv")
        files_path = os.path.join(csv_dir, "Prefetch_AccessedFiles.csv")
        write_csv_summary(parsed_ok, summary_path)
        write_csv_timeline(parsed_ok, timeline_path)
        write_csv_accessed_files(parsed_ok, files_path)
        print(f"CSV written: {summary_path}")
        print(f"CSV written: {timeline_path}")
        print(f"CSV written: {files_path}")


if __name__ == "__main__":
    main()
