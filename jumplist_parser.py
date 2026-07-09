#!/usr/bin/env python3
"""
jumplist_parser.py

Parser untuk Windows JumpList files:
  - AutomaticDestinations (*.automaticDestinations-ms)  -> format CFBF/OLE,
    tiap stream (selain "DestList") berisi satu Shell Link (LNK) binary.
  - CustomDestinations (*.customDestinations-ms)         -> format flat,
    berisi header + rangkaian LNK item + footer per "category".

Bisa dijalankan di Linux tanpa Windows API sama sekali, karena LNK/CFBF
adalah format biner terdokumentasi (MS-SHLLINK, MS-CFB, MS-SHLLINK DestList).

Dependency: olefile (pip install olefile --break-system-packages)

Author: generated for offline/forensic use di Linux.
"""

import argparse
import csv
import json
import os
import struct
import sys
import uuid
from datetime import datetime, timedelta, timezone

try:
    import olefile
except ImportError:
    print("[!] Modul 'olefile' belum terinstall. Jalankan:\n"
          "    pip install olefile --break-system-packages", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# Konstanta & helper umum
# --------------------------------------------------------------------------

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_datetime(filetime: int):
    """Konversi 64-bit Windows FILETIME ke datetime UTC. None jika 0."""
    if not filetime:
        return None
    try:
        return WINDOWS_EPOCH + timedelta(microseconds=filetime / 10)
    except (OverflowError, OSError):
        return None


def dt_iso(dt):
    return dt.isoformat() if dt else None


def guid_from_bytes(b: bytes) -> str:
    """Bytes little-endian 16 byte -> string GUID standar."""
    return str(uuid.UUID(bytes_le=b))


# CLSID Known Folder umum yang sering muncul di LinkTargetIDList (subset).
KNOWN_FOLDER_GUIDS = {
    "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7": "System32",
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "This PC (My Computer)",
    "5e6c858f-0e22-4760-9afe-ea3317b67173": "User's Files",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "d3162b92-9365-467a-956b-92703aca08af": "This PC (drives)",
    "059a3623-84ea-49e4-a3a1-6e3b73c14ec9": "Recent Items",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "f42ee2d3-909f-4907-8871-4c22fc0bf756": "Documents",
    "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Videos",
    "26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel",
    "21ec2020-3aea-1069-a2dd-08002b30309d": "Control Panel",
    "05d7b0f4-2121-4eff-bf6b-ed3f69b894d9": "Control Panel Category",
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
}


# --------------------------------------------------------------------------
# LNK (Shell Link) Parser -- mengacu ke spesifikasi MS-SHLLINK
# --------------------------------------------------------------------------

# Flags pada LinkFlags
LF_HAS_LINK_TARGET_ID_LIST      = 0x00000001
LF_HAS_LINK_INFO                = 0x00000002
LF_HAS_NAME                     = 0x00000004
LF_HAS_RELATIVE_PATH            = 0x00000008
LF_HAS_WORKING_DIR              = 0x00000010
LF_HAS_ARGUMENTS                = 0x00000020
LF_HAS_ICON_LOCATION            = 0x00000040
LF_IS_UNICODE                   = 0x00000080
LF_FORCE_NO_LINK_INFO           = 0x00000100

FILE_ATTRIBUTE_FLAGS = {
    0x00000001: "READONLY",
    0x00000002: "HIDDEN",
    0x00000004: "SYSTEM",
    0x00000010: "DIRECTORY",
    0x00000020: "ARCHIVE",
    0x00000040: "DEVICE",
    0x00000080: "NORMAL",
    0x00000100: "TEMPORARY",
    0x00000200: "SPARSE_FILE",
    0x00000400: "REPARSE_POINT",
    0x00000800: "COMPRESSED",
    0x00001000: "OFFLINE",
    0x00002000: "NOT_CONTENT_INDEXED",
    0x00004000: "ENCRYPTED",
}


class LNKParseError(Exception):
    pass


def _read_struct(data, offset, fmt):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise LNKParseError(f"Data terlalu pendek di offset {offset} untuk fmt {fmt}")
    return struct.unpack_from(fmt, data, offset), offset + size


def _read_cstring_unicode(data, offset):
    """Baca null-terminated UTF-16LE string mulai dari offset."""
    end = offset
    while end + 1 < len(data):
        if data[end] == 0 and data[end + 1] == 0:
            break
        end += 2
    try:
        s = data[offset:end].decode("utf-16-le", errors="replace")
    except Exception:
        s = ""
    return s, end + 2


def _read_cstring_ansi(data, offset):
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    try:
        s = data[offset:end].decode("cp1252", errors="replace")
    except Exception:
        s = ""
    return s, end + 1


def parse_string_data_item(data, offset, is_unicode):
    """StringData items: CountCharacters (2 bytes) + string (unicode or ansi)."""
    if offset + 2 > len(data):
        return None, offset
    (count,), offset = _read_struct(data, offset, "<H")
    if is_unicode:
        nbytes = count * 2
        raw = data[offset:offset + nbytes]
        s = raw.decode("utf-16-le", errors="replace")
    else:
        nbytes = count
        raw = data[offset:offset + nbytes]
        s = raw.decode("cp1252", errors="replace")
    return s, offset + nbytes


def parse_item_id_list(data, offset, total_len):
    """
    Parse LinkTargetIDList (rangkaian SHITEMID) secara best-effort untuk
    merekonstruksi path dari shell items, dipakai sebagai FALLBACK saat
    LinkInfo/StringData tidak menyimpan path (mis. ForceNoLinkInfo, atau
    target berada di virtual folder/library).

    Return: (list_of_segment_names, new_offset)
    Setiap segment adalah string nama folder/file/drive/GUID sebisa mungkin
    dalam urutan root -> leaf.
    """
    if offset + 2 > total_len:
        return [], offset
    (idlist_size,) = struct.unpack_from("<H", data, offset)
    idlist_start = offset + 2
    idlist_end = idlist_start + idlist_size
    idlist_data = data[idlist_start:idlist_end]

    segments = []
    pos = 0
    n = len(idlist_data)
    while pos + 2 <= n:
        (cb,) = struct.unpack_from("<H", idlist_data, pos)
        if cb == 0:
            break
        item = idlist_data[pos + 2: pos + cb]
        pos += cb
        if not item:
            continue

        seg = _extract_shitem_name(item)
        if seg:
            segments.append(seg)

    return segments, idlist_end


def _find_last_unicode_run(item: bytes, min_len: int = 1):
    """
    Cari run karakter UTF-16LE null-terminated TERAKHIR (paling mendekati
    akhir array bytes) yang terdiri dari karakter printable (0x20-0x7E, atau
    byte tinggi yang valid untuk sebagian karakter non-ASCII umum).
    Dipakai untuk long filename di extension block SHITEMID, yang secara
    empiris cenderung berada di ekor item, diikuti null terminator.
    """
    n = len(item)
    best = None
    # Cari semua null terminator UTF-16 (0x00 0x00 di posisi genap) sebagai
    # kandidat akhir string, lalu mundur untuk ambil run karakternya.
    pos = n - 2
    while pos >= 2:
        if item[pos] == 0 and item[pos + 1] == 0:
            j = pos - 2
            chars = []
            while j >= 0:
                lo, hi = item[j], item[j + 1]
                if hi != 0:
                    break
                if not (0x20 <= lo < 0x7F):
                    break
                chars.append(chr(lo))
                j -= 2
            chars.reverse()
            s = "".join(chars)
            if len(s) >= min_len and any(c.isalnum() for c in s):
                best = s
                break
        pos -= 2
    return best


def _extract_shitem_name(item: bytes):
    """
    Best-effort extraction nama dari satu SHITEMID.
    Menangani beberapa kasus umum:
      - Root/Drive item (mis. "D:\\") -> ambil dari ANSI string ber-pola X:\\
      - FileEntry item (folder/file di FAT/NTFS) -> short name (8.3 ANSI)
        di offset 12, dengan fallback mencari long name unicode di extension
        block (heuristik scan, karena layout persis bervariasi per versi Shell32).
      - GUID/Known-Folder item (root "My Computer", dsb) -> diterjemahkan via
        KNOWN_FOLDER_GUIDS jika cocok, atau diberi label "{GUID}".
      - Item lain yang tidak dikenali -> None (diabaikan, bukan fatal).
    """
    if len(item) < 3:
        return None

    class_type = item[0]

    # --- Drive/Volume item: biasanya berupa ANSI string "C:\" null-terminated
    # dimulai persis di offset 1 untuk class_type 0x2F (drive).
    if class_type == 0x2F:
        s, _ = _read_cstring_ansi(item, 1)
        if s:
            return s.rstrip("\\") + "\\"
        return None

    # --- Root / GUID item (mis. My Computer, Desktop, Libraries): 16 byte GUID
    # biasanya mulai di offset 2 untuk class_type 0x1F.
    if class_type == 0x1F and len(item) >= 18:
        try:
            g = guid_from_bytes(item[2:18])
            name = KNOWN_FOLDER_GUIDS.get(g.lower())
            return name if name else f"{{{g}}}"
        except Exception:
            return None

    # --- FileEntry item (file/folder pada filesystem): class_type biasanya
    # 0x30-0x3F (bit 0x10 = folder, 0x20+ = variasi lain).
    # Layout umum: ClassType(1) Unknown(1) FileSize(4) DateTime(4) Attrs(2)
    #              PrimaryName ANSI (null-terminated, padded ke genap)
    #              [ExtensionBlock berisi long name UTF-16LE]
    if 0x30 <= class_type <= 0x3F and len(item) >= 14:
        short_name, name_end = _read_cstring_ansi(item, 12)

        # Cari long name Unicode: pada extension block Beef0004, string Unicode
        # (long filename) hampir selalu merupakan string tercetak terakhir
        # sebelum penutup item. Maka kita scan MUNDUR dari akhir item untuk
        # menemukan run karakter UTF-16LE valid terakhir -- ini jauh lebih
        # reliable dibanding mengambil "kandidat terpanjang di mana saja",
        # yang rawan salah tangkap padding/metadata biner sebagai teks.
        long_name = _find_last_unicode_run(item, min_len=1)

        name = long_name if long_name else short_name
        return name if name else None

    return None


def parse_link_info(data, offset, total_len):
    """
    LinkInfoHeader:
      LinkInfoSize (4) LinkInfoHeaderSize (4) LinkInfoFlags (4)
      VolumeIDOffset (4) LocalBasePathOffset (4)
      CommonNetworkRelativeLinkOffset (4) CommonPathSuffixOffset (4)
      [LocalBasePathOffsetUnicode (4)] [CommonPathSuffixOffsetUnicode (4)]  (jika header size >= 0x24)
    """
    start = offset
    if offset + 28 > total_len:
        return None, offset
    (link_info_size,) = struct.unpack_from("<I", data, offset)
    end = start + link_info_size
    (header_size, flags, vol_id_off, local_base_off,
     net_off, common_suffix_off) = struct.unpack_from("<IIIIII", data, offset + 4)

    local_base_unicode_off = 0
    common_suffix_unicode_off = 0
    if header_size >= 0x24 and offset + 36 <= total_len:
        (local_base_unicode_off, common_suffix_unicode_off) = struct.unpack_from(
            "<II", data, offset + 28)

    info = {
        "link_info_size": link_info_size,
        "volume_id": None,
        "local_base_path": None,
        "common_network_relative_link": None,
        "common_path_suffix": None,
    }

    has_vol_id_and_local = bool(flags & 0x1)
    has_common_net = bool(flags & 0x2)

    if has_vol_id_and_local and vol_id_off:
        v_off = start + vol_id_off
        try:
            (vol_size, drive_type, serial, vol_label_off) = struct.unpack_from(
                "<IIII", data, v_off)
            label = ""
            if vol_label_off == 0x14 and v_off + 20 < total_len:
                # Unicode label offset variant (rare) -- fallback to ansi read
                pass
            if vol_label_off:
                label, _ = _read_cstring_ansi(data, v_off + vol_label_off)
            drive_types = {
                0: "UNKNOWN", 1: "NO_ROOT_DIR", 2: "REMOVABLE",
                3: "FIXED", 4: "REMOTE", 5: "CDROM", 6: "RAMDISK",
            }
            info["volume_id"] = {
                "drive_type": drive_types.get(drive_type, str(drive_type)),
                "serial_number": f"{serial:08X}",
                "volume_label": label,
            }
        except (struct.error, LNKParseError):
            pass

        if local_base_off:
            path, _ = _read_cstring_ansi(data, start + local_base_off)
            info["local_base_path"] = path

    if local_base_unicode_off:
        path, _ = _read_cstring_unicode(data, start + local_base_unicode_off)
        if path:
            info["local_base_path"] = path

    if has_common_net and net_off:
        n_off = start + net_off
        try:
            # CommonNetworkRelativeLink struct (MS-SHLLINK 2.3.2):
            #   CommonNetworkRelativeLinkSize (4)
            #   CommonNetworkRelativeLinkFlags (4)
            #   NetNameOffset (4)      -- relatif ke awal struct ini (n_off)
            #   DeviceNameOffset (4)   -- relatif ke awal struct ini (n_off)
            #   NetworkProviderType (4)
            #   [NetNameOffsetUnicode (4), DeviceNameOffsetUnicode (4)]  jika NetNameOffset > 0x14
            (cnrl_size, cnrl_flags, net_name_off, device_name_off,
             provider_type) = struct.unpack_from("<IIIII", data, n_off)

            net_name = ""
            device_name = ""
            if net_name_off:
                net_name, _ = _read_cstring_ansi(data, n_off + net_name_off)
            if device_name_off:
                device_name, _ = _read_cstring_ansi(data, n_off + device_name_off)

            # Versi unicode (jika NetNameOffset > 0x14, ada 2 field tambahan
            # setelah NetworkProviderType sebelum ANSI net_name dimulai)
            if net_name_off > 0x14 and n_off + 28 <= total_len:
                (net_name_off_u, device_name_off_u) = struct.unpack_from(
                    "<II", data, n_off + 20)
                if net_name_off_u:
                    u, _ = _read_cstring_unicode(data, n_off + net_name_off_u)
                    if u:
                        net_name = u
                if device_name_off_u:
                    u, _ = _read_cstring_unicode(data, n_off + device_name_off_u)
                    if u:
                        device_name = u

            # ValidDevice flag (bit 0x2) menandakan device_name (mapped drive
            # letter, misal "V:") valid untuk dipakai.
            info["common_network_relative_link"] = {
                "net_name": net_name,          # UNC path, misal \\server\share
                "device_name": device_name,    # drive letter ter-mapping, misal "V:"
                "provider_type": provider_type,
            }
        except struct.error:
            pass

    if common_suffix_off:
        suffix, _ = _read_cstring_ansi(data, start + common_suffix_off)
        info["common_path_suffix"] = suffix
    if common_suffix_unicode_off:
        suffix, _ = _read_cstring_unicode(data, start + common_suffix_unicode_off)
        if suffix:
            info["common_path_suffix"] = suffix

    # Gabungkan full path yang paling berguna.
    # Prioritas: jika ada CommonNetworkRelativeLink -> pakai UNC net_name + suffix
    # (path jaringan sebenarnya), baru fallback ke local_base_path (mis. drive
    # letter lokal atau removable media).
    suffix = info["common_path_suffix"] or ""
    net_link = info.get("common_network_relative_link")
    if net_link and net_link.get("net_name"):
        base = net_link["net_name"]
        sep = "\\" if suffix and not base.endswith("\\") else ""
        info["full_path"] = base + sep + suffix
    else:
        base = info["local_base_path"] or ""
        sep = "\\" if base and suffix and not base.endswith("\\") else ""
        info["full_path"] = (base + sep + suffix) or None

    return info, end


def parse_extra_data_blocks(data, offset, total_len):
    """
    ExtraData: rangkaian block, masing-masing:
      BlockSize (4, termasuk size field), BlockSignature (4), Data...
    Berhenti saat BlockSize < 4 (terminal block).
    Kita ekstrak yang berguna: TRACKER_DATA_BLOCK (0xA0000003) dan
    DISTRIBUTED_LINK_TRACKER untuk MAC address & droid timestamps,
    serta PropertyStoreDataBlock (opsional, di-skip parsing detail).
    """
    result = {}
    while offset + 8 <= total_len:
        (block_size,) = struct.unpack_from("<I", data, offset)
        if block_size < 4:
            break
        (signature,) = struct.unpack_from("<I", data, offset + 4)
        block_data = data[offset + 8: offset + block_size]

        if signature == 0xA0000003 and len(block_data) >= 8:
            # TrackerDataBlock: Length(4) Version(4) MachineID(16)
            # Droid(16 bytes = 2x GUID) DroidBirth(16 bytes = 2x GUID)
            try:
                length, version = struct.unpack_from("<II", block_data, 0)
                machine_id = block_data[8:24].split(b"\x00")[0].decode(
                    "ascii", errors="replace")
                droid = block_data[24:56]
                droid_birth = block_data[56:88]
                mac = None
                if len(droid) >= 32:
                    # Droid Volume GUID (16) + Droid File GUID (16)
                    file_droid = droid[16:32]
                    # Node ID (MAC) = terakhir 6 byte dari File Droid GUID (bytes 10-16 big-endian slice)
                    node = file_droid[10:16]
                    if node != b"\x00" * 6:
                        mac = ":".join(f"{b:02x}" for b in node)
                result["tracker_data_block"] = {
                    "machine_id": machine_id,
                    "mac_address": mac,
                }
            except (struct.error, IndexError):
                pass

        if block_size == 0:
            break
        offset += block_size
    return result


def parse_lnk(data, source_label=""):
    """
    Parse satu blob LNK binary lengkap. Return dict hasil parse, atau
    dict berisi 'error' jika signature tidak cocok / gagal.
    """
    result = {"source": source_label}

    if len(data) < 76:
        result["error"] = "Data terlalu pendek untuk header LNK"
        return result

    header_size, = struct.unpack_from("<I", data, 0)
    clsid = data[4:20]
    expected_clsid = bytes.fromhex("0114020000000000c000000000000046")
    if header_size != 0x4C or clsid != expected_clsid:
        result["error"] = "Bukan file LNK valid (signature/CLSID tidak cocok)"
        return result

    (link_flags, file_attrs,
     ctime, atime, mtime,
     file_size, icon_index, show_cmd,
     hotkey) = struct.unpack_from("<IIQQQIiiH", data, 20)

    is_unicode = bool(link_flags & LF_IS_UNICODE)

    attrs = [name for bit, name in FILE_ATTRIBUTE_FLAGS.items() if file_attrs & bit]

    result.update({
        "link_flags": link_flags,
        "file_attributes": attrs,
        "creation_time": dt_iso(filetime_to_datetime(ctime)),
        "access_time": dt_iso(filetime_to_datetime(atime)),
        "write_time": dt_iso(filetime_to_datetime(mtime)),
        "file_size": file_size,
        "icon_index": icon_index,
        "show_command": show_cmd,
    })

    offset = 0x4C  # akhir header

    idlist_segments = []
    # LinkTargetIDList (opsional) -- diparsing best-effort sebagai fallback
    # path ketika LinkInfo/StringData tidak menyimpan path (mis. target di
    # virtual folder/library, atau ForceNoLinkInfo).
    if link_flags & LF_HAS_LINK_TARGET_ID_LIST:
        try:
            idlist_segments, offset = parse_item_id_list(data, offset, len(data))
        except Exception:
            # fallback aman: skip sesuai size field bila parsing detail gagal
            if offset + 2 <= len(data):
                (idlist_size,) = struct.unpack_from("<H", data, offset)
                offset += 2 + idlist_size

    # LinkInfo (opsional)
    if link_flags & LF_HAS_LINK_INFO and not (link_flags & LF_FORCE_NO_LINK_INFO):
        link_info, new_offset = parse_link_info(data, offset, len(data))
        if link_info:
            result["link_info"] = link_info
            offset = new_offset

    # StringData: urutan NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON_LOCATION
    string_fields = [
        (LF_HAS_NAME, "name"),
        (LF_HAS_RELATIVE_PATH, "relative_path"),
        (LF_HAS_WORKING_DIR, "working_dir"),
        (LF_HAS_ARGUMENTS, "command_line_arguments"),
        (LF_HAS_ICON_LOCATION, "icon_location"),
    ]
    for flag_bit, key in string_fields:
        if link_flags & flag_bit:
            val, offset = parse_string_data_item(data, offset, is_unicode)
            result[key] = val

    # ExtraData blocks
    try:
        extra = parse_extra_data_blocks(data, offset, len(data))
        if extra:
            result["extra_data"] = extra
    except Exception:
        pass

    # Simpan segmen ItemIDList mentah (untuk transparansi/debug)
    if idlist_segments:
        result["idlist_path_segments"] = idlist_segments
        idlist_path = "\\".join(s.rstrip("\\") if s.endswith("\\") and len(s) > 2 else s
                                 for s in idlist_segments)
        result["idlist_derived_path"] = idlist_path
    else:
        idlist_path = None

    # Best-effort "full path" gabungan.
    # Prioritas: LinkInfo full_path (paling akurat, termasuk UNC network path)
    #            -> path hasil rekonstruksi ItemIDList (fallback saat LinkInfo
    #               tidak ada, mis. ForceNoLinkInfo / virtual folder)
    #            -> StringData.NAME
    #            -> RelativePath
    #            -> label default berbasis entry_id/source (TIDAK PERNAH None,
    #               supaya setiap entri tetap terlihat di laporan meskipun
    #               path aslinya tidak berhasil direkonstruksi).
    full_path = None
    li_full = (result.get("link_info") or {}).get("full_path")
    if li_full:
        full_path = li_full
    elif idlist_path:
        full_path = idlist_path
    elif result.get("name"):
        full_path = result["name"]
    elif result.get("relative_path"):
        full_path = result["relative_path"]

    if not full_path:
        full_path = f"(path tidak dapat direkonstruksi - {source_label or 'unknown source'})"
        result["path_unresolved"] = True

    result["resolved_path"] = full_path

    return result


# --------------------------------------------------------------------------
# DestList stream parser (dalam AutomaticDestinations)
# --------------------------------------------------------------------------

def parse_destlist_stream(data):
    """
    DestList header (Win7/8/10 serupa, versi di offset 0):
      Version (4)
      NumberOfEntries (4)
      NumberOfPinnedEntries (4)
      Unknown (8)
      LastEntryNumber (4)
      ... lalu entries.

    Tiap entry (versi >=3, Win10):
      Checksum/Unknown (8)
      MRU-based key -- unfortunately layout berbeda antar versi Windows,
      jadi kita parse secara defensif: cari NetBIOS name (ANSI 16 byte) dan
      unicode path (variable, panjang di suatu offset), lalu entry ID (4 byte)
      di akhir.
    Karena format DestList tidak didokumentasikan resmi oleh Microsoft dan
    sering berubah antar versi Windows, parser ini best-effort: mengembalikan
    daftar entry_id -> metadata (pin, access count) jika berhasil diparse,
    dan tidak fatal jika gagal.
    """
    entries = {}
    try:
        if len(data) < 32:
            return entries
        version, num_entries = struct.unpack_from("<II", data, 0)
        offset = 32  # skip header (version, num_entries, num_pinned, unknown8, last_entry_num)

        for _ in range(num_entries):
            entry_start = offset
            if offset + 8 > len(data):
                break
            # unknown checksum/signature (8 bytes)
            offset += 8
            # NetBIOS name (16 bytes, ANSI, null padded)
            if offset + 16 > len(data):
                break
            netbios = data[offset:offset + 16].split(b"\x00")[0].decode(
                "ascii", errors="replace")
            offset += 16
            # Volume Droid GUID (16), File Droid GUID (16),
            # Volume Droid Birth GUID (16), File Droid Birth GUID (16)
            if offset + 64 > len(data):
                break
            file_droid_birth = data[offset + 48:offset + 64]
            offset += 64
            # NetBIOS name may repeat; then FILETIME (8), pin status (4),
            # this layout varies; we attempt generic scan instead below.
            break  # layout terlalu bervariasi -> fallback ke scan generik
    except Exception:
        pass

    # --- Fallback robust: scan generik mencari unicode path string di DestList
    # DestList banyak berisi path unicode null-terminated yang bisa langsung
    # diekstrak tanpa perlu memahami tiap field secara presisi.
    try:
        text_offset = 0
        found_paths = []
        i = 0
        n = len(data)
        while i < n - 4:
            # Cari kandidat awal string unicode: dua byte printable diikuti 0x00
            if data[i+1] == 0 and 0x20 <= data[i] < 0x7F:
                j = i
                chars = []
                while j < n - 1 and not (data[j] == 0 and data[j+1] == 0):
                    ch = data[j]
                    if ch == 0:
                        break
                    chars.append(chr(ch))
                    j += 2
                s = "".join(chars)
                if len(s) >= 4 and ("\\" in s or ":" in s):
                    found_paths.append(s)
                i = j + 2
            else:
                i += 2
        entries["_scanned_paths"] = found_paths
    except Exception:
        pass

    return entries


# --------------------------------------------------------------------------
# AutomaticDestinations (*.automaticDestinations-ms) -- CFBF/OLE container
# --------------------------------------------------------------------------

def parse_automatic_destinations(filepath):
    """
    Return list of dict, satu per LNK stream ditemukan di dalam container,
    plus optional entry '_destlist_scan' berisi path yang berhasil di-scan
    dari stream DestList (best effort, lihat parse_destlist_stream).
    """
    results = []
    if not olefile.isOleFile(filepath):
        results.append({"error": f"{filepath} bukan file OLE/CFBF yang valid"})
        return results

    ole = olefile.OleFileIO(filepath)
    try:
        streams = ole.listdir(streams=True, storages=False)
        destlist_paths = []

        for stream_path in streams:
            name = stream_path[-1]
            full_name = "/".join(stream_path)

            if name.lower() == "destlist":
                try:
                    raw = ole.openstream(stream_path).read()
                    scan = parse_destlist_stream(raw)
                    destlist_paths = scan.get("_scanned_paths", [])
                except Exception as e:
                    pass
                continue

            # Stream lain: nama biasanya angka hex (entry id) = LNK stream
            try:
                raw = ole.openstream(stream_path).read()
            except Exception as e:
                results.append({"source": full_name, "error": f"Gagal baca stream: {e}"})
                continue

            parsed = parse_lnk(raw, source_label=f"{os.path.basename(filepath)}::{full_name}")
            parsed["entry_id"] = name
            parsed["container_file"] = os.path.basename(filepath)
            parsed["jumplist_type"] = "AutomaticDestinations"
            results.append(parsed)

        if destlist_paths:
            results.append({
                "source": f"{os.path.basename(filepath)}::DestList(scan)",
                "jumplist_type": "AutomaticDestinations",
                "container_file": os.path.basename(filepath),
                "entry_id": "DestList(scan)",
                "note": "Path hasil scan generik dari stream DestList "
                        "(pelengkap, mungkin duplikat dgn LNK di atas)",
                "scanned_paths": destlist_paths,
                "resolved_path": "; ".join(destlist_paths[:5]) + (
                    " ..." if len(destlist_paths) > 5 else ""),
            })
    finally:
        ole.close()

    return results


# --------------------------------------------------------------------------
# CustomDestinations (*.customDestinations-ms) -- flat file, rangkaian LNK
# --------------------------------------------------------------------------

LNK_HEADER_SIG = struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000c000000000000046")


def parse_custom_destinations(filepath):
    """
    CustomDestinations tidak punya container OLE; isinya kurang lebih:
      [optional category header/footer bytes]
      LNK blob 1
      LNK blob 2
      ...
      footer signature 0xBABFFBAB (4 bytes) menandai akhir tiap grup/list.

    Karena tidak ada length field per-LNK yang eksplisit di level file,
    pendekatan paling robust adalah mencari SEMUA offset di mana header LNK
    (0x4C + CLSID ShellLink) muncul, lalu memparse dari tiap offset hingga
    offset berikutnya (atau EOF).
    """
    results = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        return [{"error": f"Gagal buka file: {e}"}]

    sig = LNK_HEADER_SIG
    offsets = []
    start = 0
    while True:
        idx = data.find(sig, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1

    if not offsets:
        results.append({
            "source": os.path.basename(filepath),
            "error": "Tidak ditemukan blob LNK di dalam file (mungkin kosong atau format tidak dikenal)",
        })
        return results

    for i, off in enumerate(offsets):
        end = offsets[i + 1] if i + 1 < len(offsets) else len(data)
        blob = data[off:end]
        parsed = parse_lnk(blob, source_label=f"{os.path.basename(filepath)}::offset0x{off:X}")
        parsed["jumplist_type"] = "CustomDestinations"
        parsed["container_file"] = os.path.basename(filepath)
        parsed["byte_offset"] = off
        results.append(parsed)

    return results


# --------------------------------------------------------------------------
# Deteksi tipe file & orkestrasi
# --------------------------------------------------------------------------

def detect_and_parse(filepath):
    lower = filepath.lower()
    if lower.endswith(".automaticdestinations-ms"):
        return parse_automatic_destinations(filepath)
    elif lower.endswith(".customdestinations-ms"):
        return parse_custom_destinations(filepath)
    else:
        # Coba deteksi via signature file
        try:
            with open(filepath, "rb") as f:
                head = f.read(8)
        except Exception as e:
            return [{"error": f"Gagal buka file: {e}"}]
        if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return parse_automatic_destinations(filepath)
        else:
            return parse_custom_destinations(filepath)


def collect_files(paths):
    """Terima file individual atau direktori (scan rekursif utk *.ms)."""
    all_files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for fn in files:
                    if fn.lower().endswith((".automaticdestinations-ms",
                                             ".customdestinations-ms")):
                        all_files.append(os.path.join(root, fn))
        elif os.path.isfile(p):
            all_files.append(p)
        else:
            print(f"[!] Path tidak ditemukan: {p}", file=sys.stderr)
    return all_files


def print_summary(entries):
    print(f"{'Jenis':<22} {'Nama/App ID':<20} {'Path Target':<55} {'Last Write Time (LNK)'}")
    print("-" * 130)
    for e in entries:
        # Hanya skip entri yang benar-benar gagal total (error + tidak ada
        # informasi path apapun untuk ditampilkan).
        if "error" in e and not e.get("resolved_path") and not e.get("scanned_paths"):
            continue
        jtype = e.get("jumplist_type", "-")
        appid = e.get("container_file") or e.get("source", "-")
        path = e.get("resolved_path") or e.get("name") or "-"
        li = e.get("link_info") or {}
        net = li.get("common_network_relative_link") or {}
        if net.get("net_name"):
            mapped = f" (mapped: {net['device_name']})" if net.get("device_name") else ""
            path = f"[NET]{mapped} {path}"
        wtime = e.get("write_time") or "-"
        path_disp = (path[:52] + "...") if path and len(path) > 55 else (path or "-")
        print(f"{jtype:<22} {appid:<20} {path_disp:<55} {wtime}")


def export_json(entries, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False, default=str)


def export_csv(entries, out_path):
    fieldnames = [
        "jumplist_type", "container_file", "entry_id", "byte_offset",
        "resolved_path", "name", "relative_path", "working_dir",
        "command_line_arguments", "icon_location",
        "creation_time", "access_time", "write_time",
        "file_size", "file_attributes",
        "volume_serial_number", "volume_label", "drive_type",
        "network_unc_path", "network_mapped_drive",
        "mac_address", "machine_id",
        "error",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            row = dict(e)
            row["container_file"] = e.get("container_file") or e.get("source") or "(unknown)"
            row["resolved_path"] = e.get("resolved_path") or e.get("name") or (
                "; ".join(e.get("scanned_paths", [])[:5]) if e.get("scanned_paths") else "(tidak diketahui)")
            li = e.get("link_info") or {}
            vol = li.get("volume_id") or {}
            row["volume_serial_number"] = vol.get("serial_number")
            row["volume_label"] = vol.get("volume_label")
            row["drive_type"] = vol.get("drive_type")
            net = li.get("common_network_relative_link") or {}
            row["network_unc_path"] = net.get("net_name") or None
            row["network_mapped_drive"] = net.get("device_name") or None
            extra = e.get("extra_data") or {}
            tracker = extra.get("tracker_data_block") or {}
            row["mac_address"] = tracker.get("mac_address")
            row["machine_id"] = tracker.get("machine_id")
            if isinstance(row.get("file_attributes"), list):
                row["file_attributes"] = ";".join(row["file_attributes"])
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(
        description="Parser Windows JumpList (.automaticDestinations-ms / "
                     ".customDestinations-ms) untuk dijalankan di Linux.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh pemakaian:
  python3 jumplist_parser.py file.automaticDestinations-ms
  python3 jumplist_parser.py /path/ke/folder/AutomaticDestinations/ --json out.json
  python3 jumplist_parser.py a.customDestinations-ms b.automaticDestinations-ms --csv out.csv --json out.json
""")
    parser.add_argument("paths", nargs="+",
                         help="File JumpList atau direktori berisi banyak file JumpList")
    parser.add_argument("--json", metavar="OUT.json", help="Export hasil ke file JSON")
    parser.add_argument("--csv", metavar="OUT.csv", help="Export hasil ke file CSV")
    parser.add_argument("--quiet", action="store_true", help="Jangan print ringkasan ke terminal")
    args = parser.parse_args()

    files = collect_files(args.paths)
    if not files:
        print("[!] Tidak ada file JumpList ditemukan.", file=sys.stderr)
        sys.exit(1)

    all_entries = []
    for fp in files:
        entries = detect_and_parse(fp)
        all_entries.extend(entries)

    if not args.quiet:
        print_summary(all_entries)
        print(f"\nTotal entri: {len(all_entries)} (dari {len(files)} file)")

    if args.json:
        export_json(all_entries, args.json)
        print(f"[+] JSON disimpan: {args.json}")
    if args.csv:
        export_csv(all_entries, args.csv)
        print(f"[+] CSV disimpan: {args.csv}")


if __name__ == "__main__":
    main()
