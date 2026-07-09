#!/usr/bin/env python3
"""
evtx2csv.py — Parser file .evtx (Windows Event Log) langsung ke CSV FLAT.

Tidak ada JSON tersisa di dalam sel manapun — setiap field <Data Name="X">Y</Data>
di EventData/UserData dijadikan kolom sendiri, jadi hasilnya bisa langsung
diproses dengan awk, cut, grep, dst tanpa perlu parsing tambahan.

--------------------------------------------------------------------------
CATATAN PENTING (v3): backend parsing diganti dari `python-evtx` ke `evtx`
(Rust binding, proyek omerbenamram/pyevtx-rs).

Root cause bug versi sebelumnya: `python-evtx` membaca jumlah chunk dari
field `chunk_count` di FILE HEADER evtx, TANPA memvalidasi ke ukuran file
fisik. Untuk file yang berstatus "dirty" (proses/servicenya tidak sempat
menutup log dengan bersih -- umum terjadi pada image forensik/snapshot VM),
field metadata ini tidak terupdate dan menunjukkan angka yang jauh lebih
kecil dari jumlah chunk yang sebenarnya tertulis di file. Akibatnya ribuan
record di bagian akhir file terlewat tanpa ada pesan error sama sekali.

Terbukti pada file uji: file 25MB, `chunk_count` header = 19 -> python-evtx
cuma baca 1141 record. Padahal ukuran file cukup untuk 385 chunk fisik, dan
EvtxECmd (Zimmerman tools) maupun `evtx` (Rust) sama-sama membaca 20083
record secara utuh -- karena keduanya menghitung chunk dari ukuran file,
bukan cuma percaya field metadata di header.
--------------------------------------------------------------------------

Cara kerja:
  1. Baca file .evtx pakai library `evtx` (Rust binding, sudah battle-tested
     untuk file dirty/corrupt -- dipakai juga oleh banyak tool DFIR lain).
  2. Iterasi record dilakukan dengan pola next()/try-except manual (BUKAN
     `for record in parser.records()` polos), karena dokumentasi resmi
     library ini menyebutkan iterasi bisa melempar RuntimeError di tengah
     jalan dan menghentikan for-loop biasa secara tiba-tiba. Dengan pola
     manual, satu record gagal dilewati tapi iterasi tetap lanjut.
  3. Setiap record (XML) di-parse (System + EventData/UserData). Semua
     newline/tab/CR di dalam value dinormalisasi jadi spasi, supaya satu
     record SELALU jadi satu baris fisik CSV (aman untuk `wc -l`, `awk`,
     pemrosesan baris-per-baris pada umumnya).
  4. File dibaca sekali, seluruh record disimpan di memori lalu ditulis
     dengan header = UNION semua nama field yang pernah muncul, supaya
     header CSV lengkap & posisi kolom konsisten dari baris pertama.

Install dependency (sekali saja):
    pip install evtx --break-system-packages

Cara pakai:
    python3 evtx2csv.py <input.evtx> [-o output.csv]
                         [--event-id 1,11,13]
                         [--fields TimeCreated,EventId,Image,CommandLine,...]
                         [--delimiter ","|"|"|"tab"]

Contoh:
    # Semua event, semua kolom -> CSV lengkap
    python3 evtx2csv.py Microsoft-Windows-Sysmon_4Operational.evtx -o sysmon.csv

    # Hanya EventId 1 (Process Create) dan 11 (FileCreate)
    python3 evtx2csv.py Sysmon.evtx --event-id 1,11 -o procfile.csv

    # Delimiter pipe, lebih aman untuk awk -F'|' karena jarang muncul di data Windows
    python3 evtx2csv.py Sysmon.evtx --delimiter "|" -o sysmon_pipe.csv

    # Setelah jadi CSV (delimiter koma default), ambil kolom pakai header dinamis:
    awk -F',' 'NR==1{for(i=1;i<=NF;i++)h[$i]=i; next} {print $h["TimeCreated"], $h["Image"]}' sysmon.csv
"""

import sys
import csv
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import Counter

try:
    from evtx import PyEvtxParser
except ImportError:
    print(
        "Library 'evtx' belum terinstall.\n"
        "Jalankan dulu: pip install evtx --break-system-packages",
        file=sys.stderr,
    )
    sys.exit(1)

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Kolom tetap (selalu ada di setiap event, diambil dari elemen <System>)
FIXED_COLUMNS = [
    "TimeCreated",
    "EventId",
    "EventRecordId",
    "Provider",
    "Channel",
    "Computer",
    "UserId",
    "ProcessId",
    "ThreadId",
    "Level",
    "Task",
    "Opcode",
    "Keywords",
    "Version",
]

DELIMITER_MAP = {
    ",": ",",
    ";": ";",
    "|": "|",
    "tab": "\t",
    "\\t": "\t",
}


def clean_value(text):
    """
    Normalisasi satu nilai field supaya:
    - Tidak ada \\r atau \\n tersisa (diganti spasi) -> 1 record = 1 baris fisik CSV.
    - Tidak ada tab tersisa (diganti spasi) -> aman untuk delimiter tab juga.
    - Whitespace berlebih di awal/akhir dipangkas.
    Tanpa fungsi ini, field seperti daftar path yang dipisah "\\n" (umum di
    event WER / EventID 1001) akan membuat satu record tersebar ke banyak
    baris fisik di file CSV walau secara sintaks CSV masih "valid" (ter-quote).
    """
    if text is None:
        return ""
    text = (
        text.replace("\r\n", " ")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
    )
    text = " ".join(text.split())
    return text


def parse_record_xml(xml_str):
    """
    Parse satu record XML evtx menjadi dict flat:
    - Kolom tetap dari <System> (TimeCreated, EventId, dst)
    - Kolom dinamis dari <EventData>/<UserData> -> setiap <Data Name="X">Y</Data>
      jadi key X.
    Kalau EventData tidak berbentuk Name/value (kasus jarang, mis. hanya teks
    polos), disimpan ke kolom "EventData_Raw".

    Semua nilai teks dilewatkan clean_value() supaya tidak ada newline/tab
    tersisa di dalam sel CSV.
    """
    root = ET.fromstring(xml_str)

    system = root.find("e:System", NS)
    if system is None:
        raise ValueError(
            "Elemen <System> tidak ditemukan, kemungkinan record korup/tidak standar"
        )

    record = {}

    provider_el = system.find("e:Provider", NS)
    record["Provider"] = (
        (provider_el.get("Name") or "") if provider_el is not None else ""
    )

    eventid_el = system.find("e:EventID", NS)
    record["EventId"] = clean_value(eventid_el.text) if eventid_el is not None else ""

    record["Version"] = _text(system, "e:Version")
    record["Level"] = _text(system, "e:Level")
    record["Task"] = _text(system, "e:Task")
    record["Opcode"] = _text(system, "e:Opcode")
    record["Keywords"] = _text(system, "e:Keywords")

    tc_el = system.find("e:TimeCreated", NS)
    record["TimeCreated"] = (
        clean_value(tc_el.get("SystemTime")) if tc_el is not None else ""
    )

    erid_el = system.find("e:EventRecordID", NS)
    record["EventRecordId"] = clean_value(erid_el.text) if erid_el is not None else ""

    record["Channel"] = _text(system, "e:Channel")
    record["Computer"] = _text(system, "e:Computer")

    sec_el = system.find("e:Security", NS)
    record["UserId"] = clean_value(sec_el.get("UserID")) if sec_el is not None else ""

    exec_el = system.find("e:Execution", NS)
    if exec_el is not None:
        record["ProcessId"] = clean_value(exec_el.get("ProcessID")) or ""
        record["ThreadId"] = clean_value(exec_el.get("ThreadID")) or ""
    else:
        record["ProcessId"] = ""
        record["ThreadId"] = ""

    eventdata = root.find("e:EventData", NS)
    userdata = root.find("e:UserData", NS)

    if eventdata is not None:
        data_items = eventdata.findall("e:Data", NS)
        if data_items:
            has_name = False
            for d in data_items:
                name = d.get("Name")
                if name:
                    has_name = True
                    value = clean_value(d.text)
                    if name in record and record[name]:
                        record[name] = record[name] + " | " + value
                    else:
                        record[name] = value
            if not has_name:
                texts = [clean_value(d.text) for d in data_items]
                record["EventData_Raw"] = " | ".join(t for t in texts if t)
        else:
            raw_text = clean_value("".join(eventdata.itertext()))
            if raw_text:
                record["EventData_Raw"] = raw_text
    elif userdata is not None:
        for child in userdata.iter():
            tag = child.tag.split("}")[-1]
            if tag == "UserData":
                continue
            text = clean_value(child.text)
            if text:
                if tag in record and record[tag]:
                    record[tag] = record[tag] + " | " + text
                else:
                    record[tag] = text

    return record


def _text(parent, tag):
    el = parent.find(tag, NS)
    return clean_value(el.text) if (el is not None and el.text) else ""


def iter_records(evtx_path, error_counter):
    """
    Generator: baca .evtx via library `evtx` (Rust), yield record_dict per event.

    PENTING: pakai pola next()/try-except manual, BUKAN `for record in
    parser.records():` polos. Dokumentasi resmi PyEvtxParser.records()
    menyatakan iterasi bisa melempar RuntimeError saat menemui record
    tidak valid, dan itu akan menghentikan for-loop biasa secara tiba-tiba
    di titik itu -- persis kelas bug yang sama seperti pada python-evtx
    sebelumnya, walau sumbernya beda. Pola manual di bawah memastikan satu
    record gagal dilewati (dicatat ke error_counter) tapi iterasi lanjut
    sampai benar-benar habis (StopIteration).
    """
    parser = PyEvtxParser(str(evtx_path))
    it = iter(parser.records())
    while True:
        try:
            record = next(it)
        except StopIteration:
            break
        except RuntimeError as e:
            error_counter["record_failed"] += 1
            print(
                f"[!] Gagal membaca satu record (RuntimeError dari parser): {e}",
                file=sys.stderr,
            )
            continue

        try:
            yield parse_record_xml(record["data"])
        except Exception as e:
            error_counter["record_failed"] += 1
            rn = record.get("event_record_id", "?")
            print(f"[!] Gagal parse XML record #{rn}: {e}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(
        description="Parse file .evtx langsung menjadi CSV flat (tanpa JSON di dalam sel).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("input", help="Path file .evtx")
    ap.add_argument(
        "-o",
        "--output",
        default=None,
        help="Path file CSV output. Default: <nama_input>.csv di /mnt/user-data/outputs",
    )
    ap.add_argument(
        "--event-id",
        default=None,
        help="Filter EventId tertentu, pisah koma. Contoh: 1,11,13",
    )
    ap.add_argument(
        "--fields",
        default=None,
        help="Batasi kolom output, pisah koma, urutan sesuai input. "
        "Kalau tidak diisi, semua kolom (union) ikut ditulis.",
    )
    ap.add_argument(
        "--delimiter",
        default=",",
        help="Delimiter CSV: ',' (default), ';', '|', atau 'tab'. "
        "Gunakan '|' atau 'tab' kalau ingin lebih aman diproses awk "
        "tanpa perlu menangani quoting koma di dalam CommandLine dsb.",
    )
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"File tidak ditemukan: {in_path}", file=sys.stderr)
        sys.exit(1)
    if in_path.stat().st_size == 0:
        print(f"File kosong (0 byte): {in_path}", file=sys.stderr)
        sys.exit(1)

    delim_key = args.delimiter.lower()
    if delim_key not in DELIMITER_MAP:
        print(
            f"Delimiter '{args.delimiter}' tidak dikenal. Pilih salah satu: , ; | tab",
            file=sys.stderr,
        )
        sys.exit(1)
    delimiter = DELIMITER_MAP[delim_key]

    event_ids = None
    if args.event_id:
        event_ids = {x.strip() for x in args.event_id.split(",") if x.strip()}

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        outdir = Path("/mnt/user-data/outputs")
        outdir.mkdir(parents=True, exist_ok=True)
        out_path = outdir / f"{in_path.stem}.csv"

    print(f"[1/2] Membaca: {in_path.name} ...")

    all_columns = list(FIXED_COLUMNS)
    seen = set(all_columns)
    records_buffer = []

    errors = Counter()
    total_read = 0
    PROGRESS_EVERY = 5000

    for rec in iter_records(in_path, errors):
        total_read += 1
        if total_read % PROGRESS_EVERY == 0:
            print(f"    ... {total_read} record dibaca", file=sys.stderr)

        if event_ids is not None and rec.get("EventId") not in event_ids:
            continue
        records_buffer.append(rec)
        for k in rec.keys():
            if k not in seen:
                seen.add(k)
                all_columns.append(k)

    if args.fields:
        wanted = [f.strip() for f in args.fields.split(",") if f.strip()]
        unknown = [f for f in wanted if f not in seen]
        if unknown:
            print(
                f"[!] Peringatan: field berikut tidak pernah muncul di data, "
                f"kolomnya akan kosong semua: {', '.join(unknown)}",
                file=sys.stderr,
            )
        final_columns = wanted
    else:
        final_columns = all_columns

    if not records_buffer:
        print(
            "\n[!] Tidak ada record yang cocok (setelah filter). Tidak ada CSV dibuat.",
            file=sys.stderr,
        )
        if errors["record_failed"]:
            print(
                f"    Record gagal dibaca/parse: {errors['record_failed']}",
                file=sys.stderr,
            )
        sys.exit(1)

    print(
        f"[2/2] Menulis {len(records_buffer)} baris x {len(final_columns)} kolom -> {out_path}"
    )

    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=final_columns,
            extrasaction="ignore",
            delimiter=delimiter,
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",  # default csv module adalah "\r\n" (RFC4180); dipakai
            # "\n" murni supaya ramah untuk awk/grep/wc -l di Linux
            # dan tidak menyisakan \r yang menempel di kolom terakhir.
        )
        writer.writeheader()
        for rec in records_buffer:
            row = {k: rec.get(k, "") for k in final_columns}
            writer.writerow(row)

    print(f"\nTotal record dibaca dari evtx : {total_read}")
    print(f"Total baris ditulis ke CSV    : {len(records_buffer)}")
    print(f"Total kolom (union)           : {len(all_columns)}")
    print(f"Delimiter                     : {args.delimiter!r}")
    print(f"Output                        : {out_path}")
    if errors["record_failed"]:
        print(f"\n[!] Record gagal dibaca/parse: {errors['record_failed']}")
        print("    (detail sudah dicetak ke stderr di atas)")

    c = Counter(rec.get("EventId", "") for rec in records_buffer)
    print("\nRingkasan per EventId:")
    for eid, cnt in sorted(c.items(), key=lambda x: -x[1]):
        print(f"  {cnt:6d}  EventId={eid}")


if __name__ == "__main__":
    main()
