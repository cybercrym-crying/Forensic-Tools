#!/usr/bin/env python3
"""
evtx2csv.py — Parse a Windows Event Log (.evtx) file directly into a FLAT CSV.

No JSON is left inside any cell. Every <Data Name="X">Y</Data> field found in
EventData/UserData becomes its own column, so the output can be piped straight
into awk, cut, grep, etc. without any further parsing.

--------------------------------------------------------------------------
CHANGELOG

v5:
  - Renamed a small set of genuinely ambiguous raw field names that Windows/
    Sysmon itself uses. These are NOT collisions with fixed columns (that
    was fixed in v4) -- they're dynamic fields whose *own* names are
    confusing next to each other or next to unrelated columns:
      * "Hash"  (EventId 15, FileCreateStreamHash only) -> "StreamHash"
        Distinguishes it from "Hashes" (EventId 1/6/7/26/29), which holds
        the same "SHA1=..,MD5=..,SHA256=.." format under a near-identical
        name -- easy to miss one of the two in a single grep/awk pass.
      * "ID" (EventId 255 only) -> "SysmonErrorCode"
        The raw name "ID" sat right next to EventId/EventRecordId/
        ProcessGuid and looked like it should be some kind of record
        identifier; it actually holds a Sysmon-internal diagnostic code
        such as "IMAGE_LOAD" or "QUEUE".
      * "EventType" (EventId 12/13/14/17/18, registry/pipe events) ->
        "RegistryEventType"
        Easy to confuse with "EventId" at a glance; it actually holds an
        operation label such as "SetValue" or "DeleteKey", unrelated to
        the EventId number.
    All other field names are left exactly as Windows/Sysmon defines them
    (e.g. SourceImage/TargetImage/ParentImage, SourceProcessId/
    TargetProcessId/ParentProcessId), since those are legitimately
    different, self-explanatory fields and renaming them would only make
    cross-referencing the official Sysmon schema harder.

v4:
  - Fixed a silent column-collision bug. Sysmon (and other providers) can
    emit an EventData field named "ProcessId" or "Version" — these names
    clashed with the *fixed* <System> columns of the same name (the PID of
    the process that logged the event, and the event schema version). The
    dynamic field silently overwrote the fixed one, so the fixed column's
    real value was lost with no warning. Fixed columns are now written
    under unambiguous names (ExecutionProcessId, ExecutionThreadId,
    EventVersion) that cannot collide with anything Windows puts in
    EventData. As a second line of defense, ANY future dynamic field name
    that still collides with a fixed column is auto-suffixed ("_data")
    instead of silently overwriting — this makes the script robust for
    event types not seen during testing.
  - All comments, docstrings, and CLI/log messages translated to English.
  - Verified against multiple event shapes: EventData with Name attributes
    (Sysmon), EventData with unnamed <Data> elements (e.g. Windows Error
    Reporting, Event ID 1001), and UserData-based events (e.g. Windows
    Update Client) — all three code paths are covered by tests.

v3:
  - Switched the read backend from `python-evtx` to `evtx` (Rust binding,
    omerbenamram/pyevtx-rs). Root cause of a data-loss bug in earlier
    versions: `python-evtx` trusts the `chunk_count` field in the .evtx
    FILE HEADER without validating it against the actual file size. For a
    "dirty" file (the log wasn't closed cleanly — common with forensic
    images/VM snapshots), that header field is stale and reports far fewer
    chunks than actually exist on disk. On a 25MB test file the header
    claimed chunk_count=19, so python-evtx read only 1,141 records — while
    the file size was large enough for 385 chunks and 20,083 records, which
    both EvtxECmd (Zimmerman tools) and the `evtx` Rust backend read in
    full. `evtx` computes the chunk count from file size, so it isn't
    fooled by a stale header value.
  - Record iteration uses a manual next()/try-except loop rather than a
    plain `for record in parser.records():`, because PyEvtxParser's own
    documentation states iteration can raise RuntimeError on encountering
    an invalid record and stop the loop early. The manual pattern skips
    just the bad record and keeps going until the iterator is truly
    exhausted.
--------------------------------------------------------------------------

How it works:
  1. Read the .evtx file using the `evtx` library (Rust binding — robust
     against dirty/corrupt files, and used by several other DFIR tools).
  2. Iterate records with a manual next()/try-except loop so a single bad
     record is skipped (and logged) instead of silently truncating the
     rest of the file.
  3. Parse each record's XML (System + EventData/UserData). All newline/
     tab/CR characters inside values are normalized to single spaces, so
     one record always maps to exactly one physical CSV line (safe for
     `wc -l`, `awk`, and any line-based Unix tool).
  4. All records are buffered in memory, then written out with a header
     equal to the UNION of every field name seen across the whole file, so
     the header is complete and column positions stay consistent from the
     first row to the last.

Install the dependency (once):
    pip install evtx --break-system-packages

Usage:
    python3 evtx2csv.py <input.evtx> [-o output.csv]
                         [--event-id 1,11,13]
                         [--fields TimeCreated,EventId,Image,CommandLine,...]
                         [--delimiter ","|"|"|"tab"]

Examples:
    # All events, all columns -> full CSV
    python3 evtx2csv.py Microsoft-Windows-Sysmon_4Operational.evtx -o sysmon.csv

    # Only EventId 1 (Process Create) and 11 (FileCreate)
    python3 evtx2csv.py Sysmon.evtx --event-id 1,11 -o procfile.csv

    # Pipe delimiter — safer for awk -F'|' since '|' rarely appears in Windows data
    python3 evtx2csv.py Sysmon.evtx --delimiter "|" -o sysmon_pipe.csv

    # After conversion (default comma delimiter), pull columns by header lookup:
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
        "The 'evtx' library is not installed.\n"
        "Install it first: pip install evtx --break-system-packages",
        file=sys.stderr,
    )
    sys.exit(1)

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Fixed columns, always present for every event (derived from <System>).
# Names are chosen so they can NEVER collide with a dynamic EventData/UserData
# field name that Windows might emit (e.g. Sysmon's own "ProcessId" or
# "Version" fields, which are about the *subject* of the event, not the
# process/schema version that logged it).
FIXED_COLUMNS = [
    "TimeCreated",
    "EventId",
    "EventRecordId",
    "Provider",
    "Channel",
    "Computer",
    "UserId",
    "ExecutionProcessId",
    "ExecutionThreadId",
    "Level",
    "Task",
    "Opcode",
    "Keywords",
    "EventVersion",
]
FIXED_COLUMNS_SET = set(FIXED_COLUMNS)

DELIMITER_MAP = {
    ",": ",",
    ";": ";",
    "|": "|",
    "tab": "\t",
    "\\t": "\t",
}

# Some raw Windows/Sysmon field names are genuinely confusing on their own,
# independent of the fixed-column collision issue above -- e.g. Sysmon uses
# both "Hash" (EventId 15, FileCreateStreamHash) and "Hashes" (EventId 1, 6,
# 7, 26, 29) for the exact same "SHA1=..,MD5=..,SHA256=.." content, which is
# easy to miss with a single grep/awk across a whole export. This map renames
# just those specific names to something unambiguous; every other field name
# is left exactly as Windows/Sysmon defines it, so it still matches the
# official Sysmon schema documentation and other tools' output.
AMBIGUOUS_NAME_MAP = {
    "Hash": "StreamHash",  # EventId 15 only; distinct from "Hashes" (EventId 1/6/7/26/29)
    "ID": "SysmonErrorCode",  # EventId 255 only; a Sysmon-internal diagnostic code
    # (e.g. "IMAGE_LOAD", "QUEUE"), unrelated to EventId/EventRecordId/ProcessGuid
    "EventType": "RegistryEventType",  # EventId 12/13/14/17/18; a registry/pipe operation label
    # (e.g. "SetValue", "DeleteKey"), unrelated to EventId
}


def clean_value(text):
    """
    Normalize a single field value so that:
    - No \\r or \\n survives (replaced with a space) -> 1 record = 1 physical
      CSV line.
    - No tab survives (replaced with a space) -> also safe with --delimiter tab.
    - Leading/trailing/duplicate whitespace is collapsed.
    Without this, a field such as a newline-separated list of paths (common
    in Windows Error Reporting Event ID 1001) would spread a single record
    across multiple physical CSV lines, even though it stays valid CSV
    syntax (quoted).
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


def add_dynamic_field(record, name, value):
    """
    Add a field coming from EventData/UserData into the record dict.

    Three safety nets, applied in order:
    1. Rename known-ambiguous raw field names (see AMBIGUOUS_NAME_MAP) to
       something unambiguous, e.g. Sysmon's "Hash" (EventId 15 only) becomes
       "StreamHash" so it can't be confused with "Hashes" (EventId 1/6/7/
       26/29) in a grep/awk across the whole file.
    2. If this exact field name already appeared earlier in the SAME event
       (rare but possible), the values are concatenated with " | " instead
       of overwriting one another.
    3. If the (possibly renamed) name still collides with one of the FIXED
       (<System>-derived) columns, it is stored under "<name>_data" instead
       of overwriting the fixed column. This is a defensive fallback: the
       current FIXED_COLUMNS names were chosen specifically to avoid known
       collisions (ProcessId, Version), but this guard keeps the script safe
       against any other provider/event type that reuses a fixed column's
       name in the future.
    """
    if name in AMBIGUOUS_NAME_MAP:
        name = AMBIGUOUS_NAME_MAP[name]

    if name in FIXED_COLUMNS_SET:
        name = f"{name}_data"

    if name in record and record[name]:
        record[name] = record[name] + " | " + value
    else:
        record[name] = value


def parse_record_xml(xml_str):
    """
    Parse a single evtx record's XML into a flat dict:
    - Fixed columns from <System> (TimeCreated, EventId, etc.)
    - Dynamic columns from <EventData>/<UserData> -> each
      <Data Name="X">Y</Data> becomes key X (or "X_data" if X collides with
      a fixed column name — see add_dynamic_field).
    If EventData has no Name/value structure at all (rare — plain text
    <Data> elements with no Name attribute), everything is joined into a
    single "EventData_Raw" column.

    All text values pass through clean_value() so no newline/tab survives
    inside a CSV cell.
    """
    root = ET.fromstring(xml_str)

    system = root.find("e:System", NS)
    if system is None:
        raise ValueError(
            "<System> element not found — record is likely corrupt or non-standard"
        )

    record = {}

    provider_el = system.find("e:Provider", NS)
    record["Provider"] = (
        (provider_el.get("Name") or "") if provider_el is not None else ""
    )

    eventid_el = system.find("e:EventID", NS)
    record["EventId"] = clean_value(eventid_el.text) if eventid_el is not None else ""

    record["EventVersion"] = _text(system, "e:Version")
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
        record["ExecutionProcessId"] = clean_value(exec_el.get("ProcessID")) or ""
        record["ExecutionThreadId"] = clean_value(exec_el.get("ThreadID")) or ""
    else:
        record["ExecutionProcessId"] = ""
        record["ExecutionThreadId"] = ""

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
                    add_dynamic_field(record, name, clean_value(d.text))
            if not has_name:
                # <Data> elements with no Name attribute at all -> join into one column
                texts = [clean_value(d.text) for d in data_items]
                record["EventData_Raw"] = " | ".join(t for t in texts if t)
        else:
            # EventData is present but empty / has no <Data> children
            raw_text = clean_value("".join(eventdata.itertext()))
            if raw_text:
                record["EventData_Raw"] = raw_text
    elif userdata is not None:
        # UserData's inner structure is provider-defined and varies freely;
        # best-effort flatten: every descendant tag name -> its text content.
        for child in userdata.iter():
            tag = child.tag.split("}")[-1]  # strip XML namespace
            if tag == "UserData":
                continue
            text = clean_value(child.text)
            if text:
                add_dynamic_field(record, tag, text)

    return record


def _text(parent, tag):
    el = parent.find(tag, NS)
    return clean_value(el.text) if (el is not None and el.text) else ""


def iter_records(evtx_path, error_counter):
    """
    Generator: read a .evtx file via the `evtx` (Rust) library and yield one
    flat record dict per event.

    IMPORTANT: this uses a manual next()/try-except loop, NOT a plain
    `for record in parser.records():`. PyEvtxParser's own documentation
    states that iteration can raise RuntimeError when it encounters an
    invalid record, and that would silently stop a plain for-loop right
    there — the same class of bug that affected the previous python-evtx
    backend, just from a different root cause. The manual pattern below
    guarantees a single bad record is skipped (and counted/logged) while
    iteration continues until the iterator is genuinely exhausted
    (StopIteration).
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
                f"[!] Failed to read a record (parser RuntimeError): {e}",
                file=sys.stderr,
            )
            continue

        try:
            yield parse_record_xml(record["data"])
        except Exception as e:
            error_counter["record_failed"] += 1
            rn = record.get("event_record_id", "?")
            print(f"[!] Failed to parse XML for record #{rn}: {e}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(
        description="Parse a .evtx file directly into a flat CSV (no JSON left inside any cell).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("input", help="Path to the .evtx input file")
    ap.add_argument(
        "-o",
        "--output",
        default=None,
        help="Path to the output CSV. Default: <input_name>.csv under /mnt/user-data/outputs",
    )
    ap.add_argument(
        "--event-id",
        default=None,
        help="Filter by EventId, comma-separated. Example: 1,11,13",
    )
    ap.add_argument(
        "--fields",
        default=None,
        help="Restrict output to these columns, comma-separated, in the given order. "
        "If omitted, all columns (the union across every event) are written.",
    )
    ap.add_argument(
        "--delimiter",
        default=",",
        help="CSV delimiter: ',' (default), ';', '|', or 'tab'. "
        "Use '|' or 'tab' if you want the output to be trivially safe for "
        "awk without worrying about comma-quoting inside CommandLine, etc.",
    )
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"File not found: {in_path}", file=sys.stderr)
        sys.exit(1)
    if in_path.stat().st_size == 0:
        print(f"File is empty (0 bytes): {in_path}", file=sys.stderr)
        sys.exit(1)

    delim_key = args.delimiter.lower()
    if delim_key not in DELIMITER_MAP:
        print(
            f"Unrecognized delimiter '{args.delimiter}'. Choose one of: , ; | tab",
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

    print(f"[1/2] Reading: {in_path.name} ...")

    all_columns = list(FIXED_COLUMNS)
    seen = set(all_columns)
    records_buffer = []

    errors = Counter()
    total_read = 0
    PROGRESS_EVERY = 5000

    for rec in iter_records(in_path, errors):
        total_read += 1
        if total_read % PROGRESS_EVERY == 0:
            print(f"    ... {total_read} records read", file=sys.stderr)

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
                f"[!] Warning: these fields never appear in the data, "
                f"their columns will be empty: {', '.join(unknown)}",
                file=sys.stderr,
            )
        final_columns = wanted
    else:
        final_columns = all_columns

    if not records_buffer:
        print(
            "\n[!] No records matched the filter. No CSV file was created.",
            file=sys.stderr,
        )
        if errors["record_failed"]:
            print(
                f"    Records that failed to read/parse: {errors['record_failed']}",
                file=sys.stderr,
            )
        sys.exit(1)

    print(
        f"[2/2] Writing {len(records_buffer)} rows x {len(final_columns)} columns -> {out_path}"
    )

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        # NOTE: intentionally "utf-8", NOT "utf-8-sig". A UTF-8 BOM at the
        # start of the file is invisible in most editors but becomes part of
        # the very first header cell's text (e.g. "\ufeffTimeCreated"
        # instead of "TimeCreated"). That silently breaks any awk/grep/etc.
        # header-lookup pattern like `h[$1]=="TimeCreated"` for the FIRST
        # column only, which is a nasty, hard-to-spot bug. Modern Excel
        # and most tools read UTF-8 without a BOM just fine, so it's safer
        # to leave it out.
        writer = csv.DictWriter(
            f,
            fieldnames=final_columns,
            extrasaction="ignore",
            delimiter=delimiter,
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",  # the csv module defaults to "\r\n" (RFC4180); using a
            # plain "\n" keeps output friendly for awk/grep/wc -l on
            # Linux and avoids a stray \r stuck to the last column.
        )
        writer.writeheader()
        for rec in records_buffer:
            row = {k: rec.get(k, "") for k in final_columns}
            writer.writerow(row)

    print(f"\nTotal records read from evtx : {total_read}")
    print(f"Total rows written to CSV    : {len(records_buffer)}")
    print(f"Total columns (union)        : {len(all_columns)}")
    print(f"Delimiter                    : {args.delimiter!r}")
    print(f"Output                       : {out_path}")
    if errors["record_failed"]:
        print(f"\n[!] Records that failed to read/parse: {errors['record_failed']}")
        print("    (details were printed to stderr above)")

    c = Counter(rec.get("EventId", "") for rec in records_buffer)
    print("\nSummary by EventId:")
    for eid, cnt in sorted(c.items(), key=lambda x: -x[1]):
        print(f"  {cnt:6d}  EventId={eid}")


if __name__ == "__main__":
    main()
