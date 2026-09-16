#!/usr/bin/env python3
"""
fwd_signature_audit.py — track a device's recorded signature across snapshots.

Every collected device carries a device signature in its per-snapshot
``metadata.txt`` file, e.g.::

    signature 1 {
      cisco_ios 3 {
        value 1: "71305217"
      }
    }

The signature is supposed to be stable for the life of a device. When it is
not, the platform records more than one usage entry for the same device, which
can consume extra licenses. This script walks the snapshot history of a network
and reports the signature each snapshot holds for a set of devices, so the
snapshots where the signature first changed can be identified and pulled.

Output
------
* A CSV, oldest snapshot first, with one row per (device, snapshot):
  ``collected_at, snapshot_id, device, signature_type, signature_value,
  changed, status, raw_signature``
* A summary per device listing every distinct signature seen, with the first
  and last snapshot it appeared in. Printed to the console, embedded at the top
  of the CSV as comment rows, and written to a separate ``*_summary.txt``.

Requirements
------------
Python 3.8+. Standard library only — nothing to install.

Setup
-----
1. Set the environment variables (see README.md, which covers doing this
   securely in Windows PowerShell):

       FWD_INSTANCE    host name of the instance, e.g. example.forwardnetworks.com
       FWD_NETWORK_ID  numeric network id
       FWD_USERNAME    user name
       FWD_PASSWORD    password or API key

2. Copy devices.example.txt to devices.txt and list one device name per line.
3. Run:  python fwd_signature_audit.py

Nothing environment-specific is stored in this file; it is safe to publish.
"""

import base64
import csv
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG — edit these, or leave them and use the environment variables.
# ─────────────────────────────────────────────────────────────────────────────

# Connection. Environment variables win; the literals are fallbacks.
INSTANCE   = os.environ.get("FWD_INSTANCE",   "")   # e.g. "example.forwardnetworks.com"
NETWORK_ID = os.environ.get("FWD_NETWORK_ID", "")   # e.g. "159020"
USERNAME   = os.environ.get("FWD_USERNAME",   "")
PASSWORD   = os.environ.get("FWD_PASSWORD",   "")

# Input: one device name per line. Blank lines and lines starting with # are
# ignored. Kept out of this file so device names never reach the repository.
DEVICE_FILE = "devices.txt"

# Output file names. A timestamp is appended automatically.
OUTPUT_PREFIX = "signature_audit"

# Which snapshots to walk.
SNAPSHOT_STATE   = "PROCESSED"  # "PROCESSED", or "" for every state
INCLUDE_ARCHIVED = False        # archived snapshots usually cannot serve files
SINCE            = ""           # "YYYY-MM-DD" — ignore snapshots created before this
MAX_SNAPSHOTS    = 0            # 0 = no limit; otherwise keep only the newest N

# HTTP behaviour.
MAX_WORKERS       = 8     # parallel metadata fetches
REQUEST_TIMEOUT_S = 60
MAX_RETRIES       = 3     # retries on 429 / 5xx / connection errors
VERIFY_TLS        = True  # set False only for an instance with a self-signed cert

# Presentation.
EMBED_SUMMARY_IN_CSV = True
WRITE_SUMMARY_FILE   = True

# ─────────────────────────────────────────────────────────────────────────────
# Signature parsing
# ─────────────────────────────────────────────────────────────────────────────

# metadata.txt is protobuf text format: "name [fieldnum] {" opens a message,
# "name [fieldnum]: value" is a scalar.
_BLOCK_OPEN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:\d+\s*)?\{\s*$")
_SCALAR_RE     = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:\d+\s*)?:\s*(.+?)\s*$")
_QUOTED_RE     = re.compile(r'"((?:[^"\\]|\\.)*)"')


def extract_signature_block(text):
    """Return the body of the first top-level ``signature { ... }`` block, or None."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _BLOCK_OPEN_RE.match(line)
        if not m or m.group(1) != "signature":
            continue
        depth = 1
        body = []
        for inner in lines[i + 1:]:
            # Blank out quoted strings before counting braces, so a brace inside
            # a serial or a note cannot unbalance the scan.
            bare = _QUOTED_RE.sub('""', inner)
            depth += bare.count("{") - bare.count("}")
            if depth <= 0:
                return "\n".join(body)
            body.append(inner)
        return "\n".join(body)
    return None


def parse_signature(block):
    """Return (signature_type, signature_value) for a signature block body.

    The nested message name is the device type the collector decided on
    (cisco_ios, cisco_ios_xe, an F5 type, and so on). Its scalar fields are the
    signature itself; several fields are joined with '|'.
    """
    sig_type = ""
    values = []
    for line in block.splitlines():
        m = _BLOCK_OPEN_RE.match(line)
        if m:
            if not sig_type:
                sig_type = m.group(1)
            continue
        s = _SCALAR_RE.match(line)
        if s:
            name, raw = s.group(1), s.group(2)
            q = _QUOTED_RE.search(raw)
            val = q.group(1) if q else raw.rstrip(",")
            values.append(val if name == "value" else "{}={}".format(name, val))
    return sig_type, "|".join(values)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _ssl_context():
    if VERIFY_TLS:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_get(url, auth_header, accept):
    """GET a URL. Returns (status, text). Never raises for an HTTP status."""
    last_err = None
    for attempt in range(MAX_RETRIES + 1):
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", auth_header)
        req.add_header("Accept", accept)
        try:
            with urllib.request.urlopen(
                req, timeout=REQUEST_TIMEOUT_S, context=_ssl_context()
            ) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace") if e.fp else ""
            if e.code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                continue
            return e.code, body
        except Exception as e:  # connection reset, timeout, DNS, TLS
            last_err = e
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                continue
    return 0, "request failed: {}".format(last_err)


def base_url():
    host = INSTANCE.strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = "https://" + host
    return host


def auth_header():
    token = base64.b64encode("{}:{}".format(USERNAME, PASSWORD).encode()).decode()
    return "Basic " + token


# ─────────────────────────────────────────────────────────────────────────────
# API calls
# ─────────────────────────────────────────────────────────────────────────────

def parse_iso8601(value):
    """Parse the API's timestamps, e.g. '2019-09-20T17:40:34.567Z'."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
    return None


def list_snapshots():
    """Return snapshots for the network, oldest first, after CONFIG filtering."""
    import json

    params = {"includeArchived": "true" if INCLUDE_ARCHIVED else "false"}
    if SNAPSHOT_STATE:
        params["state"] = SNAPSHOT_STATE
    url = "{}/api/networks/{}/snapshots?{}".format(
        base_url(), urllib.parse.quote(str(NETWORK_ID), safe=""),
        urllib.parse.urlencode(params),
    )
    status, body = http_get(url, auth_header(), "application/json")
    if status != 200:
        sys.exit("Could not list snapshots (HTTP {}): {}".format(status, body[:400]))

    snaps = json.loads(body).get("snapshots", []) or []
    for s in snaps:
        s["_created"] = parse_iso8601(s.get("createdAt"))
    snaps = [s for s in snaps if s.get("id")]
    # Undated snapshots sort to the front rather than crashing the sort.
    snaps.sort(key=lambda s: s["_created"] or datetime.min.replace(tzinfo=timezone.utc))

    if SINCE:
        try:
            cutoff = datetime.strptime(SINCE, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            sys.exit("SINCE must be YYYY-MM-DD, got {!r}".format(SINCE))
        snaps = [s for s in snaps if s["_created"] and s["_created"] >= cutoff]

    if MAX_SNAPSHOTS and len(snaps) > MAX_SNAPSHOTS:
        snaps = snaps[-MAX_SNAPSHOTS:]
    return snaps


def fetch_signature(device, snap):
    """Fetch and parse one device's signature in one snapshot."""
    url = "{}/api/networks/{}/devices/{}/files/metadata.txt?snapshotId={}".format(
        base_url(),
        urllib.parse.quote(str(NETWORK_ID), safe=""),
        urllib.parse.quote(device, safe=""),
        urllib.parse.quote(str(snap["id"]), safe=""),
    )
    status, body = http_get(url, auth_header(), "text/plain")

    row = {
        "collected_at": snap.get("createdAt", ""),
        "snapshot_id": snap.get("id", ""),
        "device": device,
        "signature_type": "",
        "signature_value": "",
        "changed": "",
        "status": "",
        "raw_signature": "",
        "_created": snap["_created"],
    }

    if status == 404:
        row["status"] = "DEVICE_OR_FILE_NOT_IN_SNAPSHOT"
        return row
    if status != 200:
        row["status"] = "HTTP_{}: {}".format(status, body[:120].replace("\n", " "))
        return row

    block = extract_signature_block(body)
    if block is None:
        row["status"] = "NO_SIGNATURE_BLOCK"
        return row

    sig_type, sig_value = parse_signature(block)
    row["signature_type"] = sig_type
    row["signature_value"] = sig_value
    row["raw_signature"] = " ".join(block.split())
    row["status"] = "OK"
    return row


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def summarize(device, rows):
    """Build summary lines for one device. rows must be oldest first."""
    good = [r for r in rows if r["status"] == "OK" and r["signature_value"]]
    lines = ["Device: {}".format(device)]

    if not good:
        lines.append("  No signature found in any of the {} snapshot(s) examined.".format(len(rows)))
        problems = {}
        for r in rows:
            problems[r["status"]] = problems.get(r["status"], 0) + 1
        for status, n in sorted(problems.items(), key=lambda kv: -kv[1]):
            lines.append("  {:<40} {}".format(status, n))
        return lines

    # Distinct signatures, in order of first appearance.
    seen = {}
    for r in good:
        key = (r["signature_type"], r["signature_value"])
        entry = seen.get(key)
        if entry is None:
            seen[key] = {"first": r, "last": r, "count": 1}
        else:
            entry["last"] = r
            entry["count"] += 1

    current = (good[-1]["signature_type"], good[-1]["signature_value"])
    # The signature held by the newest snapshot is labelled 1; the rest follow
    # in order of first appearance.
    order = [current] + [k for k in seen if k != current]

    changes = sum(
        1 for a, b in zip(good, good[1:])
        if (a["signature_type"], a["signature_value"]) != (b["signature_type"], b["signature_value"])
    )
    lines.append("  {} snapshot(s) with a signature, {} distinct signature(s), {} change(s).".format(
        len(good), len(seen), changes))

    for i, key in enumerate(order, start=1):
        e = seen[key]
        sig_type, sig_value = key
        lines.append("  SIG{}{}  type={}  value={}".format(
            i, " (current)" if key == current else "", sig_type or "-", sig_value))
        lines.append("        first seen {}  snapshot {}".format(
            e["first"]["collected_at"] or "?", e["first"]["snapshot_id"]))
        lines.append("        last  seen {}  snapshot {}".format(
            e["last"]["collected_at"] or "?", e["last"]["snapshot_id"]))
        lines.append("        appears in {} snapshot(s)".format(e["count"]))

    skipped = len(rows) - len(good)
    if skipped:
        lines.append("  {} snapshot(s) returned no usable signature (see the 'status' column).".format(skipped))
    return lines


def main():
    missing = [n for n, v in (("FWD_INSTANCE", INSTANCE),
                              ("FWD_NETWORK_ID", NETWORK_ID),
                              ("FWD_USERNAME", USERNAME),
                              ("FWD_PASSWORD", PASSWORD)) if not v]
    if missing:
        sys.exit("Missing setting(s): {}. See README.md.".format(", ".join(missing)))

    here = os.path.dirname(os.path.abspath(__file__))
    device_path = DEVICE_FILE if os.path.isabs(DEVICE_FILE) else os.path.join(here, DEVICE_FILE)
    if not os.path.isfile(device_path):
        sys.exit("Device list not found: {}. Copy devices.example.txt to devices.txt.".format(device_path))

    devices = []
    with open(device_path, "r", encoding="utf-8-sig") as fh:
        for line in fh:
            name = line.strip()
            if name and not name.startswith("#") and name not in devices:
                devices.append(name)
    if not devices:
        sys.exit("No device names in {}.".format(device_path))

    print("Devices: {}".format(len(devices)))
    snaps = list_snapshots()
    if not snaps:
        sys.exit("No snapshots matched the filters in CONFIG.")
    print("Snapshots: {}  ({} .. {})".format(
        len(snaps), snaps[0].get("createdAt", "?"), snaps[-1].get("createdAt", "?")))

    total = len(devices) * len(snaps)
    print("Fetching {} metadata files with {} workers...".format(total, MAX_WORKERS))

    results = {d: [] for d in devices}
    done = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(fetch_signature, d, s): d
            for d in devices for s in snaps
        }
        for fut in as_completed(futures):
            row = fut.result()
            results[row["device"]].append(row)
            done += 1
            if done % 25 == 0 or done == total:
                print("  {}/{}".format(done, total), end="\r", flush=True)
    print()

    # Order each device's rows oldest first and mark the change points.
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    ordered_rows = []
    summary_lines = []
    for d in devices:
        rows = sorted(results[d], key=lambda r: r["_created"] or epoch)
        prev = None
        for r in rows:
            if r["status"] == "OK":
                cur = (r["signature_type"], r["signature_value"])
                if prev is None:
                    r["changed"] = "FIRST"
                elif cur != prev:
                    r["changed"] = "CHANGED"
                prev = cur
            r.pop("_created", None)
        summary_lines.extend(summarize(d, rows))
        summary_lines.append("")
        ordered_rows.extend(rows)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_path = os.path.join(here, "{}_{}.csv".format(OUTPUT_PREFIX, stamp))
    fields = ["collected_at", "snapshot_id", "device", "signature_type",
              "signature_value", "changed", "status", "raw_signature"]

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if EMBED_SUMMARY_IN_CSV:
            w.writerow(["# Device signature audit", stamp])
            for line in summary_lines:
                w.writerow(["# " + line if line else "#"])
            w.writerow([])
        w.writerow(fields)
        for r in ordered_rows:
            w.writerow([r[f] for f in fields])

    print("\n".join(summary_lines))
    print("CSV written to {}".format(csv_path))

    if WRITE_SUMMARY_FILE:
        txt_path = os.path.join(here, "{}_{}_summary.txt".format(OUTPUT_PREFIX, stamp))
        with open(txt_path, "w", encoding="utf-8") as fh:
            fh.write("Device signature audit {}\n\n".format(stamp))
            fh.write("\n".join(summary_lines))
        print("Summary written to {}".format(txt_path))


if __name__ == "__main__":
    main()
