#!/usr/bin/env python3
"""
collection_error_history.py

Walk every processed snapshot in a Forward network and report, per device and
per snapshot, which collections succeeded and which failed with a specific
collection error -- by default NO_SPACE_LEFT_ON_COLLECTED_DEVICE (the UI's
"No space left on collected device").

Standard library only (Python 3.8+). Works on Windows, macOS and Linux.
Nothing environment-specific is stored in this file; it is safe to share.


ENDPOINTS (all in the published Forward OpenAPI spec)
-----------------------------------------------------
  GET /api/networks/{networkId}/snapshots?state=PROCESSED
      -> {"snapshots": [{"id", "createdAt", "processedAt", "state", ...}]}

  GET /api/networks/{networkId}/devices?snapshotId={id}&skip=N&limit=M
      -> [{"name", "type", "vendor", "model", "platform", "osVersion",
           "managementIps", "collectionError", "processingError", ...}]
      collectionError is ABSENT when collection succeeded; otherwise it is a
      DeviceCollectionError enum value, e.g. NO_SPACE_LEFT_ON_COLLECTED_DEVICE.

  GET /api/snapshots/{snapshotId}/metrics            (optional cross-check)
      -> {"deviceCollectionFailures": {"<ERROR>": count, ...}, ...}

One device-list call per snapshot (plus one per page for big networks).
Results are cached, so re-runs only fetch snapshots not seen before.


CREDENTIALS
-----------
Read from environment variables (same convention as the other scripts):

    FWD_ACCESS_KEY    API token access key          (required)
    FWD_SECRET_KEY    API token secret key          (required)
    FWD_NETWORK_ID    network id                    (or set NETWORK_ID below)
    FWD_BASE_URL      e.g. https://fwd.app          (optional, default below)
    FWD_CA_BUNDLE     path to a PEM CA bundle       (optional, see TLS below)

API_ACCESS_KEY / API_SECRET_KEY are accepted as alternate names. If the keys
are not set, the script prompts for them (the secret is not echoed).

--- Windows PowerShell: current window only (simplest) -----------------------

    $env:FWD_ACCESS_KEY = Read-Host -Prompt "Forward access key"
    $cred = Get-Credential -UserName "forward" -Message "Forward secret key"
    $env:FWD_SECRET_KEY = $cred.GetNetworkCredential().Password
    $env:FWD_NETWORK_ID = "123456"
    $env:FWD_BASE_URL   = "https://fwd.app"      # only if not fwd.app
    python .\\collection_error_history.py

Prompting keeps the secret out of PowerShell's history file.
Avoid  setx FWD_SECRET_KEY ...  -- setx stores it in plain text in the registry.

--- Windows Command Prompt (cmd.exe) ------------------------------------------

    set FWD_ACCESS_KEY=your-access-key
    set FWD_SECRET_KEY=your-secret-key
    set FWD_NETWORK_ID=123456
    python collection_error_history.py

--- macOS / Linux -------------------------------------------------------------

    read -rs -p "access key: " FWD_ACCESS_KEY && export FWD_ACCESS_KEY; echo
    read -rs -p "secret key: " FWD_SECRET_KEY && export FWD_SECRET_KEY; echo
    export FWD_NETWORK_ID=123456
    python3 collection_error_history.py


TLS AND PROXIES
---------------
* "CERTIFICATE_VERIFY_FAILED" behind TLS inspection: point FWD_CA_BUNDLE at
  the organisation's root CA (PEM). VERIFY_TLS = False also works but
  disables verification.
* Proxies: Python honours HTTPS_PROXY automatically.


OUTPUT (folder next to this script, timestamped)
------------------------------------------------
  report.html             self-contained summary: headline stats, per-snapshot
                          chart/table, per-device timeline grid, breakdowns
  device_summary.csv      (1) one row per device: counts, rates, first/last
                          error, streaks, flips, pattern string
  device_matrix.csv       (1) device x snapshot grid: OK / ERR / other error
                          code / blank when the device was not in the snapshot
  snapshot_summary.csv    (2) one row per snapshot: total, OK, target-error
                          count, other errors, new vs recovered since previous,
                          overlap with previous, metrics cross-check
  breakdown.csv           (3) affected-device rate by platform/vendor/model/
                          OS version/type, and by snapshot hour of day (UTC)

Status codes used in the matrix and pattern strings:
    .  collected OK          X  target error (NO_SPACE_LEFT_ON_COLLECTED_DEVICE)
    o  some other error      (space) device not in that snapshot
"""

import base64
import csv
import getpass
import html
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# =============================================================================
# CONFIG -- edit these values. Credentials come from environment variables.
# =============================================================================
DEFAULT_BASE_URL = "https://fwd.app"   # used when FWD_BASE_URL is not set
NETWORK_ID = ""                        # used when FWD_NETWORK_ID is not set

# Collection error(s) to track. Values are DeviceCollectionError enum names.
# Add "NO_SPACE_LEFT_ON_COLLECTOR" too if you want the collector-side variant
# counted as the same problem (by default it shows up under "other errors").
TARGET_ERRORS = ["NO_SPACE_LEFT_ON_COLLECTED_DEVICE"]

# Which snapshots: newest N (0 = all processed), and/or a start date.
MAX_SNAPSHOTS = 0
SINCE_DATE = ""                        # "YYYY-MM-DD", "" = no cutoff

# Device-list page size. The loop stops on an empty page, so this is safe
# even if the server caps pages at a lower number.
PAGE_SIZE = 5000

# Also call /snapshots/{id}/metrics and compare its count to ours.
CROSS_CHECK_METRICS = True

# A device hit in at least this many snapshots counts as "recurring".
RECURRING_MIN_HITS = 2

# Device timeline grid in the HTML: show only affected devices (True) or all.
GRID_AFFECTED_ONLY = True
GRID_MAX_SNAPSHOTS = 120               # newest N columns in the HTML grid

MAX_WORKERS = 4                        # snapshots fetched in parallel
USE_CACHE = True                       # reuse per-snapshot results across runs
VERIFY_TLS = True                      # False only as a last resort
TIMEOUT_SECONDS = 300

# "" = a folder next to this script named collection_error_history_output
OUTPUT_DIR = ""
# =============================================================================

CACHE_VERSION = 1
OK, TARGET, OTHER, ABSENT = ".", "X", "o", " "


# -----------------------------------------------------------------------------
# Credentials and HTTP
# -----------------------------------------------------------------------------

def env_first(*names):
    for n in names:
        v = os.environ.get(n, "").strip()
        if v:
            return v
    return ""


def load_settings():
    base_url = env_first("FWD_BASE_URL") or DEFAULT_BASE_URL
    access = env_first("FWD_ACCESS_KEY", "API_ACCESS_KEY")
    secret = env_first("FWD_SECRET_KEY", "API_SECRET_KEY")
    network = env_first("FWD_NETWORK_ID") or NETWORK_ID.strip()

    missing = [n for n, v in (("FWD_ACCESS_KEY", access),
                              ("FWD_SECRET_KEY", secret),
                              ("FWD_NETWORK_ID", network)) if not v]
    if missing:
        if not sys.stdin.isatty():
            sys.exit(f"Not set: {', '.join(missing)}. "
                     "See the CREDENTIALS section at the top of this file.")
        print(f"Not set: {', '.join(missing)}; prompting "
              "(see the top of this file to set them once).")
        if not access:
            access = input("Forward access key: ").strip()
        if not secret:
            secret = getpass.getpass("Forward secret key: ").strip()
        if not network:
            network = input("Forward network id: ").strip()
    if not access or not secret or not network:
        sys.exit("Missing credentials or network id.")
    return base_url.rstrip("/"), access, secret, network


def make_ssl_context():
    ctx = ssl.create_default_context()
    ca_bundle = env_first("FWD_CA_BUNDLE")
    if ca_bundle:
        if not os.path.isfile(ca_bundle):
            sys.exit(f"FWD_CA_BUNDLE points to a missing file: {ca_bundle}")
        ctx.load_verify_locations(cafile=ca_bundle)
    if not VERIFY_TLS:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class Client:
    def __init__(self, base_url, access, secret):
        self.base_url = base_url
        token = base64.b64encode(f"{access}:{secret}".encode()).decode()
        self.auth = "Basic " + token
        self.ctx = make_ssl_context()

    def get(self, path, params=None):
        """Return (data, error_string). Exactly one is None."""
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", self.auth)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS,
                                        context=self.ctx) as resp:
                return json.loads(resp.read().decode("utf-8")), None
        except urllib.error.HTTPError as e:
            hint = {401: "auth failed - check the API keys",
                    403: "no permission on this network",
                    404: "not found",
                    409: "snapshot is still processing"}.get(e.code, "")
            return None, f"HTTP {e.code}{' (' + hint + ')' if hint else ''}"
        except urllib.error.URLError as e:
            reason = str(e.reason)
            if "CERTIFICATE_VERIFY_FAILED" in reason:
                reason += " (set FWD_CA_BUNDLE - see TLS AND PROXIES)"
            return None, f"connection error: {reason}"
        except (json.JSONDecodeError, TimeoutError, OSError) as e:
            return None, f"request failed: {e}"


# -----------------------------------------------------------------------------
# Fetching
# -----------------------------------------------------------------------------

def list_snapshots(client, network):
    data, err = client.get(f"/api/networks/{network}/snapshots",
                           {"state": "PROCESSED"})
    if err:
        sys.exit(f"Could not list snapshots for network {network}: {err}")
    snaps = data.get("snapshots", []) if isinstance(data, dict) else []
    snaps = [s for s in snaps if s.get("id")]
    if SINCE_DATE:
        snaps = [s for s in snaps if (s.get("createdAt") or "")[:10] >= SINCE_DATE]
    snaps.sort(key=lambda s: s.get("createdAt") or "")   # oldest first
    if MAX_SNAPSHOTS > 0:
        snaps = snaps[-MAX_SNAPSHOTS:]
    return snaps


def fetch_snapshot(client, network, snap_id):
    """Compact per-snapshot record: {devices: {name: [err, meta]}, metrics}."""
    devices = {}
    skip = 0
    while True:
        page, err = client.get(f"/api/networks/{network}/devices",
                               {"snapshotId": snap_id, "skip": skip,
                                "limit": PAGE_SIZE})
        if err:
            return None, err
        if not isinstance(page, list) or not page:
            break
        for d in page:
            name = d.get("name")
            if not name:
                continue
            devices[name] = {
                "e": d.get("collectionError") or "",
                "p": d.get("processingError") or "",
                "platform": d.get("platform") or "",
                "vendor": d.get("vendor") or "",
                "model": d.get("model") or "",
                "os": d.get("osVersion") or "",
                "type": d.get("type") or "",
                "src": d.get("sourceName") or "",
                "ip": ",".join(d.get("managementIps") or []),
            }
        skip += len(page)

    metrics = None
    if CROSS_CHECK_METRICS:
        m, merr = client.get(f"/api/snapshots/{snap_id}/metrics")
        if not merr and isinstance(m, dict):
            metrics = {
                "failures": m.get("deviceCollectionFailures") or {},
                "numCollectionFailureDevices": m.get("numCollectionFailureDevices"),
                "numSuccessfulDevices": m.get("numSuccessfulDevices"),
            }
    return {"devices": devices, "metrics": metrics}, None


def output_dir():
    base = OUTPUT_DIR or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "collection_error_history_output")
    os.makedirs(base, exist_ok=True)
    return base


def cache_path(network):
    return os.path.join(output_dir(), f"cache_net{network}.json")


def load_cache(network):
    if not USE_CACHE or not os.path.exists(cache_path(network)):
        return {}
    try:
        with open(cache_path(network), encoding="utf-8") as f:
            blob = json.load(f)
        if blob.get("version") == CACHE_VERSION:
            return blob.get("snapshots", {})
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_cache(network, data):
    if not USE_CACHE:
        return
    tmp = cache_path(network) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"version": CACHE_VERSION, "snapshots": data}, f)
    os.replace(tmp, cache_path(network))


# -----------------------------------------------------------------------------
# Analysis
# -----------------------------------------------------------------------------

def status_of(err):
    if not err:
        return OK
    return TARGET if err in TARGET_ERRORS else OTHER


def pct(a, b):
    return round(100.0 * a / b, 1) if b else 0.0


def runs(pattern, ch):
    """Longest run of ch, ignoring snapshots where the device was absent."""
    best = cur = 0
    for c in pattern:
        if c == ABSENT:
            continue
        cur = cur + 1 if c == ch else 0
        best = max(best, cur)
    return best


def flips(pattern):
    """OK<->target transitions, skipping absences and other errors."""
    seq = [c for c in pattern if c in (OK, TARGET)]
    return sum(1 for a, b in zip(seq, seq[1:]) if a != b)


def episodes(pattern):
    """Separate runs of the target error (absences and other errors skipped)."""
    seq = [c for c in pattern if c in (OK, TARGET)]
    return sum(1 for i, c in enumerate(seq)
               if c == TARGET and (i == 0 or seq[i - 1] != TARGET))


def jaccard(a, b):
    if not a and not b:
        return ""
    return round(len(a & b) / len(a | b), 2)


def analyse(snaps, data):
    order = [s["id"] for s in snaps if s["id"] in data]
    meta = {s["id"]: s for s in snaps}

    # Latest metadata seen for each device.
    dev_meta = {}
    for sid in order:
        for name, d in data[sid]["devices"].items():
            dev_meta[name] = d

    # Device timelines.
    devices = sorted(dev_meta)
    pattern = {n: "".join(status_of(data[sid]["devices"][n]["e"])
                          if n in data[sid]["devices"] else ABSENT
                          for sid in order)
               for n in devices}

    # Per-snapshot rows.
    snap_rows, prev_set, target_sets = [], None, []
    for i, sid in enumerate(order):
        devs = data[sid]["devices"]
        tset = {n for n, d in devs.items() if d["e"] in TARGET_ERRORS}
        other = Counter(d["e"] for d in devs.values()
                        if d["e"] and d["e"] not in TARGET_ERRORS)
        ok = sum(1 for d in devs.values() if not d["e"])
        m = data[sid].get("metrics") or {}
        m_target = (sum(int(m["failures"].get(e, 0) or 0) for e in TARGET_ERRORS)
                    if m.get("failures") is not None else "")
        created = meta[sid].get("createdAt") or ""
        row = {
            "snapshot_id": sid,
            "created_at": created,
            "processed_at": meta[sid].get("processedAt") or "",
            "devices_total": len(devs),
            "collected_ok": ok,
            "target_error": len(tset),
            "target_error_pct": pct(len(tset), len(devs)),
            "other_errors": sum(other.values()),
            "top_other_errors": "; ".join(f"{k}={v}" for k, v in other.most_common(4)),
            "new_vs_prev": len(tset - prev_set) if prev_set is not None else "",
            "recovered_vs_prev": len(prev_set - tset) if prev_set is not None else "",
            "same_as_prev": len(tset & prev_set) if prev_set is not None else "",
            "jaccard_vs_prev": jaccard(tset, prev_set) if prev_set is not None else "",
            "metrics_target_count": m_target,
            "metrics_match": ("" if m_target == "" else
                              ("yes" if m_target == len(tset) else "NO")),
        }
        snap_rows.append(row)
        target_sets.append(tset)
        prev_set = tset

    # Per-device rows.
    dev_rows = []
    for n in devices:
        p = pattern[n]
        hits = [order[i] for i, c in enumerate(p) if c == TARGET]
        present = sum(1 for c in p if c != ABSENT)
        d = dev_meta[n]
        dev_rows.append({
            "device": n,
            "platform": d["platform"], "vendor": d["vendor"],
            "model": d["model"], "os_version": d["os"], "type": d["type"],
            "source": d["src"], "management_ips": d["ip"],
            "snapshots_present": present,
            "collected_ok": p.count(OK),
            "target_error": len(hits),
            "other_error": p.count(OTHER),
            "target_error_pct": pct(len(hits), present),
            "first_target_snapshot": hits[0] if hits else "",
            "first_target_at": meta[hits[0]].get("createdAt", "") if hits else "",
            "last_target_snapshot": hits[-1] if hits else "",
            "last_target_at": meta[hits[-1]].get("createdAt", "") if hits else "",
            "longest_error_streak": runs(p, TARGET),
            "error_episodes": episodes(p),
            "ok_error_flips": flips(p),
            "status_in_latest": {OK: "OK", TARGET: "TARGET", OTHER: "OTHER",
                                 ABSENT: "ABSENT"}[p[-1]] if p else "",
            "other_error_codes": "; ".join(sorted({
                data[sid]["devices"][n]["e"] for sid in order
                if n in data[sid]["devices"]
                and data[sid]["devices"][n]["e"]
                and data[sid]["devices"][n]["e"] not in TARGET_ERRORS})),
            "pattern": p,
        })
    dev_rows.sort(key=lambda r: (-r["target_error"], r["device"]))

    affected = [r for r in dev_rows if r["target_error"]]
    affected_names = {r["device"] for r in affected}

    # Breakdowns: affected devices / population per attribute.
    breakdown = []
    for attr in ("platform", "vendor", "model", "os_version", "type", "source"):
        pop, aff, events = Counter(), Counter(), Counter()
        for r in dev_rows:
            k = r[attr] or "(blank)"
            pop[k] += 1
            if r["device"] in affected_names:
                aff[k] += 1
                events[k] += r["target_error"]
        for k in sorted(pop, key=lambda k: (-aff[k], k)):
            if aff[k] or attr in ("platform", "vendor"):
                breakdown.append({"dimension": attr, "value": k,
                                  "devices": pop[k], "affected_devices": aff[k],
                                  "affected_pct": pct(aff[k], pop[k]),
                                  "error_events": events[k]})
    # Hour of day (UTC) of snapshot creation vs error count.
    hour_snaps, hour_err = Counter(), Counter()
    weekday_snaps, weekday_err = Counter(), Counter()
    for row in snap_rows:
        try:
            dt = datetime.strptime(row["created_at"][:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue
        hour_snaps[dt.hour] += 1
        hour_err[dt.hour] += row["target_error"]
        wd = dt.strftime("%a")
        weekday_snaps[wd] += 1
        weekday_err[wd] += row["target_error"]
    for h in sorted(hour_snaps):
        breakdown.append({"dimension": "snapshot_hour_utc", "value": f"{h:02d}",
                          "devices": hour_snaps[h], "affected_devices": "",
                          "affected_pct": "",
                          "error_events": hour_err[h]})
    for wd in ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"):
        if weekday_snaps[wd]:
            breakdown.append({"dimension": "snapshot_weekday_utc", "value": wd,
                              "devices": weekday_snaps[wd], "affected_devices": "",
                              "affected_pct": "",
                              "error_events": weekday_err[wd]})

    # Headline stats.
    n_snaps = len(order)
    with_err = sum(1 for s in target_sets if s)
    counts = [len(s) for s in target_sets]
    nonzero = [c for c in counts if c]
    recurring = [r for r in affected if r["target_error"] >= RECURRING_MIN_HITS]
    one_off = [r for r in affected if r["target_error"] == 1]
    always = [r for r in affected
              if r["target_error"] == r["snapshots_present"]]
    jac = [r["jaccard_vs_prev"] for r in snap_rows
           if isinstance(r["jaccard_vs_prev"], float)]
    ever_ok_after = [r for r in affected if r["error_episodes"] >= 2]
    union_hits = sum(counts)
    top10 = sum(r["target_error"] for r in affected[:10])

    # Devices that always fail together (identical hit sets, size >= 2).
    groups = defaultdict(list)
    for r in recurring:
        groups[r["pattern"].replace(OTHER, OK)].append(r["device"])
    cohorts = sorted((g for g in groups.values() if len(g) >= 2),
                     key=len, reverse=True)

    mismatches = [r for r in snap_rows if r["metrics_match"] == "NO"]

    stats = [
        ("Processed snapshots analysed", n_snaps),
        ("Date range", f"{snap_rows[0]['created_at'][:16]}  ->  "
                       f"{snap_rows[-1]['created_at'][:16]}" if snap_rows else ""),
        ("Distinct devices seen", len(devices)),
        ("Snapshots with >=1 target error", f"{with_err} ({pct(with_err, n_snaps)}%)"),
        ("Distinct devices ever affected", f"{len(affected)} ({pct(len(affected), len(devices))}% of devices)"),
        ("Total device-snapshot error events", union_hits),
        ("Per-snapshot count (min / median / max, error snapshots only)",
         f"{min(nonzero)} / {sorted(nonzero)[len(nonzero)//2]} / {max(nonzero)}" if nonzero else "n/a"),
        (f"Recurring devices (>= {RECURRING_MIN_HITS} snapshots)", len(recurring)),
        ("One-off devices (exactly 1 snapshot)", len(one_off)),
        ("Devices failing in EVERY snapshot they appear in", len(always)),
        ("Intermittent devices (error, recover, error again: >=2 episodes)", len(ever_ok_after)),
        ("Share of all error events from the top 10 devices",
         f"{pct(top10, union_hits)}%" if union_hits else "n/a"),
        ("Mean overlap with previous snapshot's error set (Jaccard, 1.0 = identical)",
         round(sum(jac) / len(jac), 2) if jac else "n/a"),
        ("Device cohorts that always fail together (size >= 2)",
         f"{len(cohorts)} (largest {len(cohorts[0])})" if cohorts else "0"),
        ("Affected devices currently failing (latest snapshot)",
         sum(1 for r in affected if r["status_in_latest"] == "TARGET")),
        ("Snapshots where /metrics count disagrees with device list",
         len(mismatches) if CROSS_CHECK_METRICS else "not checked"),
    ]
    return {"order": order, "meta": meta, "data": data, "snap_rows": snap_rows,
            "dev_rows": dev_rows, "affected": affected, "breakdown": breakdown,
            "stats": stats, "cohorts": cohorts}


# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------

def write_csv(path, rows, fields=None):
    if not rows:
        open(path, "w").close()
        return
    fields = fields or list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def write_matrix(path, res):
    order, meta = res["order"], res["meta"]
    data = res["data"]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["device", "target_error_count"] +
                   [f"{meta[s].get('createdAt', '')[:16]} ({s})" for s in order])
        for r in res["dev_rows"]:
            cells = []
            for c, sid in zip(r["pattern"], order):
                if c == ABSENT:
                    cells.append("")
                elif c == OK:
                    cells.append("OK")
                else:   # target or other: show the actual error code
                    cells.append(data[sid]["devices"][r["device"]]["e"])
            w.writerow([r["device"], r["target_error"]] + cells)


def write_html(path, network, res):
    e = html.escape
    snap_rows, order, meta = res["snap_rows"], res["order"], res["meta"]
    maxc = max([r["target_error"] for r in snap_rows] + [1])

    bars = "".join(
        f'<div class="bar" title="{e(r["created_at"][:16])}  {r["target_error"]} devices">'
        f'<div style="height:{100 * r["target_error"] / maxc:.1f}%"></div></div>'
        for r in snap_rows)

    stats = "".join(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>"
                    for k, v in res["stats"])

    snap_tbl = "".join(
        f"<tr><td>{e(r['created_at'][:16])}</td><td class=m>{e(r['snapshot_id'])}</td>"
        f"<td>{r['devices_total']}</td><td>{r['collected_ok']}</td>"
        f"<td class=t>{r['target_error']}</td><td>{r['target_error_pct']}</td>"
        f"<td>{r['new_vs_prev']}</td><td>{r['recovered_vs_prev']}</td>"
        f"<td>{r['jaccard_vs_prev']}</td><td>{r['other_errors']}</td>"
        f"<td>{e(r['metrics_match'])}</td></tr>"
        for r in reversed(snap_rows))

    grid_rows = res["affected"] if GRID_AFFECTED_ONLY else res["dev_rows"]
    cols = order[-GRID_MAX_SNAPSHOTS:]
    off = len(order) - len(cols)
    cls = {OK: "ok", TARGET: "x", OTHER: "o", ABSENT: "na"}
    grid = "".join(
        f"<tr><td class=dn>{e(r['device'])}</td><td>{r['target_error']}</td>"
        + "".join(f'<td class="c {cls[c]}" title="{e(meta[sid].get("createdAt", "")[:16])}"></td>'
                  for c, sid in zip(r["pattern"][off:], cols))
        + "</tr>" for r in grid_rows)

    dev_tbl = "".join(
        f"<tr><td class=dn>{e(r['device'])}</td><td>{e(r['platform'])}</td>"
        f"<td>{e(r['model'])}</td><td>{e(r['os_version'])}</td>"
        f"<td>{r['snapshots_present']}</td><td class=t>{r['target_error']}</td>"
        f"<td>{r['target_error_pct']}</td><td>{r['longest_error_streak']}</td>"
        f"<td>{r['error_episodes']}</td><td>{e(r['first_target_at'][:16])}</td>"
        f"<td>{e(r['last_target_at'][:16])}</td><td>{e(r['status_in_latest'])}</td></tr>"
        for r in res["affected"])

    brk = "".join(
        f"<tr><td>{e(b['dimension'])}</td><td>{e(str(b['value']))}</td>"
        f"<td>{b['devices']}</td><td>{b['affected_devices']}</td>"
        f"<td>{b['affected_pct']}</td><td>{b['error_events']}</td></tr>"
        for b in res["breakdown"])

    cohorts = "".join(f"<li>{len(g)} devices: {e(', '.join(sorted(g)[:15]))}"
                      f"{' ...' if len(g) > 15 else ''}</li>"
                      for g in res["cohorts"][:10]) or "<li>none</li>"

    page = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Collection Error History</title>
<style>
:root{{--bg:#fff;--fg:#1d1d1f;--mut:#6e6e73;--line:#e3e3e8;--ok:#cfe8d5;--x:#d9480f;--o:#f1c27d;--na:#f4f4f6}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16171a;--fg:#ececf0;--mut:#9a9aa3;--line:#2c2d33;--ok:#24452e;--x:#ff7a45;--o:#8a6a2c;--na:#1f2025}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;padding:24px 16px;max-width:1200px;margin:auto}}
h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:16px;margin:28px 0 8px}}
.sub{{color:var(--mut)}} table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);white-space:nowrap}}
.stats th{{font-weight:500;color:var(--mut);white-space:normal}} .t{{color:var(--x);font-weight:600}}
.m{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
.wrap{{overflow-x:auto}} .chart{{display:flex;align-items:flex-end;gap:1px;height:120px;border-bottom:1px solid var(--line)}}
.bar{{flex:1;height:100%;display:flex;align-items:flex-end}} .bar div{{width:100%;background:var(--x);min-height:0}}
.grid td.c{{width:8px;min-width:8px;padding:0;height:14px;border:1px solid var(--bg)}}
.ok{{background:var(--ok)}} .x{{background:var(--x)}} .o{{background:var(--o)}} .na{{background:var(--na)}}
.dn{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
.legend span{{display:inline-block;width:10px;height:10px;margin:0 4px 0 12px;vertical-align:middle}}
</style></head><body>
<h1>Collection error history</h1>
<div class="sub">Network {e(network)} &middot; error(s): {e(', '.join(TARGET_ERRORS))} &middot;
generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>

<h2>Headline</h2><table class="stats">{stats}</table>

<h2>Affected devices per snapshot (oldest &rarr; newest)</h2>
<div class="chart">{bars}</div>

<h2>Device timeline (newest {len(cols)} snapshots)</h2>
<div class="legend sub"><span class="ok"></span>OK<span class="x"></span>target error
<span class="o"></span>other error<span class="na"></span>not in snapshot</div>
<div class="wrap"><table class="grid"><tr><th>device</th><th>hits</th><th colspan="{len(cols)}"></th></tr>{grid}</table></div>

<h2>Affected devices</h2>
<div class="wrap"><table><tr><th>device</th><th>platform</th><th>model</th><th>OS</th><th>present</th>
<th>errors</th><th>%</th><th>longest streak</th><th>episodes</th><th>first</th><th>last</th><th>latest</th></tr>{dev_tbl}</table></div>

<h2>Devices that always fail together</h2><ul>{cohorts}</ul>

<h2>Per snapshot (newest first)</h2>
<div class="wrap"><table><tr><th>created</th><th>snapshot</th><th>devices</th><th>OK</th><th>target</th><th>%</th>
<th>new</th><th>recovered</th><th>overlap</th><th>other errors</th><th>metrics match</th></tr>{snap_tbl}</table></div>

<h2>Breakdowns</h2>
<div class="sub">Attribute rows: devices = population, affected = ever hit. Hour/weekday rows: devices = snapshot count, error events = summed target errors.</div>
<div class="wrap"><table><tr><th>dimension</th><th>value</th><th>devices</th><th>affected</th><th>%</th><th>error events</th></tr>{brk}</table></div>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    base_url, access, secret, network = load_settings()
    client = Client(base_url, access, secret)

    snaps = list_snapshots(client, network)
    if not snaps:
        sys.exit("No processed snapshots matched.")
    print(f"{len(snaps)} processed snapshots on network {network}")

    cache = load_cache(network)
    todo = [s["id"] for s in snaps if s["id"] not in cache]
    print(f"{len(snaps) - len(todo)} cached, fetching {len(todo)}")

    failed = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futs = {pool.submit(fetch_snapshot, client, network, sid): sid for sid in todo}
        for i, fut in enumerate(as_completed(futs), 1):
            sid = futs[fut]
            rec, err = fut.result()
            if err:
                failed[sid] = err
                print(f"  [{i}/{len(todo)}] {sid}: FAILED {err}")
            else:
                cache[sid] = rec
                print(f"  [{i}/{len(todo)}] {sid}: {len(rec['devices'])} devices")
            if i % 20 == 0:
                save_cache(network, cache)
    save_cache(network, cache)

    data = {s["id"]: cache[s["id"]] for s in snaps if s["id"] in cache}
    if not data:
        sys.exit("No snapshot could be fetched.")
    res = analyse(snaps, data)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = os.path.join(output_dir(), f"net{network}_{stamp}")
    os.makedirs(out, exist_ok=True)
    write_csv(os.path.join(out, "device_summary.csv"), res["dev_rows"])
    write_matrix(os.path.join(out, "device_matrix.csv"), res)
    write_csv(os.path.join(out, "snapshot_summary.csv"), res["snap_rows"])
    write_csv(os.path.join(out, "breakdown.csv"), res["breakdown"])
    write_html(os.path.join(out, "report.html"), network, res)

    print()
    for k, v in res["stats"]:
        print(f"  {k:<72} {v}")
    print("\n  Top affected devices:")
    for r in res["affected"][:15]:
        print(f"    {r['device']:<40} {r['target_error']:>4}/{r['snapshots_present']:<4}"
              f" {r['platform']:<16} {r['pattern'][-60:]}")
    if failed:
        print(f"\n  {len(failed)} snapshot(s) could not be fetched; re-run to retry.")
    print(f"\nOutput: {out}")


if __name__ == "__main__":
    main()
