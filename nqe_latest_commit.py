#!/usr/bin/env python3
"""
nqe_latest_commit.py

For each NQE query listed in the CONFIG block, fetch its commit history from
Forward and print an email-pasteable summary of the latest commit ID. If you
supply a commit ID, the report also says whether it is current, how many
commits behind it is, or that it is not in the query's history.

Standard library only (Python 3.8+). Works on Windows, macOS and Linux.
Nothing environment-specific is stored in this file; it is safe to publish.


ENDPOINT
--------
    GET {FWD_BASE_URL}/api/nqe/queries/{queryId}/history
    -> {"commits": [{"id", "path", "author", "committedAt" (epoch ms), ...}]}

This endpoint is used by the Forward UI but is not in the published OpenAPI
spec, so a future release could change it. The commits list is not guaranteed
to be newest-first; the latest commit is the one with the highest committedAt.


CREDENTIALS
-----------
You need a Forward API token (Forward UI: Settings -> API Tokens). It has an
access key and a secret key. The script reads them from environment variables:

    FWD_ACCESS_KEY    API token access key          (required)
    FWD_SECRET_KEY    API token secret key          (required)
    FWD_BASE_URL      e.g. https://fwd.app          (optional, default below)
    FWD_CA_BUNDLE     path to a PEM CA bundle       (optional, see TLS below)

API_ACCESS_KEY / API_SECRET_KEY are accepted as alternate names. If the keys
are not set, the script prompts for them (the secret is not echoed).

--- Windows PowerShell: current window only (simplest) -----------------------

    $env:FWD_ACCESS_KEY = Read-Host -Prompt "Forward access key"
    $cred = Get-Credential -UserName "forward" -Message "Forward secret key"
    $env:FWD_SECRET_KEY = $cred.GetNetworkCredential().Password
    $env:FWD_BASE_URL   = "https://fwd.app"      # only if not fwd.app
    python .\\nqe_latest_commit.py

The values disappear when the window closes. Prompting (rather than typing
$env:FWD_SECRET_KEY = "abc...") keeps the secret out of PowerShell's history
file. To clear it early:  Remove-Item Env:FWD_SECRET_KEY

--- Windows PowerShell: reuse across sessions (encrypted at rest) -------------

Once: save both keys encrypted with DPAPI. Only your Windows account on this
machine can decrypt the files.

    Read-Host -AsSecureString -Prompt "Forward access key" |
        ConvertFrom-SecureString | Set-Content "$HOME\\.fwd_access_key"
    Read-Host -AsSecureString -Prompt "Forward secret key" |
        ConvertFrom-SecureString | Set-Content "$HOME\\.fwd_secret_key"

Each session (or add these lines to your profile: notepad $PROFILE):

    $a = Get-Content "$HOME\\.fwd_access_key" | ConvertTo-SecureString
    $s = Get-Content "$HOME\\.fwd_secret_key" | ConvertTo-SecureString
    $env:FWD_ACCESS_KEY = [System.Net.NetworkCredential]::new("", $a).Password
    $env:FWD_SECRET_KEY = [System.Net.NetworkCredential]::new("", $s).Password

If ConvertTo-SecureString fails with a key error, the file was created by a
different Windows account or machine; redo the "once" step.

Avoid  setx FWD_SECRET_KEY ...  -- setx stores the value in plain text in
HKCU\\Environment, readable by any process running as you, until deleted.

--- Windows Command Prompt (cmd.exe), current window only ---------------------

    set FWD_ACCESS_KEY=your-access-key
    set FWD_SECRET_KEY=your-secret-key
    python nqe_latest_commit.py

Note cmd.exe shows the secret on screen. PowerShell's prompt method is better.

--- macOS / Linux (bash or zsh) ------------------------------------------------

    read -rs -p "access key: " FWD_ACCESS_KEY && export FWD_ACCESS_KEY; echo
    read -rs -p "secret key: " FWD_SECRET_KEY && export FWD_SECRET_KEY; echo
    python3 nqe_latest_commit.py


TLS AND PROXIES
---------------
* Corporate networks that inspect TLS often cause "CERTIFICATE_VERIFY_FAILED".
  Fix it properly by pointing FWD_CA_BUNDLE at your organisation's root CA
  (PEM file). VERIFY_TLS = False below also works but disables verification.
* Proxies: Python honours the HTTPS_PROXY environment variable automatically,
  e.g.  $env:HTTPS_PROXY = "http://proxy.example.com:8080"


USAGE
-----
1. Set the credentials (above).
2. Edit QUERIES in the CONFIG block: friendly name, query ID and, optionally,
   the commit ID you want to check. The query ID is in the NQE Library
   information callout for the query (it starts with Q_ or FQ_).
3. Run:  python nqe_latest_commit.py      (Windows)
         python3 nqe_latest_commit.py     (macOS / Linux)
4. The report prints to the console and is copied to the clipboard, ready to
   paste into an email.
"""

import base64
import getpass
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# =============================================================================
# CONFIG -- edit these values. Credentials come from environment variables.
# =============================================================================
DEFAULT_BASE_URL = "https://fwd.app"  # used when FWD_BASE_URL is not set
VERIFY_TLS = True                     # False only as a last resort (see TLS above)
TIMEOUT_SECONDS = 30
COPY_TO_CLIPBOARD = True              # Windows: clip.exe   macOS: pbcopy

# One entry per query. "commit_id" is optional; leave it "" to just report
# the latest commit. The values below are placeholders.
QUERIES = [
    {
        "friendly_name": "Example query",
        "query_id": "Q_0000000000000000000000000000000000000000",
        "commit_id": "",
    },
    # {"friendly_name": "Another query",
    #  "query_id": "Q_...",
    #  "commit_id": "0123456789abcdef0123456789abcdef01234567"},
]
# =============================================================================


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

    if not access or not secret:
        if not sys.stdin.isatty():
            sys.exit("FWD_ACCESS_KEY / FWD_SECRET_KEY are not set. "
                     "See the CREDENTIALS section at the top of this file.")
        print("FWD_ACCESS_KEY / FWD_SECRET_KEY not set; prompting "
              "(see the top of this file to set them once).")
        if not access:
            access = input("Forward access key: ").strip()
        if not secret:
            secret = getpass.getpass("Forward secret key: ").strip()
    if not access or not secret:
        sys.exit("No credentials supplied.")
    return base_url.rstrip("/"), access, secret


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

    def history(self, query_id):
        """Return (commits, error_string). Exactly one is None."""
        qid = urllib.parse.quote(query_id, safe="")
        url = f"{self.base_url}/api/nqe/queries/{qid}/history"
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", self.auth)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS,
                                        context=self.ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            hint = {401: "auth failed - check the API keys",
                    403: "no permission",
                    404: "query ID not found"}.get(e.code, "")
            return None, f"HTTP {e.code}{' (' + hint + ')' if hint else ''}"
        except urllib.error.URLError as e:
            reason = str(e.reason)
            if "CERTIFICATE_VERIFY_FAILED" in reason:
                reason += " (set FWD_CA_BUNDLE - see TLS AND PROXIES)"
            return None, f"connection error: {reason}"
        except (json.JSONDecodeError, TimeoutError, OSError) as e:
            return None, f"request failed: {e}"

        commits = data.get("commits") if isinstance(data, dict) else None
        if not commits:
            return None, "no commits returned"
        return commits, None


def fmt_time(ms):
    if ms is None:
        return "unknown time"
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC")


def build_entry(client, q):
    name = q.get("friendly_name") or "(unnamed)"
    query_id = (q.get("query_id") or "").strip()
    supplied = (q.get("commit_id") or "").strip()

    lines = [name]
    if not query_id:
        lines.append("  ERROR:           no query_id supplied")
        return lines

    commits, err = client.history(query_id)
    if err:
        lines.append(f"  Query ID:        {query_id}")
        lines.append(f"  ERROR:           {err}")
        return lines

    commits = sorted(commits, key=lambda c: c.get("committedAt") or 0,
                     reverse=True)          # newest first
    latest = commits[0]

    lines.append(f"  Path:            {latest.get('path', '')}")
    lines.append(f"  Query ID:        {query_id}")
    lines.append(f"  Latest commit:   {latest.get('id', '')}")
    lines.append(f"  Committed:       {fmt_time(latest.get('committedAt'))}"
                 f" by {latest.get('author', 'unknown')}")

    if supplied:
        ids = [c.get("id", "") for c in commits]
        if supplied == ids[0]:
            status = "CURRENT"
        elif supplied in ids:
            behind = ids.index(supplied)
            status = (f"OUT OF DATE ({behind} newer "
                      f"commit{'s' if behind != 1 else ''})")
        else:
            status = "NOT FOUND in this query's history"
        lines.append(f"  Supplied commit: {supplied}")
        lines.append(f"  Status:          {status}")
    return lines


def copy_to_clipboard(text):
    try:
        if sys.platform == "win32":
            # clip.exe reads the console code page; ASCII report is safe.
            subprocess.run(["clip"], input=text.encode("ascii", "replace"),
                           check=True)
        elif sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        else:
            return False
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def main():
    if not QUERIES:
        sys.exit("Add at least one entry to QUERIES in the CONFIG block.")

    base_url, access, secret = load_settings()
    client = Client(base_url, access, secret)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"NQE Latest Commits ({base_url}) - {now}", ""]
    for q in QUERIES:
        out.extend(build_entry(client, q))
        out.append("")
    report = "\n".join(out).rstrip() + "\n"

    print(report)
    if COPY_TO_CLIPBOARD and copy_to_clipboard(report):
        print("(Copied to clipboard.)")


if __name__ == "__main__":
    main()
