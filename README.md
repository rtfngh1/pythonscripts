# fwd_signature_audit

Tracks the device signature a network's snapshots hold for a set of devices, so
you can find the snapshots where the signature changed.

Every collected device carries a signature in its per-snapshot `metadata.txt`:

```
signature 1 {
  cisco_ios 3 {
    value 1: "71305217"
  }
}
```

The signature should be stable for the life of a device. When it is not, the
platform records more than one usage entry for the same device name, which
consumes extra licenses. This script walks the snapshot history, records the
signature each snapshot holds for each device you name, and reports when each
distinct signature first and last appeared.

Python 3.8 or newer. Standard library only — nothing to install.

## Output

`signature_audit_<timestamp>.csv`, oldest snapshot first, one row per
(device, snapshot):

| column | meaning |
| --- | --- |
| `collected_at` | snapshot creation time (`createdAt`), not the processing time |
| `snapshot_id` | snapshot id — this is what you download |
| `device` | device name |
| `signature_type` | the nested message name, i.e. the device type the collector settled on (`cisco_ios`, `cisco_ios_xe`, an F5 type, …) |
| `signature_value` | the signature itself; multiple fields joined with `\|` |
| `changed` | `FIRST` on the earliest snapshot with a signature, `CHANGED` wherever it differs from the previous snapshot — grep this column for the transitions |
| `status` | `OK`, `DEVICE_OR_FILE_NOT_IN_SNAPSHOT`, `NO_SIGNATURE_BLOCK`, or `HTTP_<code>` |
| `raw_signature` | the verbatim signature block, whitespace-collapsed onto one line |

A summary per device — every distinct signature with its first and last
snapshot — is printed to the console, embedded at the top of the CSV as `#`
comment rows, and written to `signature_audit_<timestamp>_summary.txt`.

The signature present in the newest snapshot is labelled `SIG1 (current)`; the
rest follow in order of first appearance.

## Setup

### 1. Environment variables

| variable | value |
| --- | --- |
| `FWD_INSTANCE` | instance host name, e.g. `example.forwardnetworks.com` |
| `FWD_NETWORK_ID` | numeric network id |
| `FWD_USERNAME` | user name |
| `FWD_PASSWORD` | password or API key |

#### Windows PowerShell — current session only

The safest option. The value lives in the process only, disappears when the
window closes, and never lands in the registry.

```powershell
$env:FWD_INSTANCE   = "example.forwardnetworks.com"
$env:FWD_NETWORK_ID = "159020"
$env:FWD_USERNAME   = "your-username"

# Prompt for the secret instead of typing it on the command line, so it does
# not end up in the PSReadLine history file.
$cred = Get-Credential -UserName $env:FWD_USERNAME -Message "Forward API key"
$env:FWD_PASSWORD = $cred.GetNetworkCredential().Password
```

Clear it when you are done:

```powershell
Remove-Item Env:FWD_PASSWORD
```

#### Windows PowerShell — reuse the secret across sessions

Store it encrypted with DPAPI, which ties the ciphertext to your Windows account
on that machine. Nobody else who reads the file can decrypt it.

```powershell
# Once: prompt, encrypt, and save.
Read-Host -AsSecureString -Prompt "Forward API key" |
    ConvertFrom-SecureString |
    Set-Content "$HOME\.fwd_key"
```

```powershell
# Each session: decrypt into the environment variable.
$sec = Get-Content "$HOME\.fwd_key" | ConvertTo-SecureString
$env:FWD_PASSWORD = [System.Net.NetworkCredential]::new("", $sec).Password
```

To avoid retyping the whole block, put those two lines plus the non-secret
`$env:` assignments in your PowerShell profile (`notepad $PROFILE`) or in a
small `set-fwd-env.ps1` that you dot-source: `. .\set-fwd-env.ps1`. Keep that
file out of the repository — it is already covered by `.gitignore` if you name
it with a `.ps1` extension inside a folder you do not commit.

**Do not use `setx FWD_PASSWORD ...`.** `setx` writes the value in plain text to
`HKCU\Environment`, where any process running as you can read it, and it
persists until you delete it.

If `ConvertTo-SecureString` fails with a key error, the file was encrypted by a
different Windows account or on a different machine. Re-run the "once" step.

#### macOS / Linux — current shell only

```bash
export FWD_INSTANCE=example.forwardnetworks.com
export FWD_NETWORK_ID=159020
export FWD_USERNAME=your-username
read -rs -p "Forward API key: " FWD_PASSWORD; export FWD_PASSWORD; echo
```

The leading space before `export` (with `HISTCONTROL=ignorespace` set) or the
`read -rs` prompt above both keep the secret out of shell history.

### 2. Device list

```
copy devices.example.txt devices.txt     # Windows
cp   devices.example.txt devices.txt     # macOS / Linux
```

Put one device name per line, exactly as the platform spells it. `devices.txt`
is git-ignored.

### 3. Run

```
python fwd_signature_audit.py
```

## Tuning

The `CONFIG` block at the top of the script holds everything adjustable:

| setting | default | notes |
| --- | --- | --- |
| `SNAPSHOT_STATE` | `"PROCESSED"` | set to `""` to include unprocessed snapshots too |
| `INCLUDE_ARCHIVED` | `False` | archived snapshots generally cannot serve files |
| `SINCE` | `""` | `"YYYY-MM-DD"`; skip snapshots created before this |
| `MAX_SNAPSHOTS` | `0` | `0` = all; otherwise keep only the newest N |
| `MAX_WORKERS` | `8` | parallel fetches; lower it if the instance pushes back |
| `REQUEST_TIMEOUT_S` | `60` | per request |
| `MAX_RETRIES` | `3` | retries on 429, 5xx, and connection errors |
| `VERIFY_TLS` | `True` | set `False` only for an instance with a self-signed certificate |

One request is made per device per snapshot, so 3 devices against 400 snapshots
is 1,200 requests. Narrow the range with `SINCE` or `MAX_SNAPSHOTS` first if you
only need recent history.

## API endpoints used

Both are read-only.

* `GET /api/networks/{networkId}/snapshots?state=PROCESSED&includeArchived=false`
* `GET /api/networks/{networkId}/devices/{deviceName}/files/metadata.txt?snapshotId={id}`

`snapshotId` is optional on the second; omitting it returns the latest processed
snapshot's copy.

## Publishing this folder

The script, `devices.example.txt`, `.gitignore`, and this README contain no host
names, credentials, device names, or customer references. The device names in
`devices.example.txt` are made-up placeholders. Everything environment-specific
lives in environment variables, in `devices.txt`, or in the run output — all
three of which `.gitignore` keeps out of the repository.
