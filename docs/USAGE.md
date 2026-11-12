# ADACLSizeAudit — usage reference

Run `ADACLSizeAudit.exe` with **no arguments** to open the Windows Forms front-end. Supplying `/domain`
or `/forest` runs the audit **headless** on the console (switches also pre-fill the GUI). Add `/gui` to
force the front-end open even when a target is given.

## Target selection

| Switch | Meaning |
|--------|---------|
| `/domain:fqdn[,fqdn2]` | One or more domain DNS names to audit. Mutually exclusive with `/forest`. |
| `/forest:fqdn` | Audit every domain of the named forest (enumerated from its `CN=Partitions`). |
| `/server:dc-fqdn` | Preferred domain controller for the first/only target. Omit to use the DC locator. |
| `/map:dom=dc;dom2=dc2` | Pin specific DCs per domain in a forest run. |
| `/searchbase:DN` | Restrict the **Domain** partition scan to one subtree (distinguished name). |
| `/partitions:...` | Naming contexts to scan: `Domain` (default), `Configuration`, `Schema`, `DomainDnsZones`, `ForestDnsZones`. `Configuration`, `Schema` and `ForestDnsZones` are scanned once per forest. |
| `/filter:(ldap)` | LDAP filter for the scan. Default `(objectClass=*)`. |

> The tool binds only to the forest/domain/DC you name. It never probes trusts or binds to the logon domain implicitly.

## Credentials

| Switch | Meaning |
|--------|---------|
| `/user:DOMAIN\name` | Alternate credential. Prompts for the password if `/password` is omitted. |
| `/password:***` | Password for `/user` (omit to be prompted securely). |

Without `/user`, the current session identity is used.

## Thresholds and reporting

| Switch | Default | Meaning |
|--------|---------|---------|
| `/warn:KB`   | 40 | Report/warning threshold. Objects at or above are listed and counted as **Warning**. |
| `/crit:KB`   | 56 | **Critical** threshold (≈ 87.5 % of the limit). |
| `/margin:KB` | 1  | Objects within this many KB of 64 KB are reported as **At limit**. |
| `/floor:KB`  | 16 | Objects below this size are counted in the statistics but not listed individually. |
| `/top:N`     | 50 | Number of largest objects always included in the report. |

Validation: `warn` must be 1–62 KB, `crit` must be greater than `warn` and below the at-limit band.

## Scan tuning

| Switch | Default | Meaning |
|--------|---------|---------|
| `/page:N`  | 500 | LDAP page size. |
| `/max:N`   | 0 (no limit) | Stop each partition scan after N objects — handy for a quick sample. |
| `/nosacl`  | off | Do not request the SACL. Reported sizes are then DACL + owner + group only (a lower bound). |
| `/nodetail`| off | Measure sizes only; skip the per-ACE parse (faster on very large domains). Propagation and Trustees views stay empty. |
| `/ldaps`   | off | Connect over LDAPS (636) instead of LDAP 389 with signing & sealing. |
| `/port:n`  | auto | Override the LDAP port. |

## Output

| Switch | Meaning |
|--------|---------|
| `/out:folder` | Output folder. Default `Desktop\ADACLSizeAudit`. |
| `/baseline:snapshot.json` | A JSON snapshot from a previous run; growth and newly-reported objects are highlighted. |
| `/logo:file.png` | Optional logo (PNG/JPG/GIF/SVG, ≤ 1 MB) shown in the window and dashboard. |
| `/nobrowser` | Do not open the dashboard when finished. |
| `/nocsv` | Skip the CSV export. |
| `/gui` | Open the front-end even when a target is supplied. |

## Exit codes (headless)

| Code | Meaning |
|------|---------|
| `0` | Completed; nothing critical. |
| `1` | Critical objects found. |
| `2` | Objects at the limit. |
| `3` | Aborted / fatal error. |

## Permissions

- **Read** on the objects in scope is enough for owner + group + DACL sizes.
- Reading the **SACL** additionally needs the *"Manage auditing and security log"* right on the DCs. If the
  account lacks it, the tool logs a warning and continues with DACL-only sizes (a lower bound) — it never fails the run for this.

The tool is strictly **read-only**: it issues no write, add, modify or delete operation against the directory.
