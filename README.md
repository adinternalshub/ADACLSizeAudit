<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/logo.png">
    <img src="docs/logo.png" alt="ADACLSizeAudit" width="560">
  </picture>
</p>

<p align="center">
  <b>Proactively audit Active Directory security-descriptor (ACL) sizes against the 64&nbsp;KB limit.</b><br>
  Reads over LDAP only &middot; writes nothing &middot; single self-contained executable.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6.svg" alt="Windows">
  <img src="https://img.shields.io/badge/.NET%20Framework-4.0%2B-512BD4.svg" alt=".NET Framework 4.0+">
  <a href="https://adinternalshub.com/"><img src="https://img.shields.io/badge/adinternalshub.com-0f6cbd.svg" alt="adinternalshub.com"></a>
</p>

---

## Download

Grab the latest prebuilt `ADACLSizeAudit.exe` from the [**Releases**](https://github.com/adinternalshub/ADACLSizeAudit/releases) page — no build step needed.
It is a single self-contained executable; copy it to a management workstation and run it.
Prefer to build from source? See [Build](#build) below.

## Why this tool exists

Every Active Directory object stores its permissions in the `nTSecurityDescriptor` attribute, and that
attribute is **hard-capped at 64 KB** ([Microsoft — AD DS maximum limits](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/active-directory-maximum-limits-scalability)).
Once an object's descriptor approaches that ceiling, every write that would enlarge the ACL fails —
usually with the unhelpful *"The parameter is incorrect"* — and inheritance propagation to that object
stalls. It is a silent problem until the day a delegation or GPO change suddenly cannot be applied.

The common SDDL-string-length check is **not** a valid measure: SDDL text length and real binary size
differ widely. **ADACLSizeAudit measures the actual binary size** of every descriptor and parses it to
explain *why* it is large, so objects can be fixed **before** writes to them start failing.

## Features

- **Accurate binary measurement** of `nTSecurityDescriptor` (owner + group + DACL + SACL) for every object in scope.
- **Domain or whole-forest** scans over `System.DirectoryServices.Protocols` — no `ActiveDirectory` module, no RSAT, no WinRM.
- **Per-object explanation**: total bytes, headroom to 64 KB, DACL/SACL bytes and ACE counts, explicit vs. inherited, allow/deny/object ACEs.
- **Propagation analysis**: which containers push the most *inheritable* bytes down to every child object.
- **Trustee analysis**: which security principals account for the most ACL growth.
- **Environment checks**: domain head, well-known containers, **AdminSDHolder** template size, and schema default descriptors.
- **Baseline tracking**: save a JSON snapshot and compare the next run to see what grew.
- **Self-contained HTML dashboard** + **CSV** export, plus a **headless command-line mode** for scheduling.
- **Read-only and safe**: explicit targeting only, LDAP signing & sealing or LDAPS, paged searches with retry. No attribute is ever written.

## Requirements

- Windows Server 2008 R2 SP1 or later (or Windows 7 SP1 and later)
- .NET Framework 4.0 or later
- LDAP (389) or LDAPS (636) connectivity to the target domain controllers
- An account with **read** access to the objects in scope. Reading the **SACL** additionally needs the *"Manage auditing and security log"* right on the DCs (the tool falls back to DACL-only automatically if it can't read the SACL).

## Build

No Visual Studio is required — the project builds with the C# compiler that ships with the .NET Framework.

**Option A — one command (no Visual Studio):**

```bat
build.cmd
```

This locates `csc.exe` under `%WINDIR%\Microsoft.NET`, compiles the sources, embeds `res\Dashboard.html`
as a resource and produces `ADACLSizeAudit.exe`.

**Option B — Visual Studio:**

Open `ADACLSizeAudit.sln`, select **Release / Any CPU**, and build. Output lands in `bin\Release\`.

## Usage

Run **`ADACLSizeAudit.exe`** with no arguments to open the Windows Forms front-end (any switches below
pre-fill it). Supply `/domain` or `/forest` to run **headless** on the console — ideal for scheduled tasks.

```text
ADACLSizeAudit.exe [/domain:fqdn[,fqdn2] | /forest:fqdn] [/server:dc-fqdn] [/map:dom=dc;dom2=dc2]
    [/user:DOMAIN\name [/password:***]] [/partitions:Domain,Configuration,Schema,DomainDnsZones,ForestDnsZones]
    [/searchbase:DN] [/filter:(ldap)] [/warn:40] [/crit:56] [/margin:1] [/floor:16] [/top:50] [/page:500] [/max:N]
    [/nosacl] [/nodetail] [/ldaps] [/port:n] [/out:folder] [/baseline:snapshot.json] [/logo:file.png] [/nobrowser] [/nocsv] [/gui]
```

**Examples:**

```bat
:: Audit one domain through a specific DC and open the dashboard when done
ADACLSizeAudit.exe /domain:corp.example.com /server:dc01.corp.example.com

:: Audit an entire forest, including the Configuration partition, with custom thresholds
ADACLSizeAudit.exe /forest:example.com /partitions:Domain,Configuration /warn:40 /crit:52

:: Re-run against a saved baseline to highlight growth, with alternate credentials
ADACLSizeAudit.exe /domain:corp.example.com /user:CORP\auditor /baseline:ADACLSizeAudit_corp.example.com_20261101.json
```

**Exit codes:** `0` nothing critical &middot; `1` critical objects found &middot; `2` objects at the limit &middot; `3` aborted.

See [`docs/USAGE.md`](docs/USAGE.md) for every switch in detail.

## Output

Each run writes to `Desktop\ADACLSizeAudit` (override with `/out:`):

| File | Contents |
|------|----------|
| `ADACLSizeAudit_<target>_<timestamp>.html` | Self-contained dashboard: Overview, Objects, Propagation, Trustees, Checks, Run, About. No external resources. |
| `ADACLSizeAudit_<target>_<timestamp>.csv`  | Every reported object with its size breakdown (open in Excel). |
| `ADACLSizeAudit_<target>_<timestamp>.json` | Snapshot — pass it as `/baseline:` on the next run to track growth. |
| `ADACLSizeAudit_<target>_<timestamp>_log.txt` | Full run log. |

## How it measures

The tool binds over LDAP (signing & sealing, or LDAPS) to the DC you name, verifies the required server
controls, then reads the raw `nTSecurityDescriptor` of every object with the security-descriptor-flags
control and measures its **binary length** — the value the 64 KB limit actually applies to. The descriptor
header is parsed for every object; the individual ACEs of flagged objects and containers are walked to
attribute bytes to inheritance, ACE type and trustee. AdminSDHolder and the schema default descriptors are
read separately, because they set the size floor for protected and newly-created objects respectively.

## Project layout

```text
ADACLSizeAudit/
|- src/                 C# sources (Model, SdParser, Ldap, Engine, Report, ToolMark, App, MainForm)
|- res/                 Dashboard.html (embedded), app.ico
|- Properties/          AssemblyInfo.cs
|- docs/                USAGE.md, images
|- build.cmd            no-Visual-Studio build (csc)
|- ADACLSizeAudit.sln   Visual Studio solution
|- ADACLSizeAudit.csproj
|- App.config
`- LICENSE              MIT
```

## Reproduce the problem in a lab

`lab/New-ACLLimitDemo.ps1` builds a test user whose DACL sits at the 65,535-byte ceiling, so you can see the failure (and this tool's report) without waiting for production to hit it. Lab domains only; it has a `-Cleanup` switch. See [`lab/README.md`](lab/README.md).

## Contributing & security

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). For anything security
related, please read [SECURITY.md](SECURITY.md).

## License

Released under the [MIT License](LICENSE). &copy; 2026 Jinish Kunjilikkattil.

## Author

**Jinish Kunjilikkattil** &mdash; [adinternalshub.com](https://adinternalshub.com/)
Part of the **ADInternals Hub** collection of Active Directory engineering tools.
