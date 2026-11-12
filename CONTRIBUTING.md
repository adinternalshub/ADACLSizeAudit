# Contributing to ADACLSizeAudit

Thanks for your interest in improving ADACLSizeAudit! Issues and pull requests are welcome.

## Ground rules

- **The tool is read-only.** It must never issue a write, add, modify or delete operation against Active
  Directory. Any change that could write to the directory will be rejected.
- **No external dependencies at runtime.** It targets .NET Framework 4.0 and a plain Windows install — no
  NuGet packages, no PowerShell modules, no RSAT, no WinRM, and the dashboard embeds everything (no CDN).
- **Keep it buildable with `csc`.** New source files must be added to both `build.cmd` and `ADACLSizeAudit.csproj`.

## Building

```bat
build.cmd
```

or open `ADACLSizeAudit.sln` in Visual Studio (Release / Any CPU).

## Pull requests

1. Fork the repo and create a feature branch.
2. Keep changes focused; match the existing code style (the project uses explicit, allocation-aware C# 4 compatible code).
3. Describe **what** and **why** in the PR, and note any testing you did against a lab domain.
4. Update `CHANGELOG.md` under an *Unreleased* heading.

## Reporting bugs

Open a GitHub issue with the ADACLSizeAudit version (About tab → *Copy version details*), the OS / .NET
version, and the relevant lines from the run log. Never paste real distinguished names, SIDs or trustee
names from a production directory — redact them first.

Questions? Visit [adinternalshub.com](https://adinternalshub.com/).
