# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [2.0.1] — 2026-11-10
### Changed
- First **public open-source release** under the MIT License.
- Rebranded for [adinternalshub.com](https://adinternalshub.com/): author, About box, dashboard and documentation.
- About panel now links to the website and GitHub project and offers a "Report an issue" action (replaces the internal feedback e-mail).
- Added a Visual Studio solution/project (`.sln` / `.csproj`) and `AssemblyInfo` alongside the no-Visual-Studio `build.cmd`.
- New application icon and logo (theme-aware README logo for light/dark GitHub).
- GitHub Actions workflow that builds `ADACLSizeAudit.exe` and attaches it to tagged releases.
- Issue templates (bug report, feature request) and a pull-request template.

> No measurement logic changed in this release.

## [2.0.0] — 2026-10-28
### Added
- .NET application (C# / Windows Forms, .NET Framework 4.0+) for Windows Server 2008 R2 and later.
- Binary security-descriptor measurement engine, interactive front-end, self-contained HTML dashboard, CSV export, JSON baseline tracking, and a headless command-line mode.

## [1.1.0] — 2026-10-28
### Added
- PowerShell edition: tabbed front-end with an About page, an About tab in the dashboard, optional logo and a feedback link.

## [1.0.1] — 2026-10-27
### Fixed
- PowerShell edition: front-end colour variable fix.

## [1.0.0] — 2026-10-27
### Added
- PowerShell edition: binary descriptor measurement over LDAP, paged scans with retry, propagation and trustee analysis, dashboard, CSV and JSON baseline tracking.
