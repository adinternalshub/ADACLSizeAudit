# Security policy

## The tool itself

ADACLSizeAudit is a **read-only** auditing tool. It:

- binds only to the forest / domain / domain controller you explicitly name;
- uses LDAP signing and sealing, or LDAPS;
- reads the `nTSecurityDescriptor` attribute and a handful of read-only attributes (`objectClass`, `adminCount`, `whenChanged`);
- **writes nothing** to the directory and contacts no external network resource.

Audit output (HTML / CSV / JSON) can contain sensitive directory information — distinguished names, SIDs and
trustee names. Treat those files as confidential and store them accordingly. The `.gitignore` in this repo is
configured to never commit generated reports.

## Reporting a vulnerability

If you believe you have found a security issue in the **code**, please report it privately rather than opening
a public issue:

- Use GitHub's **private vulnerability reporting** on this repository, or
- contact the author via [adinternalshub.com](https://adinternalshub.com/).

Please include the version, environment and steps to reproduce. You will get an acknowledgement, and a fix or
mitigation will be prioritised.

## Supported versions

The latest release on the `main` branch is supported. Older versions are not maintained.
