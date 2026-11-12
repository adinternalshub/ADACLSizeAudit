# Lab scripts

Scripts for reproducing the conditions ADACLSizeAudit detects. **Lab domains only.**

| Script | What it does |
|---|---|
| `New-ACLLimitDemo.ps1` | Fills one test user's DACL with per-property object ACEs until the 16-bit ACL size ceiling (65,535 bytes) refuses the next entry. Reproduces the "64 KB wall": `OverflowException` from .NET tooling, "The parameter is incorrect" from native tools, and failed inheritance propagation with `-DemoPropagation`. `-Cleanup` removes everything it created. |

Every script requires an explicit `-Domain` and prompts before changing anything. None of them should ever be pointed at a production forest.
