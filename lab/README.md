# Lab scripts

Scripts that reproduce the conditions ADACLSizeAudit detects. **Lab domains only.** Never point them at a production forest.

## `New-ACLLimitDemo.ps1`

Builds one Active Directory object whose DACL sits at the 65,535-byte ceiling, so you can see the "64 KB wall" fail in ADUC, in PowerShell and in this tool's report without waiting for production to hit it.

```powershell
.\New-ACLLimitDemo.ps1 -DomainDnsName tech.mylab.local            # build the demo
.\New-ACLLimitDemo.ps1 -DomainDnsName tech.mylab.local -WhatIf    # show what it would do
.\New-ACLLimitDemo.ps1 -DomainDnsName tech.mylab.local -Cleanup   # remove everything it created
```

| Parameter | Meaning |
|---|---|
| `-DomainDnsName` | **Required.** DNS name of the test domain. The script binds only to a domain controller of this domain and never follows trusts. |
| `-BatchSize` | ACEs written per LDAP modify (default 50). |
| `-Cleanup` | Deletes `OU=ACLLimitDemo` and everything in it. |
| `-WhatIf` / `-Confirm` | Standard PowerShell safety switches. The script does not prompt on its own. |

What it does:

1. Creates `OU=ACLLimitDemo`, a **disabled** user `acl-limit-target` and six global groups `acl-limit-grp1` … `acl-limit-grp6`.
2. Reads the `schemaIDGUID` of every attribute in the schema.
3. Adds one *WriteProperty* object ACE per attribute and per group to the user's DACL (56 bytes each), writing every 50 ACEs and printing the size.
4. Stops when .NET refuses the next ACE (`Length of the access control list exceed the allowed maximum`), then writes the ACEs that fitted after the last batch, so the copy stored in AD is at the wall too.

Reference run (Windows Server, domain `tech.mylab.local`, 2026-11-25): the new user started at 2,400 bytes; the wall was reached after **1,128 ACEs**; Active Directory stored **65,568 bytes** for the whole descriptor.

What to try next:

- **ADUC:** `acl-limit-target` → Security → Advanced → Add → *Domain Users* → Properties → Allow *Write description* → OK → Apply. The domain controller refuses it: *"Unable to save permission changes on acl-limit-target. A constraint violation occurred."*
- **ADACLSizeAudit:** audit the domain; the user is reported as *at limit*.
- **Fix:** remove the demo groups' ACEs (`PurgeAccessRules` for each `acl-limit-grp*` SID) and audit again with `/baseline:` to see the reduction.
