<#
  New-ACLLimitDemo.ps1  --  LAB ONLY
  Fills one AD object's DACL to the 65,535-byte ceiling to demonstrate
  the 64 KB wall. -Cleanup removes everything it created.

  Creates : OU=ACLLimitDemo, a disabled user acl-limit-target, six groups acl-limit-grp1..6
  Usage   : .\New-ACLLimitDemo.ps1 -DomainDnsName tech.mylab.local [-WhatIf] [-Confirm]
            .\New-ACLLimitDemo.ps1 -DomainDnsName tech.mylab.local -Cleanup
  Needs   : ActiveDirectory module and Domain Admin in a TEST domain. Never run it in production.
  Author  : Jinish Kunjilikkattil - https://adinternalshub.com/ (MIT License)
  Article : "The 64 KB Wall" on adinternalshub.com explains this script part by part.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)][string]$DomainDnsName,   # FQDN of a TEST domain
  [switch]$Cleanup,
  [int]$BatchSize = 50
)
Import-Module ActiveDirectory -ErrorAction Stop

# Bind only to the domain you name -- never follow trusts.
$ctx   = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain',$DomainDnsName)
$dc    = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx).FindDomainController().Name
$root  = Get-ADRootDSE -Server $dc
$domDN = $root.defaultNamingContext
$ouDN  = "OU=ACLLimitDemo,$domDN"

if ($Cleanup) {
    if (Get-ADOrganizationalUnit -Server $dc $ouDN -ErrorAction SilentlyContinue) {
        Set-ADOrganizationalUnit    -Server $dc $ouDN -ProtectedFromAccidentalDeletion $false
        Remove-ADOrganizationalUnit -Server $dc $ouDN -Recursive -Confirm:$false
        Write-Host "Removed $ouDN"
    }
    return
}

Write-Warning "Fills a NEW test object's DACL in '$DomainDnsName' until it hits the wall."
if (-not $PSCmdlet.ShouldProcess($DomainDnsName,'create ACL-limit demo')) { return }

# 1. One container, a DISABLED target user, and six trustee groups.
New-ADOrganizationalUnit -Server $dc -Name ACLLimitDemo -Path $domDN -ProtectedFromAccidentalDeletion $false
$user   = New-ADUser  -Server $dc -Name acl-limit-target -Path $ouDN -Enabled $false -PassThru
$groups = 1..6 | ForEach-Object { New-ADGroup -Server $dc -Name "acl-limit-grp$_" -Path $ouDN -GroupScope Global -PassThru }

# 2. Every attribute's schemaIDGUID -- the GUID a per-property ACE points at.
$attrGuids = Get-ADObject -Server $dc -SearchBase $root.schemaNamingContext `
             -LDAPFilter '(objectClass=attributeSchema)' -Properties schemaIDGUID |
             ForEach-Object { [Guid]$_.schemaIDGUID }

# 3. Add one WriteProperty object ACE per attribute, per group, measuring as we go.
$de = [ADSI]"LDAP://$dc/$($user.DistinguishedName)"
$sd = $de.psbase.ObjectSecurity
$n  = 0
:build foreach ($g in $groups) {
    $sid = [System.Security.Principal.SecurityIdentifier]$g.SID
    foreach ($guid in $attrGuids) {
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid,'WriteProperty','Allow',$guid)
        try   { $sd.AddAccessRule($ace) }                         # .NET throws HERE at the wall
        catch { Write-Host "Wall hit after $n ACEs: $($_.Exception.Message)"; break build }
        if (++$n % $BatchSize -eq 0) {
            $de.psbase.ObjectSecurity = $sd; $de.psbase.CommitChanges()
            Write-Host ("  {0,5} ACEs  ->  {1,6} bytes" -f $n, $sd.GetSecurityDescriptorBinaryForm().Length)
        }
    }
}

# 4. Write the ACEs that fitted after the last full batch, so the copy on the DC is at the wall too.
try   { $de.psbase.ObjectSecurity = $sd; $de.psbase.CommitChanges()
        Write-Host ("  {0,5} ACEs  ->  {1,6} bytes  (written to AD)" -f $n, $sd.GetSecurityDescriptorBinaryForm().Length) }
catch { Write-Host "Final write refused by the domain controller: $($_.Exception.Message)" }
