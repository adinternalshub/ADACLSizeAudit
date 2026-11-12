<#
.SYNOPSIS
  LAB ONLY. Fills one test user's DACL to the 64 KB wall so the Active Directory ACL size
  limit can be reproduced and screenshotted.

.DESCRIPTION
  Creates an OU, a disabled test user and a few lab groups, then adds per-property object
  ACEs (WriteProperty on individual schema attributes - the classic delegation-bloat
  pattern) to the test user's DACL until the ACL cannot take one more entry.

  Two refusals can occur and the script reports which one it hit:
    - OverflowException from .NET while building the ACL in memory
      ("Length of the access control list exceed the allowed maximum"): the DACL has
      reached the 16-bit AclSize ceiling of 65,535 bytes. This is the wall.
    - A rejected LDAP modify from the domain controller (seen as "The parameter is
      incorrect" in native tools) when the server refuses the descriptor.

  What you get for the article:
    S1  ADUC -> test user -> Security -> add any permission -> "The parameter is incorrect"
    S2  this console output at the moment of refusal
    S3  the byte counts printed in the summary
    S4  -DemoPropagation adds an inheritable ACE on the OU so propagation to the full
        child must fail; watch the Directory Service log on the PDC while forcing it.

  Clean up with:  .\New-ACLLimitDemo.ps1 -Domain <lab> -Cleanup

.NOTES
  Author : Jinish Kunjilikkattil - https://adinternalshub.com/
  Needs  : ActiveDirectory module, Domain Admin in the LAB domain, PowerShell 5.1+.
  Never run this against a production domain.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,                        # e.g. mylab.local - must be typed, never the implicit logon domain
    [string]$Server,                        # optional DC FQDN
    [string]$OUName    = 'ACL-Limit-Demo',
    [string]$UserName  = 'acl.demo.user',
    [int]$GroupCount   = 6,                 # trustees to spread the ACEs across
    [int]$BatchSize    = 50,                # ACEs per write
    [switch]$DemoPropagation,
    [switch]$Cleanup
)

Import-Module ActiveDirectory -ErrorAction Stop
$ad = @{ Server = $(if ($Server) { $Server } else { $Domain }) }

$domainDN = (Get-ADDomain @ad).DistinguishedName
$ouDN     = "OU=$OUName,$domainDN"
$userDN   = "CN=$UserName,$ouDN"
$AclCap   = 65535      # 16-bit AclSize: no single ACL can exceed this
$SdLimit  = 65536      # the "64 KB" figure for the whole descriptor

function Get-SdInfo([string]$dn) {
    $bytes = (Get-ADObject @ad -Identity $dn -Properties nTSecurityDescriptor).nTSecurityDescriptor.GetSecurityDescriptorBinaryForm()
    $raw   = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList (,$bytes), 0
    [pscustomobject]@{
        Total    = $bytes.Length
        Dacl     = $(if ($raw.DiscretionaryAcl) { $raw.DiscretionaryAcl.BinaryLength } else { 0 })
        DaclAces = $(if ($raw.DiscretionaryAcl) { $raw.DiscretionaryAcl.Count } else { 0 })
        Sacl     = $(if ($raw.SystemAcl) { $raw.SystemAcl.BinaryLength } else { 0 })
    }
}
function Show-Size([string]$label, $i) {
    Write-Host ("    {0,-10} total {1,6:N0} B ({2,5:N1} % of 65,536) | DACL {3,6:N0} B of 65,535 ({4:N0} ACEs, {5:N0} B headroom)" -f `
        $label, $i.Total, ($i.Total * 100 / $SdLimit), $i.Dacl, $i.DaclAces, ($AclCap - $i.Dacl))
}

# ---------------------------------------------------------------- cleanup
if ($Cleanup) {
    if ($PSCmdlet.ShouldProcess($ouDN, 'Delete demo OU, user and groups')) {
        if (Get-ADOrganizationalUnit @ad -Filter "DistinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue) {
            Set-ADOrganizationalUnit @ad -Identity $ouDN -ProtectedFromAccidentalDeletion $false
            Remove-ADOrganizationalUnit @ad -Identity $ouDN -Recursive -Confirm:$false
            Write-Host "Removed $ouDN" -ForegroundColor Green
        } else { Write-Host "Nothing to clean: $ouDN not found" -ForegroundColor Yellow }
    }
    return
}

# ---------------------------------------------------------------- safety gate
Write-Host ''
Write-Host "  ACL LIMIT DEMO  -  target domain: $Domain" -ForegroundColor Cyan
Write-Host '  Fills one test user''s DACL to the 64 KB wall. LAB DOMAINS ONLY.' -ForegroundColor Yellow
if (-not $PSCmdlet.ShouldProcess($Domain, "Create demo OU/user/groups and fill the user's DACL")) { return }

# ---------------------------------------------------------------- create objects
if (-not (Get-ADOrganizationalUnit @ad -Filter "DistinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit @ad -Name $OUName -Path $domainDN -ProtectedFromAccidentalDeletion $false | Out-Null
    Write-Host "[+] OU      $ouDN"
}
if (-not (Get-ADUser @ad -Filter "DistinguishedName -eq '$userDN'" -ErrorAction SilentlyContinue)) {
    New-ADUser @ad -Name $UserName -SamAccountName $UserName -Path $ouDN -Enabled $false `
        -Description 'ACL size limit demo - safe to delete' | Out-Null
    Write-Host "[+] User    $userDN"
}
$groups = @()
for ($i = 1; $i -le $GroupCount; $i++) {
    $g = ('ACLDemo-Delegation-{0:D2}' -f $i)
    $grp = Get-ADGroup @ad -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue
    if (-not $grp) {
        $grp = New-ADGroup @ad -Name $g -GroupScope Global -Path $ouDN -PassThru -Description 'ACL size limit demo - safe to delete'
        Write-Host "[+] Group   $g"
    }
    $groups += $grp
}

# ---------------------------------------------------------------- real schema attribute GUIDs
$schemaNC = (Get-ADRootDSE @ad).schemaNamingContext
$attrs = Get-ADObject @ad -SearchBase $schemaNC -LDAPFilter '(objectClass=attributeSchema)' -Properties schemaIDGUID |
         ForEach-Object { [guid]$_.schemaIDGUID }
Write-Host "[i] $($attrs.Count) attribute GUIDs available from the schema"
$pairs = foreach ($g in $groups) { foreach ($a in $attrs) { [pscustomobject]@{ Sid = $g.SID; Guid = $a } } }

# ---------------------------------------------------------------- fill until the ACL cannot take one more entry
$path = "AD:\$userDN"
Write-Host ''; Show-Size 'start' (Get-SdInfo $userDN); Write-Host ''

$index = 0; $added = 0; $wall = $null
while ($index -lt $pairs.Count -and -not $wall) {
    $acl = Get-Acl -Path $path
    $slice = $pairs[$index..([Math]::Min($index + $BatchSize - 1, $pairs.Count - 1))]
    $fit = 0
    foreach ($p in $slice) {
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $p.Sid, [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow, $p.Guid,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        try   { $acl.AddAccessRule($rule); $fit++ }
        catch {
            # .NET will not build an ACL longer than 65,535 bytes: this is the 16-bit wall.
            $wall = [pscustomobject]@{ Where = 'client (.NET) while building the ACL'; Text = $_.Exception.InnerException.Message }
            break
        }
    }
    if ($fit -gt 0) {
        try {
            Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
            $index += $fit; $added += $fit
            Show-Size ("+{0}" -f $fit) (Get-SdInfo $userDN)
        }
        catch {
            # the server refused the descriptor: the other face of the same wall
            $wall = [pscustomobject]@{ Where = 'server (LDAP modify rejected by the DC)'; Text = $_.Exception.Message }
        }
    }
}

# ---------------------------------------------------------------- result
$final = Get-SdInfo $userDN
Write-Host ''
if ($wall) {
    Write-Host '  ================= WRITE REFUSED =================' -ForegroundColor Red
    Write-Host ("  Refused by  : {0}" -f $wall.Where) -ForegroundColor Red
    Write-Host ("  Message     : {0}" -f $wall.Text) -ForegroundColor Red
    Write-Host ''
}
Write-Host '  ================= AT THE WALL =================' -ForegroundColor Cyan
Write-Host ("  Object      : {0}" -f $userDN)
Write-Host ("  Descriptor  : {0:N0} bytes total ({1:N1} % of 65,536)" -f $final.Total, ($final.Total * 100 / $SdLimit))
Write-Host ("  DACL        : {0:N0} bytes of 65,535 (16-bit AclSize) - {1:N0} ACEs - {2:N0} bytes headroom" -f $final.Dacl, $final.DaclAces, ($AclCap - $final.Dacl))
Write-Host ("  SACL        : {0:N0} bytes" -f $final.Sacl)
Write-Host ("  Added       : {0:N0} per-property object ACEs across {1} groups" -f $added, $GroupCount)
Write-Host ''
Write-Host '  Next        : ADUC -> this user -> Security -> try to add ANY permission -> "The parameter is incorrect"' -ForegroundColor Yellow
Write-Host "                then run ADACLSizeAudit against $Domain."
Write-Host ''

# ---------------------------------------------------------------- optional: make propagation fail
if ($DemoPropagation) {
    Write-Host '[i] Adding an inheritable ACE on the OU so SDProp must push it to the full child...' -ForegroundColor Cyan
    $ouAcl  = Get-Acl -Path "AD:\$ouDN"
    $ouRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groups[0].SID, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    $ouAcl.AddAccessRule($ouRule)
    Set-Acl -Path "AD:\$ouDN" -AclObject $ouAcl
    Write-Host "    Inheritable ACE set on $ouDN."
    Write-Host '    Force propagation on the PDC emulator and watch its Directory Service log:' -ForegroundColor Yellow
    Write-Host '      $pdc = (Get-ADDomain).PDCEmulator'
    Write-Host '      Set-ADObject -Server $pdc -Identity "" -Replace @{ fixupInheritance = 1 }'
    Write-Host '    Healthy siblings take the new ACE; the full user cannot.'
}
