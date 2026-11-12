// ADACLSizeAudit - Model.cs
// Project: ADACLSizeAudit | Author: Jinish Kunjilikkattil | https://adinternalshub.com/ | MIT License
// Branding, settings and data model. C# 4 / .NET Framework 4.0 compatible (Windows Server 2008 R2 SP1 and later).
using System;
using System.Collections.Generic;
using System.Net;

namespace ADACLSizeAudit
{
    /// <summary>Product identity. Change naming, version and contact texts here only.</summary>
    public static class Branding
    {
        public const string Name = "ADACLSizeAudit";
        public const string Binary = "ADACLSizeAudit.exe";
        public const string Title = "AD ACL Size Audit";
        public const string Version = "2.0.1";
        public const string BuildDate = "2026-11-10";
        public const string Classification = "Open source (MIT License)";
        public const string Author = "Jinish Kunjilikkattil";
        public const string Team = "ADInternals Hub";
        public const string Feedback = "https://adinternalshub.com/";
        public const string Website = "https://adinternalshub.com/";
        public const string Project = "https://github.com/adinternalshub/ADACLSizeAudit";
        public const string Copyright = "Copyright (c) 2026 Jinish Kunjilikkattil. Released under the MIT License. See LICENSE for details.";
        public const string Requirements = "Windows Server 2008 R2 SP1 or later (or Windows 7 SP1 and later) with .NET Framework 4.0 or later; LDAP (389) or LDAPS (636) to the target domain controllers. No PowerShell modules, no RSAT, no WinRM, no external web resources.";
        public const string Summary = "Measures the real size of every Active Directory security descriptor (nTSecurityDescriptor) in a domain or forest and compares it with the 64 KB limit the directory enforces. It reads over LDAP only and writes nothing. Each large descriptor is explained - how many ACEs it holds, how many are inherited, which containers propagate the most bytes to their children and which trustees account for the growth - so that objects can be fixed before writes to them start failing.";

        public static readonly string[][] ReleaseNotes = new string[][]
        {
            new string[] { "2.0.1", "2026-11-10", "First public open-source release under the MIT License; rebranded for adinternalshub.com. No measurement logic changed." },
            new string[] { "2.0.1", "2026-10-28", "Build fix for the Microsoft C# compiler (ambiguous numeric overloads in the JSON writer, CS0121)." },
            new string[] { "2.0.1", "2026-10-28", ".NET application (C# / Windows Forms, .NET Framework 4.0+) for Windows Server 2008 R2 and later; same measurement engine, dashboard and baseline tracking; headless command-line mode; prepared for public open-source release." },
            new string[] { "1.1.0", "2026-10-28", "PowerShell edition: tabbed front-end with About page, About tab in the dashboard, optional logo, feedback link." },
            new string[] { "1.0.1", "2026-10-27", "PowerShell edition: front-end colour variable fix." },
            new string[] { "1.0.0", "2026-10-27", "PowerShell edition: binary descriptor measurement over LDAP, paged scans with retry, propagation and trustee analysis, dashboard, CSV and JSON baseline tracking." }
        };
    }

    public enum SizeStatus { Healthy, Warning, Critical, Limit }
    public enum CheckStatus { OK, Info, Warning, Critical, Failed }

    /// <summary>Everything one audit run needs. Filled by the GUI or by command-line switches.</summary>
    public class Settings
    {
        public const int SdLimitBytes = 65536;
        public const int AclHeaderCap = 65535;

        public string Mode = "Domain";                       // "Domain" or "Forest"
        public string Forest = "";
        public List<string> Domains = new List<string>();
        public string Server = "";
        public Dictionary<string, string> ServerMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public NetworkCredential Credential;                  // null = current session identity
        public string CredentialLabel = "current session identity";
        public List<string> Partitions = new List<string>(new string[] { "Domain" });
        public string SearchBase = "";
        public string LdapFilter = "(objectClass=*)";
        public int WarningKB = 40;
        public int CriticalKB = 56;
        public int LimitMarginKB = 1;
        public int ReportFloorKB = 16;
        public int TopN = 50;
        public int PageSize = 500;
        public int MaxObjects = 0;
        public bool IncludeSacl = true;
        public bool AceDetail = true;
        public bool UseLdaps = false;
        public int Port = 0;
        public string OutputFolder = "";
        public string BaselinePath = "";
        public string LogoPath = "";
        public bool OpenBrowser = true;
        public bool WriteCsv = true;

        public int WarnBytes { get { return WarningKB * 1024; } }
        public int CritBytes { get { return CriticalKB * 1024; } }
        public int LimitBytes { get { return SdLimitBytes - LimitMarginKB * 1024; } }
        public int FloorBytes { get { return ReportFloorKB * 1024; } }
        public int ContainerDeepBytes { get { return Math.Min(WarnBytes, 8192); } }
        public int SdFlags { get { return IncludeSacl ? 15 : 7; } }
        public int EffectivePort { get { if (Port > 0) return Port; return UseLdaps ? 636 : 389; } }

        public string TargetName { get { return Mode == "Forest" ? Forest : string.Join("+", Domains.ToArray()); } }

        public static string DefaultOutputFolder()
        {
            string desk = "";
            try { desk = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory); } catch { }
            if (string.IsNullOrEmpty(desk)) { try { desk = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments); } catch { } }
            if (string.IsNullOrEmpty(desk)) desk = System.IO.Path.GetTempPath();
            return System.IO.Path.Combine(desk, "ADACLSizeAudit");
        }

        /// <summary>Validates the settings; returns null when fine, otherwise the message to show.</summary>
        public string Validate()
        {
            if (Mode == "Forest")
            {
                if (string.IsNullOrEmpty(Forest)) return "Enter the forest DNS name.";
            }
            else
            {
                if (Domains.Count == 0 || string.IsNullOrEmpty(Domains[0])) return "Enter the domain DNS name.";
            }
            if (WarningKB < 1 || WarningKB > 62) return "The report threshold must be between 1 and 62 KB.";
            if (CriticalKB <= WarningKB) return string.Format("Critical ({0} KB) must be greater than the report threshold ({1} KB).", CriticalKB, WarningKB);
            if (CritBytes >= LimitBytes) return string.Format("Critical must be below the at-limit band ({0} KB).", LimitBytes / 1024.0);
            if (Partitions.Count == 0) return "Select at least one partition.";
            if (!string.IsNullOrEmpty(SearchBase) && SearchBase.IndexOf('=') < 0) return "The search base must be a distinguished name (OU=...,DC=...).";
            if (!string.IsNullOrEmpty(BaselinePath) && !System.IO.File.Exists(BaselinePath)) return "Baseline file not found: " + BaselinePath;
            if (ReportFloorKB > WarningKB) ReportFloorKB = WarningKB;
            if (PageSize < 50) PageSize = 50;
            if (TopN < 10) TopN = 10;
            if (string.IsNullOrEmpty(OutputFolder)) OutputFolder = DefaultOutputFolder();
            return null;
        }
    }

    public class CheckItem
    {
        public string Id; public string Area; public string Name; public CheckStatus Status; public string Detail; public string Scope;
        public CheckItem(string id, string area, string name, CheckStatus status, string detail, string scope)
        { Id = id; Area = area; Name = name; Status = status; Detail = detail; Scope = scope ?? "Run"; }
    }

    public class PartitionStat
    {
        public string Name; public string Base; public int Scanned; public int Pages; public int Retries;
        public bool Truncated; public bool Cancelled; public bool Skipped; public double DurationSec;
        public List<string> Errors = new List<string>();
    }

    public class KeyObjectInfo
    {
        public string Name; public string Dn; public int Bytes; public int DaclBytes; public int DaclAces;
        public int InheritableBytes; public int InheritableAces; public string Status = "n/a"; public string Error;
    }

    public class SchemaDefault { public string Class; public int Bytes; public int SddlLength; public string Method = "binary"; }

    public class ObjectTrustee { public string Key; public long Bytes; public int Count; public byte[] Sid; }

    public class TrusteeStat { public long Bytes; public int Aces; public int Objects; public byte[] Sid; public string Name; }

    public class ClassStat { public int Count; public long Sum; public int Max; public string MaxDn = ""; public int Flagged; }

    public class ObjectRow
    {
        public string Domain; public string Partition; public string Dn; public string Name; public string Class;
        public int Bytes; public int Headroom; public double Percent; public SizeStatus Status;
        public int DaclBytes; public int DaclAces; public int SaclBytes; public int SaclAces;
        public bool DaclProtected; public bool AdminCount; public string WhenChanged = "";
        public bool IsContainer; public bool Deep;
        public int? Explicit; public int? Inherited; public int? Allow; public int? Deny; public int? ObjectAces;
        public int? InheritableAces; public int? InheritableBytes; public int? LargestAce; public int? EstAcesLeft; public double? AvgAce;
        public string OwnerSid; public bool Truncated; public List<ObjectTrustee> Trustees = new List<ObjectTrustee>();
        public int FlaggedDescendants; public int? Delta; public bool Valid = true; public string Note = "";

        public static string StatusText(SizeStatus s) { return s.ToString(); }
    }

    public class DomainState
    {
        public string Dns = ""; public string NetBios = ""; public string Nc = ""; public string Server = ""; public string ServerUsed = "";
        public LdapSession Session; public string AuthMode = ""; public RootDse RootDse; public string DomainSid = "";
        public int Scanned; public int Unreadable; public int Invalid; public int WithSacl;
        public List<int> Sizes = new List<int>();
        public long SumBytes; public int Max; public string MaxDn = "";
        public int[] Hist = new int[17];
        public int Healthy; public int Warning; public int Critical; public int Limit;
        public List<PartitionStat> Partitions = new List<PartitionStat>();
        public List<string> UnreadableSamples = new List<string>();
        public List<string> InvalidSamples = new List<string>();
        public List<string> Errors = new List<string>();
        public List<KeyObjectInfo> KeyObjects = new List<KeyObjectInfo>();
        public int AdminSdHolderBytes; public int AdminCountObjects = -1;
        public int Median; public int P95; public int P99; public int Avg;
        public double DurationSec; public bool Connected;

        public int Flagged { get { return Warning + Critical + Limit; } }
        public void Count(SizeStatus s)
        {
            switch (s)
            {
                case SizeStatus.Healthy: Healthy++; break;
                case SizeStatus.Warning: Warning++; break;
                case SizeStatus.Critical: Critical++; break;
                default: Limit++; break;
            }
        }
    }

    public class ForestInfo { public string Name; public string RootNc; public string ConfigNc; public string SchemaNc; public string ForestFunctionality; public string DiscoveredFrom; }

    public class BaselineInfo
    {
        public string Path; public string Generated = ""; public string Target = "";
        public Dictionary<string, int> Map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public int Grown; public int Shrunk; public int New; public int Unchanged; public long GrowthBytes;
        public List<ObjectRow> TopGrowth = new List<ObjectRow>();
    }

    public class OutputFile { public string Type; public string Path; public OutputFile(string t, string p) { Type = t; Path = p; } }

    public class AuditResult
    {
        public bool Success; public int ExitCode = 3; public string Message = "";
        public string HtmlPath; public string CsvPath; public string JsonPath; public string LogPath;
        public bool Cancelled;
    }
}
