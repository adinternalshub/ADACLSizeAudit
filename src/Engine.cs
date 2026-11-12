// ADACLSizeAudit - Engine.cs
// Project: ADACLSizeAudit | Author: Jinish Kunjilikkattil | https://adinternalshub.com/ | MIT License
// The measurement engine: resolves targets, scans partitions, evaluates every descriptor,
// runs the validation checks and hands the collected state to the report builder. Read-only.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace ADACLSizeAudit
{
    public delegate void LogHandler(string level, string text);
    public delegate void StatusHandler(string text);

    public class AuditEngine
    {
        public readonly Settings S;
        public event LogHandler Log;
        public event StatusHandler Status;

        // ---- collected state (read by ReportBuilder)
        public List<DomainState> Domains = new List<DomainState>();
        public List<ObjectRow> Rows = new List<ObjectRow>();
        public List<ObjectRow> Containers = new List<ObjectRow>();
        public List<CheckItem> Checks = new List<CheckItem>();
        public List<ObjectRow> TopRows = new List<ObjectRow>();
        public Dictionary<string, TrusteeStat> TrusteeAgg = new Dictionary<string, TrusteeStat>(StringComparer.Ordinal);
        public Dictionary<string, string> SidNameCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, ClassStat> ClassStats = new Dictionary<string, ClassStat>(StringComparer.OrdinalIgnoreCase);
        public int[] Hist = new int[17];
        public List<int> AllSizes = new List<int>();
        public ForestInfo Forest;
        public List<SchemaDefault> SchemaDefaults = new List<SchemaDefault>();
        public int UserDefaultSdBytes;
        public bool SaclRequested; public bool SaclFallback;
        public DateTime StartTime; public DateTime Generated;
        public BaselineInfo Baseline;
        public List<OutputFile> OutputFiles = new List<OutputFile>();
        public List<string> LogLines = new List<string>();
        public int TopMin; public int TotalScanned; public bool SlowTranslate;
        public volatile bool CancelRequested;
        public string TargetLabel = "";

        static readonly HashSet<string> ContainerClasses = new HashSet<string>(new string[] {
            "organizationalunit", "container", "domaindns", "builtindomain", "lostandfound", "msds-quotacontainer",
            "msexchsystemobjectscontainer", "rpccontainer", "dnszone", "configuration", "dmd", "sitescontainer",
            "site", "serverscontainer", "server", "subnetcontainer" }, StringComparer.OrdinalIgnoreCase);
        static readonly string[] DefaultSdClasses = new string[] { "user", "computer", "group", "organizationalUnit", "container", "contact",
            "inetOrgPerson", "msDS-GroupManagedServiceAccount", "msDS-ManagedServiceAccount", "volume", "printQueue" };
        static readonly string[][] KeyObjects = new string[][] {
            new string[] { "Domain head", "" }, new string[] { "Users container", "CN=Users," }, new string[] { "Computers container", "CN=Computers," },
            new string[] { "Domain Controllers OU", "OU=Domain Controllers," }, new string[] { "System container", "CN=System," },
            new string[] { "Builtin container", "CN=Builtin," }, new string[] { "AdminSDHolder", "CN=AdminSDHolder,CN=System," } };

        public AuditEngine(Settings settings) { S = settings; }

        // ------------------------------------------------------------------ logging

        void Info(string t) { Emit("INFO", t); }
        void Ok(string t) { Emit("OK", t); }
        void Warn(string t) { Emit("WARN", t); }
        void Fail(string t) { Emit("FAIL", t); }
        void Section(string t) { Emit("INFO", "--- " + t + " ---"); }
        void Emit(string level, string text)
        {
            LogLines.Add(DateTime.Now.ToString("HH:mm:ss") + "  " + level.PadRight(5) + " " + text);
            var h = Log; if (h != null) h(level, text);
        }
        void SetStatus(string text) { var h = Status; if (h != null) h(text); }
        internal void AddCheck(string id, string area, string name, CheckStatus st, string detail, string scope)
        { Checks.Add(new CheckItem(id, area, name, st, detail, scope)); }

        public static string KB(long bytes, int decimals) { return (bytes / 1024.0).ToString("N" + decimals, CultureInfo.InvariantCulture) + " KB"; }
        public static string N0(long v) { return v.ToString("N0", CultureInfo.InvariantCulture); }
        public SizeStatus StatusOf(int bytes)
        {
            if (bytes >= S.LimitBytes) return SizeStatus.Limit;
            if (bytes >= S.CritBytes) return SizeStatus.Critical;
            if (bytes >= S.WarnBytes) return SizeStatus.Warning;
            return SizeStatus.Healthy;
        }

        // ------------------------------------------------------------------ run

        public AuditResult Run()
        {
            var result = new AuditResult();
            StartTime = DateTime.Now;
            SaclRequested = S.IncludeSacl;
            try
            {
                string v = S.Validate();
                if (v != null) throw new ApplicationException(v);

                Section("Target");
                ResolveTargets();
                ImportBaseline();

                Section("Connect");
                foreach (var d in Domains) { if (CancelRequested) break; ConnectDomain(d); }
                var connected = Domains.Where(d => d.Connected).ToList();
                if (connected.Count == 0) throw new ApplicationException("No domain could be connected. See the log for details.");

                Section("Scan");
                Info(string.Format("Partitions: {0} | page size {1} | report at {2} KB, critical at {3} KB, limit 64 KB | report floor {4} KB",
                    string.Join(", ", S.Partitions.ToArray()), S.PageSize, S.WarningKB, S.CriticalKB, S.ReportFloorKB));
                Info(S.IncludeSacl ? "Requesting owner, group, DACL and SACL (full descriptor size)." : "Requesting owner, group and DACL only: sizes are lower bounds.");
                bool first = true;
                foreach (var d in connected)
                {
                    if (CancelRequested) break;
                    var sw = Stopwatch.StartNew();
                    foreach (var plan in PartitionPlan(d, first))
                    {
                        if (CancelRequested) break;
                        ScanPartition(d, plan);
                    }
                    KeyObjectChecks(d);
                    if (first) SchemaDefaultCheck(d);
                    CompleteDomainStatistics(d);
                    sw.Stop();
                    d.DurationSec = Math.Round(sw.Elapsed.TotalSeconds, 1);
                    first = false;
                }

                Section("Evaluate");
                SetStatus("Evaluating results | descendants, trustees, checks");
                UpdateFlaggedDescendants();
                Info("Resolving names for " + Math.Min(80, TrusteeAgg.Count) + " trustees");
                ResolveTrusteeNames();
                CompareWithBaseline();
                CompleteRunChecks();

                Generated = DateTime.Now;
                TargetLabel = Forest != null ? Forest.Name : string.Join("+", Domains.Select(d => d.Dns).ToArray());
                string safe = Sanitize(TargetLabel);
                if (safe.Length > 60) safe = safe.Substring(0, 60);
                string stamp = Generated.ToString("yyyyMMdd_HHmmss");
                string folder = EnsureOutputFolder();
                string prefix = Path.Combine(folder, "ADACLSizeAudit_" + safe + "_" + stamp);
                result.HtmlPath = prefix + ".html"; result.CsvPath = prefix + ".csv"; result.JsonPath = prefix + ".json"; result.LogPath = prefix + "_log.txt";
                OutputFiles.Add(new OutputFile("Dashboard (HTML)", result.HtmlPath));
                OutputFiles.Add(new OutputFile("Snapshot for the next baseline (JSON)", result.JsonPath));
                if (S.WriteCsv) OutputFiles.Add(new OutputFile("Objects (CSV)", result.CsvPath));
                OutputFiles.Add(new OutputFile("Run log (TXT)", result.LogPath));

                SetStatus("Writing report | HTML, CSV, JSON");
                var rows = ReportRows();
                Info(string.Format("Writing report for {0} listed objects and {1} containers", rows.Count, Containers.Count));
                var rb = new ReportBuilder(this);
                rb.WriteSnapshot(rows, result.JsonPath);
                if (S.WriteCsv) rb.WriteCsv(rows, result.CsvPath);
                string data = rb.BuildDataJson(rows);
                rb.WriteDashboard(result.HtmlPath, data);

                ConsoleSummary(rows);
                Ok("Dashboard : " + result.HtmlPath);
                if (S.WriteCsv) Ok("CSV       : " + result.CsvPath);
                Ok("Snapshot  : " + result.JsonPath + "  (use as the baseline next time)");
                double secs = Math.Round((DateTime.Now - StartTime).TotalSeconds, 1);
                Info(string.Format("Total {0} objects in {1} s", N0(TotalScanned), secs));

                int limit = Domains.Sum(d => d.Limit), crit = Domains.Sum(d => d.Critical), warn = Domains.Sum(d => d.Warning);
                result.ExitCode = limit > 0 ? 2 : (crit > 0 ? 1 : 0);
                result.Success = true;
                result.Cancelled = CancelRequested;
                result.Message = string.Format("{0} objects scanned in {1} s: {2} at limit, {3} critical, {4} warning.", N0(TotalScanned), secs, limit, crit, warn);
            }
            catch (Exception ex)
            {
                Fail("Audit aborted: " + ex.Message);
                result.ExitCode = 3;
                result.Message = "Audit aborted: " + ex.Message;
            }
            finally
            {
                foreach (var d in Domains) { if (d.Session != null) { d.Session.Dispose(); d.Session = null; } }
                try
                {
                    if (result.LogPath != null) File.WriteAllLines(result.LogPath, LogLines.ToArray(), Encoding.UTF8);
                    else
                    {
                        string folder = EnsureOutputFolder();
                        string lp = Path.Combine(folder, "ADACLSizeAudit_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_log.txt");
                        File.WriteAllLines(lp, LogLines.ToArray(), Encoding.UTF8);
                        result.LogPath = lp;
                    }
                }
                catch { }
            }
            return result;
        }

        static string Sanitize(string s)
        {
            var sb = new StringBuilder();
            foreach (char c in s) sb.Append(char.IsLetterOrDigit(c) || c == '.' || c == '_' || c == '-' || c == '+' ? c : '_');
            return sb.ToString();
        }

        string EnsureOutputFolder()
        {
            string folder = string.IsNullOrEmpty(S.OutputFolder) ? Settings.DefaultOutputFolder() : S.OutputFolder;
            if (!Directory.Exists(folder)) Directory.CreateDirectory(folder);
            return Path.GetFullPath(folder);
        }

        // ------------------------------------------------------------------ targets

        void ResolveTargets()
        {
            if (S.Mode == "Forest")
            {
                string target = string.IsNullOrEmpty(S.Server) ? S.Forest : S.Server;
                Info(string.Format("Reading forest structure of {0} from {1}", S.Forest, target));
                using (var session = LdapSession.Open(target, S.EffectivePort, S.UseLdaps, S.Credential))
                {
                    var dse = RootDse.Read(session.Connection);
                    string rootDns = LdapUtil.DnsFromNc(dse.RootDomainNamingContext);
                    if (!string.Equals(rootDns, S.Forest.Trim().TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
                        Warn("The connected DC reports forest root " + rootDns + "; continuing with that forest.");
                    Forest = new ForestInfo { Name = rootDns, RootNc = dse.RootDomainNamingContext, ConfigNc = dse.ConfigurationNamingContext, SchemaNc = dse.SchemaNamingContext, ForestFunctionality = dse.ForestFunctionality, DiscoveredFrom = dse.DnsHostName };
                    var list = ForestDomainList(session.Connection, dse.ConfigurationNamingContext);
                    foreach (var d in list)
                    {
                        string srv = "";
                        if (S.ServerMap.ContainsKey(d.Dns)) srv = S.ServerMap[d.Dns];
                        else if (string.Equals(d.Dns, rootDns, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(S.Server)) srv = S.Server;
                        d.Server = srv;
                        Domains.Add(d);
                    }
                    AddCheck("TGT-01", "Target", "Forest discovery", CheckStatus.OK, string.Format("Forest {0}: {1} domain(s) found in CN=Partitions via {2} (forest functional level {3})", rootDns, list.Count, dse.DnsHostName, dse.ForestFunctionality), "Run");
                    Ok("Forest " + rootDns + ": " + string.Join(", ", list.Select(x => x.Dns).ToArray()));
                }
            }
            else
            {
                int i = 0;
                foreach (string name in S.Domains)
                {
                    string n = name.Trim().TrimEnd('.');
                    if (n.Length == 0) continue;
                    string srv = "";
                    if (S.ServerMap.ContainsKey(n)) srv = S.ServerMap[n];
                    else if (i == 0 && !string.IsNullOrEmpty(S.Server)) srv = S.Server;
                    Domains.Add(new DomainState { Dns = n, Nc = LdapUtil.NcFromDns(n), Server = srv });
                    i++;
                }
                AddCheck("TGT-01", "Target", "Target domains", CheckStatus.OK, string.Join(", ", S.Domains.ToArray()) + " (explicitly named; no trust enumeration)", "Run");
            }
            if (Domains.Count == 0) throw new ApplicationException("No domain to audit.");
        }

        List<DomainState> ForestDomainList(LdapConnection conn, string configNc)
        {
            var list = new List<DomainState>();
            var ps = new PagedSearch(conn, "CN=Partitions," + configNc, "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))",
                SearchScope.OneLevel, new string[] { "nCName", "dnsRoot", "nETBIOSName" }, 200, 0, false);
            while (!ps.Done)
                foreach (var e in ps.NextPage())
                {
                    string dns = LdapUtil.GetString(e, "dnsRoot");
                    if (string.IsNullOrEmpty(dns)) continue;
                    list.Add(new DomainState { Dns = dns, NetBios = LdapUtil.GetString(e, "nETBIOSName") ?? "", Nc = LdapUtil.GetString(e, "nCName") ?? "" });
                }
            if (ps.Errors.Count > 0) throw new ApplicationException("Domain enumeration failed: " + string.Join("; ", ps.Errors.ToArray()));
            return list.OrderBy(d => d.Nc.Length).ToList();
        }

        void ConnectDomain(DomainState st)
        {
            string target = string.IsNullOrEmpty(st.Server) ? st.Dns : st.Server;
            try
            {
                st.Session = LdapSession.Open(target, S.EffectivePort, S.UseLdaps, S.Credential);
                st.AuthMode = st.Session.AuthMode;
                st.RootDse = RootDse.Read(st.Session.Connection);
                st.ServerUsed = string.IsNullOrEmpty(st.RootDse.DnsHostName) ? target : st.RootDse.DnsHostName;
                if (string.IsNullOrEmpty(st.Nc)) st.Nc = st.RootDse.DefaultNamingContext;
                if (string.IsNullOrEmpty(st.Dns)) st.Dns = LdapUtil.DnsFromNc(st.Nc);

                string served = LdapUtil.DnsFromNc(st.RootDse.DefaultNamingContext);
                if (served.Length > 0 && !string.Equals(served, st.Dns, StringComparison.OrdinalIgnoreCase))
                    throw new ApplicationException(string.Format("The DC {0} serves domain {1}, not {2}. Check the preferred DC / server map.", st.ServerUsed, served, st.Dns));

                var head = LdapUtil.BaseRead(st.Session.Connection, st.Nc, new string[] { "objectSid", "name" }, 0);
                if (head != null)
                {
                    var sid = LdapUtil.GetBytes(head, "objectSid");
                    if (sid != null) { string s = SdParser.SidToString(sid, 0); if (s != null) st.DomainSid = s; }
                }
                if (string.IsNullOrEmpty(st.NetBios)) st.NetBios = st.Dns.Split('.')[0].ToUpperInvariant();
                st.Connected = true;

                var missing = new List<string>();
                if (!st.RootDse.SupportedControl.Contains(LdapSession.PagingOid)) missing.Add("paged results");
                if (!st.RootDse.SupportedControl.Contains(LdapSession.SdFlagsOid)) missing.Add("security descriptor flags");
                if (missing.Count > 0)
                {
                    AddCheck("CON-02", "Connection", "Required LDAP controls", CheckStatus.Failed, "Not advertised by " + st.ServerUsed + ": " + string.Join(", ", missing.ToArray()), st.Dns);
                    throw new ApplicationException("Required LDAP controls are not supported by " + st.ServerUsed);
                }
                string sec = (S.UseLdaps || S.EffectivePort == 636) ? "LDAPS " + S.EffectivePort : "LDAP 389 with signing and sealing";
                AddCheck("CON-01", "Connection", "LDAP bind", CheckStatus.OK, string.Format("Bound to {0} ({1}; {2}; domain functional level {3})", st.ServerUsed, sec, st.AuthMode, st.RootDse.DomainFunctionality), st.Dns);
                Ok(string.Format("Connected to {0} via {1} ({2})", st.Dns, st.ServerUsed, st.AuthMode));
            }
            catch (Exception ex)
            {
                st.Connected = false;
                st.Errors.Add(ex.Message);
                AddCheck("CON-01", "Connection", "LDAP bind", CheckStatus.Failed, ex.Message, st.Dns);
                Fail("Connection to " + st.Dns + " failed: " + ex.Message);
                if (st.Session != null) { st.Session.Dispose(); st.Session = null; }
            }
        }

        // ------------------------------------------------------------------ scan

        class PartitionPlanItem { public string Name; public string Base; public bool DomainScope; }

        List<PartitionPlanItem> PartitionPlan(DomainState st, bool firstDomain)
        {
            var plan = new List<PartitionPlanItem>();
            string rootNc = Forest != null ? Forest.RootNc : st.RootDse.RootDomainNamingContext;
            foreach (string p in S.Partitions)
            {
                switch (p)
                {
                    case "Domain": plan.Add(new PartitionPlanItem { Name = "Domain", Base = string.IsNullOrEmpty(S.SearchBase) ? st.Nc : S.SearchBase, DomainScope = true }); break;
                    case "DomainDnsZones": plan.Add(new PartitionPlanItem { Name = "DomainDnsZones", Base = "DC=DomainDnsZones," + st.Nc }); break;
                    case "Configuration": if (firstDomain) plan.Add(new PartitionPlanItem { Name = "Configuration", Base = st.RootDse.ConfigurationNamingContext }); break;
                    case "Schema": if (firstDomain) plan.Add(new PartitionPlanItem { Name = "Schema", Base = st.RootDse.SchemaNamingContext }); break;
                    case "ForestDnsZones": if (firstDomain) plan.Add(new PartitionPlanItem { Name = "ForestDnsZones", Base = "DC=ForestDnsZones," + rootNc }); break;
                }
            }
            return plan;
        }

        void ScanPartition(DomainState st, PartitionPlanItem plan)
        {
            var ps = new PartitionStat { Name = plan.Name, Base = plan.Base };
            SearchResultEntry probe = null;
            try { probe = LdapUtil.BaseRead(st.Session.Connection, plan.Base, new string[] { "objectClass" }, 0); }
            catch (Exception ex) { ps.Errors.Add("Base verification failed: " + ex.Message); }
            if (probe == null)
            {
                ps.Skipped = true;
                string msg = plan.Base + " is not hosted on " + st.ServerUsed + " or does not exist - partition skipped.";
                ps.Errors.Add(msg);
                AddCheck("SCN-02", "Scan", "Partition " + plan.Name, CheckStatus.Warning, msg, st.Dns);
                Warn(st.Dns + " [" + plan.Name + "]: " + msg);
                st.Partitions.Add(ps);
                return;
            }

            Info(st.Dns + " [" + plan.Name + "]: scanning " + plan.Base);
            var sw = Stopwatch.StartNew();
            int before = st.Scanned;
            var attrs = new string[] { "nTSecurityDescriptor", "objectClass", "adminCount", "whenChanged" };
            var cursor = new PagedSearch(st.Session.Connection, plan.Base, S.LdapFilter, SearchScope.Subtree, attrs, S.PageSize, S.SdFlags, plan.DomainScope);
            string activity = "Scanning " + st.Dns + " [" + plan.Name + "]";
            DateTime lastProgress = DateTime.Now;

            while (!cursor.Done)
            {
                var page = cursor.NextPage();
                foreach (var entry in page)
                {
                    EvaluateEntry(entry, st, plan.Name);
                    if (S.MaxObjects > 0 && st.Scanned - before >= S.MaxObjects) { ps.Truncated = true; cursor.Done = true; break; }
                }
                if ((DateTime.Now - lastProgress).TotalSeconds >= 1)
                {
                    int done = st.Scanned - before;
                    int rate = sw.Elapsed.TotalSeconds > 0 ? (int)(done / sw.Elapsed.TotalSeconds) : 0;
                    SetStatus(string.Format("{0} | {1} objects | page {2} | largest so far {3} | {4} obj/s", activity, N0(done), cursor.Pages, KB(st.Max, 1), rate));
                    lastProgress = DateTime.Now;
                }
                if (CancelRequested) { ps.Truncated = true; ps.Cancelled = true; cursor.Done = true; }
            }
            if (cursor.SaclDropped) SaclFallback = true;
            sw.Stop();

            ps.Scanned = st.Scanned - before; ps.Pages = cursor.Pages; ps.Retries = cursor.Retries;
            ps.Errors.AddRange(cursor.Errors);
            ps.DurationSec = Math.Round(sw.Elapsed.TotalSeconds, 1);
            st.Partitions.Add(ps);

            Ok(string.Format("{0} [{1}]: {2} objects in {3} s, {4} pages, largest {5}, flagged so far {6}", st.Dns, plan.Name, N0(ps.Scanned), ps.DurationSec, cursor.Pages, KB(st.Max, 1), st.Flagged));
            foreach (string e in cursor.Errors) Warn(st.Dns + " [" + plan.Name + "]: " + e);

            if (ps.Cancelled)
                AddCheck("SCN-03", "Scan", "Partition " + plan.Name + " cancelled", CheckStatus.Failed, "Cancelled by the user after " + N0(ps.Scanned) + " objects. Results are partial.", st.Dns);
            else if (ps.Truncated)
                AddCheck("SCN-03", "Scan", "Partition " + plan.Name + " truncated", CheckStatus.Warning, "Stopped after " + S.MaxObjects + " objects (sample setting). Statistics cover a sample only.", st.Dns);

            var hard = cursor.Errors.Where(e => !e.StartsWith("SACL not readable", StringComparison.Ordinal)).ToList();
            if (hard.Count > 0)
                AddCheck("SCN-04", "Scan", "Partition " + plan.Name + " completeness", CheckStatus.Critical, "The scan ended early or lost pages: " + string.Join(" | ", hard.ToArray()), st.Dns);
            else if (cursor.Retries > 0)
                AddCheck("SCN-04", "Scan", "Partition " + plan.Name + " completeness", CheckStatus.Info, cursor.Retries + " page retries were needed; all pages were received.", st.Dns);
            else
                AddCheck("SCN-04", "Scan", "Partition " + plan.Name + " completeness", CheckStatus.OK, string.Format("{0} objects in {1} pages without retries ({2} s)", N0(ps.Scanned), cursor.Pages, ps.DurationSec), st.Dns);
        }

        void EvaluateEntry(SearchResultEntry entry, DomainState st, string partition)
        {
            var attrs = entry.Attributes;
            byte[] sd = null;
            if (attrs.Contains("ntsecuritydescriptor"))
            {
                var vals = attrs["ntsecuritydescriptor"].GetValues(typeof(byte[]));
                if (vals != null && vals.Length > 0) sd = vals[0] as byte[];
            }
            var classes = new List<string>();
            if (attrs.Contains("objectclass"))
                foreach (object o in attrs["objectclass"].GetValues(typeof(string))) { string c = o as string; if (c != null) classes.Add(c); }
            EvaluateObject(entry.DistinguishedName, sd, classes, LdapUtil.GetString(entry, "adminCount"), LdapUtil.GetString(entry, "whenChanged"), st, partition);
        }

        /// <summary>Evaluates one object from its raw attributes (also used by the offline self-test).</summary>
        internal void EvaluateObject(string dn, byte[] sd, List<string> classes, string adminCount, string whenChanged, DomainState st, string partition)
        {
            st.Scanned++;
            TotalScanned++;
            if (sd == null || sd.Length == 0)
            {
                st.Unreadable++;
                if (st.UnreadableSamples.Count < 10) st.UnreadableSamples.Add(dn);
                return;
            }

            var h = SdParser.ParseHeader(sd);
            int size = sd.Length;
            if (!h.Valid)
            {
                st.Invalid++;
                if (st.InvalidSamples.Count < 10) st.InvalidSamples.Add(dn + " (" + h.Note + ")");
            }
            if (h.SaclPresent) st.WithSacl++;

            int bucket = Math.Min(16, size / 4096);
            Hist[bucket]++; st.Hist[bucket]++;
            st.Sizes.Add(size); AllSizes.Add(size);
            st.SumBytes += size;
            if (size > st.Max) { st.Max = size; st.MaxDn = dn; }

            var status = StatusOf(size);
            st.Count(status);

            string cls = "unknown";
            if (classes != null && classes.Count > 0) cls = classes[classes.Count - 1];
            if (classes == null) classes = new List<string>();
            ClassStat cs;
            if (ClassStats.TryGetValue(cls, out cs))
            {
                cs.Count++; cs.Sum += size;
                if (size > cs.Max) { cs.Max = size; cs.MaxDn = dn; }
                if (status != SizeStatus.Healthy) cs.Flagged++;
            }
            else ClassStats[cls] = new ClassStat { Count = 1, Sum = size, Max = size, MaxDn = dn, Flagged = status != SizeStatus.Healthy ? 1 : 0 };

            bool isContainer = false;
            foreach (string c in classes) if (ContainerClasses.Contains(c)) { isContainer = true; break; }
            bool deep = S.AceDetail && (size >= S.WarnBytes || (isContainer && size >= S.ContainerDeepBytes));
            bool keepRow = size >= S.FloorBytes || deep;
            if (!keepRow && TopRows.Count < S.TopN) keepRow = true;
            if (!keepRow && size > TopMin) keepRow = true;
            if (!keepRow) return;

            string changed = "";
            if (whenChanged != null && whenChanged.Length >= 12)
                changed = whenChanged.Substring(0, 4) + "-" + whenChanged.Substring(4, 2) + "-" + whenChanged.Substring(6, 2) + " " + whenChanged.Substring(8, 2) + ":" + whenChanged.Substring(10, 2);

            var row = new ObjectRow
            {
                Domain = st.Dns, Partition = partition, Dn = dn, Name = LdapUtil.RdnValue(dn), Class = cls, Bytes = size,
                Headroom = Settings.SdLimitBytes - size, Percent = Math.Round(size * 100.0 / Settings.SdLimitBytes, 1), Status = status,
                DaclBytes = h.DaclBytes, DaclAces = h.DaclAces, SaclBytes = h.SaclBytes, SaclAces = h.SaclAces, DaclProtected = h.DaclProtected,
                AdminCount = adminCount == "1", WhenChanged = changed, IsContainer = isContainer, Deep = deep, Valid = h.Valid, Note = h.Note
            };

            if (deep && h.Valid && h.DaclPresent)
            {
                bool collect = status != SizeStatus.Healthy;
                var det = SdParser.ParseAcl(sd, h.DaclOffset, h.DaclAces, collect);
                row.Explicit = det.Explicit; row.Inherited = det.Inherited; row.Allow = det.Allow; row.Deny = det.Deny; row.ObjectAces = det.ObjectAces;
                row.InheritableAces = det.InheritableAces; row.InheritableBytes = det.InheritableBytes; row.LargestAce = det.LargestAce; row.Truncated = det.Truncated;
                row.OwnerSid = h.OwnerOffset > 0 ? SdParser.SidToString(sd, h.OwnerOffset) : null;
                if (h.DaclAces > 0)
                {
                    double avg = (double)h.DaclBytes / h.DaclAces;
                    row.AvgAce = Math.Round(avg, 1);
                    row.EstAcesLeft = (int)Math.Floor(row.Headroom / Math.Max(1.0, avg));
                }
                if (collect)
                {
                    row.Trustees = det.Trustees.Values.OrderByDescending(t => t.Bytes).Take(8).ToList();
                    foreach (var kv in det.Trustees)
                    {
                        TrusteeStat a;
                        if (TrusteeAgg.TryGetValue(kv.Key, out a)) { a.Bytes += kv.Value.Bytes; a.Aces += kv.Value.Count; a.Objects++; }
                        else TrusteeAgg[kv.Key] = new TrusteeStat { Bytes = kv.Value.Bytes, Aces = kv.Value.Count, Objects = 1, Sid = kv.Value.Sid };
                    }
                }
                if (isContainer) Containers.Add(row);
            }

            if (size >= S.FloorBytes || deep) Rows.Add(row);
            AddTopRow(row);
        }

        void AddTopRow(ObjectRow row)
        {
            if (TopRows.Count < S.TopN) { TopRows.Add(row); }
            else
            {
                int minIdx = 0;
                for (int i = 1; i < TopRows.Count; i++) if (TopRows[i].Bytes < TopRows[minIdx].Bytes) minIdx = i;
                if (row.Bytes > TopRows[minIdx].Bytes) TopRows[minIdx] = row;
            }
            if (TopRows.Count >= S.TopN)
            {
                int m = int.MaxValue;
                foreach (var r in TopRows) if (r.Bytes < m) m = r.Bytes;
                TopMin = m;
            }
        }

        // ------------------------------------------------------------------ per-domain checks

        void KeyObjectChecks(DomainState st)
        {
            var results = new List<KeyObjectInfo>();
            foreach (var k in KeyObjects)
            {
                var info = new KeyObjectInfo { Name = k[0], Dn = k[1] + st.Nc };
                SearchResultEntry e = null;
                try { e = LdapUtil.BaseRead(st.Session.Connection, info.Dn, new string[] { "nTSecurityDescriptor" }, S.SdFlags); }
                catch (Exception ex) { info.Error = ex.Message; }
                if (e != null)
                {
                    var sd = LdapUtil.GetBytes(e, "nTSecurityDescriptor");
                    if (sd != null)
                    {
                        var h = SdParser.ParseHeader(sd);
                        info.Bytes = sd.Length; info.DaclBytes = h.DaclBytes; info.DaclAces = h.DaclAces;
                        info.Status = StatusOf(info.Bytes).ToString();
                        if (h.Valid && h.DaclPresent)
                        {
                            var det = SdParser.ParseAcl(sd, h.DaclOffset, h.DaclAces, false);
                            info.InheritableBytes = det.InheritableBytes; info.InheritableAces = det.InheritableAces;
                        }
                        if (info.Name == "AdminSDHolder") st.AdminSdHolderBytes = info.Bytes;
                    }
                }
                results.Add(info);
            }
            st.KeyObjects = results;

            var worst = results.Where(r => r.Status == "Warning" || r.Status == "Critical" || r.Status == "Limit").ToList();
            var chk = CheckStatus.OK;
            if (worst.Count > 0) chk = worst.Any(r => r.Status != "Warning") ? CheckStatus.Critical : CheckStatus.Warning;
            AddCheck("KEY-01", "Key objects", "Domain head and well-known containers", chk, string.Join("; ", results.Select(r => r.Name + " " + KB(r.Bytes, 1)).ToArray()), st.Dns);

            var asdh = results.FirstOrDefault(r => r.Name == "AdminSDHolder");
            int countAdmin = -1;
            try
            {
                var ps = new PagedSearch(st.Session.Connection, st.Nc, "(adminCount=1)", SearchScope.Subtree, new string[] { "1.1" }, 1000, 0, true);
                countAdmin = 0;
                while (!ps.Done) countAdmin += ps.NextPage().Count;
                if (ps.Errors.Count > 0) countAdmin = -1;
            }
            catch { countAdmin = -1; }
            st.AdminCountObjects = countAdmin;
            if (asdh != null && asdh.Bytes > 0)
            {
                var s = CheckStatus.OK;
                if (asdh.Bytes >= S.WarnBytes / 2) s = CheckStatus.Info;
                if (asdh.Bytes >= S.WarnBytes) s = CheckStatus.Warning;
                if (asdh.Bytes >= S.CritBytes) s = CheckStatus.Critical;
                string cnt = countAdmin >= 0 ? N0(countAdmin) : "an unknown number of";
                AddCheck("KEY-02", "Key objects", "AdminSDHolder template", s, string.Format("AdminSDHolder descriptor is {0} ({1} DACL ACEs); it is applied to {2} protected objects (adminCount=1).", KB(asdh.Bytes, 1), asdh.DaclAces, cnt), st.Dns);
            }
            else AddCheck("KEY-02", "Key objects", "AdminSDHolder template", CheckStatus.Warning, "AdminSDHolder could not be read.", st.Dns);
        }

        void SchemaDefaultCheck(DomainState st)
        {
            var sb = new StringBuilder();
            foreach (string c in DefaultSdClasses) sb.Append("(lDAPDisplayName=").Append(c).Append(')');
            string filter = "(&(objectClass=classSchema)(|" + sb + "))";
            var outList = new List<SchemaDefault>();
            try
            {
                var ps = new PagedSearch(st.Session.Connection, st.RootDse.SchemaNamingContext, filter, SearchScope.OneLevel, new string[] { "lDAPDisplayName", "defaultSecurityDescriptor" }, 100, 0, false);
                while (!ps.Done)
                    foreach (var e in ps.NextPage())
                    {
                        var d = new SchemaDefault { Class = LdapUtil.GetString(e, "lDAPDisplayName") ?? "?" };
                        string sddl = LdapUtil.GetString(e, "defaultSecurityDescriptor");
                        if (!string.IsNullOrEmpty(sddl))
                        {
                            d.SddlLength = sddl.Length;
                            try { d.Bytes = new RawSecurityDescriptor(sddl).BinaryLength; }
                            catch { d.Bytes = (int)(sddl.Length * 0.6); d.Method = "estimated from SDDL length"; }
                        }
                        outList.Add(d);
                    }
            }
            catch (Exception ex)
            {
                AddCheck("SCH-01", "Schema", "Class default descriptors", CheckStatus.Warning, "Schema defaults could not be read: " + ex.Message, "Run");
                return;
            }
            SchemaDefaults = outList.OrderByDescending(d => d.Bytes).ToList();
            var u = outList.FirstOrDefault(d => d.Class == "user");
            if (u != null) UserDefaultSdBytes = u.Bytes;
            var large = outList.Where(d => d.Bytes > 4096).ToList();
            if (large.Count > 0)
                AddCheck("SCH-01", "Schema", "Class default descriptors", CheckStatus.Warning, "Unusually large defaults (customised schema?): " + string.Join(", ", large.Select(d => d.Class + " " + KB(d.Bytes, 1)).ToArray()) + ". Every new object of these classes starts with that size before inheritance.", "Run");
            else
                AddCheck("SCH-01", "Schema", "Class default descriptors", CheckStatus.OK, string.Join("; ", SchemaDefaults.Take(6).Select(d => d.Class + " " + d.Bytes + " B").ToArray()), "Run");
        }

        // ------------------------------------------------------------------ post-processing

        public static int Percentile(int[] sorted, double p)
        {
            if (sorted == null || sorted.Length == 0) return 0;
            int idx = (int)Math.Ceiling(p * sorted.Length) - 1;
            if (idx < 0) idx = 0; if (idx >= sorted.Length) idx = sorted.Length - 1;
            return sorted[idx];
        }

        internal void CompleteDomainStatistics(DomainState st)
        {
            var arr = st.Sizes.ToArray();
            Array.Sort(arr);
            st.Median = Percentile(arr, 0.5); st.P95 = Percentile(arr, 0.95); st.P99 = Percentile(arr, 0.99);
            st.Avg = arr.Length > 0 ? (int)(st.SumBytes / arr.Length) : 0;
            st.Sizes.Clear();
        }

        internal void UpdateFlaggedDescendants()
        {
            var map = new Dictionary<string, ObjectRow>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in Containers) map[c.Dn] = c;
            if (map.Count == 0) return;
            foreach (var r in Rows)
            {
                if (r.Status == SizeStatus.Healthy) continue;
                string p = LdapUtil.ParentDn(r.Dn);
                int guard = 0;
                while (p != null && guard < 64)
                {
                    ObjectRow c;
                    if (map.TryGetValue(p, out c)) c.FlaggedDescendants++;
                    p = LdapUtil.ParentDn(p);
                    guard++;
                }
            }
        }

        internal void ResolveTrusteeNames()
        {
            var top = TrusteeAgg.Values.OrderByDescending(t => t.Bytes).Take(80).ToList();
            int i = 0;
            foreach (var t in top)
            {
                i++;
                if (i % 5 == 1) SetStatus("Resolving trustee names | " + i + " of " + top.Count);
                t.Name = ResolveSidName(t.Sid, false);
            }
        }

        /// <summary>Cache -> LDAP lookup in the scanned domain that owns the SID -> time-boxed local translation.</summary>
        public string ResolveSidName(byte[] sidBytes, bool cacheOnly)
        {
            string key = SdParser.SidToString(sidBytes, 0);
            if (key == null) return "invalid SID";
            string cached;
            if (SidNameCache.TryGetValue(key, out cached)) return cached;
            if (cacheOnly) return key;

            string name = null;
            bool isDomainSid = key.StartsWith("S-1-5-21-", StringComparison.Ordinal);
            bool owned = false;
            if (isDomainSid)
            {
                string domainPart = key.Substring(0, key.LastIndexOf('-'));
                foreach (var d in Domains)
                {
                    if (d.Session == null || !string.Equals(d.DomainSid, domainPart, StringComparison.OrdinalIgnoreCase)) continue;
                    owned = true;
                    try
                    {
                        var ps = new PagedSearch(d.Session.Connection, d.Nc, "(objectSid=" + LdapUtil.BinaryFilter(sidBytes) + ")", SearchScope.Subtree, new string[] { "sAMAccountName", "name" }, 2, 0, true);
                        var entries = ps.NextPage();
                        if (entries.Count > 0)
                        {
                            string sam = LdapUtil.GetString(entries[0], "sAMAccountName");
                            if (string.IsNullOrEmpty(sam)) sam = LdapUtil.GetString(entries[0], "name");
                            name = d.NetBios + "\\" + sam;
                        }
                        else name = d.NetBios + "\\<deleted or unknown " + key.Substring(key.LastIndexOf('-') + 1) + ">";
                    }
                    catch { name = null; }
                    break;
                }
            }
            if (string.IsNullOrEmpty(name) && !(isDomainSid && !owned && SlowTranslate))
            {
                var sw = Stopwatch.StartNew();
                try { name = ((NTAccount)new SecurityIdentifier(sidBytes, 0).Translate(typeof(NTAccount))).Value; } catch { name = null; }
                sw.Stop();
                if (sw.Elapsed.TotalSeconds > 3 && isDomainSid) SlowTranslate = true;
            }
            if (string.IsNullOrEmpty(name)) name = key;
            SidNameCache[key] = name;
            return name;
        }

        internal void ImportBaseline()
        {
            if (string.IsNullOrEmpty(S.BaselinePath)) return;
            if (!File.Exists(S.BaselinePath)) { AddCheck("BAS-01", "Baseline", "Baseline file", CheckStatus.Warning, "Baseline not found: " + S.BaselinePath, "Run"); return; }
            try
            {
                Baseline = SnapshotReader.Read(S.BaselinePath);
                AddCheck("BAS-01", "Baseline", "Baseline file", CheckStatus.OK, string.Format("Loaded {0} objects from {1} (generated {2}, target {3})", Baseline.Map.Count, Path.GetFileName(S.BaselinePath), Baseline.Generated, Baseline.Target), "Run");
            }
            catch (Exception ex)
            {
                Baseline = null;
                AddCheck("BAS-01", "Baseline", "Baseline file", CheckStatus.Warning, "Baseline could not be parsed: " + ex.Message, "Run");
            }
        }

        internal void CompareWithBaseline()
        {
            if (Baseline == null) return;
            var b = Baseline;
            var growth = new List<ObjectRow>();
            foreach (var r in Rows)
            {
                int old;
                if (b.Map.TryGetValue(r.Dn, out old))
                {
                    int delta = r.Bytes - old;
                    r.Delta = delta;
                    if (delta > 0) { b.Grown++; b.GrowthBytes += delta; growth.Add(r); }
                    else if (delta < 0) b.Shrunk++;
                    else b.Unchanged++;
                }
                else { r.Delta = null; if (r.Bytes >= S.FloorBytes) b.New++; }
            }
            b.TopGrowth = growth.OrderByDescending(r => r.Delta ?? 0).Take(10).ToList();
            var big = growth.Where(r => (r.Delta ?? 0) >= 4096).ToList();
            var s = CheckStatus.OK;
            if (big.Count > 0) s = CheckStatus.Warning;
            if (big.Any(r => r.Status == SizeStatus.Critical || r.Status == SizeStatus.Limit)) s = CheckStatus.Critical;
            string detail = string.Format("Since {0}: {1} objects grew ({2} in total), {3} shrank, {4} are newly above the report floor.", b.Generated, b.Grown, KB(b.GrowthBytes, 1), b.Shrunk, b.New);
            if (big.Count > 0) detail += " " + big.Count + " object(s) grew by 4 KB or more.";
            AddCheck("BAS-02", "Baseline", "Growth since baseline", s, detail, "Run");
        }

        internal void CompleteRunChecks()
        {
            int total = TotalScanned;
            int healthy = Domains.Sum(d => d.Healthy), warn = Domains.Sum(d => d.Warning), crit = Domains.Sum(d => d.Critical), limit = Domains.Sum(d => d.Limit);
            int unread = Domains.Sum(d => d.Unreadable), invalid = Domains.Sum(d => d.Invalid), withSacl = Domains.Sum(d => d.WithSacl);

            AddCheck("CFG-01", "Configuration", "Thresholds", CheckStatus.OK, string.Format("Warning >= {0} KB, Critical >= {1} KB, At limit >= {2} KB; hard limit 64 KB (65,536 bytes; a single ACL cannot exceed 65,535 bytes). Report floor {3} KB, top {4} always listed.",
                S.WarningKB, S.CriticalKB, Math.Round(S.LimitBytes / 1024.0, 1), S.ReportFloorKB, S.TopN), "Run");

            if (SaclRequested && !SaclFallback)
            {
                var s = CheckStatus.OK;
                string detail = "Owner, group, DACL and SACL were requested; " + N0(withSacl) + " object(s) returned a SACL, so the sizes are the complete descriptor sizes.";
                if (withSacl == 0 && total > 0)
                {
                    s = CheckStatus.Warning;
                    detail = "The SACL was requested but no object returned one. Either no auditing is configured in scope, or the account lacks the \"Manage auditing and security log\" right on the DCs - in that case the sizes are lower bounds (DACL + owner + group).";
                }
                AddCheck("MEA-01", "Measurement", "Descriptor parts measured", s, detail, "Run");
            }
            else if (SaclFallback)
                AddCheck("MEA-01", "Measurement", "Descriptor parts measured", CheckStatus.Warning, "The server refused the SACL for this account; the scan continued with owner, group and DACL only. Sizes are lower bounds.", "Run");
            else
                AddCheck("MEA-01", "Measurement", "Descriptor parts measured", CheckStatus.Info, "SACL not requested: owner, group and DACL only. Sizes are lower bounds.", "Run");

            if (unread > 0)
            {
                double pct = Math.Round(unread * 100.0 / Math.Max(1, total), 2);
                var samples = Domains.SelectMany(d => d.UnreadableSamples.Take(3)).ToArray();
                AddCheck("MEA-02", "Measurement", "Objects without readable descriptor", pct >= 1 ? CheckStatus.Critical : CheckStatus.Warning,
                    string.Format("{0} object(s) ({1} %) returned no nTSecurityDescriptor - the account lacks Read permissions / READ_CONTROL on them. Their size is unknown. Examples: {2}", N0(unread), pct, string.Join("; ", samples)), "Run");
            }
            else AddCheck("MEA-02", "Measurement", "Objects without readable descriptor", CheckStatus.OK, "Every scanned object returned its security descriptor.", "Run");

            if (invalid > 0)
            {
                var samples = Domains.SelectMany(d => d.InvalidSamples.Take(3)).ToArray();
                AddCheck("MEA-03", "Measurement", "Malformed descriptors", CheckStatus.Critical, invalid + " descriptor(s) could not be parsed (sizes were still counted). Examples: " + string.Join("; ", samples), "Run");
            }
            else AddCheck("MEA-03", "Measurement", "Malformed descriptors", CheckStatus.OK, "All descriptors parsed with a valid header.", "Run");

            var rs = CheckStatus.OK;
            if (warn > 0) rs = CheckStatus.Warning;
            if (crit > 0) rs = CheckStatus.Critical;
            if (limit > 0) rs = CheckStatus.Failed;
            AddCheck("RES-01", "Results", "Objects by threshold", rs, string.Format("{0} scanned: {1} healthy, {2} warning, {3} critical, {4} at limit.", N0(total), N0(healthy), warn, crit, limit), "Run");

            var atLimit = Rows.Where(r => r.Status == SizeStatus.Limit).OrderByDescending(r => r.Bytes).ToList();
            if (atLimit.Count > 0)
                AddCheck("RES-02", "Results", "Objects at the limit", CheckStatus.Failed, string.Format("These objects have less than {0} KB headroom; ACL writes and inheritance propagation to them are expected to fail: {1}",
                    S.LimitMarginKB, string.Join("; ", atLimit.Take(5).Select(r => r.Dn + " (" + KB(r.Bytes, 1) + ")").ToArray())), "Run");

            var daclCap = Rows.Where(r => r.DaclBytes >= Settings.AclHeaderCap - 512).ToList();
            if (daclCap.Count > 0)
                AddCheck("RES-03", "Results", "DACL near the 16-bit size cap", CheckStatus.Failed, daclCap.Count + " DACL(s) are within 512 bytes of 65,535 bytes: " + string.Join("; ", daclCap.Take(5).Select(r => r.Dn).ToArray()), "Run");

            int protectedFlagged = Rows.Count(r => r.Status != SizeStatus.Healthy && r.DaclProtected);
            if (protectedFlagged > 0)
                AddCheck("RES-04", "Results", "Flagged objects with blocked inheritance", CheckStatus.Info, protectedFlagged + " flagged object(s) have a protected DACL: their size comes from explicit ACEs and will not shrink when a parent container is cleaned up.", "Run");

            int adminFlagged = Rows.Count(r => r.Status != SizeStatus.Healthy && r.AdminCount);
            if (adminFlagged > 0)
                AddCheck("RES-05", "Results", "Flagged protected accounts (adminCount=1)", CheckStatus.Info, adminFlagged + " flagged object(s) carry adminCount=1; their DACL is re-stamped from AdminSDHolder every hour, so fix the template rather than the object.", "Run");

            var hot = Containers.Where(c => (c.InheritableBytes ?? 0) >= S.WarnBytes).OrderByDescending(c => c.InheritableBytes ?? 0).ToList();
            if (hot.Count > 0)
            {
                var s = hot.Any(c => (c.InheritableBytes ?? 0) >= S.CritBytes) ? CheckStatus.Critical : CheckStatus.Warning;
                AddCheck("PRP-01", "Propagation", "Containers whose inheritable ACEs exceed the warning threshold", s, string.Format("{0} container(s): every new child object starts at or above {1} KB before its own ACEs are added. {2}",
                    hot.Count, S.WarningKB, string.Join("; ", hot.Take(5).Select(c => c.Dn + " (" + KB(c.InheritableBytes ?? 0, 1) + " inheritable)").ToArray())), "Run");
            }
            else AddCheck("PRP-01", "Propagation", "Containers whose inheritable ACEs exceed the warning threshold", CheckStatus.OK, "No container propagates more than the warning threshold to its children.", "Run");

            if (CancelRequested)
                AddCheck("RUN-01", "Scan", "Run cancelled", CheckStatus.Failed, "The audit was cancelled by the user after " + N0(total) + " objects. Every figure in this report is partial.", "Run");

            AddCheck("ENV-01", "Environment", "Run context", CheckStatus.Info, string.Format("Run as {0} on {1}, {2}, {3} {4}. Read-only: no attribute was written.", CurrentUser(), Environment.MachineName, RuntimeText(), Branding.Name, Branding.Version), "Run");
        }

        public static string CurrentUser()
        {
            try { return WindowsIdentity.GetCurrent().Name; } catch { return Environment.UserName; }
        }

        public static string RuntimeText()
        {
            return ".NET Framework CLR " + Environment.Version + " on " + Environment.OSVersion.VersionString;
        }

        public List<ObjectRow> ReportRows()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var outList = new List<ObjectRow>();
            foreach (var r in Rows) if (seen.Add(r.Dn)) outList.Add(r);
            foreach (var r in TopRows) if (seen.Add(r.Dn)) outList.Add(r);
            return outList.OrderByDescending(r => r.Bytes).ToList();
        }

        internal void ConsoleSummary(List<ObjectRow> rows)
        {
            Section("Summary");
            foreach (var d in Domains)
            {
                if (!d.Connected) { Warn(d.Dns + ": not connected"); continue; }
                Info(string.Format("{0}: {1} objects, largest {2}, P95 {3}, warning {4}, critical {5}, at limit {6}, unreadable {7}",
                    d.Dns, N0(d.Scanned), KB(d.Max, 1), KB(d.P95, 1), d.Warning, d.Critical, d.Limit, d.Unreadable));
            }
            var flagged = rows.Where(r => r.Status != SizeStatus.Healthy).OrderByDescending(r => r.Bytes).ToList();
            if (flagged.Count > 0)
            {
                Info(string.Format("Flagged objects (top {0} of {1}):", Math.Min(10, flagged.Count), flagged.Count));
                foreach (var r in flagged.Take(10))
                    Emit(r.Status == SizeStatus.Warning ? "WARN" : "FAIL", string.Format("{0,-8} {1,9}  {2}", r.Status, KB(r.Bytes, 1), r.Dn));
            }
            else Ok("No object reached the warning threshold.");
            var bad = Checks.Where(c => c.Status == CheckStatus.Warning || c.Status == CheckStatus.Critical || c.Status == CheckStatus.Failed).ToList();
            if (bad.Count > 0)
            {
                Info("Checks needing attention (" + bad.Count + "):");
                foreach (var c in bad)
                {
                    string line = string.Format("{0,-8} {1}: {2}", c.Status, c.Name, c.Detail);
                    if (line.Length > 220) line = line.Substring(0, 217) + "...";
                    Emit(c.Status == CheckStatus.Warning ? "WARN" : "FAIL", line);
                }
            }
        }
    }
}
