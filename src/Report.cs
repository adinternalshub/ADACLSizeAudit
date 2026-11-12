// ADACLSizeAudit - Report.cs
// Project: ADACLSizeAudit | Author: Jinish Kunjilikkattil | https://adinternalshub.com/ | MIT License
// Serialises the engine state for the self-contained dashboard (embedded resource Dashboard.html),
// writes the CSV and the JSON snapshot, and reads a previous snapshot as baseline.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace ADACLSizeAudit
{
    /// <summary>Minimal JSON emitter (no System.Web.Extensions dependency, works on the .NET 4.0 Client Profile).</summary>
    public static class Json
    {
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        public static string Str(string s)
        {
            if (s == null) return "null";
            var sb = new StringBuilder(s.Length + 8);
            sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '/': if (i > 0 && s[i - 1] == '<') sb.Append("\\/"); else sb.Append('/'); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", Inv)); else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }
        public static string Num(int v) { return v.ToString(Inv); }
        public static string Num(long v) { return v.ToString(Inv); }
        public static string Num(double v) { return v.ToString("0.0##", Inv); }
        public static string Num(int? v) { return v.HasValue ? v.Value.ToString(Inv) : "null"; }
        public static string Num(double? v) { return v.HasValue ? v.Value.ToString("0.0##", Inv) : "null"; }
        public static string Bool(bool b) { return b ? "true" : "false"; }
        public static string StrArray(IEnumerable<string> items) { return "[" + string.Join(",", items.Select(Str).ToArray()) + "]"; }
        public static string IntArray(IEnumerable<int> items) { return "[" + string.Join(",", items.Select(i => i.ToString(Inv)).ToArray()) + "]"; }
    }

    /// <summary>Builds one JSON object incrementally: Add(name, rawJsonValue).</summary>
    public class JsonObject
    {
        readonly StringBuilder _sb = new StringBuilder(256);
        bool _first = true;
        public JsonObject() { _sb.Append('{'); }
        public JsonObject Add(string name, string rawJson)
        {
            if (!_first) _sb.Append(',');
            _first = false;
            _sb.Append('"').Append(name).Append("\":").Append(rawJson ?? "null");
            return this;
        }
        public JsonObject S(string name, string value) { return Add(name, Json.Str(value)); }
        // int, long, int? and double? each have their own overload: an int argument would otherwise be ambiguous
        // between long and int? for the Microsoft C# compiler (CS0121).
        public JsonObject N(string name, int value) { return Add(name, Json.Num(value)); }
        public JsonObject N(string name, long value) { return Add(name, Json.Num(value)); }
        public JsonObject N(string name, double value) { return Add(name, Json.Num(value)); }
        public JsonObject N(string name, int? value) { return Add(name, Json.Num(value)); }
        public JsonObject N(string name, double? value) { return Add(name, Json.Num(value)); }
        public JsonObject B(string name, bool value) { return Add(name, Json.Bool(value)); }
        public override string ToString() { return _sb.ToString() + "}"; }
    }

    public static class SnapshotReader
    {
        static readonly Regex ObjRx = new Regex("\\{\"dn\":(\"(?:[^\"\\\\]|\\\\.)*\"),\"bytes\":(\\d+)", RegexOptions.Compiled);
        static readonly Regex TopRx = new Regex("\"(generated|target)\":(\"(?:[^\"\\\\]|\\\\.)*\")", RegexOptions.Compiled);

        public static BaselineInfo Read(string path)
        {
            string text = File.ReadAllText(path, Encoding.UTF8);
            var b = new BaselineInfo { Path = path };
            foreach (Match m in TopRx.Matches(text))
            {
                if (m.Groups[1].Value == "generated") b.Generated = Unescape(m.Groups[2].Value);
                else b.Target = Unescape(m.Groups[2].Value);
            }
            foreach (Match m in ObjRx.Matches(text))
            {
                string dn = Unescape(m.Groups[1].Value);
                int bytes;
                if (int.TryParse(m.Groups[2].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out bytes)) b.Map[dn] = bytes;
            }
            if (b.Map.Count == 0 && text.IndexOf("\"objects\"", StringComparison.Ordinal) < 0) throw new ApplicationException("not a snapshot of this tool");
            return b;
        }

        /// <summary>Decodes a JSON string literal (with quotes).</summary>
        public static string Unescape(string lit)
        {
            if (lit.Length >= 2 && lit[0] == '"') lit = lit.Substring(1, lit.Length - 2);
            var sb = new StringBuilder(lit.Length);
            for (int i = 0; i < lit.Length; i++)
            {
                char c = lit[i];
                if (c != '\\' || i + 1 >= lit.Length) { sb.Append(c); continue; }
                char n = lit[++i];
                switch (n)
                {
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u':
                        if (i + 4 < lit.Length) { sb.Append((char)Convert.ToInt32(lit.Substring(i + 1, 4), 16)); i += 4; }
                        break;
                    default: sb.Append(n); break;
                }
            }
            return sb.ToString();
        }
    }

    public class ReportBuilder
    {
        readonly AuditEngine E;
        readonly Settings S;
        public ReportBuilder(AuditEngine engine) { E = engine; S = engine.S; }

        // ---------------------------------------------------------------- rows

        string RowJson(ObjectRow r, bool withTrustees)
        {
            var o = new JsonObject()
                .S("d", r.Domain).S("p", r.Partition).S("dn", r.Dn).S("n", r.Name).S("c", r.Class)
                .N("b", r.Bytes).N("hr", r.Headroom).N("pct", r.Percent).S("st", r.Status.ToString())
                .N("db", r.DaclBytes).N("da", r.DaclAces).N("sb", r.SaclBytes).N("sa", r.SaclAces)
                .B("pr", r.DaclProtected).B("ac", r.AdminCount).S("wc", r.WhenChanged).B("ct", r.IsContainer).B("dp", r.Deep)
                .N("ex", r.Explicit).N("ih", r.Inherited).N("al", r.Allow).N("dy", r.Deny).N("oa", r.ObjectAces)
                .N("ia", r.InheritableAces).N("ib", r.InheritableBytes).N("la", r.LargestAce).N("est", r.EstAcesLeft).N("avg", r.AvgAce)
                .S("ow", r.OwnerSid).B("tr", r.Truncated).N("fd", r.FlaggedDescendants).N("dl", r.Delta).B("v", r.Valid).S("nt", r.Note);
            var ts = new StringBuilder("[");
            if (withTrustees && r.Trustees != null)
            {
                bool first = true;
                foreach (var t in r.Trustees)
                {
                    if (!first) ts.Append(',');
                    first = false;
                    ts.Append(new JsonObject().S("n", E.ResolveSidName(t.Sid, true)).N("b", t.Bytes).N("c", t.Count).ToString());
                }
            }
            ts.Append(']');
            o.Add("ts", ts.ToString());
            return o.ToString();
        }

        // ---------------------------------------------------------------- meta

        string DomainsJson()
        {
            var parts = new List<string>();
            foreach (var d in E.Domains)
            {
                var pj = d.Partitions.Select(p => new JsonObject().S("name", p.Name).S("base", p.Base).N("scanned", p.Scanned).N("pages", p.Pages).N("retries", p.Retries)
                    .B("truncated", p.Truncated).B("skipped", p.Skipped).N("durationSec", p.DurationSec).Add("errors", Json.StrArray(p.Errors)).ToString()).ToArray();
                var kj = d.KeyObjects.Select(k => new JsonObject().S("name", k.Name).S("dn", k.Dn).N("bytes", k.Bytes).N("daclAces", k.DaclAces).N("inheritableBytes", k.InheritableBytes)
                    .N("inheritableAces", k.InheritableAces).S("status", k.Status).S("error", k.Error).ToString()).ToArray();
                parts.Add(new JsonObject().S("dns", d.Dns).S("netbios", d.NetBios).S("nc", d.Nc).S("server", d.ServerUsed).S("auth", d.AuthMode).B("connected", d.Connected)
                    .N("scanned", d.Scanned).N("unreadable", d.Unreadable).N("invalid", d.Invalid).N("withSacl", d.WithSacl)
                    .N("max", d.Max).S("maxDn", d.MaxDn).N("median", d.Median).N("p95", d.P95).N("p99", d.P99).N("avg", d.Avg)
                    .N("healthy", d.Healthy).N("warning", d.Warning).N("critical", d.Critical).N("limit", d.Limit)
                    .Add("hist", Json.IntArray(d.Hist)).Add("partitions", "[" + string.Join(",", pj) + "]").Add("keyObjects", "[" + string.Join(",", kj) + "]")
                    .Add("errors", Json.StrArray(d.Errors)).N("adminSdHolderBytes", d.AdminSdHolderBytes).N("adminCountObjects", d.AdminCountObjects).N("durationSec", d.DurationSec).ToString());
            }
            return "[" + string.Join(",", parts.ToArray()) + "]";
        }

        string ClassesJson()
        {
            var list = E.ClassStats.Select(kv => new { Name = kv.Key, C = kv.Value }).OrderByDescending(x => x.C.Max)
                .Select(x => new JsonObject().S("name", x.Name).N("count", x.C.Count).N("avg", x.C.Count > 0 ? (long)(x.C.Sum / x.C.Count) : 0).N("max", x.C.Max).S("maxDn", x.C.MaxDn).N("flagged", x.C.Flagged).ToString()).ToArray();
            return "[" + string.Join(",", list) + "]";
        }

        string TrusteesJson()
        {
            var list = E.TrusteeAgg.Values.OrderByDescending(t => t.Bytes).Take(80)
                .Select(t => new JsonObject().S("name", E.ResolveSidName(t.Sid, true)).S("sid", SdParser.SidToString(t.Sid, 0) ?? "").N("bytes", t.Bytes).N("aces", t.Aces).N("objects", t.Objects)
                    .N("avg", t.Aces > 0 ? Math.Round((double)t.Bytes / t.Aces, 1) : 0.0).ToString()).ToArray();
            return "[" + string.Join(",", list) + "]";
        }

        string ChecksJson()
        {
            return "[" + string.Join(",", E.Checks.Select(c => new JsonObject().S("id", c.Id).S("area", c.Area).S("name", c.Name).S("status", c.Status.ToString()).S("detail", c.Detail).S("scope", c.Scope).ToString()).ToArray()) + "]";
        }

        string BaselineJson()
        {
            var b = E.Baseline;
            if (b == null) return "null";
            var tg = b.TopGrowth.Select(r => new JsonObject().S("dn", r.Dn).N("bytes", r.Bytes).N("delta", r.Delta).S("status", r.Status.ToString()).S("domain", r.Domain).ToString()).ToArray();
            return new JsonObject().S("path", b.Path).S("generated", b.Generated).S("target", b.Target).N("compared", b.Map.Count)
                .N("grown", b.Grown).N("shrunk", b.Shrunk).N("new", b.New).N("unchanged", b.Unchanged).N("growthBytes", b.GrowthBytes)
                .Add("topGrowth", "[" + string.Join(",", tg) + "]").ToString();
        }

        public static string LogoDataUri(string logoPath, Action<string> warn)
        {
            if (string.IsNullOrEmpty(logoPath)) return "";
            if (!File.Exists(logoPath)) { if (warn != null) warn("Logo not found: " + logoPath); return ""; }
            string ext = Path.GetExtension(logoPath).ToLowerInvariant();
            string mime;
            switch (ext)
            {
                case ".png": mime = "image/png"; break;
                case ".jpg": case ".jpeg": mime = "image/jpeg"; break;
                case ".gif": mime = "image/gif"; break;
                case ".svg": mime = "image/svg+xml"; break;
                default: if (warn != null) warn("Logo format not supported (" + ext + "); use PNG, JPG, GIF or SVG."); return "";
            }
            try
            {
                var bytes = File.ReadAllBytes(logoPath);
                if (bytes.Length > 1048576) { if (warn != null) warn("Logo larger than 1 MB - skipped to keep the dashboard small."); return ""; }
                return "data:" + mime + ";base64," + Convert.ToBase64String(bytes);
            }
            catch (Exception ex) { if (warn != null) warn("Logo could not be read: " + ex.Message); return ""; }
        }

        public string BuildDataJson(List<ObjectRow> rows)
        {
            int healthy = E.Domains.Sum(d => d.Healthy), warn = E.Domains.Sum(d => d.Warning), crit = E.Domains.Sum(d => d.Critical), limit = E.Domains.Sum(d => d.Limit);
            int unread = E.Domains.Sum(d => d.Unreadable), invalid = E.Domains.Sum(d => d.Invalid), withSacl = E.Domains.Sum(d => d.WithSacl);
            int max = 0; string maxDn = "";
            foreach (var d in E.Domains) if (d.Max > max) { max = d.Max; maxDn = d.MaxDn; }
            int p50 = 0, p95 = 0, p99 = 0;
            if (E.AllSizes.Count > 0)
            {
                var all = E.AllSizes.ToArray(); Array.Sort(all);
                p50 = AuditEngine.Percentile(all, 0.5); p95 = AuditEngine.Percentile(all, 0.95); p99 = AuditEngine.Percentile(all, 0.99);
            }
            int hot = E.Containers.Count(c => (c.InheritableBytes ?? 0) >= S.WarnBytes);
            double duration = Math.Round((DateTime.Now - E.StartTime).TotalSeconds, 1);

            var rn = Branding.ReleaseNotes.Select(r => new JsonObject().S("version", r[0]).S("date", r[1]).S("text", r[2]).ToString()).ToArray();
            var files = E.OutputFiles.Select(f => new JsonObject().S("type", f.Type).S("path", f.Path).ToString()).ToArray();

            string run = new JsonObject()
                .S("tool", Branding.Name).S("binary", Branding.Binary).S("version", Branding.Version).S("classification", Branding.Classification)
                .S("generated", E.Generated.ToString("yyyy-MM-dd HH:mm:ss")).S("generatedBy", AuditEngine.CurrentUser()).S("host", Environment.MachineName)
                .S("psVersion", AuditEngine.RuntimeText()).S("target", E.TargetLabel).S("mode", S.Mode).S("forest", E.Forest != null ? E.Forest.Name : "")
                .Add("partitions", Json.StrArray(S.Partitions)).S("searchBase", S.SearchBase).S("filter", S.LdapFilter).S("credential", S.CredentialLabel)
                .N("pageSize", S.PageSize).N("maxObjects", S.MaxObjects).B("sacl", E.SaclRequested).B("saclFallback", E.SaclFallback)
                .B("ldaps", S.UseLdaps || S.EffectivePort == 636).N("port", S.EffectivePort).N("durationSec", duration).Add("outputFiles", "[" + string.Join(",", files) + "]").B("aceDetail", S.AceDetail)
                .N("rate", duration > 0 ? (long)(E.TotalScanned / duration) : 0)
                .S("title", Branding.Title).S("buildDate", Branding.BuildDate).S("author", Branding.Author).S("team", Branding.Team)
                .S("feedback", Branding.Feedback).S("copyright", Branding.Copyright).S("requirements", Branding.Requirements).S("summary", Branding.Summary)
                .S("logo", LogoDataUri(S.LogoPath, null)).Add("releaseNotes", "[" + string.Join(",", rn) + "]").ToString();

            string thresholds = new JsonObject().N("warnKB", S.WarningKB).N("critKB", S.CriticalKB).N("limitKB", Math.Round(S.LimitBytes / 1024.0, 2)).N("floorKB", S.ReportFloorKB)
                .N("topN", S.TopN).N("hardBytes", Settings.SdLimitBytes).N("warnBytes", S.WarnBytes).N("critBytes", S.CritBytes).N("limitBytes", S.LimitBytes).N("floorBytes", S.FloorBytes)
                .N("userDefaultSdBytes", E.UserDefaultSdBytes).ToString();

            string summary = new JsonObject().N("scanned", E.TotalScanned).N("healthy", healthy).N("warning", warn).N("critical", crit).N("limit", limit)
                .N("unreadable", unread).N("invalid", invalid).N("withSacl", withSacl).N("max", max).S("maxDn", maxDn).N("median", p50).N("p95", p95).N("p99", p99)
                .N("reported", rows.Count).N("containers", E.Containers.Count).N("hotContainers", hot).N("domains", E.Domains.Count).N("trustees", E.TrusteeAgg.Count).ToString();

            string schema = "[" + string.Join(",", E.SchemaDefaults.Select(d => new JsonObject().S("class", d.Class).N("bytes", d.Bytes).N("sddlLength", d.SddlLength).S("method", d.Method).ToString()).ToArray()) + "]";

            string meta = new JsonObject().Add("run", run).Add("thresholds", thresholds).Add("summary", summary).Add("hist", Json.IntArray(E.Hist))
                .Add("domains", DomainsJson()).Add("classes", ClassesJson()).Add("trustees", TrusteesJson()).Add("checks", ChecksJson())
                .Add("schemaDefaults", schema).Add("baseline", BaselineJson()).ToString();

            var sb = new StringBuilder(1024 * 1024);
            sb.Append("{\"meta\":").Append(meta).Append(",\"objects\":[");
            bool first = true;
            foreach (var r in rows) { if (!first) sb.Append(','); first = false; sb.Append(RowJson(r, true)); }
            sb.Append("],\"containers\":[");
            first = true;
            foreach (var c in E.Containers.OrderByDescending(c => c.InheritableBytes ?? 0)) { if (!first) sb.Append(','); first = false; sb.Append(RowJson(c, false)); }
            sb.Append("]}");
            return sb.ToString();
        }

        // ---------------------------------------------------------------- files

        public void WriteSnapshot(List<ObjectRow> rows, string path)
        {
            var sb = new StringBuilder(256 * 1024);
            sb.Append("{\"tool\":").Append(Json.Str(Branding.Name)).Append(",\"version\":").Append(Json.Str(Branding.Version))
              .Append(",\"generated\":").Append(Json.Str(E.Generated.ToString("yyyy-MM-dd HH:mm:ss"))).Append(",\"target\":").Append(Json.Str(E.TargetLabel))
              .Append(",\"warnKB\":").Append(S.WarningKB).Append(",\"critKB\":").Append(S.CriticalKB).Append(",\"floorKB\":").Append(S.ReportFloorKB)
              .Append(",\"scanned\":").Append(E.TotalScanned).Append(",\"objects\":[");
            bool first = true;
            foreach (var r in rows)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append("{\"dn\":").Append(Json.Str(r.Dn)).Append(",\"bytes\":").Append(r.Bytes).Append(",\"status\":").Append(Json.Str(r.Status.ToString())).Append(",\"domain\":").Append(Json.Str(r.Domain)).Append('}');
            }
            sb.Append("]}");
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        }

        static string Csv(object v)
        {
            if (v == null) return "";
            string s = v is double ? ((double)v).ToString(CultureInfo.InvariantCulture) : v.ToString();
            if (s.IndexOfAny(new char[] { '"', ',', '\n', '\r' }) >= 0) s = "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        public void WriteCsv(List<ObjectRow> rows, string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Status,Name,Class,Domain,Partition,DistinguishedName,Bytes,KB,PercentOfLimit,HeadroomBytes,DaclBytes,DaclAces,ExplicitAces,InheritedAces,SaclBytes,SaclAces,InheritableBytes,InheritableAces,EstimatedAcesLeft,InheritanceBlocked,AdminCount,IsContainer,WhenChanged,Owner,GrowthBytes");
            foreach (var r in rows)
            {
                sb.Append(string.Join(",", new string[] {
                    Csv(r.Status.ToString()), Csv(r.Name), Csv(r.Class), Csv(r.Domain), Csv(r.Partition), Csv(r.Dn), Csv(r.Bytes), Csv(Math.Round(r.Bytes / 1024.0, 2)), Csv(r.Percent), Csv(r.Headroom),
                    Csv(r.DaclBytes), Csv(r.DaclAces), Csv(r.Explicit), Csv(r.Inherited), Csv(r.SaclBytes), Csv(r.SaclAces), Csv(r.InheritableBytes), Csv(r.InheritableAces), Csv(r.EstAcesLeft),
                    Csv(r.DaclProtected), Csv(r.AdminCount), Csv(r.IsContainer), Csv(r.WhenChanged), Csv(r.OwnerSid), Csv(r.Delta) })).Append("\r\n");
            }
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        }

        public static string LoadTemplate()
        {
            var asm = Assembly.GetExecutingAssembly();
            using (var s = asm.GetManifestResourceStream("ADACLSizeAudit.Dashboard.html"))
            {
                if (s == null) throw new ApplicationException("The dashboard template resource is missing from the executable (build with /resource:res\\Dashboard.html,ADACLSizeAudit.Dashboard.html).");
                using (var r = new StreamReader(s, Encoding.UTF8)) return r.ReadToEnd();
            }
        }

        public void WriteDashboard(string path, string dataJson)
        {
            string title = Branding.Title + " - " + E.TargetLabel;
            string html = LoadTemplate().Replace("__TITLE__", WebUtility.HtmlEncode(title)).Replace("__DATA__", dataJson);
            File.WriteAllText(path, html, new UTF8Encoding(false));
        }
    }
}
