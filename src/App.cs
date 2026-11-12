// ADACLSizeAudit - App.cs
// Project: ADACLSizeAudit | Author: Jinish Kunjilikkattil | https://adinternalshub.com/ | MIT License
// Entry point. Without a target the Windows Forms front-end opens; with /domain or /forest the audit runs
// headless (console output, exit code 0 none critical / 1 critical / 2 at limit / 3 aborted).
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace ADACLSizeAudit
{
    static class App
    {
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool AttachConsole(int pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool AllocConsole();
        const int ATTACH_PARENT_PROCESS = -1;

        [STAThread]
        static int Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e) { WriteCrash(e.ExceptionObject as Exception); };
            var opts = ParseArgs(args);
            if (opts.ContainsKey("?") || opts.ContainsKey("help") || opts.ContainsKey("h"))
            {
                OpenConsole();
                Console.WriteLine(Usage());
                return 0;
            }

            Settings settings = null;
            string parseError = null;
            try { settings = SettingsFromArgs(opts); }
            catch (Exception ex) { parseError = ex.Message; }

            bool headless = settings != null && parseError == null && !opts.ContainsKey("gui") &&
                            (opts.ContainsKey("domain") || opts.ContainsKey("forest"));
            if (headless) return RunHeadless(settings, opts);

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException += delegate(object s, ThreadExceptionEventArgs e) { WriteCrash(e.Exception); };
            if (parseError != null) MessageBox.Show(parseError + Environment.NewLine + Environment.NewLine + Usage(), Branding.Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            Application.Run(new MainForm(settings ?? new Settings()));
            return 0;
        }

        static int RunHeadless(Settings settings, Dictionary<string, string> opts)
        {
            OpenConsole();
            Console.WriteLine();
            Console.WriteLine("  " + Branding.Name + " " + Branding.Version + " - security descriptor size audit against the 64 KB limit");
            Console.WriteLine("  Classification: " + Branding.Classification + " | read-only | LDAP via System.DirectoryServices.Protocols");
            Console.WriteLine();
            if (opts.ContainsKey("user") && settings.Credential != null && string.IsNullOrEmpty(settings.Credential.Password))
            {
                Console.Write("Password for " + opts["user"] + ": ");
                settings.Credential.Password = ReadPassword();
                Console.WriteLine();
            }
            var engine = new AuditEngine(settings);
            engine.Log += delegate(string level, string text)
            {
                var old = Console.ForegroundColor;
                switch (level) { case "OK": Console.ForegroundColor = ConsoleColor.Green; break; case "WARN": Console.ForegroundColor = ConsoleColor.Yellow; break; case "FAIL": Console.ForegroundColor = ConsoleColor.Red; break; default: Console.ForegroundColor = ConsoleColor.Gray; break; }
                Console.WriteLine("[" + level.PadRight(4) + "] " + text);
                Console.ForegroundColor = old;
            };
            DateTime last = DateTime.MinValue;
            engine.Status += delegate(string text)
            {
                if ((DateTime.Now - last).TotalSeconds >= 2) { Console.WriteLine("       " + text); last = DateTime.Now; }
            };
            Console.CancelKeyPress += delegate(object s, ConsoleCancelEventArgs e) { e.Cancel = true; engine.CancelRequested = true; Console.WriteLine("Cancel requested - writing a partial report."); };
            var result = engine.Run();
            if (result.Success && settings.OpenBrowser && result.HtmlPath != null)
            {
                try { System.Diagnostics.Process.Start(result.HtmlPath); } catch { }
            }
            return result.ExitCode;
        }

        static void OpenConsole()
        {
            try
            {
                if (!AttachConsole(ATTACH_PARENT_PROCESS)) AllocConsole();
                var stdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                Console.SetOut(stdout);
                Console.WriteLine();
            }
            catch { }
        }

        static string ReadPassword()
        {
            var sb = new StringBuilder();
            while (true)
            {
                var k = Console.ReadKey(true);
                if (k.Key == ConsoleKey.Enter) break;
                if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; continue; }
                if (k.KeyChar != '\0') sb.Append(k.KeyChar);
            }
            return sb.ToString();
        }

        public static Dictionary<string, string> ParseArgs(string[] args)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string raw in args)
            {
                if (string.IsNullOrEmpty(raw)) continue;
                string a = raw;
                if (a.StartsWith("--")) a = a.Substring(2); else if (a.StartsWith("/") || a.StartsWith("-")) a = a.Substring(1);
                int i = a.IndexOfAny(new char[] { ':', '=' });
                if (i < 0) d[a] = ""; else d[a.Substring(0, i)] = a.Substring(i + 1).Trim('"');
            }
            return d;
        }

        static int IntOpt(Dictionary<string, string> o, string key, int def)
        {
            string v; int n;
            if (o.TryGetValue(key, out v) && int.TryParse(v, out n)) return n;
            return def;
        }

        public static Settings SettingsFromArgs(Dictionary<string, string> o)
        {
            var s = new Settings();
            string v;
            if (o.TryGetValue("forest", out v) && v.Length > 0) { s.Mode = "Forest"; s.Forest = v.Trim(); }
            if (o.TryGetValue("domain", out v) && v.Length > 0)
            {
                s.Mode = "Domain";
                foreach (string p in v.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)) s.Domains.Add(p.Trim());
            }
            if (o.TryGetValue("server", out v)) s.Server = v.Trim();
            if (o.TryGetValue("map", out v))
                foreach (string pair in v.Split(new char[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = pair.IndexOf('=');
                    if (eq > 0) s.ServerMap[pair.Substring(0, eq).Trim()] = pair.Substring(eq + 1).Trim();
                }
            if (o.TryGetValue("user", out v) && v.Length > 0)
            {
                string user = v, domain = "";
                int bs = v.IndexOf('\\');
                if (bs > 0) { domain = v.Substring(0, bs); user = v.Substring(bs + 1); }
                string pw; o.TryGetValue("password", out pw);
                s.Credential = new NetworkCredential(user, pw ?? "", domain);
                s.CredentialLabel = "explicit credential (" + v + ")";
            }
            if (o.TryGetValue("partitions", out v) && v.Length > 0)
            {
                s.Partitions.Clear();
                foreach (string p in v.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string q = p.Trim();
                    string[] valid = { "Domain", "Configuration", "Schema", "DomainDnsZones", "ForestDnsZones" };
                    bool okp = false;
                    foreach (string x in valid) if (string.Equals(x, q, StringComparison.OrdinalIgnoreCase)) { s.Partitions.Add(x); okp = true; }
                    if (!okp) throw new ApplicationException("Unknown partition '" + q + "'. Valid: Domain, Configuration, Schema, DomainDnsZones, ForestDnsZones.");
                }
            }
            if (o.TryGetValue("searchbase", out v)) s.SearchBase = v.Trim();
            if (o.TryGetValue("filter", out v) && v.Length > 0) s.LdapFilter = v;
            s.WarningKB = IntOpt(o, "warn", s.WarningKB);
            s.CriticalKB = IntOpt(o, "crit", s.CriticalKB);
            s.LimitMarginKB = IntOpt(o, "margin", s.LimitMarginKB);
            s.ReportFloorKB = IntOpt(o, "floor", s.ReportFloorKB);
            s.TopN = IntOpt(o, "top", s.TopN);
            s.PageSize = IntOpt(o, "page", s.PageSize);
            s.MaxObjects = IntOpt(o, "max", s.MaxObjects);
            s.Port = IntOpt(o, "port", 0);
            if (o.ContainsKey("nosacl")) s.IncludeSacl = false;
            if (o.ContainsKey("nodetail")) s.AceDetail = false;
            if (o.ContainsKey("ldaps")) s.UseLdaps = true;
            if (o.TryGetValue("out", out v)) s.OutputFolder = v.Trim();
            if (o.TryGetValue("baseline", out v)) s.BaselinePath = v.Trim();
            if (o.TryGetValue("logo", out v)) s.LogoPath = v.Trim();
            if (o.ContainsKey("nobrowser")) s.OpenBrowser = false;
            if (o.ContainsKey("nocsv")) s.WriteCsv = false;
            return s;
        }

        public static string Usage()
        {
            return Branding.Binary + " [/domain:fqdn[,fqdn2] | /forest:fqdn] [/server:dc-fqdn] [/map:dom=dc;dom2=dc2]" + Environment.NewLine +
                   "    [/user:DOMAIN\\name [/password:***]] [/partitions:Domain,Configuration,Schema,DomainDnsZones,ForestDnsZones]" + Environment.NewLine +
                   "    [/searchbase:DN] [/filter:(ldap)] [/warn:40] [/crit:56] [/margin:1] [/floor:16] [/top:50] [/page:500] [/max:N]" + Environment.NewLine +
                   "    [/nosacl] [/nodetail] [/ldaps] [/port:n] [/out:folder] [/baseline:snapshot.json] [/logo:file.png] [/nobrowser] [/nocsv] [/gui]" + Environment.NewLine +
                   Environment.NewLine +
                   "Without /domain or /forest the Windows Forms front-end opens (switches pre-fill it). Exit codes: 0 none critical," + Environment.NewLine +
                   "1 critical objects, 2 objects at the limit, 3 aborted. " + Branding.Copyright;
        }

        public static void WriteCrash(Exception ex)
        {
            if (ex == null) return;
            string text = Branding.Name + " " + Branding.Version + " crashed at " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + Environment.NewLine +
                          AuditEngine.RuntimeText() + Environment.NewLine + Environment.NewLine + ex.ToString();
            string path = null;
            try
            {
                string folder = Settings.DefaultOutputFolder();
                Directory.CreateDirectory(folder);
                path = Path.Combine(folder, "ADACLSizeAudit_crash.txt");
                File.WriteAllText(path, text, Encoding.UTF8);
            }
            catch { }
            try
            {
                MessageBox.Show("An unexpected error stopped the tool:" + Environment.NewLine + Environment.NewLine + ex.Message +
                    (path != null ? Environment.NewLine + Environment.NewLine + "Details were written to " + path : ""),
                    Branding.Title + " - unexpected error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch { }
        }
    }
}
