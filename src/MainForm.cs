// ADACLSizeAudit - MainForm.cs
// Project: ADACLSizeAudit | Author: Jinish Kunjilikkattil | https://adinternalshub.com/ | MIT License
// Windows Forms front-end: Audit tab (target, thresholds, scope, output), About tab, run bar with progress and log.
// Built on layout panels so it fits any resolution / DPI; the audit runs on a BackgroundWorker.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Windows.Forms;

namespace ADACLSizeAudit
{
    public class MainForm : Form
    {
        readonly Settings _initial;
        readonly Font _bold;
        readonly Font _mono;

        // inputs
        RadioButton _modeDomain, _modeForest;
        TextBox _target, _server, _user, _password, _searchBase, _outFolder, _baseline, _logo;
        CheckBox _useCred, _partDomain, _partConfig, _partSchema, _partDdz, _partFdz, _sacl, _detail, _openWhenDone, _csv;
        NumericUpDown _warn, _crit, _maxObjects;
        Label _credUserLabel, _credPwLabel;
        // run bar
        Button _run, _cancel, _openLast, _openFolder, _close;
        ProgressBar _progress;
        Label _status;
        TextBox _log;
        TabControl _tabs;
        PictureBox _aboutLogo, _headerLogo;
        readonly List<Control> _inputs = new List<Control>();

        BackgroundWorker _worker;
        AuditEngine _engine;
        AuditResult _lastResult;

        public MainForm(Settings initial)
        {
            _initial = initial ?? new Settings();
            _bold = new Font("Segoe UI", 9f, FontStyle.Bold);
            _mono = new Font("Consolas", 8.5f);
            Build();
            ApplySettings(_initial);
            LogLine("INFO", "Ready. " + Branding.Name + " " + Branding.Version + " - " + Branding.Classification + " - " + Branding.Website);
        }

        // ------------------------------------------------------------------ construction helpers

        Label L(string text, bool muted, bool bold)
        {
            var l = new Label { Text = text, AutoSize = true, Margin = new Padding(0, 6, 0, 2) };
            if (muted) l.ForeColor = ToolMark.Muted;
            if (bold) l.Font = _bold;
            return l;
        }
        Label Wrap(string text, bool muted)
        {
            var l = L(text, muted, false);
            l.Dock = DockStyle.Fill;
            l.Margin = new Padding(0, 4, 0, 4);
            l.MinimumSize = new Size(0, text.Length > 70 ? 32 : 16);   // room for two lines before the first layout pass settles
            return l;
        }
        TextBox T() { var t = new TextBox { Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 4) }; _inputs.Add(t); return t; }
        CheckBox C(string text, bool chk) { var c = new CheckBox { Text = text, AutoSize = true, Checked = chk, Margin = new Padding(0, 3, 12, 3) }; _inputs.Add(c); return c; }
        NumericUpDown Num(int min, int max, int val)
        {
            var n = new NumericUpDown { Minimum = min, Maximum = max, Value = Math.Max(min, Math.Min(max, val)), Width = 90, ThousandsSeparator = true, Margin = new Padding(0, 2, 0, 4) };
            _inputs.Add(n); return n;
        }
        Button B(string text, EventHandler onClick, bool primary)
        {
            var b = new Button { Text = text, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(8, 3, 8, 3), Margin = new Padding(0, 0, 8, 0), MinimumSize = new Size(90, 30) };
            if (primary) { b.BackColor = ToolMark.Accent; b.ForeColor = Color.White; b.FlatStyle = FlatStyle.Flat; b.FlatAppearance.BorderSize = 0; b.Font = _bold; }
            b.Click += onClick;
            return b;
        }
        static TableLayoutPanel Grid(int cols)
        {
            var t = new TableLayoutPanel { ColumnCount = cols, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Top, Padding = new Padding(10, 6, 10, 8) };
            for (int i = 0; i < cols; i++) t.ColumnStyles.Add(new ColumnStyle(i == 0 ? SizeType.Percent : SizeType.AutoSize, i == 0 ? 100f : 0f));
            return t;
        }
        static GroupBox Group(string title, Control content)
        {
            var g = new GroupBox { Text = title, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Fill, Margin = new Padding(6), BackColor = Color.White, Padding = new Padding(4, 4, 4, 6) };
            g.Controls.Add(content);
            return g;
        }
        static void Row(TableLayoutPanel t, params Control[] cells)
        {
            int row = t.RowCount++;
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            for (int i = 0; i < cells.Length; i++) if (cells[i] != null) t.Controls.Add(cells[i], i, row);
        }
        static void Span(TableLayoutPanel t, Control c)
        {
            int row = t.RowCount++;
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.Controls.Add(c, 0, row);
            t.SetColumnSpan(c, t.ColumnCount);
        }
        static FlowLayoutPanel Flow(params Control[] items)
        {
            var f = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, FlowDirection = FlowDirection.LeftToRight, WrapContents = true, Dock = DockStyle.Fill, Margin = new Padding(0) };
            foreach (var c in items) f.Controls.Add(c);
            return f;
        }
        static TableLayoutPanel WithButton(Control main, Button btn)
        {
            var t = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Fill, Margin = new Padding(0) };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            btn.Margin = new Padding(6, 2, 0, 4); btn.MinimumSize = new Size(74, 25);
            t.Controls.Add(main, 0, 0); t.Controls.Add(btn, 1, 0);
            return t;
        }

        // ------------------------------------------------------------------ build

        void Build()
        {
            Text = Branding.Title + "  -  " + Branding.Name + " " + Branding.Version;
            Font = new Font("Segoe UI", 9f);
            AutoScaleMode = AutoScaleMode.Font;
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(900, 760);
            Size = new Size(980, 900);
            BackColor = ToolMark.Canvas;
            var ico = ToolMark.MakeIcon(); if (ico != null) Icon = ico;
            FormClosing += MainForm_FormClosing;

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(10, 8, 10, 8) };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Controls.Add(root);

            // header
            var head = new TableLayoutPanel { ColumnCount = 3, AutoSize = true, Dock = DockStyle.Top, Margin = new Padding(0, 0, 0, 6) };
            head.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            head.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            head.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            _headerLogo = new PictureBox { Size = new Size(36, 36), SizeMode = PictureBoxSizeMode.Zoom, Margin = new Padding(4, 2, 10, 2) };
            _headerLogo.Image = ToolMark.LoadLogoOrMark(_initial.LogoPath, 36, null);
            head.Controls.Add(_headerLogo, 0, 0);
            head.SetRowSpan(_headerLogo, 2);
            var title = new Label { Text = Branding.Title, AutoSize = true, Font = new Font("Segoe UI", 12f, FontStyle.Bold), Margin = new Padding(0, 2, 0, 0) };
            head.Controls.Add(title, 1, 0);
            head.Controls.Add(L("Security descriptor size audit against the 64 KB limit. Reads over LDAP, measures the binary size, explains it. Read-only.", true, false), 1, 1);
            var ver = new Label { Text = Branding.Version + "  |  " + Branding.Classification, AutoSize = true, ForeColor = ToolMark.Muted, Margin = new Padding(0, 6, 4, 0), TextAlign = ContentAlignment.TopRight };
            head.Controls.Add(ver, 2, 0);
            root.Controls.Add(head, 0, 0);

            // tabs
            _tabs = new TabControl { Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 6) };
            var pageAudit = new TabPage("  Audit  ") { BackColor = ToolMark.Canvas, Padding = new Padding(2), AutoScroll = true };
            var pageAbout = new TabPage("  About  ") { BackColor = Color.White, AutoScroll = true, Padding = new Padding(2) };
            _tabs.TabPages.Add(pageAudit); _tabs.TabPages.Add(pageAbout);
            root.Controls.Add(_tabs, 0, 1);
            BuildAuditPage(pageAudit);
            BuildAboutPage(pageAbout);

            // bottom: run bar + progress + status + log
            var bottom = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Dock = DockStyle.Top, Margin = new Padding(0) };
            _run = B("Run audit", delegate { StartRun(); }, true);
            _cancel = B("Cancel", delegate { RequestCancel(); }, false); _cancel.Enabled = false;
            _openLast = B("Open last dashboard", delegate { OpenLast(); }, false); _openLast.Enabled = false;
            _openFolder = B("Open report folder", delegate { OpenFolder(); }, false);
            _close = B("Close", delegate { Close(); }, false); _close.Margin = new Padding(0);
            var bar = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 6) };
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            var left = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Margin = new Padding(0) };
            left.Controls.Add(_run); left.Controls.Add(_cancel); left.Controls.Add(_openLast); left.Controls.Add(_openFolder);
            bar.Controls.Add(left, 0, 0); bar.Controls.Add(_close, 1, 0);
            bottom.RowStyles.Add(new RowStyle(SizeType.AutoSize)); bottom.Controls.Add(bar, 0, 0);
            _progress = new ProgressBar { Dock = DockStyle.Fill, Height = 8, Style = ProgressBarStyle.Continuous, Margin = new Padding(0, 0, 0, 4) };
            bottom.RowStyles.Add(new RowStyle(SizeType.AutoSize)); bottom.Controls.Add(_progress, 0, 1);
            _status = new Label { Text = "Ready.", AutoSize = false, Dock = DockStyle.Fill, Height = 18, AutoEllipsis = true, Margin = new Padding(0, 0, 0, 4) };
            bottom.RowStyles.Add(new RowStyle(SizeType.AutoSize)); bottom.Controls.Add(_status, 0, 2);
            _log = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, WordWrap = false, Font = _mono, BackColor = Color.White, Dock = DockStyle.Fill, Height = 150, Margin = new Padding(0) };
            bottom.RowStyles.Add(new RowStyle(SizeType.Absolute, 150f)); bottom.Controls.Add(_log, 0, 3);
            root.Controls.Add(bottom, 0, 2);
            AcceptButton = _run;
        }

        void BuildAuditPage(TabPage page)
        {
            var grid = new TableLayoutPanel { ColumnCount = 2, RowCount = 2, Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(0) };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));
            grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            page.Controls.Add(grid);

            // ---- target
            var t = Grid(1);
            _modeDomain = new RadioButton { Text = "Domain", AutoSize = true, Checked = true, Margin = new Padding(0, 2, 16, 2) };
            _modeForest = new RadioButton { Text = "Forest (all domains)", AutoSize = true, Margin = new Padding(0, 2, 0, 2) };
            _inputs.Add(_modeDomain); _inputs.Add(_modeForest);
            Span(t, Flow(_modeDomain, _modeForest));
            Span(t, L("DNS name", false, false));
            _target = T(); Span(t, _target);
            Span(t, L("Preferred domain controller (optional, FQDN)", false, false));
            _server = T(); Span(t, _server);
            _useCred = C("Use alternate credentials", false);
            _useCred.CheckedChanged += delegate { ToggleCred(); };
            Span(t, _useCred);
            var cred = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0) };
            cred.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f)); cred.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));
            cred.RowStyles.Add(new RowStyle(SizeType.AutoSize)); cred.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _credUserLabel = L("User (DOMAIN\\name)", true, false); _credPwLabel = L("Password", true, false);
            _user = T(); _user.Margin = new Padding(0, 2, 8, 4); _password = T(); _password.UseSystemPasswordChar = true;
            cred.Controls.Add(_credUserLabel, 0, 0); cred.Controls.Add(_credPwLabel, 1, 0); cred.Controls.Add(_user, 0, 1); cred.Controls.Add(_password, 1, 1);
            Span(t, cred);
            Span(t, Wrap("The tool binds only to the name you enter (or the preferred DC); the logon domain is never used implicitly and trusts are not enumerated.", true));
            grid.Controls.Add(Group("Target", t), 0, 0);

            // ---- thresholds
            var th = Grid(2);
            _warn = Num(1, 62, _initial.WarningKB);
            Row(th, L("Report objects at or above (KB)", false, false), _warn);
            _crit = Num(2, 62, _initial.CriticalKB);
            Row(th, L("Critical at or above (KB)", false, false), _crit);
            var lim = L("64 KB  (65,536 bytes)", false, true); lim.ForeColor = ToolMark.Limit;
            Row(th, L("Hard limit", false, false), lim);
            Span(th, Wrap("Writes that would push an object past 64 KB fail and inheritance stops propagating to it. Objects within " + _initial.LimitMarginKB + " KB of the limit are reported as \"At limit\".", true));
            Span(th, Wrap("Default: report at 40 KB, critical at 56 KB.", true));
            grid.Controls.Add(Group("Thresholds", th), 1, 0);

            // ---- scope
            var sc = Grid(1);
            Span(sc, L("Partitions", false, false));
            _partDomain = C("Domain", true); _partConfig = C("Configuration", false); _partSchema = C("Schema", false); _partDdz = C("DomainDnsZones", false); _partFdz = C("ForestDnsZones", false);
            Span(sc, Flow(_partDomain, _partConfig, _partSchema, _partDdz, _partFdz));
            Span(sc, L("Search base (optional DN, domain partition only)", false, false));
            _searchBase = T(); Span(sc, _searchBase);
            Span(sc, L("Sample only the first N objects per partition (0 = all)", false, false));
            _maxObjects = Num(0, 50000000, _initial.MaxObjects); _maxObjects.Width = 120;
            _sacl = C("Include SACL", true); _detail = C("ACE detail", true);
            _sacl.Margin = new Padding(16, 5, 12, 3);
            Span(sc, Flow(_maxObjects, _sacl, _detail));
            Span(sc, Wrap("ACE detail explains flagged objects and containers (inheritance, trustees); switch it off for a size-only run on very large domains.", true));
            grid.Controls.Add(Group("Scope", sc), 0, 1);

            // ---- output
            var ou = Grid(1);
            Span(ou, L("Report folder", false, false));
            _outFolder = T();
            Span(ou, WithButton(_outFolder, B("Browse", delegate { PickFolder(); }, false)));
            Span(ou, L("Baseline snapshot from a previous run (optional JSON)", false, false));
            _baseline = T();
            Span(ou, WithButton(_baseline, B("Browse", delegate { PickFile(_baseline, "Audit snapshot (*.json)|*.json|All files (*.*)|*.*", "Select the JSON snapshot of a previous run"); }, false)));
            Span(ou, L("Corporate logo for window and dashboard (optional PNG/JPG/GIF/SVG)", false, false));
            _logo = T();
            Span(ou, WithButton(_logo, B("Browse", delegate { PickFile(_logo, "Images (*.png;*.jpg;*.jpeg;*.gif;*.svg)|*.png;*.jpg;*.jpeg;*.gif;*.svg|All files (*.*)|*.*", "Select the logo file"); }, false)));
            _openWhenDone = C("Open the dashboard when finished", true); _csv = C("Also write the CSV of listed objects", true);
            Span(ou, _openWhenDone); Span(ou, _csv);
            Span(ou, Wrap("Every run also writes a JSON snapshot (next baseline) and a run log.", true));
            grid.Controls.Add(Group("Output", ou), 1, 1);
            ToggleCred();
        }

        void BuildAboutPage(TabPage page)
        {
            var t = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Top, Padding = new Padding(16, 12, 16, 12), BackColor = Color.White };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120f));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            page.Controls.Add(t);

            var headRow = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 10) };
            headRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); headRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            _aboutLogo = new PictureBox { Size = new Size(56, 56), SizeMode = PictureBoxSizeMode.Zoom, Margin = new Padding(0, 0, 14, 0) };
            _aboutLogo.Image = ToolMark.LoadLogoOrMark(_initial.LogoPath, 56, null);
            headRow.Controls.Add(_aboutLogo, 0, 0); headRow.SetRowSpan(_aboutLogo, 2);
            headRow.Controls.Add(new Label { Text = Branding.Name + " " + Branding.Version, AutoSize = true, Font = new Font("Segoe UI", 13f, FontStyle.Bold), Margin = new Padding(0, 4, 0, 0) }, 1, 0);
            headRow.Controls.Add(L(Branding.Title + "  -  " + Branding.Classification + "  -  build " + Branding.BuildDate, true, false), 1, 1);
            Span(t, headRow);

            Span(t, L("What this tool does", false, true));
            Span(t, Wrap(Branding.Summary, false));
            Span(t, L("How it measures", false, true));
            Span(t, Wrap("Binds over LDAP (System.DirectoryServices.Protocols) to the domain controller you name with signing and sealing or LDAPS, verifies the required server controls, reads the raw nTSecurityDescriptor of every object with the security-descriptor-flags control and measures its binary length - the value the 64 KB limit applies to. The header of every descriptor is parsed; the individual ACEs of flagged objects and containers are walked to attribute bytes to inheritance, ACE type and trustee. The domain head, well-known containers, AdminSDHolder and the schema default descriptors are read separately.", false));
            Span(t, L("Details", false, true));
            Row(t, L("Author", true, false), Wrap(Branding.Author, false));
            Row(t, L("Team", true, false), Wrap(Branding.Team, false));
            Row(t, L("License", true, false), Wrap(Branding.Classification, false));
            Row(t, L("Requirements", true, false), Wrap(Branding.Requirements, false));
            Row(t, L("Dependencies", true, false), Wrap("None - single executable, no PowerShell modules, no RSAT, no WinRM, no external web resources in the dashboard.", false));
            var siteLink = new LinkLabel { Text = Branding.Website, AutoSize = true, Margin = new Padding(0, 6, 0, 2), LinkColor = ToolMark.Accent, ActiveLinkColor = ToolMark.Accent, VisitedLinkColor = ToolMark.Accent };
            siteLink.LinkClicked += delegate { OpenUrl(Branding.Website); };
            Row(t, L("Website", true, false), siteLink);
            var repoLink = new LinkLabel { Text = Branding.Project, AutoSize = true, Margin = new Padding(0, 2, 0, 2), LinkColor = ToolMark.Accent, ActiveLinkColor = ToolMark.Accent, VisitedLinkColor = ToolMark.Accent };
            repoLink.LinkClicked += delegate { OpenUrl(Branding.Project); };
            Row(t, L("Project", true, false), repoLink);

            var btns = Flow(B("Visit adinternalshub.com", delegate { OpenUrl(Branding.Website); }, true),
                            B("Report an issue", delegate { OpenUrl(Branding.Project + "/issues"); }, false),
                            B("Copy version details", delegate { CopyVersion(); }, false),
                            B("Command-line switches", delegate { MessageBox.Show(this, App.Usage(), Branding.Title + " - command line", MessageBoxButtons.OK, MessageBoxIcon.Information); }, false));
            btns.Margin = new Padding(0, 12, 0, 8);
            Span(t, btns);
            var cp = Wrap(Branding.Copyright, true);
            cp.Margin = new Padding(0, 10, 0, 0);
            Span(t, cp);
        }

        // ------------------------------------------------------------------ settings <-> form

        void ApplySettings(Settings s)
        {
            if (s.Mode == "Forest") { _modeForest.Checked = true; _target.Text = s.Forest; }
            else { _modeDomain.Checked = true; _target.Text = s.Domains.Count > 0 ? string.Join(",", s.Domains.ToArray()) : ""; }
            _server.Text = s.Server ?? "";
            if (s.Credential != null)
            {
                _useCred.Checked = true;
                _user.Text = string.IsNullOrEmpty(s.Credential.Domain) ? s.Credential.UserName : s.Credential.Domain + "\\" + s.Credential.UserName;
                _password.Text = s.Credential.Password ?? "";
            }
            _partDomain.Checked = s.Partitions.Contains("Domain"); _partConfig.Checked = s.Partitions.Contains("Configuration"); _partSchema.Checked = s.Partitions.Contains("Schema");
            _partDdz.Checked = s.Partitions.Contains("DomainDnsZones"); _partFdz.Checked = s.Partitions.Contains("ForestDnsZones");
            _searchBase.Text = s.SearchBase ?? "";
            _sacl.Checked = s.IncludeSacl; _detail.Checked = s.AceDetail;
            _outFolder.Text = string.IsNullOrEmpty(s.OutputFolder) ? Settings.DefaultOutputFolder() : s.OutputFolder;
            _baseline.Text = s.BaselinePath ?? ""; _logo.Text = s.LogoPath ?? "";
            _openWhenDone.Checked = s.OpenBrowser; _csv.Checked = s.WriteCsv;
            ToggleCred();
        }

        Settings ReadSettings()
        {
            var s = new Settings();
            string name = _target.Text.Trim().TrimEnd('.');
            if (_modeForest.Checked) { s.Mode = "Forest"; s.Forest = name; }
            else
            {
                s.Mode = "Domain";
                foreach (string p in name.Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)) s.Domains.Add(p.Trim().TrimEnd('.'));
            }
            s.Server = _server.Text.Trim();
            if (_useCred.Checked)
            {
                string u = _user.Text.Trim();
                if (u.Length == 0) throw new ApplicationException("Enter the user name for the alternate credential (DOMAIN\\name) or untick the option.");
                string user = u, domain = "";
                int bs = u.IndexOf('\\'); if (bs > 0) { domain = u.Substring(0, bs); user = u.Substring(bs + 1); }
                s.Credential = new NetworkCredential(user, _password.Text, domain);
                s.CredentialLabel = "explicit credential (" + u + ")";
            }
            s.Partitions.Clear();
            if (_partDomain.Checked) s.Partitions.Add("Domain");
            if (_partConfig.Checked) s.Partitions.Add("Configuration");
            if (_partSchema.Checked) s.Partitions.Add("Schema");
            if (_partDdz.Checked) s.Partitions.Add("DomainDnsZones");
            if (_partFdz.Checked) s.Partitions.Add("ForestDnsZones");
            s.SearchBase = _searchBase.Text.Trim();
            s.WarningKB = (int)_warn.Value; s.CriticalKB = (int)_crit.Value; s.MaxObjects = (int)_maxObjects.Value;
            s.LimitMarginKB = _initial.LimitMarginKB; s.ReportFloorKB = _initial.ReportFloorKB; s.TopN = _initial.TopN; s.PageSize = _initial.PageSize;
            s.LdapFilter = _initial.LdapFilter; s.UseLdaps = _initial.UseLdaps; s.Port = _initial.Port;
            foreach (var kv in _initial.ServerMap) s.ServerMap[kv.Key] = kv.Value;
            s.IncludeSacl = _sacl.Checked; s.AceDetail = _detail.Checked;
            s.OutputFolder = _outFolder.Text.Trim(); s.BaselinePath = _baseline.Text.Trim(); s.LogoPath = _logo.Text.Trim();
            s.OpenBrowser = _openWhenDone.Checked; s.WriteCsv = _csv.Checked;
            if (name.Length == 0) throw new ApplicationException("Enter the domain or forest DNS name.");
            foreach (char ch in name) if (!(char.IsLetterOrDigit(ch) || ch == '.' || ch == '-' || ch == ',' || ch == ';' || ch == ' ')) throw new ApplicationException("The target must be a DNS name such as child.corp.net.");
            string v = s.Validate();
            if (v != null) throw new ApplicationException(v);
            return s;
        }

        void ToggleCred()
        {
            bool on = _useCred.Checked;
            _user.Enabled = on; _password.Enabled = on; _credUserLabel.Enabled = on; _credPwLabel.Enabled = on;
        }

        // ------------------------------------------------------------------ actions

        void PickFolder()
        {
            using (var dlg = new FolderBrowserDialog { Description = "Folder for the report files", ShowNewFolderButton = true })
            {
                if (Directory.Exists(_outFolder.Text)) dlg.SelectedPath = _outFolder.Text;
                if (dlg.ShowDialog(this) == DialogResult.OK) _outFolder.Text = dlg.SelectedPath;
            }
        }

        void PickFile(TextBox target, string filter, string title)
        {
            using (var dlg = new OpenFileDialog { Filter = filter, Title = title })
            {
                if (Directory.Exists(_outFolder.Text)) dlg.InitialDirectory = _outFolder.Text;
                if (dlg.ShowDialog(this) == DialogResult.OK) target.Text = dlg.FileName;
            }
        }

        void OpenLast()
        {
            if (_lastResult != null && _lastResult.HtmlPath != null && File.Exists(_lastResult.HtmlPath))
            { try { Process.Start(_lastResult.HtmlPath); } catch (Exception ex) { LogLine("WARN", "Could not open the dashboard: " + ex.Message); } }
        }

        void OpenFolder()
        {
            string f = _outFolder.Text.Trim();
            try { if (!Directory.Exists(f)) Directory.CreateDirectory(f); Process.Start("explorer.exe", "\"" + f + "\""); }
            catch (Exception ex) { LogLine("WARN", "Could not open the folder: " + ex.Message); }
        }

        void OpenUrl(string url)
        {
            try { Process.Start(url); }
            catch (Exception ex) { MessageBox.Show(this, "Could not open " + url + Environment.NewLine + ex.Message, Branding.Title, MessageBoxButtons.OK, MessageBoxIcon.Information); }
        }

        static string VersionText()
        {
            return Branding.Name + " " + Branding.Version + " (build " + Branding.BuildDate + ")" + Environment.NewLine +
                   "Classification: " + Branding.Classification + Environment.NewLine +
                   "Author: " + Branding.Author + ", " + Branding.Team + Environment.NewLine +
                   "Host: " + Environment.MachineName + " | User: " + AuditEngine.CurrentUser() + Environment.NewLine +
                   AuditEngine.RuntimeText();
        }

        void CopyVersion()
        {
            try { Clipboard.SetText(VersionText()); LogLine("INFO", "Version details copied to the clipboard."); }
            catch (Exception ex) { LogLine("WARN", "Clipboard not available: " + ex.Message); }
        }

        void LogLine(string level, string text)
        {
            _log.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + level.PadRight(5) + " " + text + Environment.NewLine);
        }

        // ------------------------------------------------------------------ run / cancel

        void SetBusy(bool busy)
        {
            foreach (var c in _inputs) c.Enabled = !busy;
            if (!busy) ToggleCred();
            _run.Enabled = !busy; _cancel.Enabled = busy; _close.Enabled = !busy;
            if (busy) { _progress.Style = ProgressBarStyle.Marquee; _progress.MarqueeAnimationSpeed = 30; }
            else { _progress.Style = ProgressBarStyle.Continuous; _progress.Value = 0; }
        }

        void StartRun()
        {
            Settings s;
            try { s = ReadSettings(); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "Check the settings", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }

            _tabs.SelectedIndex = 0;
            _log.Clear();
            _status.Text = "Starting...";
            _openLast.Enabled = false;
            _lastResult = null;
            _headerLogo.Image = ToolMark.LoadLogoOrMark(s.LogoPath, 36, null);
            _aboutLogo.Image = ToolMark.LoadLogoOrMark(s.LogoPath, 56, null);
            SetBusy(true);

            _engine = new AuditEngine(s);
            _worker = new BackgroundWorker { WorkerReportsProgress = true };
            var w = _worker;
            _engine.Log += delegate(string level, string text) { try { w.ReportProgress(0, new string[] { "log", level, text }); } catch { } };
            _engine.Status += delegate(string text) { try { w.ReportProgress(0, new string[] { "status", "", text }); } catch { } };
            w.DoWork += delegate(object sender, DoWorkEventArgs e) { e.Result = _engine.Run(); };
            w.ProgressChanged += delegate(object sender, ProgressChangedEventArgs e)
            {
                var m = e.UserState as string[];
                if (m == null) return;
                if (m[0] == "log") LogLine(m[1], m[2]); else _status.Text = m[2];
            };
            w.RunWorkerCompleted += delegate(object sender, RunWorkerCompletedEventArgs e)
            {
                SetBusy(false);
                var r = e.Error != null ? new AuditResult { Success = false, Message = "Audit aborted: " + e.Error.Message } : e.Result as AuditResult;
                _lastResult = r;
                if (r != null && r.Success)
                {
                    _openLast.Enabled = true;
                    _progress.Value = 100;
                    _status.Text = (r.Cancelled ? "Cancelled - partial report written. " : "") + r.Message;
                }
                else
                {
                    string msg = r != null && !string.IsNullOrEmpty(r.Message) ? r.Message : "Audit failed.";
                    _status.Text = msg;
                    MessageBox.Show(this, msg, "Audit failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };
            w.RunWorkerAsync();
        }

        void RequestCancel()
        {
            if (_engine == null) return;
            _engine.CancelRequested = true;
            _cancel.Enabled = false;
            LogLine("WARN", "Cancel requested - finishing the current page and writing a partial report.");
        }

        void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (_worker != null && _worker.IsBusy)
            {
                RequestCancel();
                e.Cancel = true;
                LogLine("WARN", "Close requested - cancelling the running audit first; close again when it has finished.");
            }
        }
    }
}
