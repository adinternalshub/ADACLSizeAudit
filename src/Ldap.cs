// ADACLSizeAudit - Ldap.cs
// Project: ADACLSizeAudit | Author: Jinish Kunjilikkattil | https://adinternalshub.com/ | MIT License
// LDAP layer on System.DirectoryServices.Protocols: explicit targets only, signing/sealing or LDAPS,
// paged searches with retry and SACL fallback. No ActiveDirectory module, no WinRM.
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using System.Threading;

namespace ADACLSizeAudit
{
    public class LdapSession : IDisposable
    {
        public LdapConnection Connection;
        public string Target; public int Port; public string AuthMode;

        public const string SdFlagsOid = "1.2.840.113556.1.4.801";
        public const string PagingOid = "1.2.840.113556.1.4.319";
        public const string DomainScopeOid = "1.2.840.113556.1.4.1339";

        /// <summary>Opens and binds to an explicit target (DC FQDN or domain DNS name; the latter goes through the DC locator).</summary>
        public static LdapSession Open(string target, int port, bool ssl, NetworkCredential cred)
        {
            var id = new LdapDirectoryIdentifier(target, port, false, false);
            var conn = new LdapConnection(id);
            conn.SessionOptions.ProtocolVersion = 3;
            conn.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            conn.Timeout = TimeSpan.FromMinutes(5);
            conn.AutoBind = false;
            conn.AuthType = AuthType.Negotiate;
            if (ssl || port == 636) conn.SessionOptions.SecureSocketLayer = true;
            else { conn.SessionOptions.Signing = true; conn.SessionOptions.Sealing = true; }

            string authMode = "current session identity";
            if (cred != null)
            {
                conn.Credential = cred;
                authMode = "explicit credential (" + (string.IsNullOrEmpty(cred.Domain) ? cred.UserName : cred.Domain + "\\" + cred.UserName) + ")";
            }
            try { conn.Bind(); }
            catch (LdapException ex)
            {
                conn.Dispose();
                string hint;
                switch (ex.ErrorCode)
                {
                    case 49: hint = "invalid credentials or the account is not permitted to bind"; break;
                    case 81: hint = "server unavailable (name resolution, firewall, LDAP port)"; break;
                    case 8: hint = "server requires signing/sealing or LDAPS"; break;
                    default: hint = ex.Message; break;
                }
                throw new ApplicationException(string.Format("LDAP bind to {0}:{1} failed ({2}): {3}", target, port, ex.ErrorCode, hint));
            }
            catch (Exception ex)
            {
                conn.Dispose();
                throw new ApplicationException(string.Format("LDAP bind to {0}:{1} failed: {2}", target, port, ex.Message));
            }
            return new LdapSession { Connection = conn, Target = target, Port = port, AuthMode = authMode };
        }

        public void Dispose()
        {
            if (Connection != null) { try { Connection.Dispose(); } catch { } Connection = null; }
        }
    }

    public class RootDse
    {
        public string DefaultNamingContext = ""; public string RootDomainNamingContext = ""; public string ConfigurationNamingContext = "";
        public string SchemaNamingContext = ""; public string DnsHostName = ""; public string ServerName = ""; public string DomainFunctionality = "";
        public string ForestFunctionality = ""; public List<string> SupportedControl = new List<string>(); public List<string> NamingContexts = new List<string>();

        public static RootDse Read(LdapConnection conn)
        {
            var attrs = new string[] { "defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext", "schemaNamingContext",
                "namingContexts", "dnsHostName", "serverName", "supportedControl", "domainFunctionality", "forestFunctionality" };
            var e = LdapUtil.BaseRead(conn, null, attrs, 0);
            if (e == null) throw new ApplicationException("RootDSE could not be read.");
            var r = new RootDse();
            r.DefaultNamingContext = LdapUtil.GetString(e, "defaultNamingContext") ?? "";
            r.RootDomainNamingContext = LdapUtil.GetString(e, "rootDomainNamingContext") ?? "";
            r.ConfigurationNamingContext = LdapUtil.GetString(e, "configurationNamingContext") ?? "";
            r.SchemaNamingContext = LdapUtil.GetString(e, "schemaNamingContext") ?? "";
            r.DnsHostName = LdapUtil.GetString(e, "dnsHostName") ?? "";
            r.ServerName = LdapUtil.GetString(e, "serverName") ?? "";
            r.DomainFunctionality = LdapUtil.GetString(e, "domainFunctionality") ?? "";
            r.ForestFunctionality = LdapUtil.GetString(e, "forestFunctionality") ?? "";
            r.SupportedControl = LdapUtil.GetStrings(e, "supportedControl");
            r.NamingContexts = LdapUtil.GetStrings(e, "namingContexts");
            return r;
        }
    }

    /// <summary>Paged search cursor. Call NextPage() until Done is true.</summary>
    public class PagedSearch
    {
        readonly LdapConnection _conn;
        readonly SearchRequest _req;
        readonly PageResultRequestControl _pager;
        public int SdFlags; public bool Done; public int Pages; public int Retries; public int Entries;
        public bool SaclDropped;
        public List<string> Errors = new List<string>();

        public PagedSearch(LdapConnection conn, string baseDn, string filter, SearchScope scope, string[] attrs, int pageSize, int sdFlags, bool domainScope)
        {
            _conn = conn;
            _req = new SearchRequest(baseDn, filter, scope, attrs);
            _pager = new PageResultRequestControl(pageSize);
            _pager.IsCritical = true;
            _req.Controls.Add(_pager);
            SdFlags = sdFlags;
            if (sdFlags > 0) _req.Controls.Add(new SecurityDescriptorFlagControl((SecurityMasks)sdFlags));
            if (domainScope) _req.Controls.Add(new DomainScopeControl());
        }

        public List<SearchResultEntry> NextPage()
        {
            var empty = new List<SearchResultEntry>();
            if (Done) return empty;
            SearchResponse resp = null;
            int attempt = 0;
            while (resp == null)
            {
                attempt++;
                try
                {
                    resp = (SearchResponse)_conn.SendRequest(_req);
                }
                catch (DirectoryOperationException ex)
                {
                    ResultCode? rc = null;
                    if (ex.Response != null) rc = ex.Response.ResultCode;
                    if (rc == ResultCode.InsufficientAccessRights && (SdFlags & 8) != 0 && !SaclDropped)
                    {
                        // the account may not read the SACL: retry the same page without it
                        SaclDropped = true;
                        SdFlags = SdFlags & 7;
                        for (int i = _req.Controls.Count - 1; i >= 0; i--)
                            if (_req.Controls[i] is SecurityDescriptorFlagControl) _req.Controls.RemoveAt(i);
                        _req.Controls.Add(new SecurityDescriptorFlagControl((SecurityMasks)SdFlags));
                        Errors.Add("SACL not readable with this account - continuing with owner, group and DACL only.");
                        continue;
                    }
                    if (rc == ResultCode.SizeLimitExceeded && ex.Response is SearchResponse)
                    {
                        resp = (SearchResponse)ex.Response;
                        Errors.Add("Server size limit reached; partial page accepted.");
                        break;
                    }
                    Errors.Add(string.Format("Directory operation failed ({0}): {1}", rc.HasValue ? rc.Value.ToString() : "n/a", ex.Message));
                    Done = true;
                    return empty;
                }
                catch (LdapException ex)
                {
                    Retries++;
                    if (attempt >= 3)
                    {
                        Errors.Add(string.Format("LDAP error {0} after {1} attempts: {2}", ex.ErrorCode, attempt, ex.Message));
                        Done = true;
                        return empty;
                    }
                    Thread.Sleep(2000 * attempt);
                }
                catch (Exception ex)
                {
                    Errors.Add("Unexpected error: " + ex.Message);
                    Done = true;
                    return empty;
                }
            }

            Pages++;
            Entries += resp.Entries.Count;
            byte[] cookie = null;
            foreach (DirectoryControl c in resp.Controls)
            {
                var prc = c as PageResultResponseControl;
                if (prc != null) cookie = prc.Cookie;
            }
            if (cookie == null || cookie.Length == 0) Done = true; else _pager.Cookie = cookie;

            var list = new List<SearchResultEntry>(resp.Entries.Count);
            foreach (SearchResultEntry e in resp.Entries) list.Add(e);
            return list;
        }
    }

    public static class LdapUtil
    {
        public static string GetString(SearchResultEntry e, string name)
        {
            if (e == null || !e.Attributes.Contains(name)) return null;
            var vals = e.Attributes[name].GetValues(typeof(string));
            if (vals == null || vals.Length == 0) return null;
            return vals[0] as string;
        }

        public static List<string> GetStrings(SearchResultEntry e, string name)
        {
            var list = new List<string>();
            if (e == null || !e.Attributes.Contains(name)) return list;
            foreach (object o in e.Attributes[name].GetValues(typeof(string))) list.Add(o as string);
            return list;
        }

        public static byte[] GetBytes(SearchResultEntry e, string name)
        {
            if (e == null || !e.Attributes.Contains(name)) return null;
            var vals = e.Attributes[name].GetValues(typeof(byte[]));
            if (vals == null || vals.Length == 0) return null;
            return vals[0] as byte[];
        }

        /// <summary>Reads one object (scope Base). Returns null when it does not exist on this DC.</summary>
        public static SearchResultEntry BaseRead(LdapConnection conn, string dn, string[] attrs, int sdFlags)
        {
            var req = new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, attrs);
            if (sdFlags > 0) req.Controls.Add(new SecurityDescriptorFlagControl((SecurityMasks)sdFlags));
            SearchResponse resp;
            try { resp = (SearchResponse)conn.SendRequest(req); }
            catch (DirectoryOperationException ex)
            {
                if (ex.Response != null)
                {
                    var rc = ex.Response.ResultCode;
                    if (rc == ResultCode.NoSuchObject || rc == ResultCode.Referral) return null;
                }
                throw;
            }
            if (resp.Entries.Count == 0) return null;
            return resp.Entries[0];
        }

        public static string DnsFromNc(string nc)
        {
            if (string.IsNullOrEmpty(nc)) return "";
            var parts = new List<string>();
            foreach (string rdn in SplitDn(nc))
            {
                string t = rdn.Trim();
                if (t.StartsWith("DC=", StringComparison.OrdinalIgnoreCase)) parts.Add(t.Substring(3));
            }
            return string.Join(".", parts.ToArray());
        }

        public static string NcFromDns(string dns)
        {
            string d = dns.Trim().TrimEnd('.');
            return "DC=" + string.Join(",DC=", d.Split('.'));
        }

        /// <summary>Splits a DN at unescaped commas.</summary>
        public static List<string> SplitDn(string dn)
        {
            var parts = new List<string>();
            var sb = new StringBuilder();
            for (int i = 0; i < dn.Length; i++)
            {
                char ch = dn[i];
                if (ch == '\\' && i + 1 < dn.Length) { sb.Append(ch).Append(dn[i + 1]); i++; continue; }
                if (ch == ',') { parts.Add(sb.ToString()); sb.Length = 0; continue; }
                sb.Append(ch);
            }
            parts.Add(sb.ToString());
            return parts;
        }

        public static string ParentDn(string dn)
        {
            if (string.IsNullOrEmpty(dn)) return null;
            for (int i = 0; i < dn.Length; i++)
            {
                char ch = dn[i];
                if (ch == '\\') { i++; continue; }
                if (ch == ',') return dn.Substring(i + 1).TrimStart();
            }
            return null;
        }

        public static string RdnValue(string dn)
        {
            if (string.IsNullOrEmpty(dn)) return "";
            int i = 0;
            while (i < dn.Length)
            {
                char ch = dn[i];
                if (ch == '\\') { i += 2; continue; }
                if (ch == ',') break;
                i++;
            }
            string rdn = dn.Substring(0, Math.Min(i, dn.Length));
            int eq = rdn.IndexOf('=');
            return eq >= 0 ? rdn.Substring(eq + 1) : rdn;
        }

        public static string BinaryFilter(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 3);
            foreach (byte b in bytes) sb.Append('\\').Append(b.ToString("x2"));
            return sb.ToString();
        }

        public static string EscapeFilterValue(string v)
        {
            var sb = new StringBuilder();
            foreach (char c in v)
            {
                switch (c)
                {
                    case '*': sb.Append("\\2a"); break;
                    case '(': sb.Append("\\28"); break;
                    case ')': sb.Append("\\29"); break;
                    case '\\': sb.Append("\\5c"); break;
                    case '\0': sb.Append("\\00"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }
    }
}
