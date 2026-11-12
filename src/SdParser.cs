// ADACLSizeAudit - SdParser.cs
// Project: ADACLSizeAudit | Author: Jinish Kunjilikkattil | https://adinternalshub.com/ | MIT License
// Parses self-relative security descriptors without any platform ACL API, so it runs identically everywhere.
using System;
using System.Collections.Generic;
using System.Text;

namespace ADACLSizeAudit
{
    public class SdHeader
    {
        public int Bytes; public bool Valid = true; public string Note = "";
        public bool DaclPresent; public int DaclBytes; public int DaclAces; public int DaclOffset;
        public bool SaclPresent; public int SaclBytes; public int SaclAces; public int SaclOffset;
        public bool DaclProtected; public bool SaclProtected;
        public int OwnerOffset; public int GroupOffset;
    }

    public class AclDetail
    {
        public int Explicit; public int Inherited; public int Allow; public int Deny; public int Audit; public int ObjectAces;
        public int InheritableAces; public int InheritableBytes; public int InheritOnlyAces; public int LargestAce; public bool Truncated;
        public Dictionary<string, ObjectTrustee> Trustees = new Dictionary<string, ObjectTrustee>(StringComparer.Ordinal);
    }

    public static class SdParser
    {
        const int SE_DACL_PRESENT = 0x0004;
        const int SE_SACL_PRESENT = 0x0010;
        const int SE_DACL_PROTECTED = 0x1000;
        const int SE_SACL_PROTECTED = 0x2000;
        const int OBJECT_INHERIT_ACE = 0x01;
        const int CONTAINER_INHERIT_ACE = 0x02;
        const int INHERIT_ONLY_ACE = 0x08;
        const int INHERITED_ACE = 0x10;

        static int U32(byte[] b, int off)
        {
            uint v = BitConverter.ToUInt32(b, off);
            return v > int.MaxValue ? int.MaxValue : (int)v;
        }

        /// <summary>Cheap header-only parse used for every object.</summary>
        public static SdHeader ParseHeader(byte[] sd)
        {
            var h = new SdHeader();
            h.Bytes = sd.Length;
            if (sd.Length < 20) { h.Valid = false; h.Note = "descriptor shorter than its header"; return h; }
            if (sd[0] != 1) { h.Valid = false; h.Note = "unexpected descriptor revision " + sd[0]; return h; }

            int ctl = BitConverter.ToUInt16(sd, 2);
            h.OwnerOffset = U32(sd, 4);
            h.GroupOffset = U32(sd, 8);
            h.SaclOffset = U32(sd, 12);
            h.DaclOffset = U32(sd, 16);
            h.DaclProtected = (ctl & SE_DACL_PROTECTED) != 0;
            h.SaclProtected = (ctl & SE_SACL_PROTECTED) != 0;

            if ((ctl & SE_DACL_PRESENT) != 0 && h.DaclOffset > 0)
            {
                if (h.DaclOffset + 8 <= sd.Length)
                {
                    h.DaclPresent = true;
                    h.DaclBytes = BitConverter.ToUInt16(sd, h.DaclOffset + 2);
                    h.DaclAces = BitConverter.ToUInt16(sd, h.DaclOffset + 4);
                }
                else { h.Valid = false; h.Note = "DACL offset beyond descriptor"; }
            }
            if ((ctl & SE_SACL_PRESENT) != 0 && h.SaclOffset > 0)
            {
                if (h.SaclOffset + 8 <= sd.Length)
                {
                    h.SaclPresent = true;
                    h.SaclBytes = BitConverter.ToUInt16(sd, h.SaclOffset + 2);
                    h.SaclAces = BitConverter.ToUInt16(sd, h.SaclOffset + 4);
                }
                else { h.Valid = false; h.Note = "SACL offset beyond descriptor"; }
            }
            return h;
        }

        public static int SidLength(byte[] b, int offset)
        {
            if (offset < 0 || offset + 8 > b.Length) return 0;
            int count = b[offset + 1];
            int len = 8 + 4 * count;
            if (offset + len > b.Length) return 0;
            return len;
        }

        /// <summary>Formats a binary SID as S-1-... (no platform SID classes needed).</summary>
        public static string SidToString(byte[] b, int offset)
        {
            int len = SidLength(b, offset);
            if (len == 0) return null;
            int rev = b[offset];
            int count = b[offset + 1];
            long auth = 0;
            for (int i = 2; i <= 7; i++) auth = (auth << 8) | b[offset + i];
            var sb = new StringBuilder(64);
            sb.Append("S-").Append(rev).Append('-').Append(auth);
            for (int i = 0; i < count; i++) sb.Append('-').Append(BitConverter.ToUInt32(b, offset + 8 + 4 * i));
            return sb.ToString();
        }

        /// <summary>Walks every ACE of one ACL (flagged objects and containers only).</summary>
        public static AclDetail ParseAcl(byte[] sd, int aclOffset, int aceCount, bool collectTrustees)
        {
            var d = new AclDetail();
            int pos = aclOffset + 8;
            int len = sd.Length;
            const int inhMask = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;

            for (int i = 0; i < aceCount; i++)
            {
                if (pos + 4 > len) { d.Truncated = true; break; }
                int type = sd[pos];
                int flags = sd[pos + 1];
                int size = BitConverter.ToUInt16(sd, pos + 2);
                if (size < 4 || pos + size > len) { d.Truncated = true; break; }

                if ((flags & INHERITED_ACE) != 0) d.Inherited++; else d.Explicit++;
                if ((flags & inhMask) != 0) { d.InheritableAces++; d.InheritableBytes += size; }
                if ((flags & INHERIT_ONLY_ACE) != 0) d.InheritOnlyAces++;
                if (size > d.LargestAce) d.LargestAce = size;

                bool isObject = (type >= 5 && type <= 8) || (type >= 11 && type <= 13);
                if (isObject) d.ObjectAces++;
                if (type == 0 || type == 5 || type == 9 || type == 11) d.Allow++;
                else if (type == 1 || type == 6 || type == 10 || type == 12) d.Deny++;
                else if (type == 2 || type == 7 || type == 13) d.Audit++;

                if (collectTrustees)
                {
                    int sidOff = pos + 8;
                    if (isObject && pos + 12 <= len)
                    {
                        uint oflags = BitConverter.ToUInt32(sd, pos + 8);
                        sidOff = pos + 12;
                        if ((oflags & 1) != 0) sidOff += 16;
                        if ((oflags & 2) != 0) sidOff += 16;
                    }
                    if (sidOff + 8 <= len)
                    {
                        int sidLen = 8 + 4 * sd[sidOff + 1];
                        if (sidOff + sidLen <= len)
                        {
                            string key = BitConverter.ToString(sd, sidOff, sidLen);
                            ObjectTrustee t;
                            if (d.Trustees.TryGetValue(key, out t)) { t.Bytes += size; t.Count++; }
                            else
                            {
                                var copy = new byte[sidLen];
                                Array.Copy(sd, sidOff, copy, 0, sidLen);
                                d.Trustees[key] = new ObjectTrustee { Key = key, Bytes = size, Count = 1, Sid = copy };
                            }
                        }
                    }
                }
                pos += size;
            }
            return d;
        }
    }
}
