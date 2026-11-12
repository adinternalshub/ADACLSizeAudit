// ADACLSizeAudit - ToolMark.cs
// Project: ADACLSizeAudit | Author: Jinish Kunjilikkattil | https://adinternalshub.com/ | MIT License
// Neutral tool mark (rounded blue tile, three capacity bars, limit line) used when no corporate logo is supplied.
using System;
using System.Drawing;
using System.Drawing.Drawing2D;

namespace ADACLSizeAudit
{
    public static class ToolMark
    {
        public static readonly Color Accent = Color.FromArgb(15, 108, 189);
        public static readonly Color Muted = Color.FromArgb(97, 97, 97);
        public static readonly Color Limit = Color.FromArgb(122, 0, 16);
        public static readonly Color Canvas = Color.FromArgb(243, 242, 241);

        public static Bitmap Draw(int size)
        {
            var bmp = new Bitmap(size, size);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);
                float k = size / 56f;
                float d = 22 * k;
                float x0 = 2 * k, y0 = 2 * k, w = 52 * k;
                using (var path = new GraphicsPath())
                {
                    path.AddArc(x0, y0, d, d, 180, 90);
                    path.AddArc(x0 + w - d, y0, d, d, 270, 90);
                    path.AddArc(x0 + w - d, y0 + w - d, d, d, 0, 90);
                    path.AddArc(x0, y0 + w - d, d, d, 90, 90);
                    path.CloseFigure();
                    using (var b = new SolidBrush(Accent)) g.FillPath(b, path);
                }
                using (var w1 = new SolidBrush(Color.White))
                using (var w2 = new SolidBrush(Color.FromArgb(217, 255, 255, 255)))
                using (var w3 = new SolidBrush(Color.FromArgb(179, 255, 255, 255)))
                {
                    g.FillRectangle(w1, 13 * k, 16 * k, 30 * k, 5 * k);
                    g.FillRectangle(w2, 13 * k, 26 * k, 22 * k, 5 * k);
                    g.FillRectangle(w3, 13 * k, 36 * k, 14 * k, 5 * k);
                    g.FillRectangle(w1, 45 * k, 12 * k, Math.Max(1f, 2 * k), 33 * k);
                }
            }
            return bmp;
        }

        public static Image LoadLogoOrMark(string logoPath, int size, Action<string> warn)
        {
            if (!string.IsNullOrEmpty(logoPath) && System.IO.File.Exists(logoPath))
            {
                try
                {
                    using (var img = Image.FromFile(logoPath)) return new Bitmap(img);   // copy, so the file is not locked
                }
                catch (Exception ex) { if (warn != null) warn("Logo could not be loaded for the window: " + ex.Message); }
            }
            return Draw(size);
        }

        public static Icon MakeIcon()
        {
            try { using (var bmp = Draw(32)) return Icon.FromHandle(bmp.GetHicon()); } catch { return null; }
        }
    }
}
