using System.Diagnostics;
using System;
using System.Text;
using Microsoft.VisualBasic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

public static class Utils
{
    private static string EncryptAES256(string input, string pass)
    {
        var AES = new System.Security.Cryptography.RijndaelManaged();

        try
        {
            var hash = new byte[32];
            var temp = new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(Encoding.Unicode.GetBytes(pass));

            Array.Copy(temp, 0, hash, 0, 16);
            Array.Copy(temp, 0, hash, 15, 16);

            AES.Key = hash;
            AES.Mode = System.Security.Cryptography.CipherMode.ECB;

            var Buffer = Encoding.Unicode.GetBytes(input);

            return Convert.ToBase64String(AES.CreateEncryptor().TransformFinalBlock(Buffer, 0, Buffer.Length));
        }
        catch
        {
            Process.GetCurrentProcess().Kill();

            return "";
        }
    }

    private static string DecryptAES256(string input, string pass)
    {
        var AES = new System.Security.Cryptography.RijndaelManaged();

        try
        {
            var hash = new byte[32];
            var temp = new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(Encoding.Unicode.GetBytes(pass));

            Array.Copy(temp, 0, hash, 0, 16);
            Array.Copy(temp, 0, hash, 15, 16);

            AES.Key = hash;
            AES.Mode = System.Security.Cryptography.CipherMode.ECB;

            var Buffer = Convert.FromBase64String(input);

            return Encoding.Unicode.GetString(AES.CreateDecryptor().TransformFinalBlock(Buffer, 0, Buffer.Length));
        }
        catch
        {
            Process.GetCurrentProcess().Kill();

            return "";
        }
    }

    public static string CustomEncrypt(string text)
    {
        string result = "";

        text = Strings.StrReverse(EncryptAES256(Strings.StrReverse(text), "KERJKJEHKRGEUHWGRUHWEGRUYHGWE8R7YGHWEUYGRUYEWGRUYGWERUYGWEURYIWEUIYR"));

        for (int i = 0; i < text.Length; i++)
        {
            result += (char)((text[i] - 17));
        }

        result = Compress(Strings.StrReverse(PersonalEncrypt(Strings.StrReverse(result))));
        return result;
    }

    public static string CustomDecrypt(string text)
    {
        text = Decompress(text);
        string result = "";
        text = Strings.StrReverse(text);
        text = PersonalDecrypt(text);
        text = Strings.StrReverse(text);

        for (int i = 0; i < text.Length; i++)
        {
            result += (char)(text[i] + 17);
        }

        result = Strings.StrReverse(result);
        result = DecryptAES256(result, "KERJKJEHKRGEUHWGRUHWEGRUYHGWE8R7YGHWEUYGRUYEWGRUYGWERUYGWEURYIWEUIYR");
        result = Strings.StrReverse(result);

        return result;
    }

    private static string PersonalEncrypt(string text)
    {
        string result = "";

        for (int i = 0; i < text.Length; i++)
        {
            int j = Convert.ToInt32(text[i]);
            j += 37;
            string theNumber = Strings.StrReverse(EncryptAES256(Strings.StrReverse(j.ToString()), "KEHWKJQHWEKJHWQKJEHKQJWHE"));

            if (result == "")
            {
                result = "(_[_{_" + theNumber + "_}_]_)";
            }
            else
            {
                result += "|||(_[_{_" + theNumber + "_}_]_)";
            }
        }

        return Strings.StrReverse(EncryptAES256(Strings.StrReverse(result), "EJRLKEJRLKJWERLKJEWLKRJWLEKJRLKWEJ"));
    }

    private static string PersonalDecrypt(string text)
    {
        text = Strings.StrReverse(text);
        text = DecryptAES256(text, "EJRLKEJRLKJWERLKJEWLKRJWLEKJRLKWEJ");
        text = Strings.StrReverse(text);

        string result = "";

        text = text.Replace("(_[_{_", "");
        text = text.Replace("_}_]_)", "");

        string[] splitted = Strings.Split(text, "|||");

        foreach (string str in splitted)
        {
            string t = Strings.StrReverse(str);
            t = DecryptAES256(t, "KEHWKJQHWEKJHWQKJEHKQJWHE");
            t = Strings.StrReverse(t);

            int l = int.Parse(t);
            l -= 37;
            result += Convert.ToChar(l);
        }

        return result;
    }

    private static string Decompress(string input)
    {
        byte[] compressed = Convert.FromBase64String(input);
        byte[] decompressed = Decompress(compressed);
        return Encoding.Unicode.GetString(decompressed);
    }

    private static string Compress(string input)
    {
        byte[] encoded = Encoding.Unicode.GetBytes(input);
        byte[] compressed = Compress(encoded);
        return Convert.ToBase64String(compressed);
    }

    private static byte[] Decompress(byte[] input)
    {
        using (var source = new MemoryStream(input))
        {
            byte[] lengthBytes = new byte[4];
            source.Read(lengthBytes, 0, 4);

            var length = BitConverter.ToInt32(lengthBytes, 0);
            using (var decompressionStream = new GZipStream(source,
                CompressionMode.Decompress))
            {
                var result = new byte[length];
                decompressionStream.Read(result, 0, length);
                return result;
            }
        }
    }

    private static byte[] Compress(byte[] input)
    {
        using (var result = new MemoryStream())
        {
            var lengthBytes = BitConverter.GetBytes(input.Length);
            result.Write(lengthBytes, 0, 4);

            using (var compressionStream = new GZipStream(result,
                CompressionMode.Compress))
            {
                compressionStream.Write(input, 0, input.Length);
                compressionStream.Flush();

            }
            return result.ToArray();
        }
    }

    internal static readonly char[] chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
    internal static readonly char[] everything = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray();
    internal static readonly char[] numbers = "123456789".ToCharArray();

    public static string GetUniqueKey(int size)
    {
        try
        {
            byte[] data = new byte[4 * size];

            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }

            StringBuilder result = new StringBuilder(size);

            for (int i = 0; i < size; i++)
            {
                var rnd = BitConverter.ToUInt32(data, i * 4);
                var idx = rnd % chars.Length;

                result.Append(chars[idx]);
            }

            return result.ToString();
        }
        catch
        {
            return "";
        }
    }

    public static string GetUniqueKey1(int size)
    {
        try
        {
            byte[] data = new byte[4 * size];

            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }

            StringBuilder result = new StringBuilder(size);

            for (int i = 0; i < size; i++)
            {
                var rnd = BitConverter.ToUInt32(data, i * 4);
                var idx = rnd % everything.Length;

                result.Append(everything[idx]);
            }

            return result.ToString();
        }
        catch
        {
            return "";
        }
    }

    public static long GetUniqueLong(int size)
    {
        try
        {
            byte[] data = new byte[4 * size];

            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }

            StringBuilder result = new StringBuilder(size);

            for (int i = 0; i < size; i++)
            {
                var rnd = BitConverter.ToUInt32(data, i * 4);
                var idx = rnd % numbers.Length;

                result.Append(numbers[idx]);
            }

            return long.Parse(result.ToString());
        }
        catch
        {
            return 0L;
        }
    }
}