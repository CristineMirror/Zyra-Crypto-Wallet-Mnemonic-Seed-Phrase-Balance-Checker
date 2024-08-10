using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.Collections.Generic;
using System.Linq;

public class QDataStream
{
    private MemoryStream stream;

    public QDataStream(byte[] data)
    {
        stream = new MemoryStream(data);
    }

    public byte[] Read(int n)
    {
        if (n < 0)
        {
            n = 0;
        }
        byte[] data = new byte[n];
        int bytesRead = stream.Read(data, 0, n);
        if (n != 0 && bytesRead == 0)
        {
            return null;
        }
        if (n != 0 && bytesRead != n)
        {
            throw new Exception("unexpected eof");
        }
        return data;
    }

    public byte[] ReadBuffer()
    {
        byte[] lengthBytes = Read(4);
        if (lengthBytes == null)
        {
            return null;
        }
        int length = BitConverter.ToInt32(lengthBytes, 0);
        byte[] data = Read(length);
        if (data == null)
        {
            throw new Exception("unexpected eof");
        }
        return data;
    }

    public uint ReadUInt32()
    {
        byte[] data = Read(4);
        if (data == null)
        {
            return 0;
        }
        return BitConverter.ToUInt32(data, 0);
    }

    public ulong ReadUInt64()
    {
        byte[] data = Read(8);
        if (data == null)
        {
            return 0;
        }
        return BitConverter.ToUInt64(data, 0);
    }

    public int ReadInt32()
    {
        byte[] data = Read(4);
        if (data == null)
        {
            return 0;
        }
        return BitConverter.ToInt32(data, 0);
    }
}

public class Program
{
    private static readonly Dictionary<int, Tuple<string, int>> DC_TABLE = new Dictionary<int, Tuple<string, int>>
    {
        { 1, new Tuple<string, int>("149.154.175.50", 443) },
        { 2, new Tuple<string, int>("149.154.167.51", 443) },
        { 3, new Tuple<string, int>("149.154.175.100", 443) },
        { 4, new Tuple<string, int>("149.154.167.91", 443) },
        { 5, new Tuple<string, int>("149.154.171.5", 443) }
    };

    public static byte[] CreateLocalKey(byte[] passcode, byte[] salt)
    {
        int iterations = passcode.Length > 0 ? 100000 : 1;
        byte[] hash = SHA512.Create().ComputeHash(CombineByteArrays(salt, passcode, salt));
        return new Rfc2898DeriveBytes(hash, salt, iterations).GetBytes(256);
    }

    public static Tuple<byte[], byte[]> PrepareAesOldmtp(byte[] authKey, byte[] msgKey, bool send)
    {
        int x = send ? 0 : 8;

        using (SHA1 sha1 = SHA1.Create())
        {
            byte[] a = sha1.ComputeHash(CombineByteArrays(msgKey, authKey.Skip(x).Take(32).ToArray()));
            byte[] b = sha1.ComputeHash(CombineByteArrays(authKey.Skip(32 + x).Take(16).ToArray(), msgKey, authKey.Skip(48 + x).Take(16).ToArray()));
            byte[] c = sha1.ComputeHash(CombineByteArrays(authKey.Skip(64 + x).Take(32).ToArray(), msgKey));
            byte[] d = sha1.ComputeHash(CombineByteArrays(msgKey, authKey.Skip(96 + x).Take(32).ToArray()));

            byte[] key = CombineByteArrays(a.Take(8).ToArray(), b.Skip(8).ToArray(), c.Skip(4).Take(12).ToArray());
            byte[] iv = CombineByteArrays(a.Skip(8).ToArray(), b.Take(8).ToArray(), c.Skip(16).ToArray(), d.Take(8).ToArray());

            return new Tuple<byte[], byte[]>(key, iv);
        }
    }

    public static byte[] AesDecryptLocal(byte[] ciphertext, byte[] authKey, byte[] key128)
    {
        Tuple<byte[], byte[]> keyIv = PrepareAesOldmtp(authKey, key128, false);
        return Cryptg.DecryptIge(ciphertext, keyIv.Item1, keyIv.Item2);
    }

    public static QDataStream DecryptLocal(byte[] data, byte[] key)
    {
        byte[] encryptedKey = data.Take(16).ToArray();
        byte[] decryptedData = AesDecryptLocal(data.Skip(16).ToArray(), key, encryptedKey);
        byte[] sha1Hash = SHA1.Create().ComputeHash(decryptedData);
        if (!encryptedKey.SequenceEqual(sha1Hash.Take(16)))
        {
            throw new Exception("failed to decrypt");
        }
        int length = BitConverter.ToInt32(decryptedData, 0);
        byte[] extractedData = decryptedData.Skip(4).Take(length).ToArray();
        return new QDataStream(extractedData);
    }

    public static QDataStream ReadFile(string name)
    {
        byte[] fileData = File.ReadAllBytes(name);
        byte[] magic = fileData.Take(4).ToArray();
        if (!magic.SequenceEqual(Encoding.ASCII.GetBytes("TDF$")))
        {
            throw new Exception("invalid magic");
        }
        byte[] versionBytes = fileData.Skip(4).Take(4).ToArray();
        byte[] data = fileData.Skip(8).ToArray();
        byte[] dataWithoutDigest = data.Take(data.Length - 16).ToArray();
        byte[] digest = data.Skip(data.Length - 16).ToArray();

        byte[] dataLenBytes = BitConverter.GetBytes(dataWithoutDigest.Length);
        byte[] md5Input = CombineByteArrays(dataWithoutDigest, dataLenBytes, versionBytes, magic);
        byte[] md5Digest = MD5.Create().ComputeHash(md5Input);
        if (!md5Digest.SequenceEqual(digest))
        {
            throw new Exception("invalid digest");
        }

        return new QDataStream(dataWithoutDigest);
    }

    public static QDataStream ReadEncryptedFile(string name, byte[] key)
    {
        QDataStream stream = ReadFile(name);
        byte[] encryptedData = stream.ReadBuffer();
        return DecryptLocal(encryptedData, key);
    }

    public static string AccountDataString(int index = 0)
    {
        string s = "data";
        if (index > 0)
        {
            s += $"#{index + 1}";
        }
        byte[] digest = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(s));
        return BitConverter.ToString(digest, 0, 8).ToLower().Replace("-", "");
    }

    public static Tuple<int, byte[]> ReadUserAuth(string directory, byte[] localKey, int index = 0)
    {
        string name = AccountDataString(index);
        string path = Path.Combine(directory, $"{name}s");
        QDataStream stream = ReadEncryptedFile(path, localKey);
        if (stream.ReadUInt32() != 0x4B)
        {
            throw new Exception("unsupported user auth config");
        }
        stream = new QDataStream(stream.ReadBuffer());
        uint userId = stream.ReadUInt32();
        uint mainDc = stream.ReadUInt32();
        if (userId == 0xFFFFFFFF && mainDc == 0xFFFFFFFF)
        {
            userId = stream.ReadUInt64();
            mainDc = stream.ReadUInt32();
        }
        if (!DC_TABLE.ContainsKey((int)mainDc))
        {
            throw new Exception($"unsupported main dc: {mainDc}");
        }
        int length = (int)stream.ReadUInt32();
        for (int i = 0; i < length; i++)
        {
            uint authDc = stream.ReadUInt32();
            byte[] authKey = stream.Read(256);
            if (authDc == mainDc)
            {
                return new Tuple<int, byte[]>((int)authDc, authKey);
            }
        }
        throw new Exception("invalid user auth config");
    }

    public static string BuildSession(int dc, string ip, int port, byte[] key)
    {
        byte[] ipBytes = IPAddress.Parse(ip).GetAddressBytes();
        byte[] data = CombineByteArrays(new byte[] { (byte)dc }, ipBytes, BitConverter.GetBytes((short)port), key);
        string encodedData = Convert.ToBase64String(data).Replace('+', '-').Replace('/', '_');
        return "1" + encodedData;
    }

    public static List<string> ConvertTdata(string path)
    {
        QDataStream stream = ReadFile(Path.Combine(path, "key_datas"));
        byte[] salt = stream.ReadBuffer();
        if (salt.Length != 32)
        {
            throw new Exception("invalid salt length");
        }
        byte[] keyEncrypted = stream.ReadBuffer();
        byte[] infoEncrypted = stream.ReadBuffer();

        byte[] passcodeKey = CreateLocalKey(new byte[0], salt);
        QDataStream keyInnerData = DecryptLocal(keyEncrypted, passcodeKey);
        byte[] localKey = keyInnerData.Read(256);
        if (localKey.Length != 256)
        {
            throw new Exception("invalid local key");
        }

        List<string> sessions = new List<string>();
        QDataStream infoData = DecryptLocal(infoEncrypted, localKey);
        int count = (int)infoData.ReadUInt32();
        for (int i = 0; i < count; i++)
        {
            uint index = infoData.ReadUInt32();
            Tuple<int, byte[]> dcKey = ReadUserAuth(path, localKey, (int)index);
            Tuple<string, int> dcInfo = DC_TABLE[dcKey.Item1];
            sessions.Add(BuildSession(dcKey.Item1, dcInfo.Item1, dcInfo.Item2, dcKey.Item2));
        }
        return sessions;
    }

    public static byte[] CombineByteArrays(params byte[][] arrays)
    {
        byte[] combined = new byte[arrays.Sum(arr => arr.Length)];
        int offset = 0;
        foreach (byte[] arr in arrays)
        {
            Buffer.BlockCopy(arr, 0, combined, offset, arr.Length);
            offset += arr.Length;
        }
        return combined;
    }

    public static void Main(string[] args)
    {
        List<string> sessions = ConvertTdata(args[0]);
        Console.WriteLine(string.Join(Environment.NewLine, sessions));
    }
}