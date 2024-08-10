using System;
using System.Security.Cryptography;
using System.Text;

public class Mnemonic
{
    private const int PBKDF2_ROUNDS = 2048;
    private const int MCOUNT = 64;

    public static string ToMnemonic(byte[] data)
    {
        if (data.Length != 16 && data.Length != 20 && data.Length != 24 && data.Length != 28 && data.Length != 32)
        {
            throw new ArgumentException("Data length should be 16, 20, 24, 28, or 32 bytes.");
        }

        string[] wordlist = LoadWordList(); // Load the wordlist

        string h = BitConverter.ToString(new SHA256Managed().ComputeHash(data)).Replace("-", "");
        string b = Convert.ToString(BitConverter.ToInt32(data, 0), 2).PadLeft(data.Length * 8, '0') +
                   Convert.ToString(int.Parse(h, System.Globalization.NumberStyles.HexNumber), 2).PadLeft(256, '0').Substring(0, data.Length * 8 / 32);

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < b.Length / 11; i++)
        {
            int idx = Convert.ToInt32(b.Substring(i * 11, 11), 2);
            result.Append(wordlist[idx]);
            if (i < b.Length / 11 - 1)
            {
                result.Append(" ");
            }
        }

        return result.ToString();
    }

    private static string[] LoadWordList()
    {
        // Load the wordlist from file or any other source
        return new string[] { "word1", "word2", "word3", /* Add all words here */ };
    }
}

public class Program
{
    public static void Main()
    {
        byte[] data = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }; // Example data
        string mnemonic = Mnemonic.ToMnemonic(data);
        Console.WriteLine(mnemonic);
    }
}