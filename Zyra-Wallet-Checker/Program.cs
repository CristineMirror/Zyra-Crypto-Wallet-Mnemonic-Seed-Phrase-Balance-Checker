using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Data.SQLite;

public class Program
{
    static HashSet<string> BAD_EXTENSIONS = new HashSet<string> { ".jpg", ".png", ".jpeg", ".ico", ".gif", ".iso", ".dll", ".sys", ".zip", ".rar", ".7z", ".cab", ".dat" };
    static List<string> BAD_DIRS = new List<string> { "ololololz" };
    static List<string> BAD_FILES = new List<string> { "ololololo" };
    static HashSet<string> ENABLE_LANG = new HashSet<string> { "english", "chinese_simplified", "chinese_traditional", "french", "italian", "japanese", "korean", "portuguese", "spanish" };
    static HashSet<int> WORDS_CHAIN_SIZES = new HashSet<int> { 12, 15, 18, 24 };
    static int EXWORDS = 2;

    public static void Main()
    {
        string SOURCE_DIR = "d:/LOGS/TEST_Telegram/";
        string LOG_DIR = "./logs/";

        foreach (string dir in Directory.GetDirectories(SOURCE_DIR))
        {
            if (Directory.GetFiles(dir).Length == 0)
                continue;

            bool isBadDir = false;
            foreach (string badDir in BAD_DIRS)
            {
                if (dir.ToLower().Contains(badDir))
                {
                    isBadDir = true;
                    break;
                }
            }
            if (isBadDir)
                continue;

            foreach (string file in Directory.GetFiles(dir))
            {
                string fileName = Path.GetFileNameWithoutExtension(file);
                string fileExt = Path.GetExtension(file);

                if (BAD_EXTENSIONS.Contains(fileExt))
                    continue;

                bool isBadFile = false;
                foreach (string badFile in BAD_FILES)
                {
                    if (fileName.ToLower().Contains(badFile))
                    {
                        isBadFile = true;
                        break;
                    }
                }
                if (isBadFile)
                    continue;

                try
                {
                    string filePath = Path.GetFullPath(file);
                    FindInFile(filePath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("ERROR on parse file: " + ex.Message);
                }
            }
        }
    }

    static void FindInFile(string path)
    {
        string data = File.ReadAllText(path);
        foreach (Match m in Regex.Matches(data, "[a-z]+", RegexOptions.IgnoreCase))
        {
            string word = m.Groups[0].Value.ToLower();
            // Logic to process words and phrases
        }

        // Additional logic for parsing ETH keys if needed
    }
}
