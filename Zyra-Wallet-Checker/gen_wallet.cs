using System;
using System.Collections.Generic;
using System.Text;
using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;

public class WalletGenerator
{
    public Dictionary<string, Dictionary<int, List<Dictionary<string, string>>>> GenerateWalletsBip(string mnemonic)
    {
        ExtKey masterKey = new ExtKey(new Mnemonic(mnemonic).DeriveExtKey());
        byte[] seedBytes = masterKey.PrivateKey.ToBytes();

        Dictionary < string, Dictionary<int, List<Dictionary<string, string>>> bitcoinResult = new Dictionary<string, Dictionary<int, List<Dictionary<string, string>>>>();

        Dictionary<string, CoinType> coinTypes = new Dictionary<string, CoinType>
        {
            { "bitcoin", CoinType.Bitcoin },
            { "litecoin", CoinType.Litecoin },
            { "bitcoin_cash", CoinType.BitcoinCash },
            { "bitcoin_sv", CoinType.BitcoinSV },
            { "binance_chain", CoinType.BinanceChain }
        };

        foreach (var coinType in coinTypes)
        {
            bitcoinResult[coinType.Key] = new Dictionary<int, List<Dictionary<string, string>>>();

            ExtKey masterKey44 = masterKey.Derive(new KeyPath($"m/44'/{(int)coinType.Value}'/0'"));
            ExtKey masterKey49 = masterKey.Derive(new KeyPath($"m/49'/{(int)coinType.Value}'/0'"));
            ExtKey masterKey84 = masterKey.Derive(new KeyPath($"m/84'/{(int)coinType.Value}'/0'"));

            for (int acc = 0; acc < 5; acc++)
            {
                ExtKey accountKey44 = masterKey44.Derive(acc, true);
                ExtKey accountKey49 = masterKey49.Derive(acc, true);
                ExtKey accountKey84 = masterKey84.Derive(acc, true);

                List<Dictionary<string, string>> addresses = new List<Dictionary<string, string>();
                for (int i = 0; i < 10; i++)
                {
                    ExtKey addressKey44 = accountKey44.Derive(i, true);
                    ExtKey addressKey49 = accountKey49.Derive(i, true);
                    ExtKey addressKey84 = accountKey84.Derive(i, true);

                    Dictionary<string, string> item = new Dictionary<string, string>
                    {
                        { "p2pkh", addressKey44.PrivateKey.PubKey.GetAddress(Network.Main).ToString() },
                        { "p2sh", addressKey49.PrivateKey.PubKey.GetScriptAddress(Network.Main).ToString() },
                        { "p2wkh", addressKey84.PrivateKey.PubKey.WitHash.GetAddress(Network.Main).ToString() }
                    };
                    addresses.Add(item);
                }
                bitcoinResult[coinType.Key][acc] = addresses;
            }
        }

        // Similar logic for other coin types

        return bitcoinResult;
    }
}