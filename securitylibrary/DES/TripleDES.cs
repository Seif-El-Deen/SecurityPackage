using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES ds = new DES();
            string x = ds.Decrypt(cipherText, key[0]);
            x = ds.Encrypt(x, key[1]);
            x = ds.Decrypt(x, key[0]);
            return x;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES ds = new DES();
            string x = ds.Encrypt(plainText, key[0]);
            x = ds.Decrypt(x, key[1]);
            x = ds.Encrypt(x, key[0]);
            return x;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
