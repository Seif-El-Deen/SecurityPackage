using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            key = key % 26;
            string myText = "";
            int[] letterAscii = new int[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                // mytext+=plainText[i]+key;
                if ((int)plainText[i] + key > 122)
                {
                    letterAscii[i] = ((int)plainText[i] - 26) + key;
                }
                else
                {
                    letterAscii[i] = (int)plainText[i] + key;
                }
                myText += (char)letterAscii[i];

            }

            return myText;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            key = key % 26;
            string myText = "";
            int[] letterAscii = new int[cipherText.Length];
            for (int i = 0; i < cipherText.Length; i++)
            {
                if ((int)cipherText[i] - key < 97)
                {
                    letterAscii[i] = (int)(cipherText[i] + 26) - key;
                }
                else
                {
                    letterAscii[i] = (int)cipherText[i] - key;
                }
                myText += (char)(letterAscii[i]);

            }

            return myText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int key = ((int)plainText[0] - (int)cipherText[0]);
            return key >= 0 ? (26 - key) % 26 : -key % 26;
        }
    }
}