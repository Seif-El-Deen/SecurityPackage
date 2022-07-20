using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            string str;
            int key = 0;
            for (int i = 2; i < plainText.Length; i++)
            {
                str = Encrypt(plainText, i);
                if (str == cipherText)
                {
                    key = i;
                    break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            string decrypt_string = "";
            cipherText = cipherText.ToLower();
            int tmp = 0;
            double columns = (double)cipherText.Length / (double)key;
            int NumOfColumns = (int)Math.Ceiling(columns);
            char[,] arr = new char[key, NumOfColumns];
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < NumOfColumns; j++)
                {
                    if (tmp == cipherText.Length)
                    {
                        break;
                    }
                    arr[i, j] = cipherText[tmp];
                    tmp++;
                }
            }
            for (int j = 0; j < NumOfColumns; j++)
            {
                for (int i = 0; i < key; i++)
                {
                    decrypt_string += arr[i, j];
                }
            }
            return decrypt_string;
        }

        public string Encrypt(string plainText, int key)
        {
            List<string> ciphertext = new List<string>();
            int j = 0;
            int cont = 0;
            for (int i = 0; i < key; i++)
            {
                
                string val = "";
                j = cont;
                while(j<plainText.Length)
                {
                    val += plainText[j];
                    j += key;
                }
                ciphertext.Add(val);
                cont++;
            }

            string str = "";
            foreach(string x in ciphertext)
            {
                str += x;
            }
            //Console.WriteLine(str);
            return str.ToUpper();

        }
    }
}