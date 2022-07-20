using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            int LetterCount = 26;
            StringBuilder value_of_key = new StringBuilder("00000000000000000000000000");
            bool[] Char_Found = new bool[LetterCount];

            for (int i = 0; i < plainText.Length; i++)
            {

                char CharOCipher = cipherText[i];      // bnlf 3la kol element fe el ciphertext     
                Char_Found[CharOCipher - 'A'] = true;  // we n5le mkano be true 
                int index = plainText[i] - 97;
                value_of_key[index] = CharOCipher;
            }

            for (int i = 0; i < LetterCount; i++)
            {
                if (value_of_key[i] == '0')
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (Char_Found[j] == false)
                        {
                            value_of_key[i] = (char)('A' + j);
                            Char_Found[j] = true;
                            break;
                        }
                    }
                }
            }

            return value_of_key.ToString().ToLower();
        }



        public string Decrypt(string cipherText, string key)
        {
            string letters = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();
            char[] P_T = new char[cipherText.Length];
            int[] q = new int[cipherText.Length];
            int index = 0;
            for (int i = 0; i < cipherText.Length; i++)  //E B G
            {
                for (int j = 0; j < key.Length; j++) // from D to K 
                {
                    if (cipherText[i] == key[j]) // find index bta3 el cipher text
                    {
                        q[index] = j;     //store index 
                        index++;
                    }
                }
            }
            for (int i = 0; i < q.Length; i++)     // bnlf 3la el array 
            {
                int z = q[i];             // bn5zn index bta3 el array fel z 
                P_T[i] = letters[z];      // bngeb value el index w bn5znha fel P_T
            }
            return new string(P_T);
        }

        public string Encrypt(string plainText, string key)
        {

            string letters = "abcdefghijklmnopqrstuvwxyz";
            int[] k = new int[plainText.Length];
            char[] C_T = new char[plainText.Length];
            int index = 0;
            for (int i = 0; i < plainText.Length; i++)  //ahmed
            {
                if (char.IsLetter(plainText[i]) == true) //a 
                {
                    for (int j = 0; j < letters.Length; j++) //htlf 3la abc
                    {
                        if (plainText[i] == letters[j])    //hyrg3 el letter index 
                        {
                            k[index] = j;
                            index++;
                        }
                    }
                }
            }
            for (int i = 0; i < k.Length; i++)
            {
                int x = k[i];
                C_T[i] = key[x];
            }
            return new string(C_T);
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>

        public string AnalyseUsingCharFrequency(string cipher)  // osamaahmed
        {
            cipher = cipher.ToLower();
            char[] P_T = new char[cipher.Length];

            int[] connect_char_with_rep = new int[cipher.Length];
            char[] new_char_for_plain = new char[cipher.Length]; // ETAO.... 3la 7sb # of uniqe letter

            char[] arranged_char = new char[cipher.Length];

            int[] char_rep = new int[cipher.Length];

            //contains sorted distinct chars of the cipher
            char[] char_in_cipher = new char[cipher.Length];
            string letters = "abcdefghijklmnopqrstuvwxyz";
            string X_Z = "ETAOINSRHLDCUMFPGWYBVKXJQZ";

            int index = 0;

            ///////////////
            ///my code
            ///////////

            //this would get the unique chars in the cipher and sort them in alphabitical order
            char_in_cipher = cipher.Distinct().ToArray();
            Array.Sort(char_in_cipher);
            string str = new string(char_in_cipher);

            // this would order according to the frequency
            char[] orderd_freq_cipher = new char[str.Length];
            orderd_freq_cipher = rep(cipher, str);

            //make substring of english freq letters 
            X_Z = X_Z.Substring(0, orderd_freq_cipher.Length);

            //now comparing the strings
            StringBuilder plaintext = new StringBuilder(cipher);
            for (int i = 0; i < cipher.Length; i++)
            {
                for (int j = 0; j < orderd_freq_cipher.Length; j++)
                {
                    if (cipher[i] == orderd_freq_cipher[j])
                        plaintext[i] = X_Z[j];

                }
            }
            Console.WriteLine(plaintext);
            string result = plaintext.ToString().ToLower();
            return result;





            //getting the freq of each char
            //int [] arr = new int[char_in_cipher.Length];
            //int i = 0;
            //int repeted;
            //foreach(char e in char_in_cipher)
            //{ repeted = 0;
            //    foreach(char c in cipher)
            //    {

            //        if (e == c)
            //            repeted++;
            //    }
            //    arr[i] = repeted;
            //    i++;
            //}


            //for (int i = 0; i <= letters.Length; i++)
            //{
            //    bool found = false;
            //    for (int j = 0; j <= cipher.Length+1; j++)
            //    {
            //        int k = cipher.Length;
            //        if (letters[i] == cipher[j])
            //        {
            //            found = true;
            //            continue;
            //        }
            //        if (found)
            //            continue;

            //        char_in_cipher[index] = letters[i]; //  a d e h m o
            //        index++;
            //    }
            //}

            //int index_of_char_rep = 0;

            //for (int i = 0; i < char_in_cipher.Length; i++)
            //{
            //    bool found = false;
            //    int count = 0;
            //    for (int j = 0; j < cipher.Length; j++)
            //    {
            //        if (letters[i] == cipher[j])
            //        {
            //            found = true;
            //            continue;
            //        }
            //        if (found)
            //            continue;

            //        count++;
            //    }
            //    char_rep[index_of_char_rep] = count;
            //    index_of_char_rep++;
            //}

            //int repeted = 0;
            //for (int i = 0; i < connect_char_with_rep.Length; i++)
            //{
            //    connect_char_with_rep[repeted] = char_rep[i];
            //    repeted++;
            //}

            //// arrange array and char in cipher together
            //int temp_rep;
            //for (int i = 0; i < char_rep.Length; i++)
            //{
            //    for (int j = i + 1; j < char_rep.Length; j++)
            //    {
            //        if (char_rep[i] < char_rep[j])
            //        {
            //            temp_rep = char_rep[i];
            //            char_rep[i] = char_rep[j];
            //            char_rep[j] = temp_rep;

            //        }
            //    }
            //}

            //for (int i = 0; i < char_in_cipher.Length; i++)
            //{
            //    for (int j = 0; j < arranged_char.Length; j++)
            //    {
            //        bool found = false;
            //        if (connect_char_with_rep[i] == char_rep[j])
            //        {
            //            found = true;
            //            continue;
            //        }
            //        if (found)
            //            continue;

            //        arranged_char[j] = char_in_cipher[i];
            //    }
            //}

            //int OS = 0;
            //for (int i = 0; i < char_rep.Length; i++)
            //{
            //    new_char_for_plain[OS] = X_Z[i];
            //    OS++;
            //}

            //for (int i = 0; i < char_in_cipher.Length; i++)
            //{
            //    bool found = false;
            //    for (int j = 0; j < cipher.Length; j++)
            //    {
            //        if (arranged_char[i] == cipher[j])
            //        {
            //            found = true;
            //            continue;
            //        }
            //        if (found)
            //            continue;

            //        P_T[j] = new_char_for_plain[i];
            //    }
            //}

        }
        public char[] rep(string cipher, string ord_cipher)
        {
            Dictionary<Char, Double> freq_of_cipher = new Dictionary<char, double>();
            foreach (char a in ord_cipher)
            {
                freq_of_cipher.Add(a, 0);
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                if (freq_of_cipher.ContainsKey(cipher[i]))
                {
                    freq_of_cipher[cipher[i]]++;
                }
            }

            //foreach (KeyValuePair<char, double> kvp in freq_of_cipher)
            //{
            //    //textBox3.Text += ("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
            //    Console.WriteLine("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
            //}
            var sortedDict = from entry in freq_of_cipher orderby entry.Value descending select entry;
            foreach (KeyValuePair<char, double> kvp in sortedDict)
            {
                //textBox3.Text += ("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
                Console.WriteLine("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
            }
            var x = sortedDict.ToList();
            char[] arr = new char[x.Count];
            for (int i = 0; i < x.Count; i++)
            {
                arr[i] = x[i].Key;

            }

            return arr;




        }
    }
}
/*
 public string Analyse(string plainText, string cipherText)
        {
            char[] Ke = new char[cipherText.Length];
            char[] remain = new char[cipherText.Length];
            int index = 0;
            int remain_index=0;
            for(int i=0 ; i < plainText.Length; i++)
            {
                for(int j=0 ; j < cipherText.Length ; j++)
                {
                    if (plainText[i] == cipherText[j])
                    {
                        Ke[index] = cipherText[j];
                        index++;
                    }
                    else
                    {
                        Ke[index] = '\0';
                        remain[remain_index] = cipherText[j];
                        index++;
                        remain_index++;
                    }
                }
            }
            int integ=0;
            for(int i=0; i< Ke.Length; i++)
            {
                if(Ke[i] == '\0')
                {
                    Ke[i] = remain[integ];
                    integ++;
                }
            }
            return new string (Ke);
        }
 */


/*
  public string Analyse(string plainText, string cipherText)
        {
            char[] letters = new char[26];
            char[] key = new char[26];

            int[] indices = new int[26];
            int used = 0;

            // Populate letters array with the alphabet
            for (int i = 0; i < letters.Length; i++)
            {
                letters[i] = (char)(i + 97);
            }

            // Put every ciphertext letter in the corresponding index in the plaintext string
            // And store used indices
            for (int i = 0; i < cipherText.Length; ++i)
            {
                int index = (int)plainText[i] - 97;
                bool isUsed = false;
                for (int j = 0; j < used; ++j)
                {
                    if (index == indices[j])
                    {
                        isUsed = true;
                        break;
                    }
                }

                if (!isUsed)
                {
                    key[index] = cipherText[i];
                    used++;
                }
            }

            for (int i = 0; i < key.Length; ++i)
            {

            }

            return null;
        }*/











/*for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < cipherText.Length; j++)
                {
                    if (plainText[i] == cipherText[j])
                    {
                        Ke[index] = cipherText[j];
                        index++;
                    }
                    else
                    {
                        ptr[indexOfarr] = index;
                        index++;
                        remain[remain_index] = cipherText[j];
                        remain_index++;
                        indexOfarr++;
                    }
                }
            }
            int integ = 0;
            for (int i = 0; i < ptr.Length; i++)
            {
                int x = ptr[i];
                
                Ke[x]= remain[integ];
                integ++;
            }
            */
/*int integ = 0;
for (int i = 0; i < Ke.Length; i++)
{
    if (Ke[i] == '\0')
    {
        Ke[i] = remain[integ];
        integ++;
    }
}
*/
















/* public string Analyse(string plainText, string cipherText)
        {
            string letters = "abcdefghijklmnopqrstuvwxyz";
            int[] ptr = new int[plainText.Length];
            char[] Ke = new char[letters.Length];
            char[] remain = new char[letters.Length];
            //int indexOfarr = 0;
            int index = 0;
            //int remain_index = 0;
            
            for(int i = 0; i < plainText.Length; i++)  // بنقارن ال بلابن تيكست ب ال حروف
            {
                for(int j = 0; j < letters.Length; j++)  // وبناخد ال سيفر بتاعه وبنخزنه في اراي بمكانه 
                {
                    if(plainText[i] == letters[j])
                    {
                        Ke[j] = cipherText[i];
                    }
                }
            }

            for (int i = 0; i < letters.Length; i++)
            {
                for (int j = 0; j < cipherText.Length; j++)  // compare each letter with the ciphertext
                {
                    if (letters[i] != cipherText[j])
                    {
                        remain[index] = letters[i]; // 4ayl el letters el unused (m4 mawgodeen fe el ciphertext)
                        index++;
                    }
                }
            }

            for(int i = 0; i < remain.Length; i++)
            {
                for(int j=0; j < Ke.Length; j++)
                {
                    if (Ke[j] == '0')

                    {
                         Ke[j] = remain[i];
                    }
                }

            }
            return new string(Ke);
        }
*/