using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            Dictionary<char, Dictionary<char, char>> matrixValues = new Dictionary<char, Dictionary<char, char>>();

            //VigenereTable Creation
            // row Loop
            for (char j = 'a'; j < 'z'; j++)
            {
                Dictionary<char, char> rowValues = new Dictionary<char, char>();
                //column loop
                int i = 0;
                for (char l = Char.ToUpper(j), k = 'a'; i < 26; l++, i++, k++)
                {
                    rowValues.Add(k, l);
                    if (l == 'Z')
                    {
                        l = '@';
                    }
                }
                matrixValues.Add(j, rowValues);
            }
            // To get the key 
            String key = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                for (char j = 'a'; j < 'z'; j++)
                {
                    if (Char.ToLower(matrixValues[plainText[i]][j]) == cipherText[i])
                    {
                        key += j;
                    }
                }
            }
            //To Know The count of each letter in the key string
            Dictionary<char, int> eachLetterCount = new Dictionary<char, int>();

            for (int i = 0; i < key.Length; i++)
            {
                if (eachLetterCount.ContainsKey(key[i]))
                {
                    eachLetterCount[key[i]]++;
                }
                else
                {
                    eachLetterCount.Add(key[i], 1);
                }
            }

            //To know the count of each number in the eachLetterCount
            Dictionary<int, int> eachCountConut = new Dictionary<int, int>();
            foreach (KeyValuePair<char, int> letterCount in eachLetterCount)
            {
                if (eachCountConut.ContainsKey(letterCount.Value))
                {
                    eachCountConut[letterCount.Value]++;
                }
                else
                {
                    eachCountConut.Add(letterCount.Value, 1);
                }
            }
            // To Know the max repeated number which is the number that the word is repeated with
            int maxRepeatedCount = -10;
            foreach (KeyValuePair<int, int> letterCount in eachCountConut)
            {
                if (letterCount.Value > maxRepeatedCount)
                {
                    maxRepeatedCount = letterCount.Value;
                }
            }
            //Console.WriteLine("MaxRepeatedCount:{0}",maxRepeatedCount);
            Dictionary<String, int> subStrings = new Dictionary<String, int>();
            int maxRepeatedSubStringCount = -10;
            String maxRepeatedSubString = "";
            for (int i = 0; i < key.Length; i++)
            {
                for (int j = i; j < key.Length / 3 + 1; j++)
                {
                    //      Console.WriteLine(key.Substring(i,j));
                    if (subStrings.ContainsKey(key.Substring(i, j)))
                    {
                        subStrings[key.Substring(i, j)]++;

                    }
                    else
                    {
                        subStrings.Add(key.Substring(i, j), 1);
                    }
                    if (subStrings[key.Substring(i, j)] > maxRepeatedSubStringCount)
                    {
                        maxRepeatedSubStringCount = subStrings[key.Substring(i, j)];
                        maxRepeatedSubString = key.Substring(i, j);
                    }
                }

            }




            return maxRepeatedSubString;
        }


        public string Decrypt(string cipherText, string key)
        {
            String key_stream = key;
            int i = 0;
            cipherText = cipherText.ToLower();
            while (cipherText.Length > key_stream.Length)
            {
                key_stream += key[i];
                i++;
                if (i == key.Length)
                {
                    i = 0;
                }
            }
            if (cipherText.Length < key_stream.Length)
            {
                key_stream = key_stream.Substring(cipherText.Length);
            }

            //Console.WriteLine(key_stream);
            //Console.WriteLine(cipherText);


            Dictionary<char, Dictionary<char, char>> matrixValues = new Dictionary<char, Dictionary<char, char>>();

            //VigenereTable Creation
            // row Loop
            for (char j = 'a'; j < 'z'; j++)
            {
                Dictionary<char, char> rowValues = new Dictionary<char, char>();
                //column loop
                i = 0;
                for (char l = Char.ToUpper(j), k = 'a'; i < 26; l++, i++, k++)
                {
                    rowValues.Add(k, l);
                    if (l == 'Z')
                    {
                        l = '@';
                    }
                }
                matrixValues.Add(j, rowValues);
            }



            String PlainText = "";
            for (int k = 0; k < cipherText.Length; k++)
            {
                for (char l = 'a'; l <= 'z'; l++)
                {
                    if (cipherText[k] == char.ToLower(matrixValues[key_stream[k]][l]))
                    {
                        PlainText += l;
                    }
                }
            }



            return PlainText.ToLower();
        }


        public string Encrypt(string plainText, string key)
        {
            String key_stream = key;
            int i = 0;
            while (plainText.Length > key_stream.Length)
            {
                key_stream += key[i];
                i++;
                if (i == key.Length)
                {
                    i = 0;
                }
            }
            if (plainText.Length < key_stream.Length)
            {
                key_stream = key_stream.Substring(plainText.Length);
            }

            Console.WriteLine(key_stream);
            Console.WriteLine(plainText);


            Dictionary<char, Dictionary<char, char>> matrixValues = new Dictionary<char, Dictionary<char, char>>();

            //VigenereTable Creation
            // row Loop
            for (char j = 'a'; j < 'z'; j++)
            {
                Dictionary<char, char> rowValues = new Dictionary<char, char>();
                //column loop
                i = 0;
                for (char l = Char.ToUpper(j), k = 'a'; i < 26; l++, i++, k++)
                {
                    rowValues.Add(k, l);
                    if (l == 'Z')
                    {
                        l = '@';
                    }
                }
                matrixValues.Add(j, rowValues);
            }

            String ChipherText = "";

            for (i = 0; i < plainText.Length; i++)
            {
                ChipherText += matrixValues[plainText[i]][key_stream[i]];

            }


            return ChipherText;
        }
    }

}

//public string Analyse(string plainText, string cipherText)
//{
//    cipherText = cipherText.ToLower();
//    Dictionary<char, Dictionary<char, char>> matrixValues = new Dictionary<char, Dictionary<char, char>>();

//    //VigenereTable Creation
//    // row Loop
//    for (char j = 'a'; j < 'z'; j++)
//    {
//        Dictionary<char, char> rowValues = new Dictionary<char, char>();
//        //column loop
//        int i = 0;
//        for (char l = Char.ToUpper(j), k = 'a'; i < 26; l++, i++, k++)
//        {
//            rowValues.Add(k, l);
//            if (l == 'Z')
//            {
//                l = '@';
//            }
//        }
//        matrixValues.Add(j, rowValues);
//    }

//    String key = "";
//    for (int i = 0; i < plainText.Length; i++)
//    {
//        for (char j = 'a'; j < 'z'; j++)
//        {
//            if (Char.ToLower(matrixValues[plainText[i]][j]) == cipherText[i])
//            {
//                key += j;
//            }
//        }
//    }
//    //To Know The count of each letter in the key string
//    Dictionary<char, int> eachLetterCount = new Dictionary<char, int>();

//    for(int i=0;i< key.Length; i++)
//    {
//        if (eachLetterCount.ContainsKey(key[i]))
//        {
//            eachLetterCount[key[i]]++;
//        }
//        else
//        {
//            eachLetterCount.Add(key[i], 1);
//        }
//    }

//    //To know the count of each number in the eachLetterCount
//    Dictionary<int,int> eachCountConut=new Dictionary<int,int>();
//    foreach(KeyValuePair<char,int> letterCount in eachLetterCount)
//    {
//        if (eachCountConut.ContainsKey(letterCount.Value))
//        {
//            eachCountConut[letterCount.Value]++;
//        }
//        else
//        {
//            eachCountConut.Add(letterCount.Value, 1);
//        }
//    }
//    // To Know the max repeated number which is the number that the word is repeated with
//    int maxRepeatedCount = -10;
//    foreach (KeyValuePair<int, int> letterCount in eachCountConut)
//    {
//        if(letterCount.Value > maxRepeatedCount)
//        {
//            maxRepeatedCount = letterCount.Value;
//        }
//    }
//    Console.WriteLine("MaxRepeatedCount:{0}",maxRepeatedCount);
//    Dictionary<String,int> subStrings=new Dictionary<String,int>();
//    for(int i=0;i<key.Length; i++)
//    {
//        for(int j = i; j < key.Length / maxRepeatedCount-1; j++)
//        {
//            //Console.WriteLine(key.Substring(i,j));
//            if (subStrings.ContainsKey(key.Substring(i, j)))
//            {
//                subStrings[key.Substring(i, j)]++;
//            }
//            else
//            {
//                subStrings.Add(key.Substring(i, j), 1);
//            }
//        }

//    }
//    foreach (KeyValuePair<string, int> subStringCount in subStrings)
//    {
//        Console.WriteLine("SubString:{0} ,RepeatedTimes:{1}",subStringCount.Key,subStringCount.Value);

//        if (subStringCount.Value == maxRepeatedCount-1)
//        {
//            key= subStringCount.Key;
//            break;
//        }
//    }


//    return key;
//}