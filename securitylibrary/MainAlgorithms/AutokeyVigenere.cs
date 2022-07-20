using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {

        public char[,] GenerateMatrix()
        {
            string conn_value = "";
            string[] carry_alphap = new string[26];
            char[] carry_chars = new char[26];
            int count = 0;
            for (int i = 0; i < carry_alphap.Length; i++)
            {

                for (int j = 0; j < 26; j++)  // ( 97  98  99 )     ( 123 % 96 ) + 70 
                {
                    if ((j + 97 + count) <= 122)
                    {
                        carry_chars[j] = (char)(j + 97 + count);
                    }
                    else
                    {
                        carry_chars[j] = (char)(((j + 97 + count) % 96) + 70);
                    }
                }
                for (int k = 0; k < 26; k++)
                {
                    conn_value += carry_chars[k];
                }
                carry_alphap[i] = conn_value;
                conn_value = "";
                count++;
            }

            char[,] val = new char[26, 26];
            int count_full = 0;
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    val[i, j] = carry_alphap[count_full][j];
                }
                count_full++;
            }

            return val;
        }

        public char Get_Char_Plain(char key_char, char cip_char)
        {
            int cc = 0;
            string str = "abcdefghijklmnopqrstuvwxyz";
            for (int j = 0; j < 26; j++)
            {
                if (key_char == str[j])
                {
                    cc = j;
                }
            }

            char[,] mat = GenerateMatrix();
            int reee = 0;
            for (int j = 0; j < 26; j++)
            {
                if (cip_char == mat[j, cc])
                {
                    reee = j;
                }
            }
            char re = str[reee];
            return re;
        }




        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            string str = "abcdefghijklmnopqrstuvwxyz";
            int[] key_index = new int[plainText.Length];
            char[,] mat = GenerateMatrix();
            string key = "";
            // get indexes of key        
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < str.Length; j++)
                {
                    if (plainText[i] == str[j])
                    {
                        key_index[i] += j;
                    }
                }
            }
            int[] index_plain = new int[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == mat[j, key_index[i]])
                    {
                        index_plain[i] = j;
                    }
                }
            }
            for (int i = 0; i < index_plain.Length; i++)
            {
                key += str[index_plain[i]];
            }

            int count = 0;
            int[] length = new int[key.Length];
            for (int j = 0; j < key.Length; j++)
            {
                if (plainText[count] == key[j])
                {
                    length[count] = j;
                    count++;
                }
            }

            string new_key = "";
            int x = length[0], y = length[1], z = length[2];
            if (y - x == 1 || z - y == 1 || z - x == 2)
            {
                for (int i = 0; i < x; i++)
                {
                    new_key += key[i];
                }
            }

            if (y - x == 1 || z - y == 1 || z - x == 2)
            {
                return new_key;
            }
            else
            {
                return key;
            }
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string str = "abcdefghijklmnopqrstuvwxyz";
            int[] key_index = new int[key.Length];
            char[,] mat = GenerateMatrix();
            string plain_text = "";
            // get indexes of key        
            for (int i = 0; i < key.Length; i++)
            {
                for (int j = 0; j < str.Length; j++)
                {
                    if (key[i] == str[j])
                    {
                        key_index[i] += j;
                    }
                }
            }
            int[] index_plain = new int[key.Length];
            for (int i = 0; i < key.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == mat[j, key_index[i]])
                    {
                        index_plain[i] = j;
                    }
                }
            }

            for (int i = 0; i < index_plain.Length; i++)
            {
                plain_text += str[index_plain[i]];
            }

            if (plain_text.Length < cipherText.Length)
            {
                int count_pla = 0;
                int count_cip = key.Length;
                while (plain_text.Length < cipherText.Length)
                {
                    plain_text += Get_Char_Plain(plain_text[count_pla], cipherText[count_cip]);
                    count_pla++;
                    count_cip++;
                }
                return plain_text;
            }
            else
                return plain_text;

        }

        public string Encrypt(string plainText, string key)
        {
            char[] carry_me = new char[plainText.Length - key.Length];
            string car = "";
            string keeey = "";
            int index = 0;
            for (int i = 0; i < carry_me.Length; i++)
            {
                carry_me[i] = plainText[index];
                index++;
            }
            for (int i = 0; i < carry_me.Length; i++)
            {
                car += carry_me[i];
            }

            keeey = key + car;

            int cipher_index = 0;
            int Key_index = 0;
            string str = "abcdefghijklmnopqrstuvwxyz";

            char[,] matrix = GenerateMatrix();

            char[] ca = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (plainText[i] == str[j])
                    {
                        cipher_index = j;
                    }

                    if (keeey[i] == str[j])
                    {
                        Key_index = j;
                    }

                }
                ca[i] = matrix[cipher_index, Key_index];
            }
            string answer = "";
            for (int i = 0; i < ca.Length; i++)
            {
                answer += ca[i];
            }
            return answer;
        }

    }
}


/*
char[,] mat = GenerateMatrix();
string str = "abcdefghijklmnopqrstuvwxyz";
int[] key_index = new int[cipherText.Length];
//char[] output_index = new char [cipherText.Length];
string plain_text = "";
for (int i = 0; i < cipherText.Length; i++)
{
    for (int j = 0; j < str.Length; j++)
    {
        if (cipherText[i] == str[j])
        {
            key_index[i] = key[i];
        }
    }
}
for (int i = 0; i < cipherText.Length; i++)
{
    int result = (int)cipherText[i] - (int)key_index[i];
    if (result < 0)
    {
        result = -result;
    }
    plain_text += (char)(result + 97);
    //plain_text += output_index[i];
}
return plain_text;
*/





/*
  public string Decrypt(string cipherText, string key)
        {

            char[,] mat = GenerateMatrix();
            string str = "abcdefghijklmnopqrstuvwxyz";
            int[] key_index = new int[key.Length];
            string plain_text = "";
            for (int i = 0; i < key.Length; i++)
            {
                for (int j = 0; j < str.Length; j++)
                {
                    // update here
                    if (key[i] == str[j])
                    {
                        key_index[i] = j;             // key = ahmed --> 0 8 13 5 4
                    }
                }
            }
            int cipher_count = 0;
            for (int i = 0; i <= key_index.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (mat[key_index[i], j] == cipherText[cipher_count])
                    {
                        plain_text += str[j];
                    }
                }
                cipher_count++;
            }

            if (key.Length == cipherText.Length)
            {
                return plain_text;
            }

            else
            {
                int diff_len = cipherText.Length - key.Length;
                int[] complete = new int[diff_len];
                if (diff_len <= plain_text.Length)
                {                    
                    for (int i = 0; i < diff_len; i++)
                    {
                        for (int j = 0; j < str.Length; j++)
                        {
                            if (plain_text[i] == str[j])
                            {
                                complete[i] = plain_text[i];       // key = ahmed --> 0 8 13 5 4
                            }
                        }
                    }
                    int cipher_count2 = 0;
                    for (int i = 0; i <= complete.Length; i++)
                    {
                        for (int j = 0; j < 26; j++)
                        {
                             if (mat[complete[i], j] == cipherText[cipher_count2])
                             {
                                plain_text += str[j];
                             }
                        }
                        cipher_count2++;
                    }
                    return plain_text;
                }
                else 
                {
                    int length_for_step = plain_text.Length;
                    double value = diff_len / plain_text.Length; //15.5555
                    int times_of_diff = (int) Math.Floor(value); // round down  15 time                   
                    int last_position_start = times_of_diff * length_for_step;
                    int mod_value = diff_len % plain_text.Length; // 0.5555 ->  3
                    int count = 0; 
                    while (times_of_diff != 0) 
                    { 
                        for (int i = 0; i < plain_text.Length ; i++)
                        {
                            for (int j = 0; j < str.Length; j++)
                            {
                                if (plain_text[i] == str[j])
                                {
                                    complete[i] = plain_text[i + count];
                                }
                            }
                        }
                        
                        int cipher_count2 = 0;
                        for (int i = 0; i <= complete.Length; i++)
                        {
                            for (int j = 0; j < 26; j++)
                            {
                                if (mat[complete[i], j] == cipherText[cipher_count2])
                                {
                                    plain_text += str[j];
                                }
                            }
                            cipher_count2++;
                        }

                        count += length_for_step;
                        times_of_diff--;
                    }


                    for (int i = 0; i < mod_value; i++)
                    {
                        for (int j = 0; j < str.Length; j++)
                        {
                            if (plain_text[i] == str[j])
                            {
                                complete[i] = plain_text[i + last_position_start];
                            }
                        }
                    }

                    int cipher_count3 = 0;
                    for (int i = 0; i <= complete.Length; i++)
                    {
                        for (int j = 0; j < 26; j++)
                        {
                            if (mat[complete[i], j] == cipherText[cipher_count3])
                            {
                                plain_text += str[j];
                            }
                        }
                        cipher_count3++;
                    }

                    return plain_text;
                }
            }
        }

 */