using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public static string Insert_At(string stred, int pos, char val)  // 8
        {
            string str;
            string p1 = "";
            for (int i = 0; i < pos; i++)
            {
                p1 += stred[i];
            }
            string p2 = "";
            for (int i = pos; i < stred.Length; i++)
            {
                p2 += stred[i];
            }
            str = p1 + val + p2;
            return str;
        }
        public static void arrsorting(int[] unsortarr)
        {
            int temp;
            for (int i = 0; i < unsortarr.Length - 1; i++)
            {
                for (int j = 0; j < unsortarr.Length - (i + 1); j++)
                {
                    if (unsortarr[j] > unsortarr[j + 1])
                    {
                        temp = unsortarr[j + 1];
                        unsortarr[j + 1] = unsortarr[j];
                        unsortarr[j] = temp;
                    }
                }
            }
        }
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            List<List<char>> Key = new List<List<char>>();
            int Column = 0;
            int row = 0;
            int Count = 0;
            int found = 0;
            int Count2 = 1;
            // getting the length of the row 
            if (cipherText[0] == plainText[0])
            {
                for (int i = 1; i < plainText.Length; i++)
                {
                    if (plainText[i] == cipherText[1])
                    {
                        Column = i;
                        row = (int)Math.Round((Convert.ToDouble(plainText.Length) / Convert.ToDouble(Column)));
                        break;
                    }
                }
            }
            else
            {
                for (int i = 1; i < plainText.Length; i++)
                {
                    if (cipherText[0] == plainText[i])
                    {
                        if (cipherText[1] == plainText[i + 1])
                            i++;
                        for (int j = i + 2; j < plainText.Length; j++)
                        {
                            if (cipherText[1] == plainText[j])
                            {
                                Column = j - i;
                                double pl_len = Convert.ToDouble(plainText.Length);
                                double col_len = Convert.ToDouble(Column);
                                row = (int)Math.Round(pl_len / col_len);
                                found = 1;
                                break;
                            }
                        }
                    }
                    if (found == 1)
                        break;
                }
            }

            for (int i = 0; i < row; i++)
            {
                List<char> Rows_in_Matrx = new List<char>();
                for (int j = 0; j < Column; j++)
                {
                    if (Count >= plainText.Length)
                    {
                        Rows_in_Matrx.Add('x');
                        continue;
                    }
                    Rows_in_Matrx.Add(plainText[Count++]);
                }
                Key.Add(Rows_in_Matrx);
            }

            //return key of cipher
            int[] Get_Key = new int[Column];
            for (int i = 0; i < cipherText.Length - 1; i += row)
            {
                for (int j = 0; j < Column; j++)
                {
                    if (cipherText[i] == Key[0][j] && cipherText[i + 1] == Key[1][j])
                    {
                        Get_Key[j] = Count2;
                        break;
                    }
                }
                Count2++;
            }
            List<int> return_key = Get_Key.ToList<int>();
            return return_key;
        }


        public string Decrypt(string cipherText, List<int> key)
        {
            string str = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();
            string new_cipherText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < str.Length; j++)
                {
                    if (cipherText[i] == str[j])
                    {
                        new_cipherText += cipherText[i];
                    }
                }
            }

            int depth = key.Count;
            int LengthOfrow;  // length of row   3

            if (new_cipherText.Length % depth == 0)
            {
                LengthOfrow = new_cipherText.Length / depth;
            }
            else
            {
                int rem = new_cipherText.Length % depth;
                int len = new_cipherText.Length - rem;
                LengthOfrow = (len / depth) + 1;
            }
            int x = (depth * LengthOfrow) - new_cipherText.Length; // 3X
            int[] arr = new int[key.Count];
            int[] top_num = new int[x];
            int count2 = 0;
            if (new_cipherText.Length < (depth * LengthOfrow)) // 25 - 28 3
            {

                for (int i = 0; i < key.Count; i++)
                {
                    arr[i] = key[i];

                }
                for (int i = (arr.Length - x); i < arr.Length; i++)
                {
                    top_num[count2] = arr[i];
                    count2++;
                }

                for (int i = 0; i < top_num.Length; i++)
                {
                    new_cipherText = Insert_At(new_cipherText, (top_num[i] * LengthOfrow) - 1, 'x');
                }

            }



            char[,] Mat = new char[LengthOfrow, depth];  // 4,4  

            foreach (int i in key)
            {
                int count = (i - 1) * LengthOfrow;
                for (int j = 0; j < LengthOfrow; j++)
                {

                    Mat[j, i - 1] = new_cipherText[count];
                    count++;
                }
            }
            string plaintext = "";
            for (int i = 0; i < LengthOfrow; i++)
            {
                foreach (int j in key)
                {
                    plaintext += Mat[i, j - 1];
                }
            }
            return plaintext;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int[] key_arr = new int[key.Count]; // array of Get_Key : 1 4 3 2 
            int[] compare_arr = new int[key.Count];
            int[] carry_indexes = new int[key.Count];
            int count_key = 0;
            foreach (int i in key)
            {
                key_arr[count_key] = i;
                compare_arr[count_key] = i;
                count_key++;
            }
            arrsorting(compare_arr);

            int counter = 0;
            for (int i = 0; i < compare_arr.Length; i++)
            {
                for (int j = 0; j < key_arr.Length; j++)
                {
                    if (compare_arr[i] == key_arr[j])
                    {
                        carry_indexes[counter] = j;
                        counter++;
                    }
                }
            }


            int depth = key_arr.Length;
            string str = "abcdefghijklmnopqrstuvwxyz";
            string new_plainText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < str.Length; j++)
                {
                    if (plainText[i] == str[j])
                    {
                        new_plainText += plainText[i];
                    }
                }
            }

            //int depth = Get_Key.Count; // length of column   5    // need comment here for sec solu 
            int LengthOfrow;  // length of row   3

            if (new_plainText.Length % depth == 0)
            {
                LengthOfrow = new_plainText.Length / depth;
            }
            else
            {
                int rem = new_plainText.Length % depth;
                int len = new_plainText.Length - rem;
                LengthOfrow = (len / depth) + 1;
            }

            if (new_plainText.Length < (depth * LengthOfrow))
            {
                while (new_plainText.Length < (depth * LengthOfrow)) // 15 < 16 -> T  16 < 16 -> F
                {
                    new_plainText += 'x';
                }
            }

            char[,] Mat = new char[LengthOfrow, depth];  // 4,4            
            int count = 0;
            for (int i = 0; i < LengthOfrow; i++)  // 4
            {
                for (int j = 0; j < depth; j++)   // 4
                {
                    Mat[i, j] = new_plainText[count];
                    count++;
                }
            }

            string cipher_text = "";

            for (int i = 0; i < key_arr.Length; i++) //4
            {
                for (int j = 0; j < LengthOfrow; j++)  // 4
                {
                    cipher_text += Mat[j, carry_indexes[i]];
                }
            }


            /*
            // another solution 
            int coubterrr = 0;
            int [] c = new int[Get_Key.Count]; 
            for (int j = 1; j < Get_Key.Count; j++)           
            {
               foreach (int i in Get_Key)   
               {
                    if (j == i)
                    {
                        c[coubterrr]= j;
                        coubterrr++;
                    }
               }
            }
                       
            for (int i = 0; i < Get_Key.Count; i++) //4
            {
                for (int j = 0; j < LengthOfrow; j++)  // 4
                {
                    cipher_text += Mat[j, c[i]];
                }
            }
            */

            cipher_text = cipher_text.ToUpper();
            return cipher_text;

        }
    }
}
