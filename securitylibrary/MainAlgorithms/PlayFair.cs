using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string ciphertxt = handle_plaintext(cipherText);
            string str = decrypt_logic(cipherText, key);

            return str;
        }

        public string Encrypt(string plainText, string key)
        {
            string plaintxt = handle_plaintext(plainText);
            string str = encrypt_logic(plaintxt, key);

            return str;
        }

        public string handle_plaintext(string palin_text)
        {
            string tmp_plaintxt = palin_text;

            //check if a pair have the same leter add x
            int k = 0;

            for (int i = 0; ((i < tmp_plaintxt.Length) && ((i + 1) < tmp_plaintxt.Length)); i += 2)
            {
                if (tmp_plaintxt[i] == tmp_plaintxt[i + 1])
                {
                    tmp_plaintxt = tmp_plaintxt.Insert(i + 1, "X");
                }

                k++;
            }

            //check if odd append x at the end
            if (tmp_plaintxt.Length % 2 != 0)
                tmp_plaintxt += 'X';

            tmp_plaintxt = tmp_plaintxt.ToUpper();

            return tmp_plaintxt;
        }

        public char[,] generate_key_matrix(string key)
        {
            string defaultKeySquare = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            char[,] arr = new char[5, 5];
            key = key.ToUpper();

            //replace each J letter with the letter I
            key.Replace('J', 'I');

            string tmp_key = new String(key.Distinct().ToArray());
            tmp_key += defaultKeySquare;

            string tmp_key2 = new String(tmp_key.Distinct().ToArray());



            string str = tmp_key2.Substring(0, 25);
            Console.WriteLine(str);
            int k = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    arr[i, j] = str[k];
                    k++;
                }
            }



            return arr;
        }

        public void get_index(char[,] matrix, char ch, ref int row, ref int col)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == ch)
                    {
                        row = i;
                        col = j;
                    }
                }
            }

        }

        public string encrypt_logic(string input, string key)
        {

            StringBuilder result = new StringBuilder(input.ToUpper());
            for (int i = 0; i < input.Length; i += 2)
            {
                int row1 = 0;
                int row2 = 0;
                int col1 = 0;
                int col2 = 0;

                char[,] matrix = generate_key_matrix(key);

                get_index(matrix, input[i], ref row1, ref col1);

                get_index(matrix, input[i + 1], ref row2, ref col2);

                if (row1 == row2)
                {
                    result[i] = matrix[row1, (col1 + 1) % 5];
                    result[i + 1] = matrix[row2, (col2 + 1) % 5];
                }
                else if (col1 == col2)
                {
                    result[i] = matrix[(row1 + 1) % 5, col1];
                    result[i + 1] = matrix[(row2 + 1) % 5, col2];
                }
                else
                {
                    result[i] = matrix[row1, col2];
                    result[i + 1] = matrix[row2, col1]; ;
                }

            }

            string str_result = result.ToString();

            return str_result;
        }

        public string decrypt_logic(string input, string key)
        {

            StringBuilder result = new StringBuilder(input.ToUpper());
            for (int i = 0; i < input.Length; i += 2)
            {
                int row1 = 0;
                int row2 = 0;
                int col1 = 0;
                int col2 = 0;

                char[,] matrix = generate_key_matrix(key);

                get_index(matrix, input[i], ref row1, ref col1);

                get_index(matrix, input[i + 1], ref row2, ref col2);

                if (row1 == row2)
                {
                    result[i] = matrix[row1, (col1 + 4) % 5];
                    result[i + 1] = matrix[row2, (col2 + 4) % 5];
                }
                else if (col1 == col2)
                {
                    result[i] = matrix[(row1 + 4) % 5, col1];
                    result[i + 1] = matrix[(row2 + 4) % 5, col2];
                }
                else
                {
                    result[i] = matrix[row1, col2];
                    result[i + 1] = matrix[row2, col1]; ;
                }

            }


            string str = result.ToString();
            string val = str.Substring(0, 1);
            for (int i = 1; i < str.Length - 1; i++)
            {
                if (!(str[i] == 'X' && str[i - 1] == str[i + 1] && i % 2 != 0))
                {
                    val += str.Substring(i, 1);
                }
            }
            if (str[str.Length - 1] != 'X')
                val += str.Substring(str.Length - 1, 1);
            str = val.ToLower();

            return str;

            //for (int i = 1; i < result.Length - 1; i++)
            //{
            //    if ((result[i - 1] == result[i + 1]) && (result[i] == 'X') && (i % 2 != 0))
            //    {
            //        result = result.Remove(i, 1);
            //    }
            //    if (result[result.Length - 1] == 'X')
            //        result = result.Remove(result.Length - 1, 1);
            //}


            //  return result.ToString().ToUpper();
        }

    }
}