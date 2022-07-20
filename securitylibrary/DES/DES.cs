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
    /// 

    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            int[] Bit_64_plain = new int[64];
            convert_text_to_binary(Bit_64_plain, cipherText);
            int[,] mat_plain = new int[8, 8];
            perm_Plain_text(Bit_64_plain, mat_plain);
            string IP = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    IP += mat_plain[i, j];
                }
            }
            //------------------------------------------------------//



            //permution for key
            int[] Bit_64_Key = new int[64];
            convert_text_to_binary(Bit_64_Key, key);
            int[,] mat_key = new int[8, 7];
            perm_Key_Text(Bit_64_Key, mat_key);

            //Get C & D Matrix
            int count = 0;
            int[] new_key = new int[56];
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    new_key[count] = mat_key[i, j];
                    count++;
                }
            }

            int[] C = new int[new_key.Length / 2];
            int[] D = new int[new_key.Length / 2];
            for (int i = 0; i < new_key.Length / 2; i++)
            {
                C[i] = new_key[i];
            }
            int counter = 0;
            for (int i = new_key.Length / 2; i < new_key.Length; i++)
            {
                D[counter] = new_key[i];
                counter++;
            }
            //---------------------------------------------//

            //Shift Left One bit
            //shift 2 bits
            // perm 2 
            // list carry all keys in 16 round
            List<int[]> All_Keys = new List<int[]>();
            int Round_Key = 1;
            while (Round_Key != 17)
            {
                int[] keyCD = new int[48];
                int[] Last_key = new int[C.Length + D.Length];
                int[,] mat_Key_perm2 = new int[8, 6];

                if (Round_Key == 1 || Round_Key == 2 || Round_Key == 9 || Round_Key == 16)
                {
                    Shift_Left_one_bit(C);
                    Shift_Left_one_bit(D);

                    int cnt = 0;
                    for (int i = 0; i < Last_key.Length; i++)
                    {
                        if (i >= C.Length)
                        {
                            Last_key[i] = D[cnt];
                            cnt++;
                            continue;
                        }
                        Last_key[i] = C[i];
                    }
                    perm_Two_Key_Text(Last_key, mat_Key_perm2);
                    int c1 = 0;
                    for (int i = 0; i < 8; i++)
                    {
                        for (int j = 0; j < 6; j++)
                        {
                            keyCD[c1] = mat_Key_perm2[i, j];
                            c1++;
                        }
                    }
                    All_Keys.Add(keyCD);
                }
                else
                {
                    Shift_Left_Two_bit(C);
                    Shift_Left_Two_bit(D);
                    int cnt2 = 0;
                    for (int i = 0; i < Last_key.Length; i++)
                    {
                        if (i >= C.Length)
                        {
                            Last_key[i] = D[cnt2];
                            cnt2++;
                            continue;
                        }
                        Last_key[i] = C[i];
                    }

                    perm_Two_Key_Text(Last_key, mat_Key_perm2);
                    int c2 = 0;
                    for (int i = 0; i < 8; i++)
                    {
                        for (int j = 0; j < 6; j++)
                        {
                            keyCD[c2] = mat_Key_perm2[i, j];
                            c2++;
                        }
                    }
                    All_Keys.Add(keyCD);
                }
                Round_Key++;
            }


            // Now Back To Plain >>>> Again shit here we go again
            // divide IP >> LEFT and RIGHT
            List<int[]> Left_List = new List<int[]>();
            List<int[]> Right_List = new List<int[]>();
            int[] Left_IP = new int[IP.Length / 2];
            int[] Right_IP = new int[IP.Length / 2];
            int Right_IPCount = 0;
            for (int i = 0; i < IP.Length / 2; i++)
            {
                Left_IP[i] = IP[i] - 48;
            }
            for (int i = IP.Length / 2; i < IP.Length; i++)
            {
                Right_IP[Right_IPCount] = IP[i] - 48;
                Right_IPCount++;
            }

            Left_List.Add(Left_IP);
            Right_List.Add(Right_IP);
            int k = 15;

            for (int i = 0; i < 16; i++)
            {
                Left_List.Add(Right_List[i]);

                // expand then Xor with key0 
                int[] new_right_IP = new int[48];
                Expand_Right(Right_List[i], new_right_IP);
                //
                int[] value = new int[48];
                Key_Xor_Right(All_Keys[k], new_right_IP, value);

                // divide value >> key after Xor in List and each index carry 6 index for s1...s8
                int[] key_for_round1 = new int[32];
                from_S1_TO_S8(value, key_for_round1);
                //
                int[] permed_key3 = new int[32];
                permutation_3(key_for_round1, permed_key3);
                //
                int[] last_Right = new int[32];
                vale_Xor_left(permed_key3, Left_List[i], last_Right);     //R1 = left_ip >>> L2 = R1 //// L1 = R0

                Right_List.Add(last_Right);
                k--;
            }
            int[] L16 = new int[32];
            int[] R16 = new int[32];
            R16 = Right_List.LastOrDefault();
            L16 = Left_List.LastOrDefault();

            int[] full_key = new int[L16.Length + R16.Length];

            for (int i = 0; i < full_key.Length / 2; i++)
            {
                full_key[i] = R16[i];
            }

            for (int i = 0; i < L16.Length; i++)
            {
                Console.Write(L16[i]);
            }
            Console.WriteLine("\n");
            for (int i = 0; i < R16.Length; i++)
            {
                Console.Write(R16[i]);
            }
            Console.WriteLine("\n");
            int countee = 0;
            for (int i = full_key.Length / 2; i < full_key.Length; i++)
            {
                full_key[i] = L16[countee];
                countee++;
            }

            int[] last_arr = new int[64];
            last_permutation(full_key, last_arr);

            string x = "";
            convert_from_binary_to_hexa(last_arr, ref x);
            return x;
        }

        public static void convert_text_to_binary(int[] arr, string text)
        {
            int count = 0;
            string s2 = "";
            for (int i = 2; i < text.Length; i++)
            {
                s2 = Convert.ToString(Convert.ToInt32(text[i].ToString(), 16), 2).PadLeft(4, '0');
                for (int j = 0; j < s2.Length; j++)
                {
                    arr[count] = s2[j];
                    arr[count] -= 48;
                    count++;
                }
            }
        }
        public static void perm_Plain_text(int[] arr, int[,] mat)
        {
            int[] perm_number = new int[64];
            int x = 58;
            int y = 57;
            for (int i = 0; i < perm_number.Length / 2; i++)
            {
                perm_number[i] = x;
                if (x <= 6)
                {
                    x = x - 6;
                    x = x + 72;
                }
                x -= 8;
            }
            for (int i = perm_number.Length / 2; i < perm_number.Length; i++)
            {
                perm_number[i] = y;
                if (y <= 6)
                {
                    y = y - 6;
                    y = y + 72;
                }
                y -= 8;
            }

            int count = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    mat[i, j] = arr[perm_number[count] - 1];
                    count++;
                }
            }
        }

        public static void perm_Key_Text(int[] arr, int[,] mat)
        {
            int[] key_numbers = new int[56] {57,49,41,33,25,17,9,1 ,58 ,50, 42, 34 ,26, 18,
            10, 2, 59, 51, 43, 35 ,27,19 ,11 ,3 ,60, 52, 44, 36,63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,14, 6, 61, 53, 45 ,37, 29,21, 13, 5, 28, 20, 12, 4};

            int count = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    mat[i, j] = arr[key_numbers[count] - 1];
                    count++;
                }
            }

        }

        public static void perm_Two_Key_Text(int[] arr, int[,] mat)
        {
            int[] key_numbers = new int[48] {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32};

            int count = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    mat[i, j] = arr[key_numbers[count] - 1];
                    count++;
                }
            }

        }

        public static void Shift_Left_one_bit(int[] arr)
        {
            int x = arr[0];
            for (int i = 0; i < arr.Length - 1; i++)
            {
                arr[i] = arr[i + 1];
            }
            arr[arr.Length - 1] = x;
        }

        public static void Shift_Left_Two_bit(int[] arr)
        {
            Shift_Left_one_bit(arr);
            Shift_Left_one_bit(arr);
        }

        // function to expand the ripht_IP 
        public static void Expand_Right(int[] Right, int[] NewRight)
        {
            int[] New_Right = new int[48] {32, 1, 2 ,3 ,4 ,5, 4 ,5 ,6, 7 ,8, 9,8 ,9 ,10 ,11, 12, 13,
            12 ,13 ,14, 15, 16, 17,16, 17, 18, 19, 20, 21, 20 ,21 ,22 ,23, 24, 25,
            24, 25 ,26 ,27 ,28, 29, 28, 29, 30, 31, 32, 1};

            int[,] mat = new int[8, 6];
            int count = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    mat[i, j] = Right[New_Right[count] - 1];
                    count++;
                }
            }

            int newcount = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    NewRight[newcount] = mat[i, j];
                    newcount++;
                }
            }
        }

        // function to calculate key xor right_IP 
        public static void Key_Xor_Right(int[] Key, int[] Right, int[] answer)
        {
            int count = 0;
            for (int i = 0; i < 48; i++)
            {
                if (Key[i] == Right[i])
                {
                    answer[count] = 0;
                }
                if (Key[i] != Right[i])
                {
                    answer[count] = 1;
                }
                count++;
            }
        }

        public static void S1(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64] {14 ,4 ,13, 1, 2 ,15, 11, 8 ,3, 10 ,6 ,12 ,5, 9, 0, 7,
             0, 15 ,7, 4 ,14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
             4, 1, 14 ,8, 13, 6 ,2 ,11, 15, 12, 9 ,7, 3, 10, 5, 0,
             15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0 ,6 ,13};

            int count = 0;
            int[,] mat = new int[4, 16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    mat[i, j] = New_Right[count];
                    count++;
                }
            }

            string row = ArrS1[0].ToString() + ArrS1[5].ToString();
            string col = ArrS1[1].ToString() + ArrS1[2].ToString() + ArrS1[3].ToString() + ArrS1[4].ToString();

            int row_val = int.Parse(Convert.ToInt32(row, 2).ToString());
            int col_val = int.Parse(Convert.ToInt32(col, 2).ToString());

            int x = mat[row_val, col_val];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }

        }

        public static void S2(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64] {15 ,1 ,8 ,14, 6, 11, 3 ,4, 9, 7, 2, 13, 12, 0, 5, 10,
             3, 13, 4 ,7 ,15, 2 ,8 ,14, 12, 0, 1, 10, 6, 9, 11, 5,
             0, 14, 7 ,11, 10, 4 ,13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
             13, 8, 10, 1, 3, 15, 4, 2, 11, 6 ,7 ,12, 0, 5, 14, 9};

            int count = 0;
            int[,] mat = new int[4, 16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    mat[i, j] = New_Right[count];
                    count++;
                }
            }


            string row = ArrS1[0].ToString() + ArrS1[5].ToString();
            string col = ArrS1[1].ToString() + ArrS1[2].ToString() + ArrS1[3].ToString() + ArrS1[4].ToString();

            int row_val = int.Parse(Convert.ToInt32(row, 2).ToString());
            int col_val = int.Parse(Convert.ToInt32(col, 2).ToString());

            int x = mat[row_val, col_val];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }

        }

        public static void S3(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64] {10, 0 ,9 ,14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7 ,0 ,9 ,3 ,4 ,6 ,10 ,2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5 ,10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7 ,4 ,15, 14, 3, 11, 5, 2, 12};

            int count = 0;
            int[,] mat = new int[4, 16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    mat[i, j] = New_Right[count];
                    count++;
                }
            }

            string row = ArrS1[0].ToString() + ArrS1[5].ToString();
            string col = ArrS1[1].ToString() + ArrS1[2].ToString() + ArrS1[3].ToString() + ArrS1[4].ToString();

            int row_val = int.Parse(Convert.ToInt32(row, 2).ToString());
            int col_val = int.Parse(Convert.ToInt32(col, 2).ToString());

            int x = mat[row_val, col_val];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }

        }

        public static void S4(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64] {7, 13, 14, 3 ,0 ,6 ,9 ,10 ,1 ,2 ,8, 5, 11, 12, 4, 15,
             13, 8 ,11 ,5 ,6 ,15, 0 ,3 ,4 ,7 ,2 ,12, 1, 10, 14, 9,
             10 ,6 ,9 ,0 ,12 ,11, 7 ,13 ,15, 1, 3, 14, 5, 2, 8, 4,
             3, 15, 0 ,6 ,10, 1, 13, 8 ,9 ,4, 5, 11, 12, 7, 2, 14};

            int count = 0;
            int[,] mat = new int[4, 16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    mat[i, j] = New_Right[count];
                    count++;
                }
            }

            string row = ArrS1[0].ToString() + ArrS1[5].ToString();
            string col = ArrS1[1].ToString() + ArrS1[2].ToString() + ArrS1[3].ToString() + ArrS1[4].ToString();

            int row_val = int.Parse(Convert.ToInt32(row, 2).ToString());
            int col_val = int.Parse(Convert.ToInt32(col, 2).ToString());

            int x = mat[row_val, col_val];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }

        }

        public static void S5(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64] {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
             4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3};

            int count = 0;
            int[,] mat = new int[4, 16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    mat[i, j] = New_Right[count];
                    count++;
                }
            }
            string row = ArrS1[0].ToString() + ArrS1[5].ToString();
            string col = ArrS1[1].ToString() + ArrS1[2].ToString() + ArrS1[3].ToString() + ArrS1[4].ToString();

            int row_val = int.Parse(Convert.ToInt32(row, 2).ToString());
            int col_val = int.Parse(Convert.ToInt32(col, 2).ToString());

            int x = mat[row_val, col_val];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }

        }

        public static void S6(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64] {12 ,1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13};

            int count = 0;
            int[,] mat = new int[4, 16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    mat[i, j] = New_Right[count];
                    count++;
                }
            }

            string row = ArrS1[0].ToString() + ArrS1[5].ToString();
            string col = ArrS1[1].ToString() + ArrS1[2].ToString() + ArrS1[3].ToString() + ArrS1[4].ToString();

            int row_val = int.Parse(Convert.ToInt32(row, 2).ToString());
            int col_val = int.Parse(Convert.ToInt32(col, 2).ToString());

            int x = mat[row_val, col_val];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }
        }


        public static void S7(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64] {4 ,11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12};

            int count = 0;
            int[,] mat = new int[4, 16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    mat[i, j] = New_Right[count];
                    count++;
                }
            }

            string row = ArrS1[0].ToString() + ArrS1[5].ToString();
            string col = ArrS1[1].ToString() + ArrS1[2].ToString() + ArrS1[3].ToString() + ArrS1[4].ToString();

            int row_val = int.Parse(Convert.ToInt32(row, 2).ToString());
            int col_val = int.Parse(Convert.ToInt32(col, 2).ToString());

            int x = mat[row_val, col_val];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }
        }


        public static void S8(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64] {13 ,2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11};

            int count = 0;
            int[,] mat = new int[4, 16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    mat[i, j] = New_Right[count];
                    count++;
                }
            }

            string row = ArrS1[0].ToString() + ArrS1[5].ToString();
            string col = ArrS1[1].ToString() + ArrS1[2].ToString() + ArrS1[3].ToString() + ArrS1[4].ToString();

            int row_val = int.Parse(Convert.ToInt32(row, 2).ToString());
            int col_val = int.Parse(Convert.ToInt32(col, 2).ToString());

            int x = mat[row_val, col_val];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }
        }



        public static void from_S1_TO_S8(int[] value, int[] key_xor_right_final)
        {
            List<int[]> value_div = new List<int[]>();
            int valCount = 0;
            int counter_for_value = 0;
            while (valCount != 8)
            {
                int[] arr = new int[6];
                for (int i = 0; i < 6; i++)
                {
                    arr[i] = value[counter_for_value];
                    counter_for_value++;
                }
                value_div.Add(arr);
                valCount++;
            }
            int count_key_xor_right_final = 0;
            int collectKey = 0;
            while (collectKey != 8)
            {
                int[] x = new int[4];
                if (collectKey == 0)
                    S1(x, value_div[0]);
                else if (collectKey == 1)
                    S2(x, value_div[1]);
                else if (collectKey == 2)
                    S3(x, value_div[2]);
                else if (collectKey == 3)
                    S4(x, value_div[3]);
                else if (collectKey == 4)
                    S5(x, value_div[4]);
                else if (collectKey == 5)
                    S6(x, value_div[5]);
                else if (collectKey == 6)
                    S7(x, value_div[6]);
                else
                    S8(x, value_div[7]);

                for (int i = 0; i < 4; i++)
                {
                    key_xor_right_final[count_key_xor_right_final] = x[i] - 48;
                    count_key_xor_right_final++;
                }
                collectKey++;
            }
        }

        /////////////////////////////////


        public static void permutation_3(int[] enter, int[] back)
        {
            int[] New_Right = new int[32] {16, 7 ,20, 21,29, 12 ,28, 17,1 ,
                    15, 23, 26,5, 18 ,31, 10,
                    2 ,8 ,24, 14,32, 27, 3, 9, 19, 13, 30, 6,22, 11, 4, 25};

            int count = 0;
            int[,] mat = new int[8, 4];
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mat[i, j] = enter[New_Right[count] - 1];
                    count++;
                }
            }
            int counter = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    back[counter] = mat[i, j];
                    counter++;
                }
            }
        }


        // function take asnwer from top function and Xor with left
        public static void vale_Xor_left(int[] last_xor, int[] NewLeft, int[] Lastright)
        {
            int count = 0;
            for (int i = 0; i < 32; i++)
            {
                if (NewLeft[i] == last_xor[i])
                {
                    Lastright[count] = 0;
                }
                if (NewLeft[i] != last_xor[i])
                {
                    Lastright[count] = 1;
                }
                count++;
            }
        }


        public static void last_permutation(int[] last_enter, int[] last_back)
        {
            int[] per = {40, 8, 48 ,16, 56, 24, 64, 32,39, 7, 47, 15, 55, 23, 63, 31,38, 6, 46, 14, 54, 22, 62, 30,
                  37, 5, 45, 13, 53, 21, 61, 29,36, 4, 44, 12, 52, 20, 60, 28,35, 3, 43, 11, 51, 19, 59, 27,
                  34, 2, 42, 10, 50, 18, 58, 26,
                  33, 1, 41, 9, 49, 17, 57,25};
            int count = 0;
            int[,] mat = new int[8, 8];
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    mat[i, j] = last_enter[per[count] - 1];
                    count++;
                }
            }
            int counter = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    last_back[counter] = mat[i, j];
                    counter++;
                }
            }

        }

        public static void convert_from_binary_to_hexa(int[] arr, ref string hexa)
        {

            Dictionary<string, char> Binary = new Dictionary<string, char>();
            Binary["0000"] = '0';
            Binary["0001"] = '1';
            Binary["0010"] = '2';
            Binary["0011"] = '3';
            Binary["0100"] = '4';
            Binary["0101"] = '5';
            Binary["0110"] = '6';
            Binary["0111"] = '7';
            Binary["1000"] = '8';
            Binary["1001"] = '9';
            Binary["1010"] = 'A';
            Binary["1011"] = 'B';
            Binary["1100"] = 'C';
            Binary["1101"] = 'D';
            Binary["1110"] = 'E';
            Binary["1111"] = 'F';


            string str = "0x";
            string first_four_bits = "";

            for (int i = 0; i < arr.Length; i += 4)
            {

                first_four_bits += arr[i].ToString(); ;
                first_four_bits += arr[i + 1].ToString();
                first_four_bits += arr[i + 2].ToString();
                first_four_bits += arr[i + 3].ToString();


                str += Binary[first_four_bits];
                first_four_bits = "";
            }
            hexa = str;

        }

        public override string Encrypt(string plainText, string key)
        {
            // initial permution for plain text
            int[] Bit_64_plain = new int[64];
            convert_text_to_binary(Bit_64_plain, plainText);
            int[,] mat_plain = new int[8, 8];
            perm_Plain_text(Bit_64_plain, mat_plain);
            string IP = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    IP += mat_plain[i, j];
                }
            }
            //------------------------------------------------------//



            //permution for key
            int[] Bit_64_Key = new int[64];
            convert_text_to_binary(Bit_64_Key, key);
            int[,] mat_key = new int[8, 7];
            perm_Key_Text(Bit_64_Key, mat_key);

            //Get C & D Matrix
            int count = 0;
            int[] new_key = new int[56];
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    new_key[count] = mat_key[i, j];
                    count++;
                }
            }

            int[] C = new int[new_key.Length / 2];
            int[] D = new int[new_key.Length / 2];
            for (int i = 0; i < new_key.Length / 2; i++)
            {
                C[i] = new_key[i];
            }
            int counter = 0;
            for (int i = new_key.Length / 2; i < new_key.Length; i++)
            {
                D[counter] = new_key[i];
                counter++;
            }
            //---------------------------------------------//

            //Shift Left One bit
            //shift 2 bits
            // perm 2 
            // list carry all keys in 16 round
            List<int[]> All_Keys = new List<int[]>();
            int Round_Key = 1;
            while (Round_Key != 17)
            {
                int[] keyCD = new int[48];
                int[] Last_key = new int[C.Length + D.Length];
                int[,] mat_Key_perm2 = new int[8, 6];

                if (Round_Key == 1 || Round_Key == 2 || Round_Key == 9 || Round_Key == 16)
                {
                    Shift_Left_one_bit(C);
                    Shift_Left_one_bit(D);

                    int cnt = 0;
                    for (int i = 0; i < Last_key.Length; i++)
                    {
                        if (i >= C.Length)
                        {
                            Last_key[i] = D[cnt];
                            cnt++;
                            continue;
                        }
                        Last_key[i] = C[i];
                    }
                    perm_Two_Key_Text(Last_key, mat_Key_perm2);
                    int c1 = 0;
                    for (int i = 0; i < 8; i++)
                    {
                        for (int j = 0; j < 6; j++)
                        {
                            keyCD[c1] = mat_Key_perm2[i, j];
                            c1++;
                        }
                    }
                    All_Keys.Add(keyCD);
                }
                else
                {
                    Shift_Left_Two_bit(C);
                    Shift_Left_Two_bit(D);
                    int cnt2 = 0;
                    for (int i = 0; i < Last_key.Length; i++)
                    {
                        if (i >= C.Length)
                        {
                            Last_key[i] = D[cnt2];
                            cnt2++;
                            continue;
                        }
                        Last_key[i] = C[i];
                    }

                    perm_Two_Key_Text(Last_key, mat_Key_perm2);
                    int c2 = 0;
                    for (int i = 0; i < 8; i++)
                    {
                        for (int j = 0; j < 6; j++)
                        {
                            keyCD[c2] = mat_Key_perm2[i, j];
                            c2++;
                        }
                    }
                    All_Keys.Add(keyCD);
                }
                Round_Key++;
            }


            // Now Back To Plain >>>> Again shit here we go again
            // divide IP >> LEFT and RIGHT
            List<int[]> Left_List = new List<int[]>();
            List<int[]> Right_List = new List<int[]>();
            int[] Left_IP = new int[IP.Length / 2];
            int[] Right_IP = new int[IP.Length / 2];
            int Right_IPCount = 0;
            for (int i = 0; i < IP.Length / 2; i++)
            {
                Left_IP[i] = IP[i] - 48;
            }
            for (int i = IP.Length / 2; i < IP.Length; i++)
            {
                Right_IP[Right_IPCount] = IP[i] - 48;
                Right_IPCount++;
            }

            Left_List.Add(Left_IP);
            Right_List.Add(Right_IP);

            for (int i = 0; i < 16; i++)
            {
                Left_List.Add(Right_List[i]);

                // expand then Xor with key0 
                int[] new_right_IP = new int[48];
                Expand_Right(Right_List[i], new_right_IP);
                //
                int[] value = new int[48];
                Key_Xor_Right(All_Keys[i], new_right_IP, value);

                // divide value >> key after Xor in List and each index carry 6 index for s1...s8
                int[] key_for_round1 = new int[32];
                from_S1_TO_S8(value, key_for_round1);
                //
                int[] permed_key3 = new int[32];
                permutation_3(key_for_round1, permed_key3);
                //
                int[] last_Right = new int[32];
                vale_Xor_left(permed_key3, Left_List[i], last_Right);     //R1 = left_ip >>> L2 = R1 //// L1 = R0

                Right_List.Add(last_Right);
            }
            int[] L16 = new int[32];
            int[] R16 = new int[32];
            R16 = Right_List.LastOrDefault();
            L16 = Left_List.LastOrDefault();

            int[] full_key = new int[L16.Length + R16.Length];

            for (int i = 0; i < full_key.Length / 2; i++)
            {
                full_key[i] = R16[i];
            }

            for (int i = 0; i < L16.Length; i++)
            {
                Console.Write(L16[i]);
            }
            Console.WriteLine("\n");
            for (int i = 0; i < R16.Length; i++)
            {
                Console.Write(R16[i]);
            }
            Console.WriteLine("\n");
            int countee = 0;
            for (int i = full_key.Length / 2; i < full_key.Length; i++)
            {
                full_key[i] = L16[countee];
                countee++;
            }

            int[] last_arr = new int[64];
            last_permutation(full_key, last_arr);

            string x = "";
            convert_from_binary_to_hexa(last_arr, ref x);
            return x;
        }
    }
}
