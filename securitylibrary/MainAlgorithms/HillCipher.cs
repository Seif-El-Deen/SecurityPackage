using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> Key = new List<int>();

            for (int index = 0, count = 2; index < 2; index++, count += 2)
            {
                for (int res1 = 0; res1 < 26; res1++)
                {
                    for (int res2 = 0; res2 < 26; res2++)
                    {
                        if (((res1 * plainText[0]) + (res2 * plainText[1])) % 26 == cipherText[index] &&
                            ((res1 * plainText[2]) + (res2 * plainText[3])) % 26 == cipherText[index + 2])
                        {
                            Key.Add(res1);
                            Key.Add(res2);
                            break;
                        }
                    }
                    if (Key.Count == count)
                        break;
                }
            }
            if (Key.Count < 4)
                throw new InvalidAnlysisException();

            return Key;
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
        /************/
        private int[,] ConvertListToMatrix(List<int> key)
        {
            int[,] keyMatrix;
            int count;
            if (key.Count % 2 == 0)
            {
                keyMatrix = new int[2, 2];
                count = 0;
                for (int x = 0; x < 2; x++)
                {
                    for (int y = 0; y < 2; y++)
                    {
                        keyMatrix[x, y] = key[count];
                        count++;
                    }
                }
            }
            else if (key.Count % 3 == 0)
            {
                keyMatrix = new int[3, 3];
                count = 0;
                for (int x = 0; x < 3; x++)
                {
                    for (int y = 0; y < 3; y++)
                    {
                        keyMatrix[x, y] = key[count];
                        count++;
                    }
                }
            }
            else
            {
                keyMatrix = new int[3, 2];
            }
            return keyMatrix;
        }
        /************/

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plain = new List<int>();

            int m = (int)Math.Sqrt(key.Count);
            List<List<int>> keymat = generate_matrix(key, m, true);//true if we generate a key matrix
            List<List<int>> cipher_mat = generate_matrix(cipherText, m, false); //false if we generate a non key matrix

            int[,] keymatrix = this.ConvertListToMatrix(key);
            if (keymatrix.GetLength(0) != keymatrix.GetLength(1))
                throw new System.Exception();

            foreach (List<int> keyrow in keymat)
            {
                if (keyrow.Count != keymat.Count)
                    throw new System.Exception();
            }

            keymat = GetInverse(keymat, m);

            for (int i = 0; i < cipherText.Count / m; i++)
            {
                List<int> tmp = MultiblyMatrix(keymat, cipher_mat[i], m);
                for (int j = 0; j < m; j++)
                {
                    plain.Add(tmp[j]);
                }
            }
            if (plain.FindAll(s => s.Equals(0)).Count == plain.Count)
                throw new System.Exception();

            return plain;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipher = new List<int>();

            int m = (int)Math.Sqrt(key.Count);
            List<List<int>> keymat = generate_matrix(key, m, true);//true if we generate a key matrix
            List<List<int>> plain_mat = generate_matrix(plainText, m, false); //false if we generate a non key matrix

            for (int i = 0; i < plainText.Count / m; i++)
            {
                List<int> tmp = MultiblyMatrix(keymat, plain_mat[i], m);
                for (int j = 0; j < m; j++)
                {
                    cipher.Add(tmp[j]);
                }
            }
            return cipher;

        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<int> Key = new List<int>();

            for (int i = 0, count = 3; i < 3; i++, count += 3)
            {
                for (int res1 = 0; res1 < 26; res1++)
                {
                    for (int res2 = 0; res2 < 26; res2++)
                    {
                        for (int res3 = 0; res3 < 26; res3++)
                        {
                            if (((res1 * plain3[0]) + (res2 * plain3[1]) + (res3 * plain3[2])) % 26 == cipher3[i] &&
                                ((res1 * plain3[3]) + (res2 * plain3[4]) + (res3 * plain3[5])) % 26 == cipher3[i + 3] &&
                                ((res1 * plain3[6]) + (res2 * plain3[7]) + (res3 * plain3[8])) % 26 == cipher3[i + 6])
                            {
                                Key.Add(res1);
                                Key.Add(res2);
                                Key.Add(res3);
                                break;
                            }
                        }
                        if (Key.Count == count)
                            break;
                    }
                    if (Key.Count == count)
                        break;
                }
            }
            return Key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }

        private List<List<int>> generate_matrix(List<int> key, int m, bool iskey)
        {
            List<List<int>> result = new List<List<int>>();
            int rows = key.Count / m;

            if (iskey)
                rows = m;


            int index = 0;
            for (int i = 0; i < rows; i++)
            {
                List<int> row_elements = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    row_elements.Add(key[index]);
                    index++;
                }
                result.Add(row_elements);
            }


            return result;
        }
        private List<int> MultiblyMatrix(List<List<int>> key, List<int> MatRow, int m)
        {
            List<int> result = new List<int>();
            foreach (List<int> keyRow in key)
            {
                int tmp = 0;
                for (int i = 0; i < m; i++)
                {
                    tmp += keyRow[i] * MatRow[i];
                }
                tmp %= 26;
                while (tmp < 0)
                    tmp += 26;
                result.Add(tmp);
            }
            return result;
        }



        private List<List<int>> GetInverse(List<List<int>> keymat, int m)
        {
            int determinant = GetDeterminant(keymat, m);
            while (determinant < 0)
                determinant += 26;

            determinant = findB(determinant);

            if (m == 2)
            {
                int tmp = keymat[0][0] * determinant;

                keymat[0][0] = keymat[1][1] * determinant;
                keymat[1][1] = tmp;
                keymat[0][1] *= (-1 * determinant);
                keymat[1][0] *= (-1 * determinant);

                return keymat;
            }
            keymat = GetMinorMat(keymat, m);
            keymat = GetCoFacMat(keymat, m);

            for (int i = 0; i < m; i++)
                for (int j = 0; j < m; j++)
                    keymat[i][j] *= determinant;

            keymat = GetAdjointMat(keymat, m);

            return keymat;
        }
        private List<List<int>> GetAdjointMat(List<List<int>> mat, int m)
        {
            for (int i = 0; i < m; i++)
            {
                for (int j = i + 1; j < m; j++)
                {
                    int tmp = mat[i][j];
                    mat[i][j] = mat[j][i];
                    mat[j][i] = tmp;
                }
            }
            return mat;
        }
        private List<List<int>> GetCoFacMat(List<List<int>> mat, int m)
        {
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    if ((i + j) % 2 != 0)
                    {
                        mat[i][j] *= -1;
                    }
                }
            }
            return mat;
        }
        private List<List<int>> GetMinorMat(List<List<int>> mat, int m)
        {
            List<List<int>> result = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> res = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    List<List<int>> tmp1 = new List<List<int>>();
                    for (int k = 0; k < m; k++)
                    {
                        List<int> tmp2 = new List<int>();
                        for (int l = 0; l < m; l++)
                        {
                            if (k != i && l != j)
                            {
                                tmp2.Add(mat[k][l]);
                            }
                        }
                        if (tmp2.Count != 0)
                        {
                            tmp1.Add(tmp2);
                        }

                    }
                    int min = GetDeterminant(tmp1, m - 1);
                    res.Add(min);
                }
                result.Add(res);
            }

            return result;
        }
        private int findB(int det)
        {
            int res = 0;
            for (int i = 2; i < 26; i++)
            {
                if (((i * det) % 26) == 1)
                {
                    res = i;
                    break;
                }

            }
            return res;
        }

        private int GetDeterminant(List<List<int>> keymat, int m)
        {
            int determinant = 0;

            if (m == 2)
            {
                determinant = keymat[0][0] * keymat[1][1] - keymat[1][0] * keymat[0][1];
                return determinant;
            }
            else
            {
                for (int i = 0; i < 3; i++)
                    determinant += (keymat[0][i] * (keymat[1][(i + 1) % 3] * keymat[2][(i + 2) % 3] - keymat[1][(i + 2) % 3] * keymat[2][(i + 1) % 3]));
            }
            return determinant;
        }
    }
}
