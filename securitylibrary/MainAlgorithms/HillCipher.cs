using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {

            List<int> mayBeKey = new List<int>();

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            mayBeKey = new List<int>(new[] { i, j, k, l });
                            List<int> aa = Encrypt(plainText, mayBeKey);
                            if (aa.SequenceEqual(cipherText))
                            {
                                return mayBeKey;
                            }

                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
            


        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int ct_size = cipherText.Count;
            int key_size = key.Count(), k = 0, index = 0;
            int[] pt_array = new int[100];
            int det, det_mod, b;
            int[] inversed_key = new int[100];

            for (int i = 0; i < key_size; i++) // show if key has negative value
            {
                if (key[i] < 0 || key[i] > 26)
                {
                    throw new NotImplementedException();
                }
            }
            if (key_size == 4) // matrix 2x2
            {
                k = 2;
                det = (key[0] * key[3]) - (key[1] * key[2]);
                det_mod = det % 26;
                if (det_mod < 0)
                    det_mod += 26;
                int gcd = GCD(26, det_mod);
                if (gcd == 1)
                {

                    // b = determinant_inverse(det_mod, 26);


                    int x = 1 / (key[0] * key[3] - key[1] * key[2]);
                    inversed_key[1] = key[1] * -1;
                    inversed_key[2] = key[2] * -1;
                    inversed_key[0] = key[3];
                    inversed_key[3] = key[0];

                    for (int i = 0; i < 4; i++)
                    {
                        inversed_key[i] = inversed_key[i] * x;
                    }
                    for (int i = 0; i < 4; i++)
                    {
                        if (inversed_key[i] < 0) { inversed_key[i] += 26; }
                    }

                    for (int i = 0; i < ct_size; i = i + k)
                    {
                        for (int j = 0; j < key_size; j = j + k)
                        {
                            int multiple_val = 0;
                            for (int m = 0; m < k; m++)
                            {
                                int Raw_Index = j + m;//raw element index of key in the key matrix
                                int Column_Index = i + m; //column element index of cipherText in the matrix
                                multiple_val = multiple_val + (inversed_key[Raw_Index] * cipherText[Column_Index]); // multiple value of key*ct(i)
                            }
                            int result = multiple_val % 26; // ct=(key*ct) mod 26
                            pt_array[index] = result;// add result to end of thr list
                            index++;
                        }
                    }

                    List<int> pt = new List<int>(pt_array);// convert array to list 
                    return pt;
                }

                else
                {
                    throw new NotImplementedException();
                }
            }



            else if (key_size == 9) // matrix 3x3
            {
                k = 3;
                det = key[0] * (key[4] * key[8] - key[5] * key[7])
                    - key[1] * (key[3] * key[8] - key[5] * key[6])
                    + key[2] * (key[3] * key[7] - key[4] * key[6]);

                det_mod = (det % 26);
                if (det_mod < 1)
                {
                    det_mod += 26;
                }
                b = determinant_inverse(det_mod, 26);

                inversed_key[0] = ((b * 1) * (key[4] * key[8] - key[5] * key[7])) % 26;
                inversed_key[1] = ((b * (-1)) * ((key[3] * key[8]) - (key[6] * key[5]))) % 26;
                inversed_key[2] = ((b * 1) * (key[3] * key[7] - key[4] * key[6])) % 26;
                inversed_key[3] = ((b * (-1)) * (key[1] * key[8] - key[2] * key[7])) % 26;
                inversed_key[4] = ((b * 1) * (key[0] * key[8] - key[2] * key[6])) % 26;
                inversed_key[5] = ((b * (-1)) * (key[0] * key[7] - key[1] * key[6])) % 26;
                inversed_key[6] = ((b * 1) * (key[1] * key[5] - key[4] * key[2])) % 26;
                inversed_key[7] = ((b * (-1)) * (key[0] * key[5] - key[3] * key[2])) % 26;
                inversed_key[8] = ((b * 1) * (key[0] * key[4] - key[1] * key[3])) % 26;
                for (int i = 0; i < 9; i++)
                {
                    if (inversed_key[i] < 0) { inversed_key[i] += 26; }
                }

                int temp1 = inversed_key[1];
                int temp2 = inversed_key[2];
                int temp3 = inversed_key[5];

                inversed_key[1] = inversed_key[3];
                inversed_key[3] = temp1;
                inversed_key[2] = inversed_key[6];
                inversed_key[6] = temp2;
                inversed_key[5] = inversed_key[7];
                inversed_key[7] = temp3;


                List<int> inver_k = new List<int>(inversed_key);// convert array to list 

                for (int i = 0; i < ct_size; i = i + k)
                {
                    for (int j = 0; j < key_size; j = j + k)
                    {
                        int multiple_val = 0;
                        for (int m = 0; m < k; m++)
                        {
                            int Raw_Index = j + m;//raw element index of key in the key matrix
                            int Column_Index = i + m; //column element index of plainText in the matrix
                            multiple_val = multiple_val + (inversed_key[Raw_Index] * cipherText[Column_Index]); // multiple value of key*pt(i)
                        }
                        int result = multiple_val % 26; // ct=(key*pt) mod 26
                        pt_array[index] = result;// add result to end of thr list
                        index++;
                    }
                }
                List<int> pt = new List<int>(pt_array);// convert array to list 
                return pt;

            }

            else
                throw new Exception();

            // throw new NotImplementedException();
        }
        public int determinant_inverse(int a, int m)
        {

            for (int x = 1; x < m; x++)
                if (((a % m) * (x % m)) % m == 1)
                    return x;
            return 1;
        }


        public int GCD(int x, int y)
        {
            if (y == 0)
            {
                return x;
            }

            int val = x % y;

            return GCD(y, val);
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count);
            double[,] key2D = new double[m, m];
            int col = plainText.Count % m != 0 ? (plainText.Count / m) + 1 : plainText.Count / m;
            double[,] plain2D = new double[m, col];

            for (int i = 0; i < key.Count; i++)
                key2D[i / m, i % m] = key[i];

            for (int j = 0; j < plainText.Count; j++)
                plain2D[j % m, j / m] = plainText[j];

            Matrix<double> keyMatrix = DenseMatrix.OfArray(key2D);
            Matrix<double> plainMatrix = DenseMatrix.OfArray(plain2D);
            Matrix<double> cipherMatrix = (keyMatrix.Multiply(plainMatrix)).Modulus(26);

            List<int> cipher = cipherMatrix.Enumerate().ToList().ConvertAll(x => (int)x);

            return cipher;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int m = 3;
            int col = plain3.Count() % m != 0 ? (plain3.Count() / m) + 1 : plain3.Count() / m;

            double[,] plain2D = new double[m, col];
            double[,] cipher2D = new double[m, col];

            for (int j = 0; j < plain3.Count(); j++)
                plain2D[j % m, j / m] = plain3[j];

            for (int j = 0; j < cipher3.Count(); j++)
                cipher2D[j % m, j / m] = cipher3[j];

            Matrix<double> key = DenseMatrix.Create(3, 3, 0);
            Matrix<double> plainMtrx = DenseMatrix.OfArray(plain2D);

            int determant = (int)plainMtrx.Determinant() % 26;
            determant = determant >= 0 ? determant : determant + 26;

            
            int b;
            for (b = 0; b < 26; b++)
                if (b * determant % 26 == 1)
                    break;

            
            Matrix<double> cipherMtrx = DenseMatrix.OfArray(cipher2D);
            
            Matrix<double> plainMtrxInv = DenseMatrix.Create(3, 3, 1);
            //get the inverse of the matrix 
            //----------------------------------------------
            int x1, x2, y1, y2;
            double res;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    x1 = i > 0 ? 0 : 1;
                    x2 = i < 2 ? 2 : 1;
                    y1 = j == 0 ? 1 : 0;
                    y2 = j == 2 ? 1 : 2;

                    res = (b * Math.Pow(-1, i + j) * (plainMtrx[x1, y1] * plainMtrx[x2, y2] - plainMtrx[x1, y2] * plainMtrx[x2, y1])) % 26;
                    plainMtrxInv[i, j] = res >= 0 ? res : res + 26;
                }
            }

            plainMtrxInv = plainMtrxInv.Transpose();
            //--------------------------------------------------

            key = cipherMtrx.Multiply(plainMtrxInv).Modulus(26);

            List<int> mayBeKey = new List<int>();

            mayBeKey = key.Transpose().Enumerate().ToList().ConvertAll(x => (int)x);

            return mayBeKey;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();

        }

    }
}
