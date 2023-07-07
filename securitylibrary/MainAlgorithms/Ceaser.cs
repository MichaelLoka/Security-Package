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
            string encrypted_result;
            int[] ind_pt = new int[plainText.Length];
            char[] arr = new char[plainText.Length];

            // Shifting the Plain Text With the Value of Key
            for (int i = 0; i < plainText.Length; i++)
            {
                // Ceaser Cipher Equation
                // Subtructing & Adding the 'a' to Convert the ASCII Code to Index
                ind_pt[i] = (plainText[i] - 'a' + key) % 26;
                arr[i] = ((char)(ind_pt[i] + 'a'));
            }
            encrypted_result = new string(arr);
            return encrypted_result.ToUpper();
        }
        public string Decrypt(string cipherText, int key)
        {
            string cipherText_lowercase = cipherText.ToLower();
            int[] ind_pt = new int[cipherText.Length];
            char[] arr = new char[cipherText.Length];
            string decrypted_result;
            // Shifting the Cipher Text Back With the Value of Key
            for (int j = 0; j < cipherText.Length; j++)
            {
                // Subtructing & Adding the 'a' to Convert the ASCII Code to Index
                ind_pt[j] = cipherText_lowercase[j] - ('a' + key);
                // Return the Decrypted Letter to the Alphapetic Bound
                if (ind_pt[j] < 0)
                {
                    ind_pt[j] += 26;
                }
                arr[j] = (Char)(ind_pt[j] + 'a');

            }
            decrypted_result = new string(arr);
            return decrypted_result;
        }

        public int Analyse(string plainText, string cipherText)
        {
            string ct_lowercase = cipherText.ToLower();
            string pt_lowercase = plainText.ToLower();
            // Subtructing the Plain Text form the Cipher to get the Key
            int key = ct_lowercase[0] - pt_lowercase[0];
            // Return the Key to the Alphapetic Bound
            if (key < 0)
            {
                return (key + 26);
            }
            return key;
        }
    }
}
