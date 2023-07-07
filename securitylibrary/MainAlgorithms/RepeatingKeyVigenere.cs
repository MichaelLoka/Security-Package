using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        char[,] keytable = new char[26, 26];
        public void Form_Tableau()
        {
            //Forming the Vigenere 
            for (int i = 0; i < 26; i++){
                for (int j = 0; j < 26; j++){
                    keytable[i, j] = (char)(('A' + j + i));
                    if (keytable[i, j] > 90){
                        keytable[i, j] = (char)(keytable[i, j] - 26);
                    }
                }
            }
        }

        public string Analyse(string plainText, string cipherText)
        {
            string ct = cipherText.ToUpper();
            string pt = plainText.ToUpper();
            string key = "";

            Form_Tableau();

            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (keytable[(int)(pt[i] - 65), j] == ct[i])
                    {
                        key += (char)(j + 65);
                    }
                }
            }
            string match = key.Substring(0, 5);
            int key_length = key.IndexOf(match, key.IndexOf(match) + 1);
            key = key.Substring(0, key_length);

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string ct = cipherText.ToUpper();
            string ks = key.ToUpper();
            string pt = "";

            //Completing the Key Stream with the Key (Repeating Key)
            for (int i = 0; i < ct.Length - key.Length; i++)
            {
                ks += ks[i % (key.Length)];
            }

            Form_Tableau();

            //Forming the Plain Text from the cipher using the Tableau
            for (int i = 0; i < ct.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (keytable[j, (int)ks[i] - 65] == ct[i])
                    {
                        pt += (char)(j + 65);
                    }
                }
            }
            return pt;
        }

        public string Encrypt(string plainText, string key)
        {
            string k = key.ToUpper();
            string pt = plainText.ToUpper();
            string ct = "";

            //Completing the Key Stream with the Key (Repeating Key)
            for (int i = 0; i < plainText.Length - key.Length; i++)
            {
                k += k[i % (key.Length)];
            }

            Form_Tableau();

            //Ciphering the Plain Text using the Tableau
            for (int i = 0; i < plainText.Length; i++)
            {
                ct += keytable[(int)pt[i] - 65, (int)k[i] - 65];
            }
            return ct;
        }
    }
}