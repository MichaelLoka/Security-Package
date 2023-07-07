using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            char secondLetter = cipherText[1];
            int secondIndex = 0;

            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == secondLetter)
                {
                    if (cipherText[2] != plainText[2 * i])
                        continue;
                    return i;
                }
            }

            return secondIndex;
        }

        public string Decrypt(string cipherText, int key)
        {
            char[] plain = new char[cipherText.Length];
            int index = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < cipherText.Length; j += key)
                {
                    plain[j] = cipherText[index];
                    index++;
                }
            }
            string plainText = new string(plain);

            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            for (int i = 0; i < key; i++)
                for (int j = i; j < plainText.Length; j += key)
                    cipherText += plainText[j];

            return cipherText;
        }
    }
}
