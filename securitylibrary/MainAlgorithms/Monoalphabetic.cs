using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        string alphabet = "abcdefghijklmnopqrstuvwxyz";

        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            Dictionary<char, char> Decryptor = new Dictionary<char, char>();
            // Maping Each Letter of the Alphabet to it's Coresponding Cipher Letter
            for (int i = 0; i < plainText.Length; i++)
            {
                if (!(Decryptor.ContainsKey(plainText[i])))
                {
                    Decryptor.Add(plainText[i], cipherText[i]);
                    key += Decryptor[plainText[i]];
                }
            }
            key = key.ToLower();
            // Adding the rest of alphabet to the key
            if (key.Length != 26)
            {
                for (int i = 0; i < alphabet.Length; i++)
                {
                    if (!(Decryptor.ContainsKey(alphabet[i])))
                    {
                        for (int j = 0; j < alphabet.Length; j++)
                        {
                            if (!(key.Contains(alphabet[j])))
                            {
                                Decryptor.Add(alphabet[i], alphabet[j]);
                                key += Decryptor[alphabet[i]];
                                break;
                            }
                        }
                    }
                }
            }
            key = "";
            for (int i = 0; i < alphabet.Length; i++)
            {
                key += Decryptor[alphabet[i]];
            }
            return key.ToLower();

        }

        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, char> Decryptor = new Dictionary<char, char>();
            // Maping Each Character of the Key to the Alphabet
            for (int i = 0; i < alphabet.Length; i++)
                Decryptor.Add(key[i], alphabet[i]);

            cipherText = cipherText.ToLower();

            string decryptedMessgae = "";
            // Forming the Decrypted Message
            for (int i = 0; i < cipherText.Length; i++)
                decryptedMessgae += Decryptor[cipherText[i]];

            return decryptedMessgae;
        }

        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, char> Encryptor = new Dictionary<char, char>();
            // Maping Each Character of the Alphabet to the Key
            for (int i = 0; i < alphabet.Length; i++)
                Encryptor.Add(alphabet[i], key[i]);

            // Forming the Original Message
            string encryptedMessgae = "";
            for (int i = 0; i < plainText.Length; i++)
                encryptedMessgae += Encryptor[plainText[i]];

            return encryptedMessgae;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string plain = "";
            string freq_info = "zqjxkvbywgpfmucdlhrsnioate";
            var letters = new Dictionary<char, int>();
            var key = new Dictionary<char, char>();

            // Finding the Frequency of each letter in the Cipher Text
            for (int i = 0; i < cipher.Length; i++)
            {
                if (!letters.ContainsKey(cipher[i]))
                {
                    letters.Add(cipher[i], 1);
                }
                else
                {
                    letters[cipher[i]]++;
                }
            }
            // Converting the Dictionary to a List
            var letters_lst = letters.ToList();
            // Arranging the List Ascendingly according to the Frequency
            letters_lst.Sort((pair1, pair2) => pair1.Value.CompareTo(pair2.Value));

            // Maping Each Letter in the List to its Corresponding Letter in the Alphabet
            for (int i = 0; i < letters_lst.Count; i++)
            {
                key.Add(letters_lst[i].Key, freq_info[i]);
            }

            // Forming the Orginal Text Using the Key Dictonary
            for (int i = 0; i < cipher.Length; i++)
            {
                plain += key[cipher[i]];
            }
            return plain;
        }
    }
}
