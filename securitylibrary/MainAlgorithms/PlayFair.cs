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
            string keyCopy = key;
            String alpha = "abcdefghiklmnopqrstuvwxyz";
            char[,] keymatrix = new char[5, 5];
            string keyOriginal = string.Empty;
            string newPlainTextCopy = string.Empty;

            // Removing Duplicates from the Key
            for (int i = 0; i < keyCopy.Length; i++)
            {
                if (!keyOriginal.Contains(keyCopy[i]))
                {
                    keyOriginal += keyCopy[i];
                }
            }
            // Filling the Key with the Remaining Alpabet Letters
            for (int i = 0; i < alpha.Length; i++)
            {
                if (!keyOriginal.Contains(alpha[i]))
                {
                    keyOriginal += alpha[i];
                }
            }
            // Filling the Matrix with the Key
            for (int i = 0; i < 25; i++)
            {
                keymatrix[(i / 5), (i % 5)] = keyOriginal[i];
            }
            int index1 = 0;
            int index2 = 0;
            int iPosition = 0;
            int jPosition = 0;
            int iPosition2 = 0;
            int jPosition2 = 0;
            string plainText = string.Empty;
            List<char> cipherList = new List<char>(cipherText.ToLower());
            // Checking the Presence of x(s) in the Cipher Text
            for (int i = 0; i < cipherList.Count; i++)
            {
                if (cipherList[i] == 'x' && i % 2 != 0)
                {
                    continue;
                }
                else
                {
                    cipherList[i] = cipherList[i];
                }
            }
            int cipherListLength = cipherList.Count;
            // Getting the Postition of each letter in the Cipher text form the Matrix
            for (int i = 0; i < cipherListLength - 1; i = i + 2)
            {
                index1 = keyOriginal.IndexOf(cipherList[i]);
                iPosition = index1 / 5;
                jPosition = index1 % 5;

                index2 = keyOriginal.IndexOf(cipherList[i + 1]);
                iPosition2 = index2 / 5;
                jPosition2 = index2 % 5;
                // If the 2 Letters are in the same Row
                if (iPosition == iPosition2)
                {
                    --jPosition;
                    if (jPosition < 0)
                        jPosition += 5;
                    --jPosition2;
                    if (jPosition2 < 0)
                        jPosition2 += 5;
                    plainText += keymatrix[iPosition, (jPosition)];
                    plainText += keymatrix[iPosition2, (jPosition2)];
                }
                // If the 2 Letters are in the same Column
                else if (jPosition == jPosition2)
                {
                    --iPosition;
                    if (iPosition < 0)
                        iPosition += 5;
                    --iPosition2;
                    if (iPosition2 < 0)
                        iPosition2 += 5;
                    plainText += keymatrix[(iPosition), jPosition];
                    plainText += keymatrix[(iPosition2), jPosition2];
                }
                // Different Row and Column
                else
                {
                    plainText += keymatrix[iPosition, jPosition2];
                    plainText += keymatrix[iPosition2, jPosition];
                }
            }
            // Removing x(s) from the Plain Text
            if (plainText[plainText.Length - 1] == 'x')
            {
                plainText = plainText.Remove(plainText.Length - 1, 1);
            }
            for (int i = 0; i < plainText.Length - 2; i++)
            {
                if (plainText[i] == plainText[i + 2] && plainText[i + 1] == 'x')
                {
                    plainText = plainText.Remove(i + 1, 1);
                }
                else
                {
                    i++;
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string keyCopy = key;
            String alpha = "abcdefghiklmnopqrstuvwxyz";
            char[,] keymatrix = new char[5, 5];
            string keyOriginal = string.Empty;
            string plainTextCopy = plainText;
            List<char> plaiinTextList = new List<char>(plainTextCopy);
            string newPlainTextCopy = string.Empty;
            // Removing Duplicate Letters from the Key
            for (int i = 0; i < keyCopy.Length; i++)
            {
                if (!keyOriginal.Contains(keyCopy[i]))
                {
                    keyOriginal += keyCopy[i];
                }
            }
            // Filling the Key with the Remaining Alpabet
            for (int i = 0; i < alpha.Length; i++)
            {
                if (!keyOriginal.Contains(alpha[i]))
                {
                    keyOriginal += alpha[i];
                }
            }
            // Filling the Matrix with the Key
            for (int i = 0; i < 25; i++)
            {
                keymatrix[(i / 5), (i % 5)] = keyOriginal[i];
            }
            // Checking the Presence of two Similar Letters in Consequnce
            for (int i = 0; i < plaiinTextList.Count - 1; i = i + 2)
            {
                // Inserting x between the Repeated Letters
                if (plaiinTextList[i] == plaiinTextList[i + 1])
                {
                    plaiinTextList.Insert(i + 1, 'x');
                }
            }
            if (plaiinTextList.Count % 2 != 0)
            {
                plaiinTextList.Add('x');
            }
            int index1 = 0;
            int index2 = 0;
            int plaintextlen = plaiinTextList.Count;
            int iPosition = 0;
            int jPosition = 0;
            int iPosition2 = 0;
            int jPosition2 = 0;
            string cipherText = string.Empty;
            // Getting the Postition of each letter in the Plain text form the Matrix
            for (int i = 0; i < plaintextlen - 1; i += 2)
            {
                index1 = keyOriginal.IndexOf(plaiinTextList[i]);
                iPosition = index1 / 5;
                jPosition = index1 % 5;

                index2 = keyOriginal.IndexOf(plaiinTextList[i + 1]);
                iPosition2 = index2 / 5;
                jPosition2 = index2 % 5;

                // If the 2 Letters are in the same Row
                if (iPosition == iPosition2)
                {
                    cipherText += keymatrix[iPosition, (jPosition + 1) % 5];
                    cipherText += keymatrix[iPosition2, (jPosition2 + 1) % 5];
                }
                // If the 2 Letters are in the same Column
                else if (jPosition == jPosition2)
                {
                    cipherText += keymatrix[(iPosition + 1) % 5, jPosition];
                    cipherText += keymatrix[(iPosition2 + 1) % 5, jPosition2];
                }
                // Differnt Row and Column
                else
                {
                    cipherText += keymatrix[iPosition, jPosition2];
                    cipherText += keymatrix[iPosition2, jPosition];
                }
            }
            return cipherText.ToUpper();
        }
    }
}
