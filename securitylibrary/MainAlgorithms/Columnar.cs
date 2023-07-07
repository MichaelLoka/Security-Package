using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            int numberOfRows = 0;
            int numberOfColumns = 0;
            int counter = 0;
            cipherText = cipherText.ToLower();
            int check = 0;

            for (int i = 4; i < 8; i++)
            {
                if (plainText.Length % i == 0)
                {
                    numberOfColumns = i;
                }
            }
            numberOfRows = plainText.Length / numberOfColumns;
            char[,] firstMatrix = new char[numberOfRows, numberOfColumns];
            char[,] secondMatrix = new char[numberOfRows, numberOfColumns];
            List<int> key = new List<int>(numberOfColumns);


            for (int i = 0; i < numberOfRows; i++)
            {
                for (int j = 0; j < numberOfColumns; j++)
                {
                    if (counter < plainText.Length)
                        firstMatrix[i, j] = plainText[counter];
                    if (counter >= plainText.Length)
                    {
                        if (firstMatrix.Length > plainText.Length)
                            firstMatrix[i, j] = 'x';
                    }
                    counter++;
                }
            }

            counter = 0;
            for (int i = 0; i < numberOfColumns; i++)
            {
                for (int j = 0; j < numberOfRows; j++)
                {
                    if (counter == plainText.Length)
                        break;
                    secondMatrix[j, i] = cipherText[counter];
                    counter++;
                }
            }

            for (int i = 0; i < numberOfColumns; i++)
            {
                for (int j = 0; j < numberOfColumns; j++)
                {
                    for (int l = 0; l < numberOfRows; l++)
                    {
                        if (firstMatrix[l, i] == secondMatrix[l, j])
                        {
                            check++;
                        }
                        if (check == numberOfRows)
                            key.Add(j + 1);
                    }
                    check = 0;
                }
            }
            if (key.Count == 0)
            {
                for (int i = 0; i < numberOfColumns + 2; i++)
                {
                    key.Add(0);
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToLower();
            int cipherTextLength = cipherText.Length;
            List<char> cipherList = new List<char>(cipherText);
            double maxelement = -1;
            for (int i = 0; i < key.Count; i++)
            {
                if (key[i] > maxelement)
                    maxelement = key[i];
            }
            int numberOfColumns = (int)maxelement;
            int numberOfRows = (int)Math.Ceiling((double)cipherTextLength / maxelement);
            char[,] cipherTextMatrix = new char[numberOfRows, numberOfColumns];
            Console.WriteLine(numberOfColumns + " " + numberOfRows);
            int emptySquaresInMatrix = (numberOfColumns * numberOfRows) - cipherTextLength;
            int columnNumber = 1;
            int index = 0;
            for (int i = 0; i < numberOfColumns; i++)
            {
                int columnTurn = key.IndexOf(columnNumber);
                ++columnNumber;
                for (int j = 0; j < numberOfRows; j++)
                {
                    if (j != numberOfRows - 1)
                    {
                        cipherTextMatrix[j, columnTurn] = cipherList[index];
                        ++index;
                    }
                    else if ((j == numberOfRows - 1) && !(((i + 1) + emptySquaresInMatrix) > numberOfColumns))
                    {
                        cipherTextMatrix[j, columnTurn] = cipherList[index];
                        ++index;
                    }

                }
            }
            string plainText = string.Empty;
            for (int i = 0; i < numberOfRows; i++)
            {
                for (int j = 0; j < numberOfColumns; j++)
                {
                    plainText += cipherTextMatrix[i, j];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            List<char> listPT = new List<char>(plainText);
            int plainTextLength = plainText.Length;
            double maxelement = -1;
            for (int i = 0; i < key.Count; i++)
            {
                if (key[i] > maxelement)
                    maxelement = key[i];
            }
            int numberOfColumns = (int)maxelement;
            int numberOfRows = (int)Math.Ceiling((double)plainTextLength / maxelement);
            char[,] plainTextMatrix = new char[numberOfRows, numberOfColumns];
            Console.WriteLine(numberOfColumns + " " + numberOfRows);
            // for X
            int emptySquaresInMatrix = (numberOfColumns * numberOfRows) - plainTextLength;
            for (int i = 0; i < emptySquaresInMatrix; i++)
            {
                listPT.Add('x');
            }

            ///
            int index = 0;
            for (int i = 0; i < numberOfRows; i++)
            {
                for (int j = 0; j < numberOfColumns; j++)
                {
                    plainTextMatrix[i, j] = listPT[index];
                    ++index;
                }
            }
            string cipherText = string.Empty;
            int columnNumber = 1;
            while (maxelement != 0)
            {
                int columnTurn = key.IndexOf(columnNumber);
                ++columnNumber;
                for (int j = 0; j < numberOfRows; j++)
                {
                    cipherText += plainTextMatrix[j, columnTurn];
                }
                maxelement--;
            }
            return cipherText;
        }
    }
}
