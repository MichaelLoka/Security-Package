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

        static int[] pc1 = new int[] { 57, 49, 41, 33, 25, 17, 9,
                     1, 58, 50, 42, 34, 26, 18,
                     10, 2, 59, 51, 43, 35, 27,
                     19, 11, 3, 60, 52, 44, 36,
                     63, 55, 47, 39, 31, 23, 15,
                     7, 62, 54, 46, 38, 30, 22,
                     14, 6, 61, 53, 45, 37, 29,
                     21, 13, 5, 28, 20, 12, 4 };

        static int[] pc2 = new int[] { 14, 17, 11, 24, 1, 5,
                         3, 28, 15, 6, 21, 10,
                         23, 19, 12, 4, 26, 8,
                         16, 7, 27, 20, 13, 2,
                         41, 52, 31, 37, 47, 55,
                         30, 40, 51, 45, 33, 48,
                         44, 49, 39, 56, 34, 53,
                         46, 42, 50, 36, 29, 32 };


        static int[] round_table = new int[]{ 1, 1, 2, 2,
                            2, 2, 2, 2,
                            1, 2, 2, 2,
                            2, 2, 2, 1 };

        //for plaintext

        //Initial Permutation Table * 
        private static int[] firstPermutationTable = new int[] { 58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
                                       62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
                                       57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
                                       61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7 };



        //Expansion Permutation Table  *
        private static int[] expansionPersmutationTable = new int[] { 32,1,2,3,4,5,4,5,6,7,8,9,
                                        8,9,10,11,12,13,12,13,14,15,16,17,
                                        16,17,18,19,20,21,20,21,22,23,24,25,
                                        24,25,26,27,28,29,28,29,30,31,32,1 };

        private static int[] P = new int[]
                                                    {16 ,7,   20,  21 , 29 , 12 , 28,  17,
                                                        1,   15 , 23 , 26  ,5 ,  18,  31 , 10,
                                                        2,   8,   24 , 14 , 32 , 27  ,3  , 9
                                                        ,19,  13,  30,  6,   22 , 11 , 4  , 25
                                                    };


        //region SBoxes definition
        static int[,,] Sbox = new int[8, 4, 16] {{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                     {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                     {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                     {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} },

                       {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                       {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                       {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                       {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},

                       {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                       {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                       {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                       {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},

                       {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                       {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                       {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                       {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},

                      {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                      {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                      {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                      {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},

                      {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                      {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                      {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                      {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},

                       {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                       {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                       {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                       {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},

                       {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                       {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                       {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                       {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};



        //Final Permutation Table * 
        private static int[] finalPermutationTable = new int[] { 40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
                                       38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
                                       36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
                                       34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25 };


        public static string convertHexaToBinary(string hexaString)
        {
            var converter = new Dictionary<char, string>{
            { '0', "0000"},
            { '1', "0001"},
            { '2', "0010"},
            { '3', "0011"},

            { '4', "0100"},
            { '5', "0101"},
            { '6', "0110"},
            { '7', "0111"},

            { '8', "1000"},
            { '9', "1001"},
            { 'A', "1010"},
            { 'B', "1011"},

            { 'C', "1100"},
            { 'D', "1101"},
            { 'E', "1110"},
            { 'F', "1111"}};

            string result = "";
            for (int i = 0; i < hexaString.Length; i++)
            {
                hexaString = hexaString.Replace("0x", "");
                result += converter[hexaString[i]];
            }
            return result;

        }

        public static string convertBinaryToHexa(string binString)
        {
            var converter = new Dictionary<string, char>{
            {"0000", '0'},
            {"0001", '1'},
            { "0010",'2'},
            { "0011", '3'},

            { "0100", '4'},
            { "0101",'5'},
            { "0110", '6'},
            {"0111", '7'},

            { "1000", '8'},
            { "1001", '9'},
            { "1010", 'A'},
            { "1011",'B'},

            { "1100",'C'},
            {"1101", 'D'},
            {"1110", 'E'},
            {"1111", 'F'}};

            string result = "";
            binString = binString.Replace("0x", "");

            for (int i = 0; i < binString.Length; i += 4)
            {

                result += converter[binString.Substring(i, 4)];
            }
            return result;

        }
        public static List<string> leftCircularShift(List<char> roundedBlockList, int[] roundingTable)
        {

            List<string> resultList = new List<string>();
            for (int i = 0; i < roundingTable.Length; i++)
            {
                if (roundingTable[i] == 2) // shift 2 or 1 bit
                {

                    char entry1 = roundedBlockList[0];
                    char entry2 = roundedBlockList[1];
                    roundedBlockList.RemoveAt(1);
                    roundedBlockList.RemoveAt(0);
                    roundedBlockList.Add(entry1);
                    roundedBlockList.Add(entry2);

                }
                else
                {
                    char entry1 = roundedBlockList[0];
                    roundedBlockList.RemoveAt(0);
                    roundedBlockList.Add(entry1);

                }
                string s = new string(roundedBlockList.ToArray());
                resultList.Add(s);

            }
            return resultList;

        }
        public static string permuteTable(string permutedString, int[] permutationTable)
        {
            string result = "";
            for (int i = 0; i < permutationTable.Length; i++)
            {
                result += permutedString[permutationTable[i] - 1];
            }
            return result;
        }


        public static List<string> keyGeneration(string key, int[] pc1, int[] roundTable, int[] pc2)
        {
            string permutedKey = permuteTable(key, pc1);
            string initialC_Block = permutedKey.Substring(0, 28);
            string initialD_Block = permutedKey.Substring(28, 28);

            List<char> C_Block = initialC_Block.ToList();

            List<char> D_Block = initialD_Block.ToList();

            List<string> C_list = leftCircularShift(C_Block, round_table);
            List<string> D_list = leftCircularShift(D_Block, round_table);

            List<string> keys = new List<string>();
            for (int i = 0; i < C_list.Count; i++)
            {
                keys.Add(permuteTable(C_list[i] + D_list[i], pc2));
            }
            return keys;
        }
        public static string expansion(string expandedString /*48 bits*/, string key, int[] expansionTable)
        {
            string permutedString = permuteTable(expandedString, expansionTable);
            string XOR_String = XOR(permutedString, key);
            string sbox_string = sbox(XOR_String);//here the 48 bit string will be 32 bit
            return permuteTable(sbox_string, P);

        }

        public static string XOR(string first, string second)
        {
            string result = "";
            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] == second[i])

                    result += "0";

                else
                    result += "1";
            }
            return result;
        }
        //given 48 bit string we have to retrun 32 bit string
        public static string sbox(string s)
        {
            string result = "";
            string str = "";

            for (int i = 0; i < s.Length; i += 6)
            {
                str = s.Substring(i, 6);
                // convert binary string to decimal
                int firstAndLastBits = Convert.ToInt32(string.Concat(str[0], str[5]), 2);
                int middleFourBits = Convert.ToInt32(str.Substring(1, 4), 2);
                string entry = Convert.ToString(Sbox[i / 6, firstAndLastBits, middleFourBits], 2);
                if (entry.Length < 4)
                {
                    int l = 4 - entry.Length;
                    for (int j = 0; j < l; j++)
                    {
                        entry = entry.Insert(0, "0");
                    }
                }
                result += entry;

            }
            return result;

        }
        public static string encryptPlain(string plainText, List<string> keys, int[] fistPermutationTable, int[] finalPermutationTable, int[] expansionTable)
        {
            string permutedPlain = permuteTable(plainText, fistPermutationTable);

            string[] L = new string[17];
            string[] R = new string[17];
            L[0] = permutedPlain.Substring(0, 32);
            R[0] = permutedPlain.Substring(32, 32);

            for (int i = 1; i <= 16; i++)
            {

                //this 32 bit string is the result of permutation , XOR and S_BOX
                string expandedString = expansion(R[i - 1], keys[i - 1], expansionTable);
                L[i] = R[i - 1];
                R[i] = XOR(L[i - 1], expandedString);


            }
            string concatenationResultOfR_And_L = string.Concat(R[16], L[16]);
            string result = permuteTable(concatenationResultOfR_And_L, finalPermutationTable);
            return result;


        }
        public override string Encrypt(string plainText, string key)
        {
            string binPlain = convertHexaToBinary(plainText);
            string binKey = convertHexaToBinary(key);
            List<string> readyKeys = keyGeneration(binKey, pc1, round_table, pc2);
            string result = encryptPlain(binPlain, readyKeys, firstPermutationTable, finalPermutationTable, expansionPersmutationTable);
            result = convertBinaryToHexa(result);
            string concatResult = string.Concat("0x", result);


            return concatResult;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string input = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            key = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string ip = "";
            ip = IP(input);


            List<string> keys = new List<string>();
            //preparing the Sub Keys

            string intialSubKey = PC_1(key);
            string roundedKey = intialSubKey;
            string subkey = "";
            for (int i = 1; i <= 16; i++)
            {
                roundedKey = ROUND_KEY(roundedKey, i);
                subkey = PC_2(roundedKey);
                keys.Add(subkey);
            }

            string first_Half = ip.Substring(0, 32);
            string second_Half = ip.Substring(32, 32);
            string temp_secondHalf = "";

            for (int i = 0; i < 16; i++)
            {
                // E-bit table
                string ebit = E_BIT_TABLE(second_Half);
                string xorBit = "";



                for (int j = 0; j < ebit.Length; j++)
                    xorBit += (keys[keys.Count - 1 - i][j] ^ ebit[j]).ToString();



                xorBit = S_BOX(xorBit);


                xorBit = Permut(xorBit);


                temp_secondHalf = "";
                for (int k = 0; k < xorBit.Length; k++)
                    temp_secondHalf += (xorBit[k] ^ first_Half[k]).ToString();


                first_Half = second_Half;
                second_Half = temp_secondHalf;

            }
            string final = second_Half + first_Half;
            string cipher = IP_1(final);



            string pt = "0x" + Convert.ToInt64(cipher, 2).ToString("X").PadLeft(16, '0');

            return pt;
        }

        static string PC_1(string key)
        {
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };
            string tmp = "";

            for (int i = 0; i < 56; i++)
                tmp += key[PC_1[i / 7, i % 7] - 1];


            return tmp;
        }

        static string PC_2(string key)
        {
            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };
            string tmp = "";

            for (int i = 0; i < 48; i++)
                tmp += key[PC_2[i / 6, i % 6] - 1];


            return tmp;
        }

        static string ROUND_KEY(string key, int roundNum)
        {
            string c = key.Substring(0, 28);
            string d = key.Substring(28, 28);
            //1 2 9 16
            if (roundNum == 1 || roundNum == 2 || roundNum == 9 || roundNum == 16)
            {
                char firstLetter = c[0];
                c = c.Remove(0, 1);
                c += firstLetter;

                firstLetter = d[0];
                d = d.Remove(0, 1);
                d += firstLetter;

                return c + d;

            }

            string temp = c.Substring(0, 2);
            c = c.Remove(0, 2);
            c += temp;

            temp = d.Substring(0, 2);
            d = d.Remove(0, 2);
            d += temp;

            return c + d;


        }

        static string E_BIT_TABLE(string secondHalf)
        {
            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };
            string tmp = "";

            for (int i = 0; i < 48; i++)
                tmp += secondHalf[EB[i / 6, i % 6] - 1];

            return tmp;
        }

        static string S_BOX(string Xored)
        {
            int[,,] Sbox = new int[8, 4, 16] {{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                     {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                     {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                     {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} },

                       {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                       {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                       {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                       {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},

                       {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                       {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                       {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                       {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},

                       {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                       {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                       {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                       {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},

                      {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                      {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                      {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                      {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},

                      {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                      {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                      {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                      {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},

                       {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                       {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                       {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                       {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},

                       {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                       {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                       {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                       {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};

            string result = "";
            string str = "";

            for (int i = 0; i < Xored.Length; i += 6)
            {
                str = Xored.Substring(i, 6);
                // convert binary string to decimal
                int firstAndLastBits = Convert.ToInt32(string.Concat(str[0], str[5]), 2);
                int middleFourBits = Convert.ToInt32(str.Substring(1, 4), 2);
                string entry = Convert.ToString(Sbox[i / 6, firstAndLastBits, middleFourBits], 2);
                if (entry.Length < 4)
                {
                    int l = 4 - entry.Length;
                    for (int j = 0; j < l; j++)
                    {
                        entry = entry.Insert(0, "0");
                    }
                }
                result += entry;

            }
            return result;

        }

        static string Permut(string s)
        {
            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
            string temp = "";

            for (int i = 0; i < 32; i++)
                temp += s[P[i / 4, i % 4] - 1];

            return temp;
        }


        static string IP_1(string s)
        {
            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };
            string temp = "";
            for (int i = 0; i < 64; i++)
                temp += s[IP_1[i / 8, i % 8] - 1];

            return temp;
        }

        static string IP(string key)
        {
            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            string temp = "";
            for (int i = 0; i < 64; i++)
                temp += key[IP[i / 8, i % 8] - 1];

            return temp;
        }
    }
}