using System;
using System.Collections.Generic;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>

    public class AES : CryptographicTechnique
    {
        static int Constant = 0;
        static string[,] ISBox =
        {

            { "52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb" },
            { "7c", "e3" ,"39", "82", "9b" ,"2f", "ff" ,"87", "34" ,"8e", "43", "44" ,"c4", "de" ,"e9" ,"cb" },
            { "54", "7b" ,"94", "32", "a6" ,"c2" ,"23" ,"3d", "ee" ,"4c" ,"95", "0b", "42", "fa", "c3", "4e" },
            { "08", "2e", "a1", "66", "28", "d9", "24", "b2" ,"76" ,"5b" ,"a2", "49", "6d" ,"8b" ,"d1" ,"25" },
            { "72", "f8", "f6", "64", "86" ,"68", "98", "16", "d4", "a4", "5c" ,"cc" ,"5d" ,"65" ,"b6" ,"92" },
            { "6c", "70", "48", "50", "fd" ,"ed" ,"b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84" },
            { "90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06" },
            { "d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b" },
            { "3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73" },
            { "96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e" },
            { "47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b" },
            { "fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4" },
            { "1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f" },
            { "60", "51", "7f" ,"a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef" },
            { "a0", "e0", "3b" ,"4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb" ,"3c", "83", "53", "99", "61" },
            { "17", "2b", "04" ,"7e", "ba", "77", "d6", "26", "e1", "69", "14" ,"63", "55", "21", "0c", "7d"}
        };

        static string[,] t_9 = new string[,]
        {
           {  "00", "09", "12", "1b", "24", "2d", "36", "3f", "48", "41", "5a", "53", "6c", "65", "7e", "77" },
           {  "90", "99", "82", "8b", "b4", "bd", "a6", "af", "d8", "d1", "ca", "c3", "fc", "f5", "ee", "e7" },
           {  "3b", "32", "29", "20", "1f", "16", "0d", "04", "73", "7a", "61", "68", "57", "5e", "45", "4c" },
           {  "ab", "a2", "b9", "b0", "8f", "86", "9d", "94", "e3", "ea", "f1", "f8", "c7", "ce", "d5", "dc" },
           {  "76", "7f", "64", "6d", "52", "5b", "40", "49", "3e", "37", "2c", "25", "1a", "13", "08", "01" },
           {  "e6", "ef", "f4", "fd", "c2", "cb", "d0", "d9", "ae", "a7", "bc", "b5", "8a", "83", "98", "91" },
           {  "4d", "44", "5f", "56", "69", "60", "7b", "72", "05", "0c", "17", "1e", "21", "28", "33", "3a" },
           {  "dd", "d4", "cf", "c6", "f9", "f0", "eb", "e2", "95", "9c", "87", "8e", "b1", "b8", "a3", "aa" },
           {  "ec", "e5", "fe", "f7", "c8", "c1", "da", "d3", "a4", "ad", "b6", "bf", "80", "89", "92", "9b" },
           {  "7c", "75", "6e", "67", "58", "51", "4a", "43", "34", "3d", "26", "2f", "10", "19", "02", "0b" },
           {  "d7", "de", "c5", "cc", "f3", "fa", "e1", "e8", "9f", "96", "8d", "84", "bb", "b2", "a9", "a0" },
           {  "47", "4e", "55", "5c", "63", "6a", "71", "78", "0f", "06", "1d", "14", "2b", "22", "39", "30" },
           {  "9a", "93", "88", "81", "be", "b7", "ac", "a5", "d2", "db", "c0", "c9", "f6", "ff", "e4", "ed" },
           {  "0a", "03", "18", "11", "2e", "27", "3c", "35", "42", "4b", "50", "59", "66", "6f", "74", "7d" },
           {  "a1", "a8", "b3", "ba", "85", "8c", "97", "9e", "e9", "e0", "fb", "f2", "cd", "c4", "df", "d6" },
           {  "31", "38", "23", "2a", "15", "1c", "07", "0e", "79", "70", "6b", "62", "5d", "54", "4f", "46" }
        };
        static string[,] t_11 = new string[,]
        {
            {  "00", "0b", "16", "1d", "2c", "27", "3a", "31", "58", "53", "4e", "45", "74", "7f", "62", "69" },
            {  "b0", "bb", "a6", "ad", "9c", "97", "8a", "81", "e8", "e3", "fe", "f5", "c4", "cf", "d2", "d9" },
            {  "7b", "70", "6d", "66", "57", "5c", "41", "4a", "23", "28", "35", "3e", "0f", "04", "19", "12" },
            {  "cb", "c0", "dd", "d6", "e7", "ec", "f1", "fa", "93", "98", "85", "8e", "bf", "b4", "a9", "a2" },
            {  "f6", "fd", "e0", "eb", "da", "d1", "cc", "c7", "ae", "a5", "b8", "b3", "82", "89", "94", "9f" },
            {  "46", "4d", "50", "5b", "6a", "61", "7c", "77", "1e", "15", "08", "03", "32", "39", "24", "2f" },
            {  "8d", "86", "9b", "90", "a1", "aa", "b7", "bc", "d5", "de", "c3", "c8", "f9", "f2", "ef", "e4" },
            {  "3d", "36", "2b", "20", "11", "1a", "07", "0c", "65", "6e", "73", "78", "49", "42", "5f", "54" },
            {  "f7", "fc", "e1", "ea", "db", "d0", "cd", "c6", "af", "a4", "b9", "b2", "83", "88", "95", "9e" },
            {  "47", "4c", "51", "5a", "6b", "60", "7d", "76", "1f", "14", "09", "02", "33", "38", "25", "2e" },
            {  "8c", "87", "9a", "91", "a0", "ab", "b6", "bd", "d4", "df", "c2", "c9", "f8", "f3", "ee", "e5" },
            {  "3c", "37", "2a", "21", "10", "1b", "06", "0d", "64", "6f", "72", "79", "48", "43", "5e", "55" },
            {  "01", "0a", "17", "1c", "2d", "26", "3b", "30", "59", "52", "4f", "44", "75", "7e", "63", "68" },
            {  "b1", "ba", "a7", "ac", "9d", "96", "8b", "80", "e9", "e2", "ff", "f4", "c5", "ce", "d3", "d8" },
            {  "7a", "71", "6c", "67", "56", "5d", "40", "4b", "22", "29", "34", "3f", "0e", "05", "18", "13" },
            {  "ca", "c1", "dc", "d7", "e6", "ed", "f0", "fb", "92", "99", "84", "8f", "be", "b5", "a8", "a3" }
        };
        static string[,] t_13 = new string[,]
        {
            {  "00", "0d", "1a", "17", "34", "39", "2e", "23", "68", "65", "72", "7f", "5c", "51", "46", "4b" },
            {  "d0", "dd", "ca", "c7", "e4", "e9", "fe", "f3", "b8", "b5", "a2", "af", "8c", "81", "96", "9b" },
            {  "bb", "b6", "a1", "ac", "8f", "82", "95", "98", "d3", "de", "c9", "c4", "e7", "ea", "fd", "f0" },
            {  "6b", "66", "71", "7c", "5f", "52", "45", "48", "03", "0e", "19", "14", "37", "3a", "2d", "20" },
            {  "6d", "60", "77", "7a", "59", "54", "43", "4e", "05", "08", "1f", "12", "31", "3c", "2b", "26" },
            {  "bd", "b0", "a7", "aa", "89", "84", "93", "9e", "d5", "d8", "cf", "c2", "e1", "ec", "fb", "f6" },
            {  "d6", "db", "cc", "c1", "e2", "ef", "f8", "f5", "be", "b3", "a4", "a9", "8a", "87", "90", "9d" },
            {  "06", "0b", "1c", "11", "32", "3f", "28", "25", "6e", "63", "74", "79", "5a", "57", "40", "4d" },
            {  "da", "d7", "c0", "cd", "ee", "e3", "f4", "f9", "b2", "bf", "a8", "a5", "86", "8b", "9c", "91" },
            {  "0a", "07", "10", "1d", "3e", "33", "24", "29", "62", "6f", "78", "75", "56", "5b", "4c", "41" },
            {  "61", "6c", "7b", "76", "55", "58", "4f", "42", "09", "04", "13", "1e", "3d", "30", "27", "2a" },
            {  "b1", "bc", "ab", "a6", "85", "88", "9f", "92", "d9", "d4", "c3", "ce", "ed", "e0", "f7", "fa" },
            {  "b7", "ba", "ad", "a0", "83", "8e", "99", "94", "df", "d2", "c5", "c8", "eb", "e6", "f1", "fc" },
            {  "67", "6a", "7d", "70", "53", "5e", "49", "44", "0f", "02", "15", "18", "3b", "36", "21", "2c" },
            {  "0c", "01", "16", "1b", "38", "35", "22", "2f", "64", "69", "7e", "73", "50", "5d", "4a", "47" },
            {  "dc", "d1", "c6", "cb", "e8", "e5", "f2", "ff", "b4", "b9", "ae", "a3", "80", "8d", "9a", "97" }
        };
        static string[,] t_14 = new string[,]
        {
            {  "00", "0e", "1c", "12", "38", "36", "24", "2a", "70", "7e", "6c", "62", "48", "46", "54", "5a" },
            {  "e0", "ee", "fc", "f2", "d8", "d6", "c4", "ca", "90", "9e", "8c", "82", "a8", "a6", "b4", "ba" },
            {  "db", "d5", "c7", "c9", "e3", "ed", "ff", "f1", "ab", "a5", "b7", "b9", "93", "9d", "8f", "81" },
            {  "3b", "35", "27", "29", "03", "0d", "1f", "11", "4b", "45", "57", "59", "73", "7d", "6f", "61" },
            {  "ad", "a3", "b1", "bf", "95", "9b", "89", "87", "dd", "d3", "c1", "cf", "e5", "eb", "f9", "f7" },
            {  "4d", "43", "51", "5f", "75", "7b", "69", "67", "3d", "33", "21", "2f", "05", "0b", "19", "17" },
            {  "76", "78", "6a", "64", "4e", "40", "52", "5c", "06", "08", "1a", "14", "3e", "30", "22", "2c" },
            {  "96", "98", "8a", "84", "ae", "a0", "b2", "bc", "e6", "e8", "fa", "f4", "de", "d0", "c2", "cc" },
            {  "41", "4f", "5d", "53", "79", "77", "65", "6b", "31", "3f", "2d", "23", "09", "07", "15", "1b" },
            {  "a1", "af", "bd", "b3", "99", "97", "85", "8b", "d1", "df", "cd", "c3", "e9", "e7", "f5", "fb" },
            {  "9a", "94", "86", "88", "a2", "ac", "be", "b0", "ea", "e4", "f6", "f8", "d2", "dc", "ce", "c0" },
            {  "7a", "74", "66", "68", "42", "4c", "5e", "50", "0a", "04", "16", "18", "32", "3c", "2e", "20" },
            {  "ec", "e2", "f0", "fe", "d4", "da", "c8", "c6", "9c", "92", "80", "8e", "a4", "aa", "b8", "b6" },
            {  "0c", "02", "10", "1e", "34", "3a", "28", "26", "7c", "72", "60", "6e", "44", "4a", "58", "56" },
            {  "37", "39", "2b", "25", "0f", "01", "13", "1d", "47", "49", "5b", "55", "7f", "71", "63", "6d" },
            {  "d7", "d9", "cb", "c5", "ef", "e1", "f3", "fd", "a7", "a9", "bb", "b5", "9f", "91", "83", "8d" }
        };
        public static int[] mult2 = new int[]
       {
            0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
            0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
            0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
            0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
            0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
            0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
            0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
            0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
            0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
            0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
            0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
            0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
            0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
            0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
            0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
            0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5};

        public static int[] mult3 = new int[]
        {
            0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
            0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
            0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
            0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
            0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
            0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
            0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
            0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
            0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
            0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
            0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
            0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
            0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
            0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
            0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
            0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a};
        public override string Decrypt(string cipherText, string key)
        {
            string[,] cipher_matrix = new string[4, 4];
            string[,] KeyMatrix = new string[4, 4];
            string[,] RoundKeyMatrix = new string[4, 4];
            List<string> ExpandedKeyMatrix = new List<string>();


            for (int i = 0; i < 32; i += 2)
                cipher_matrix[(i / 2) % 4, (i / 2) / 4] = cipherText.Substring(i + 2, 2);

            for (int i = 0; i < 32; i += 2)
                KeyMatrix[(i / 2) % 4, (i / 2) / 4] = key.Substring(i + 2, 2);

            KeyExpansion(KeyMatrix, ExpandedKeyMatrix);
            FillRoundKey(ExpandedKeyMatrix, 10, RoundKeyMatrix);
            AddRoundKey(cipher_matrix, RoundKeyMatrix); //Initial Round
            for (int i = 9; i > 0; --i)
            {
                FillRoundKey(ExpandedKeyMatrix, i, RoundKeyMatrix);

                cipher_matrix = inverse_shift_rows(cipher_matrix);
                cipher_matrix = inverse_sub_bytes(cipher_matrix);
                AddRoundKey(cipher_matrix, RoundKeyMatrix);
                cipher_matrix = inverse_mix_columns(cipher_matrix);
            }
            cipher_matrix = inverse_shift_rows(cipher_matrix);
            cipher_matrix = inverse_sub_bytes(cipher_matrix);
            FillRoundKey(ExpandedKeyMatrix, 0, RoundKeyMatrix);
            AddRoundKey(cipher_matrix, RoundKeyMatrix);

            string Plain_Text = "0x";
            for (int i = 0; i < 16; i++)
            {
                Plain_Text += cipher_matrix[i % 4, i / 4];

            }
            return Plain_Text;

        }
        public static int[] S_Box = new int[]
            {0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76
            ,0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0
            ,0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15
            ,0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75
            ,0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84
            ,0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf
            ,0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8
            ,0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2
            ,0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73
            ,0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb
            ,0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79
            ,0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08
            ,0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a
            ,0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e
            ,0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf
            ,0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16};

        public static int[,] Rcon = new int[,]
        {
            { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        };

        static void KeyExpansion(string[,] KeyMatrix, List<string> ExpandedKeyMatrix)
        {
            int Rcon_index = 0;
            string[,] NewRoundKey = new string[4, 4];
            // Add the original 16 Key bit to the Expanded Matrix
            for (int i = 0; i < 16; i++)
                ExpandedKeyMatrix.Add(KeyMatrix[i % 4, i / 4]);

            // Calculate the Round Matrix
            for (int i = 0; i < 10; i++)
            {
                if (i == 0)
                    NewRoundKey = Calc_Round_Matrix(KeyMatrix, Rcon_index);
                else
                    NewRoundKey = Calc_Round_Matrix(NewRoundKey, Rcon_index);
                // Add Each Round Matrix to the Expanded Key Matrix
                for (int x = 0; x < 4; x++)
                    for (int y = 0; y < 4; y++)
                        ExpandedKeyMatrix.Add(NewRoundKey[y, x]);
                Rcon_index++; // Next Round Key Iteration
            }
            /*for (int i = 1; i <= ExpandedKeyMatrix.Count; i++)
                Console.Write(ExpandedKeyMatrix[i - 1] + " ");*/
        }
        static string[,] Calc_Round_Matrix(string[,] KeyMatrix, int index)
        {
            string[,] RoundKey = new string[4, 4];
            // Take the 4 Bytes of the Last Column
            int[] Main_Col = new int[4];
            for (int i = 0; i < 4; i++)
                Main_Col[i] = Convert.ToInt32(KeyMatrix[i, 3], 16);

            // Shift them Up by 1
            int t_tmp = Main_Col[0];
            for (int i = 0; i < 3; i++)
                Main_Col[i] = Main_Col[i + 1];
            Main_Col[3] = t_tmp;

            // Substitute using S_Box
            for (int i = 0; i < 4; i++)
                Main_Col[i] = S_Box[Main_Col[i]];

            // XORing the 1st Column of the Key with the Deduced Column with the First Rcon Column
            for (int i = 0; i < 4; i++)
                Main_Col[i] = Convert.ToInt32(KeyMatrix[i, 0], 16) ^ Main_Col[i] ^ Rcon[i, index];

            // Form the remaining of the Round Matrix
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (i == 0)
                        RoundKey[j, i] = Main_Col[j].ToString("X2");
                    else
                        RoundKey[j, i] = (Convert.ToInt32(KeyMatrix[j, i], 16) ^ Main_Col[j]).ToString("X2");
                }
                for (int l = 0; l < 4; l++)
                    Main_Col[l] = Convert.ToInt32(RoundKey[l, i], 16);
            }

            return RoundKey;
        }

        static void FillRoundKey(List<string> ExpandedKeyMatrix, int index, string[,] RoundKeyMatrix)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    RoundKeyMatrix[j, i] = ExpandedKeyMatrix[16 * index + 4 * i + j];
        }

        static void AddRoundKey(string[,] PlainMatrix, string[,] RoundKeyMatrix)
        {
            for (int i = 0; i < 16; i++)
            {
                int x = Convert.ToInt32(PlainMatrix[i % 4, i / 4], 16);
                int y = Convert.ToInt32(RoundKeyMatrix[i % 4, i / 4], 16);
                PlainMatrix[i % 4, i / 4] = (x ^ y).ToString("X2");
            }
        }
        static public string[,] inverse_shift_rows(string[,] cipher_matrix)
        {
            //shift first row
            string temp = cipher_matrix[1, 0];
            string temp2 = cipher_matrix[1, 2];
            cipher_matrix[1, 0] = cipher_matrix[1, 3];
            cipher_matrix[1, 2] = cipher_matrix[1, 1];
            cipher_matrix[1, 1] = temp;
            cipher_matrix[1, 3] = temp2;

            // shift sec row
            temp = cipher_matrix[2, 0];
            temp2 = cipher_matrix[2, 3];
            cipher_matrix[2, 0] = cipher_matrix[2, 2];
            cipher_matrix[2, 3] = cipher_matrix[2, 1];
            cipher_matrix[2, 1] = temp2;
            cipher_matrix[2, 2] = temp;

            // shift third row 
            temp = cipher_matrix[3, 2];
            temp2 = cipher_matrix[3, 3];
            cipher_matrix[3, 3] = cipher_matrix[3, 0];
            cipher_matrix[3, 0] = cipher_matrix[3, 1];
            cipher_matrix[3, 2] = temp2;
            cipher_matrix[3, 1] = temp;
            return cipher_matrix;

        }
        static public string[,] inverse_sub_bytes(string[,] cipher_matrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    var x = cipher_matrix[i, j];
                    var col = x.Substring(0, 1);
                    var row = x.Substring(1, 1);
                    int dec_col = int.Parse(col, System.Globalization.NumberStyles.HexNumber);
                    int dec_row = int.Parse(row, System.Globalization.NumberStyles.HexNumber);


                    cipher_matrix[i, j] = ISBox[dec_col, dec_row];

                }
            }

            return cipher_matrix;
        }
        static public string[,] inverse_mix_columns(string[,] cipher_matrix)
        {
            string val1 = "", val2 = "", val3 = "", val4 = "";
            int m = 0;
            int[,] inv_state = new int[4, 4]
            {
                {14,11,13,9 },
                {9,14,11,13 },
                {13,9,14,11 },
                {11,13,9,14 }
            };
            string[,] c_matrix = new string[4, 4];
            for (int c = 0; c < 4; c++)
            {
                for (int i = 0; i < 4; i++)
                {

                    for (int j = 0; j < 4; j++)

                    {
                        if (inv_state[i, j] == 14)

                        {
                            var x = cipher_matrix[j, m];
                            var col = x.Substring(0, 1);
                            var row = x.Substring(1, 1);
                            int dec_col = int.Parse(col, System.Globalization.NumberStyles.HexNumber);
                            int dec_row = int.Parse(row, System.Globalization.NumberStyles.HexNumber);
                            val1 = t_14[dec_col, dec_row];
                        }
                        else if (inv_state[i, j] == 11)
                        {
                            var x = cipher_matrix[j, m];
                            var col = x.Substring(0, 1);
                            var row = x.Substring(1, 1);
                            int dec_col = int.Parse(col, System.Globalization.NumberStyles.HexNumber);
                            int dec_row = int.Parse(row, System.Globalization.NumberStyles.HexNumber);
                            val2 = t_11[dec_col, dec_row];
                        }
                        else if (inv_state[i, j] == 13)
                        {
                            var x = cipher_matrix[j, m];
                            var col = x.Substring(0, 1);
                            var row = x.Substring(1, 1);
                            int dec_col = int.Parse(col, System.Globalization.NumberStyles.HexNumber);
                            int dec_row = int.Parse(row, System.Globalization.NumberStyles.HexNumber);
                            val3 = t_13[dec_col, dec_row];
                        }
                        else //(inv_state[i, j] == 9)
                        {
                            var x = cipher_matrix[j, m];
                            var col = x.Substring(0, 1);
                            var row = x.Substring(1, 1);
                            int dec_col = int.Parse(col, System.Globalization.NumberStyles.HexNumber);
                            int dec_row = int.Parse(row, System.Globalization.NumberStyles.HexNumber);
                            val4 = t_9[dec_col, dec_row];
                        }

                    }
                    c_matrix[i, m] = xor(val1, val2, val3, val4);

                }
                m++;
            }



            return c_matrix;


        }
        static public string xor(string val1, string val2, string val3, string val4)

        {
            string val1_x = val1.Substring(0, 1);
            string val1_y = val1.Substring(1, 1);
            int dec_val1_x = int.Parse(val1_x, System.Globalization.NumberStyles.HexNumber);
            int dec_val1_y = int.Parse(val1_y, System.Globalization.NumberStyles.HexNumber);

            string val2_x = val2.Substring(0, 1);
            string val2_y = val2.Substring(1, 1);
            int dec_val2_x = int.Parse(val2_x, System.Globalization.NumberStyles.HexNumber);
            int dec_val2_y = int.Parse(val2_y, System.Globalization.NumberStyles.HexNumber);

            string val3_x = val3.Substring(0, 1);
            string val3_y = val3.Substring(1, 1);
            int dec_val3_x = int.Parse(val3_x, System.Globalization.NumberStyles.HexNumber);
            int dec_val3_y = int.Parse(val3_y, System.Globalization.NumberStyles.HexNumber);

            string val4_x = val4.Substring(0, 1);
            string val4_y = val4.Substring(1, 1);
            int dec_val4_x = int.Parse(val4_x, System.Globalization.NumberStyles.HexNumber);
            int dec_val4_y = int.Parse(val4_y, System.Globalization.NumberStyles.HexNumber);

            string result1 = (dec_val1_x ^ dec_val2_x).ToString("X");
            string result2 = (dec_val1_y ^ dec_val2_y).ToString("X");
            string xor_val1_val2 = result1 + result2;

            string result3 = (dec_val3_x ^ dec_val4_x).ToString("X");
            string result4 = (dec_val3_y ^ dec_val4_y).ToString("X");
            string xor_val3_val4 = result3 + result4;

            string val1_val2_x = xor_val1_val2.Substring(0, 1);
            string val1_val2_y = xor_val1_val2.Substring(1, 1);
            int decx = int.Parse(val1_val2_x, System.Globalization.NumberStyles.HexNumber);
            int decy = int.Parse(val1_val2_y, System.Globalization.NumberStyles.HexNumber);


            string val3_val4_x = xor_val3_val4.Substring(0, 1);
            string val3_val4_y = xor_val3_val4.Substring(1, 1);
            int dec2_x = int.Parse(val3_val4_x, System.Globalization.NumberStyles.HexNumber);
            int dec2_y = int.Parse(val3_val4_y, System.Globalization.NumberStyles.HexNumber);

            string res1 = (decx ^ dec2_x).ToString("X");
            string res2 = (decy ^ dec2_y).ToString("X");

            string final_result = res1 + res2;

            return final_result;

        }
        public override string Encrypt(string plainText, string key)
        {
            string[,] PlainMatrix = new string[4, 4];
            string[,] KeyMatrix = new string[4, 4];
            string[,] RoundKeyMatrix = new string[4, 4];
            List<string> ExpandedKeyMatrix = new List<string>();

            for (int i = 0; i < 32; i += 2)
                PlainMatrix[(i / 2) % 4, (i / 2) / 4] = plainText.Substring(i + 2, 2);

            for (int i = 0; i < 32; i += 2)
                KeyMatrix[(i / 2) % 4, (i / 2) / 4] = key.Substring(i + 2, 2);

            KeyExpansion(KeyMatrix, ExpandedKeyMatrix);
            FillRoundKey(ExpandedKeyMatrix, 0, RoundKeyMatrix);
            AddRoundKey(PlainMatrix, RoundKeyMatrix); //Initial Round
            for (int i = 0; i < 9; i++)
            {
                FillRoundKey(ExpandedKeyMatrix, i + 1, RoundKeyMatrix);

                SubBytes(PlainMatrix);
                ShiftRows(PlainMatrix);
                MixColumns(PlainMatrix);
                AddRoundKey(PlainMatrix, RoundKeyMatrix);
            }
            SubBytes(PlainMatrix);
            ShiftRows(PlainMatrix);
            FillRoundKey(ExpandedKeyMatrix, 10, RoundKeyMatrix);
            AddRoundKey(PlainMatrix, RoundKeyMatrix);

            string Cipher_Text = "0x";
            for (int i = 0; i < 16; i++)
                Cipher_Text += PlainMatrix[i % 4, i / 4];

            return Cipher_Text;
        }
        static void SubBytes(string[,] PlainMatrix)
        {
            for (int i = 0; i < 32; i += 2)
            {
                int S_Value_Index = Convert.ToInt32(PlainMatrix[(i / 2) % 4, (i / 2) / 4], 16);
                PlainMatrix[(i / 2) % 4, (i / 2) / 4] = S_Box[S_Value_Index].ToString("X2");
            }
        }
        static void ShiftRows(string[,] PlainMatrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    string first = PlainMatrix[i, 0];
                    for (int k = 0; k < 3; k++)
                        PlainMatrix[i, k] = PlainMatrix[i, k + 1];
                    PlainMatrix[i, 3] = first;
                }

            }
        }
        static void MixColumns(string[,] PlainMatrix)
        {
            int[] temp = new int[16];

            for (int i = 0; i < 16; i++)
                temp[i] = Convert.ToInt32(PlainMatrix[i % 4, i / 4], 16);

            for (int j = 0; j < 4; j++)
            {
                PlainMatrix[0, j] = (mult2[temp[0 + j * 4]] ^ mult3[temp[1 + j * 4]] ^ temp[2 + j * 4] ^ temp[3 + j * 4]).ToString("X2");
                PlainMatrix[1, j] = (temp[0 + j * 4] ^ mult2[temp[1 + j * 4]] ^ mult3[temp[2 + j * 4]] ^ temp[3 + j * 4]).ToString("X2");
                PlainMatrix[2, j] = (temp[0 + j * 4] ^ temp[1 + j * 4] ^ mult2[temp[2 + j * 4]] ^ mult3[temp[3 + j * 4]]).ToString("X2");
                PlainMatrix[3, j] = (mult3[temp[0 + j * 4]] ^ temp[1 + j * 4] ^ temp[2 + j * 4] ^ mult2[temp[3 + j * 4]]).ToString("X2");
            }
        }
    }
}
