using System;
using System.Collections;

namespace DES
{
    public class DESEncryption
    {
        private BitArray text;
        private BitArray key;

        //sets the text to be encoded or decoded
        public void setText(String input)
        { text = getArray(input); }

        //return String representation of the BitArray
        public String getText()
        {
            String returnText = "";
            int[] num = new int[4];

            for (int x = 0; x < text.Length; x++)
            {
                num[x % 4] = Convert.ToInt16(text[x]);

                if ((x + 1) % 4 == 0 && x != 0)
                {
                    int tempNum = calcNum(num);

                    if (tempNum >= 0 && tempNum <= 9)
                        returnText += tempNum;
                    else if (tempNum >= 10)
                        returnText += (char)(tempNum + 55);
                }
            }

            return returnText;
        }

        //sets the key to be used 
        public void setKey(String input)
        { key = getArray(input); }

        //encodes plaintext to ciphertext
        public void encode()
        {
            iPerm();

            for (int x = 0; x <= 16; x++) //16 rounds
                scramble(x);

            swap();

            fPerm();
        }

        //decodes ciphertext back to plaintext
        public void decode()
        {
            BitArray[] keys = new BitArray[16];

            iPerm();

            swap();

            BitArray first = generateKey(0);

            for (int x = 0; x < keys.Length; x++)
                keys[x] = generateKey(x + 1);

            for (int x = 0; x < keys.Length; x++)
                descrambler(x, keys[(keys.Length - 1) - x]);

            fPerm();
        }

        //resulting text after each
        //decode round
        private void descrambler(int round, BitArray currentKey)
        {
            BitArray rText = new BitArray(32);
            BitArray lText = new BitArray(32);
            BitArray tempText = new BitArray(32);

            for (int x = 0; x < text.Length / 2; x++)
            {
                lText[x] = text[x];
                rText[x] = text[x + text.Length / 2];
            }

            tempText = mangler(lText, currentKey, round);
            tempText = tempText.Xor(rText);

            rText = lText;
            lText = tempText;

            for (int x = 0; x < text.Length / 2; x++)
            {
                text[x] = lText[x];
                text[x + text.Length / 2] = rText[x];
            }
        }

        //swap left half with right half
        private void swap()
        {
            bool num;

            for (int x = 0; x < text.Length / 2; x++)
            {
                num = text[x + text.Length / 2];
                text[x + text.Length / 2] = text[x];
                text[x] = num;
            }
        }

        //preforms initial permutation on text
        private void iPerm()
        {
            BitArray tempText = new BitArray(64);

            int[] iPerm = { 58, 50, 42, 34, 26, 18, 10,  2,
                            60, 52, 44, 36, 28, 20, 12,  4,
                            62, 54, 46, 38, 30, 22, 14,  6,
                            64, 56, 48, 40, 32, 24, 16,  8,
                            57, 49, 41, 33, 25, 17,  9,  1,
                            59, 51, 43, 35, 27, 19, 11,  3,
                            61, 53, 45, 37, 29, 21, 13,  5,
                            63, 55, 47, 39, 31, 23, 15,  7};

            for (int x = 0; x < iPerm.Length; x++)
                tempText[x] = text[iPerm[x] - 1];

            text = tempText;
        }


        //preforms the final permutation on text
        private void fPerm()
        {
            BitArray tempText = new BitArray(64);

            int[] fPerm = { 40,  8, 48, 16, 56, 24, 64, 32,
                            39,  7, 47, 15, 55, 23, 63, 31,
                            38,  6, 46, 14, 54, 22, 62, 30,
                            37,  5, 45, 13, 53, 21, 61, 29,
                            36,  4, 44, 12, 52, 20, 60, 28,
                            35,  3, 43, 11, 51, 19, 59, 27,
                            34,  2, 42, 10, 50, 18, 58, 26,
                            33,  1, 41,  9, 49, 17, 57, 25};

            for (int x = 0; x < fPerm.Length; x++)
                tempText[x] = text[fPerm[x] - 1];

            text = tempText;
        }

        //resulting text after each 
        //encode round
        private void scramble(int round)
        {
            BitArray roundKey = generateKey(round);

            if (round != 0)
            {
                BitArray rText = new BitArray(32);
                BitArray lText = new BitArray(32);

                for (int x = 0; x < text.Length / 2; x++)
                {
                    lText[x] = text[x];
                    rText[x] = text[x + text.Length / 2];
                }

                for (int x = 0; x < rText.Length; x++)
                    text[x] = rText[x];

                rText = mangler(rText, roundKey, round);
                rText = rText.Xor(lText);

                for (int x = 0; x < text.Length / 2; x++)
                    text[x + text.Length / 2] = rText[x];
            }
        }

        //expands 32 bit text to 48 bit
        //to be xor'd with 48 bit key
        //then returns text to 32 bits
        private BitArray mangler(BitArray text, BitArray roundKey, int round)
        {
            BitArray newText = new BitArray(48);
            BitArray returnText = new BitArray(32);
            int count = 0;

            int[] expand = { 32,  1,  2,  3,  4,  5,
                              4,  5,  6,  7,  8,  9,
                              8,  9, 10, 11, 12, 13,
                             12, 13, 14, 15, 16, 17,
                             16, 17, 18, 19, 20, 21,
                             20, 21, 22, 23, 24, 25,
                             24, 25, 26, 27, 28, 29,
                             28, 29, 30, 31, 32,  1
                           };

            int[] perm = {  16,  7, 20, 21,
                            29, 12, 28, 17,
                             1, 15, 23, 26,
                             5, 18, 31, 10,
                             2,  8, 24, 14,
                            32, 27,  3,  9,
                            19, 13, 30,  6,
                            22, 11,  4, 25
                         };

            //pads each 4 bits with the previous and following
            //bit to turn 4 bits into 6 bits
            for (int x = 0; x < newText.Length; x++)
                newText[x] = text[expand[x] - 1];

            //xor key with 48 bit text
            newText = newText.Xor(roundKey);

            int table = 0;
            int invert = 3;
            int[] num = new int[4];
            bool[] row = new bool[2];

            //reduces 48 bit text to 32 bits
            for (int x = 0; x < newText.Length; x++)
                if (x % 6 == 0)
                {
                    row[0] = newText[x];
                    row[1] = newText[x + 5];
                }
                else if ((x + 1) % 6 != 0)
                    num[(x - 1) % 6] = Convert.ToInt16(newText[x]);
                else
                {
                    int[] tempRow = { Convert.ToInt16(row[0]), Convert.ToInt16(row[1]) };
                    String value = invertString(Table.table[table++, calcNum(tempRow), calcNum(num)]);
                    invert += 4;

                    for (int y = 0; y < value.Length; y++)
                        if (value[y] == '1')
                            returnText[count++] = true;
                        else
                            returnText[count++] = false;
                }

            BitArray tempText = new BitArray(32);

            //permutates text
            for (int x = 0; x < tempText.Length; x++)
                tempText[x] = returnText[perm[x] - 1];

            return tempText;
        }

        //inverts string from table
        private String invertString(string invert)
        {
            String temp = "";

            for (int x = invert.Length - 1; x >= 0; x--)
                temp += invert[x];

            return temp;
        }

        //gets decimal representation of binary number
        private int calcNum(int[] num)
        {
            int sum = 0;

            for (int x = 0; x < num.Length; x++)
                if (num[x] == 1)
                    sum += (int)Math.Pow(2, x);

            return sum;
        }

        //creates key based on current round
        private BitArray generateKey(int round)
        {
            BitArray newKey = new BitArray(56);
            BitArray permKey = new BitArray(48);

            //initial permutation of key resulting in a
            //48 bit key from 56 bit key
            if (round == 0)
            {
                int[] iPerm = { 57, 49, 41, 33, 25, 17,  9,
                                 1, 58, 50, 42, 34, 26, 18,
                                10,  2, 59, 51, 43, 35, 27,
                                19, 11,  3, 60, 52, 44, 36,
                                63, 55, 47, 39, 31, 23, 15,
                                 7, 62, 54, 46, 38, 30, 22,
                                14,  6, 61, 53, 45, 37, 29,
                                21, 13,  5, 28, 20, 12,  4};

                for (int x = 0; x < iPerm.Length; x++)
                    newKey[x] = key[iPerm[x] - 1];

                key = newKey;
            }
            //Permutates key based on current round
            else
            {
                int rotations = 1;

                //indicates which rounds get shifted twice
                if (!(round == 1 || round == 2 || round == 9 || round == 16))
                    rotations++;

                for (int x = 0; x < newKey.Length / 2; x++)
                {
                    int shift = (x + rotations) % (key.Length / 2);

                    newKey[x] = key[shift];
                    newKey[x + (newKey.Length / 2)] = key[shift + (key.Length / 2)];
                }

                for (int x = 0; x < newKey.Length / 2; x++)
                {
                    key[x] = newKey[x];
                    key[x + key.Length / 2] = newKey[x + newKey.Length / 2];
                }

                int[] perm = { 14, 17, 11, 24,  1,  5,
                                3, 28, 15,  6, 21, 10,
                               23, 19, 12,  4, 26,  8,
                               16,  7, 27, 20, 13,  2,
                               41, 52, 31, 37, 47, 55,
                               30, 40, 51, 45, 33, 48,
                               44, 49, 39, 56, 34, 53,
                               46, 42, 50, 36, 29, 32};

                for (int x = 0; x < perm.Length; x++)
                    permKey[x] = key[perm[x] - 1];
            }

            return permKey;
        }

        //Turns string of hex digits into a
        //binary array
        private BitArray getArray(String input)
        {
            BitArray tempArray;

            byte[] hex = new byte[16];

            for (int x = 0; x < hex.Length; x++)
            {
                int temp = input[x];

                if (temp >= '0' && temp <= '9')
                    temp -= '0';
                else if (temp >= 'A' && temp <= 'F')
                    temp -= '7';

                hex[x] = Convert.ToByte(temp);
            }

            tempArray = new BitArray(hex);
            int pos = 0, count = 0;
            bool[] bData = new bool[64];

            for (int x = 0; ((pos + 1) * 4) + x < tempArray.Length; x++)
            {
                if (x % 4 == 0 && x > 3)
                {
                    pos += 2;
                    x = 0;
                }

                bData[count++] = tempArray[(pos * 4) + x];
            }

            tempArray = new BitArray(bData);

            return tempArray;
        }
    }
}