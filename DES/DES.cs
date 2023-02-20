using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DES
{
    public class DES
    {
        Tables table = new Tables();
        int[] plaintextbin = new int[5000];
        char[] ptca;
        int[] ciphertextbin = new int[5000];
        char[] ctca;
        int[] keybin = new int[64];
        char[] kca;
        int[] ptextbitslice = new int[64];
        int[] ctextbitslice = new int[64];
        int[] ippt = new int[64];
        int[] ipct = new int[64];
        int[] ptLPT = new int[32];
        int[] ptRPT = new int[32];
        int[] ctLPT = new int[32];
        int[] ctRPT = new int[32];
        int[] changedkey = new int[56];
        int[] shiftedkey = new int[56];
        int[] tempRPT = new int[32];
        int[] tempLPT = new int[32];
        int[] CKey = new int[28];
        int[] DKey = new int[28];
        int[] compressedkey = new int[48];
        int[] ctExpandedLPT = new int[48];
        int[] ptExpandedRPT = new int[48];
        int[] XoredRPT = new int[48];
        int[] XoredLPT = new int[48];
        int[] row = new int[2];
        int rowindex;
        int[] column = new int[4];
        int columnindex;
        int sboxvalue;
        int[] tempsboxarray = new int[4];
        int[] ptSBoxRPT = new int[32];
        int[] ctSBoxLPT = new int[32];
        int[] ctPBoxLPT = new int[32];
        int[] ptPBoxRPT = new int[32];
        int[] attachedpt = new int[64];
        int[] attachedct = new int[64];
        int[] fppt = new int[64];
        int[] fpct = new int[64];

        private int ConvertTextToBits(char[] chararray, int[] savedarray)
        {
            int j = 0;
            for (int i = 0; i < chararray.Length; ++i)
            {
                int[] ba = new int[8];
                int k = 8 - 1;
                char[] bd = Convert.ToString(Convert.ToInt32(chararray[i]), 2).ToCharArray();

                for (int a = bd.Length - 1; a >= 0; --a, --k)
                {
                    if (bd[a] == '1')
                        ba[k] = 1;
                    else
                        ba[k] = 0;
                }

                while (k >= 0)
                {
                    ba[k] = 0;
                    --k;
                }
                j = i * 8;
                AssignArray1ToArray2b(ba, savedarray, j);
            }
            return (j + 8);
        }

        private void AssignArray1ToArray2b(int[] array1, int[] array2, int fromIndex)
        {
            int x, y;
            for (x = 0, y = fromIndex; x < array1.Length; ++x, ++y)
            {
                array2[y] = array1[x];
            }
        }

        private int AppendZeroes(int[] appendedarray, int len)
        {
            int zeroes;
            if (len % 64 != 0)
            {
                zeroes = (64 - (len % 64));

                for (int i = 0; i < zeroes; ++i)
                    appendedarray[len++] = 0;
            }
            return len;
        }

        private void Discard8thBitsFromKey()
        {
            for (int i = 0, j = 0; i < 64; i++)
            {
                if ((i + 1) % 8 == 0)
                    continue;
                changedkey[j++] = keybin[i];
            }
        }

        private void AssignChangedKeyToShiftedKey()
        {
            for (int i = 0; i < 56; i++)
            {
                shiftedkey[i] = changedkey[i];
            }
        }

        private void InitialPermutation(int[] sentarray, int[] savedarray)
        {
            int tmp;
            for (int i = 0; i < 64; i++)
            {
                tmp = table.GetInitialPermutation(i);
                savedarray[i] = sentarray[tmp - 1];
            }
        }

        private void DivideIntoLPTAndRPT(int[] sentarray, int[] savedLPT, int[] savedRPT)
        {
            for (int i = 0, k = 0; i < 32; i++, ++k)
            {
                savedLPT[k] = sentarray[i];
            }
            for (int i = 32, k = 0; i < 64; i++, ++k)
            {
                savedRPT[k] = sentarray[i];
            }
        }

        private void SaveTemporaryHPT(int[] fromHPT, int[] toHPT)
        {
            for (int i = 0; i < 32; i++)
            {
                toHPT[i] = fromHPT[i];
            }
        }

        private void DivideIntoCKeyAndDKey()
        {
            for (int i = 0, j = 0; i < 28; i++, ++j)
            {
                CKey[j] = shiftedkey[i];
            }
            for (int i = 28, j = 0; i < 56; i++, ++j)
            {
                DKey[j] = shiftedkey[i];
            }
        }

        private void CircularLeftShift(int[] HKey)
        {
            int i, FirstBit = HKey[0];
            for (i = 0; i < 27; i++)
            {
                HKey[i] = HKey[i + 1];
            }
            HKey[i] = FirstBit;
        }

        private void AttachCKeyAndDKey()
        {
            int j = 0;
            for (int i = 0; i < 28; i++)
            {
                shiftedkey[j++] = CKey[i];
            }
            for (int i = 0; i < 28; i++)
            {
                shiftedkey[j++] = DKey[i];
            }
        }

        private void CompressionPermutation()
        {
            int temp;
            for (int i = 0; i < 48; i++)
            {
                temp = table.GetCompression(i);
                compressedkey[i] = shiftedkey[temp - 1];
            }
        }

        private void ExpansionPermutation(int[] HPT, int[] ExpandedHPT)
        {
            int temp;
            for (int i = 0; i < 48; i++)
            {
                temp = table.GetExpansion(i);
                ExpandedHPT[i] = HPT[temp - 1];
            }
        }

        private void XOROperation(int[] array1, int[] array2, int[] array3, int SizeOfTheArray)
        {
            for (int i = 0; i < SizeOfTheArray; i++)
            {
                array3[i] = array1[i] ^ array2[i];
            }
        }

        private void AssignSBoxHPT(int[] temparray, int[] SBoxHPTArray, int fromIndex)
        {
            int j = fromIndex;
            for (int i = 0; i < 4; i++)
            {
                SBoxHPTArray[j++] = tempsboxarray[i];
            }
        }

        private void SBoxSubstituion(int[] XoredHPT, int[] SBoxHPT)
        {
            int r, t, j = 0, q = 0;
            for (int i = 0; i < 48; i += 6)
            {
                row[0] = XoredHPT[i];
                row[1] = XoredHPT[i + 5];
                string stringvalue = "";
                for (int a = 0; a < row.Length; a++)
                {
                    stringvalue += row[a].ToString();
                }
                rowindex = Convert.ToInt32(stringvalue, 2);
                column[0] = XoredHPT[i + 1];
                column[1] = XoredHPT[i + 2];
                column[2] = XoredHPT[i + 3];
                column[3] = XoredHPT[i + 4];
                stringvalue = "";
                for (int a = 0; a < column.Length; a++)
                {
                    stringvalue += column[a].ToString();
                }
                columnindex = Convert.ToInt32(stringvalue, 2);
                t = ((16 * (rowindex)) + (columnindex));
                sboxvalue = table.GetSBox(j++, t);
                int k = 4 - 1;
                char[] bd = Convert.ToString(sboxvalue, 2).ToCharArray();

                for (int a = bd.Length - 1; a >= 0; --a, --k)
                {
                    if (bd[a] == '1')
                        tempsboxarray[k] = 1;
                    else
                        tempsboxarray[k] = 0;
                }

                while (k >= 0)
                {
                    tempsboxarray[k] = 0;
                    --k;
                }
                r = q * 4;
                AssignSBoxHPT(tempsboxarray, SBoxHPT, r);
                ++q;
            }
        }

        private void PBoxPermutation(int[] SBoxHPT, int[] PBoxHPT)
        {
            int temp;
            for (int i = 0; i < 32; i++)
            {
                temp = table.GetPBox(i);
                PBoxHPT[i] = SBoxHPT[temp - 1];
            }
        }

        private void Swap(int[] tempHPT, int[] HPT)
        {
            for (int i = 0; i < 32; i++)
            {
                int temp = HPT[i];
                HPT[i] = tempHPT[i];
                tempHPT[i] = temp;
            }
        }

        private void SixteenRounds()
        {
            int n;
            for (int i = 0; i < 16; i++)
            {
                SaveTemporaryHPT(ptRPT, tempRPT);
                n = table.GetEncryption(i);
                DivideIntoCKeyAndDKey();
                for (int j = 0; j < n; j++)
                {
                    CircularLeftShift(CKey);
                    CircularLeftShift(DKey);
                }
                AttachCKeyAndDKey();
                CompressionPermutation();
                ExpansionPermutation(ptRPT, ptExpandedRPT);
                XOROperation(compressedkey, ptExpandedRPT, XoredRPT, 48);
                SBoxSubstituion(XoredRPT, ptSBoxRPT);
                PBoxPermutation(ptSBoxRPT, ptPBoxRPT);
                XOROperation(ptPBoxRPT, ptLPT, ptRPT, 32);
                Swap(tempRPT, ptLPT);
            }
        }

        private void AttachLPTAndRPT(int[] savedLPT, int[] savedRPT, int[] AttachedPT)
        {
            int j = 0;
            for (int i = 0; i < 32; i++)
            {
                AttachedPT[j++] = savedLPT[i];
            }
            for (int i = 0; i < 32; i++)
            {
                AttachedPT[j++] = savedRPT[i];
            }
        }

        private void FinalPermutation(int[] fromPT, int[] toPT)
        {
            int temp;
            for (int i = 0; i < 64; i++)
            {
                temp = table.GetFinalPermutation(i);
                toPT[i] = fromPT[temp - 1];
            }
        }

        private void StartEncryption()
        {
            InitialPermutation(ptextbitslice, ippt);
            DivideIntoLPTAndRPT(ippt, ptLPT, ptRPT);
            AssignChangedKeyToShiftedKey();
            SixteenRounds();
            AttachLPTAndRPT(ptLPT, ptRPT, attachedpt);
            FinalPermutation(attachedpt, fppt);
        }

        private string ConvertBitsToText(int[] sentarray, int len)
        {
            string finaltext = "";
            int j, k, decimalvalue;
            int[] tempbitarray = new int[8];
            for (int i = 0; i < len; i += 8)
            {
                for (k = 0, j = i; j < (i + 8); ++k, ++j)
                {
                    tempbitarray[k] = sentarray[j];
                }
                string stringvalue = "";
                for (int a = 0; a < tempbitarray.Length; a++)
                {
                    stringvalue += tempbitarray[a].ToString();
                }
                decimalvalue = Convert.ToInt32(stringvalue, 2);
                if (decimalvalue == 0) break;
                finaltext += (char)decimalvalue;
            }
            return finaltext;
        }

        public string Encrypt(string plaintext, string key)
        {
            string ciphertext = null;
            ptca = plaintext.ToCharArray();
            kca = key.ToCharArray();
            int j, k;
            int st = ConvertTextToBits(ptca, plaintextbin);
            int fst = AppendZeroes(plaintextbin, st);
            int sk = ConvertTextToBits(kca, keybin);
            int fsk = AppendZeroes(keybin, sk);
            Discard8thBitsFromKey();
            for (int i = 0; i < fst; i += 64)
            {
                for (k = 0, j = i; j < (i + 64); ++j, ++k)
                {
                    ptextbitslice[k] = plaintextbin[j];
                }
                StartEncryption();
                for (k = 0, j = i; j < (i + 64); ++j, ++k)
                {
                    ciphertextbin[j] = fppt[k];
                }
            }
            ciphertext = ConvertBitsToText(ciphertextbin, fst);
            return ciphertext;
        }

        private void CircularRightShift(int[] HKey)
        {
            int i, LastBit = HKey[27];
            for (i = 27; i >= 1; --i)
            {
                HKey[i] = HKey[i - 1];
            }
            HKey[i] = LastBit;
        }

        private void ReversedSixteenRounds()
        {
            int n;
            for (int i = 0; i < 16; i++)
            {
                SaveTemporaryHPT(ctLPT, tempLPT);
                CompressionPermutation();
                ExpansionPermutation(ctLPT, ctExpandedLPT);
                XOROperation(compressedkey, ctExpandedLPT, XoredLPT, 48);
                SBoxSubstituion(XoredLPT, ctSBoxLPT);
                PBoxPermutation(ctSBoxLPT, ctPBoxLPT);
                XOROperation(ctPBoxLPT, ctRPT, ctLPT, 32);
                Swap(tempLPT, ctRPT);
                n = table.GetDecryption(i);
                DivideIntoCKeyAndDKey();
                for (int j = 0; j < n; j++)
                {
                    CircularRightShift(CKey);
                    CircularRightShift(DKey);
                }
                AttachCKeyAndDKey();
            }
        }

        private void StartDecryption()
        {
            InitialPermutation(ctextbitslice, ipct);
            DivideIntoLPTAndRPT(ipct, ctLPT, ctRPT);
            AssignChangedKeyToShiftedKey();
            ReversedSixteenRounds();
            AttachLPTAndRPT(ctLPT, ctRPT, attachedct);
            FinalPermutation(attachedct, fpct);
        }

        public string Decrypt(string ciphertext, string key)
        {
            string plaintext = null;
            ctca = ciphertext.ToCharArray();
            kca = key.ToCharArray();
            int j, k;
            int st = ConvertTextToBits(ctca, ciphertextbin);
            int fst = AppendZeroes(ciphertextbin, st);
            int sk = ConvertTextToBits(kca, keybin);
            int fsk = AppendZeroes(keybin, sk);
            Discard8thBitsFromKey();
            for (int i = 0; i < fst; i += 64)
            {
                for (k = 0, j = i; j < (i + 64); ++j, ++k)
                {
                    ctextbitslice[k] = ciphertextbin[j];
                }
                StartDecryption();
                for (k = 0, j = i; j < (i + 64); ++j, ++k)
                {
                    plaintextbin[j] = fpct[k];
                }
            }
            plaintext = ConvertBitsToText(plaintextbin, fst);
            return plaintext;
        }
    }
}