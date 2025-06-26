using KeepCoding;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SecureFunctions
{
    public sealed class SecureHashAlgorithmOne
    {
        private ulong[] _HInitial = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
        private ulong[] _KInitial = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

        private ulong[] _H = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
        private ulong[] _K = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

        private ulong[] _LetterConstants = new ulong[5];

        /// <summary>
        /// Creates a new instance of SHA1 hash algorithm.
        /// </summary>
        /// <param name="H">Initial hash result values, as an array of 5 ulongs. Leave the array blank and of length 0 if you wish to use the standard SHA1 hash.</param>
        /// <param name="K">Constants to be used in the hashing algorithm, as an array of 4 ulongs. Do the same as H if you wish to use the standard SHA1 hash.</param>
        /// <exception cref="ArgumentException">When H is not empty but also not of length 5, or K is not empty but also not of length 4.</exception>
        public SecureHashAlgorithmOne(ulong[] H, ulong[] K)
        {
            if (H.Length != 0)
            {
                if (H.Length != 5)
                    throw new ArgumentException("H.Length must be 5.");
                else
                    for (int i = 0; i < _H.Length; i++)
                        _HInitial[i] = H[i];
            }
            if (K.Length != 0)
            {
                if (K.Length != 4)
                    throw new ArgumentException("K.Length must be 4.");
                else
                    for (int i = 0; i < _K.Length; i++)
                        _KInitial[i] = K[i];
            }
        }

        /// <summary>
        /// Calculates the SHA1 hash of a given input.
        /// </summary>
        /// <param name="message">UTF-8 string representing the input.</param>
        /// <returns>A string of 40 hex digits, representing the final hash of the message.</returns>
        public string MessageCode(string message)
        {
            for (int i = 0; i < 5; i++)
                _H[i] = _HInitial[i];

            for (int i = 0; i < 4; i++)
                _K[i] = _KInitial[i];

            string bitstring = "";
            for (int i = 0; i < message.Length; i++)
                bitstring += LeftZeroPad(Convert.ToString(message[i], 2), 8);

            bitstring = HashPad(bitstring);

            for (int i = 0; i < bitstring.Length / 512; i++)
                MessageCodeBlock(bitstring.Substring(512 * i, 512));

            string result = "";
            for (int i = 0; i < _H.Length; i++)
                result += LeftZeroPad(Convert.ToString((uint)_H[i], 16), 8);
            return result;
        }

        private void MessageCodeBlock(string block)
        {
            ulong[] words = new ulong[80];
            for (int i = 0; i < 16; i++)
                words[i] = Convert.ToUInt64(block.Substring(32 * i, 32), 2);

            for (int i = 0; i < _H.Length; i++)
                _LetterConstants[i] = _H[i];

            for (int t = 0; t < 80; t++)
            {
                if (15 < t)
                    words[t] = ShiftCircleLeft(words[t - 3] ^ words[t - 8] ^ words[t - 14] ^ words[t - 16], 1);

                ulong temp = Add(Add(Add(Add(ShiftCircleLeft(_LetterConstants[0], 5), f(t, _LetterConstants[1], _LetterConstants[2], _LetterConstants[3])), _LetterConstants[4]), words[t]), K(t));
                _LetterConstants[4] = _LetterConstants[3];
                _LetterConstants[3] = _LetterConstants[2];
                _LetterConstants[2] = ShiftCircleLeft(_LetterConstants[1], 30);
                _LetterConstants[1] = _LetterConstants[0];
                _LetterConstants[0] = temp;
            }

            for (int i = 0; i < _H.Length; i++)
                _H[i] = Add(_H[i], _LetterConstants[i]);
        }

        string LeftZeroPad(string s, int length)
        {
            string r = s;
            if (s.Length >= length)
                return s;
            while (r.Length < length)
                r = "0" + r;
            return r;
        }

        private ulong ShiftCircleLeft(ulong x, int n)
        {
            return ((x << n) | (x >> (32 - n))) & uint.MaxValue;
        }

        private ulong Add(ulong x, ulong y)
        {
            return (x + y) & uint.MaxValue;
        }

        private string HashPad(string bitstring)
        {
            string r = bitstring + "1";
            while (r.Length % 512 != 448)
                r += "0";
            r += ModifiedBinaryConvert(bitstring.Length);
            return r;
        }

        private string ModifiedBinaryConvert(int x)
        {
            string t = Convert.ToString(x, 2);
            while (t.Length < 64)
                t = "0" + t;
            return t;
        }

        private ulong f(int t, ulong B, ulong C, ulong D)
        {
            if (t < 20)
                return (B & C) | ((~B) & D);
            else if (t < 40)
                return B ^ C ^ D;
            else if (t < 60)
                return (B & C) | (B & D) | (C & D);
            else
                return B ^ C ^ D;
        }

        private ulong K(int t)
        {
            if (t < 20)
                return _K[0];
            else if (t < 40)
                return _K[1];
            else if (t < 60)
                return _K[2];
            else
                return _K[3];
        }
    }

    public sealed class AdvancedEncryptionStandard
    {
        public enum CipherType
        {
            ECB,
            CBC
        }
        private CipherType _cipherType;

        public enum PaddingType
        {
            ANSIX923,
            ISO10126,
            PKCS
        };
        private PaddingType _paddingType;

        private int _keyLength;
        private uint[] _initialisationVector = new uint[4];
        private List<uint> _keys = new List<uint>();

        private int[] _shuffle = new int[] { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
        private uint[] _polynomialModuli = new uint[] { 1, 0, 0, 0, 1, 1, 0, 1, 1 };

        public AdvancedEncryptionStandard(uint[] key, uint[] initialisationVector, CipherType type = CipherType.ECB, PaddingType paddingType = PaddingType.ANSIX923)
        {
            if(type == CipherType.CBC)
            {
                if (initialisationVector.Length != 4)
                    throw new ArgumentException("Initialisation vector must be 4 words.");
                
                Array.Copy(initialisationVector, _initialisationVector, _initialisationVector.Length);
            }
            _paddingType = paddingType;

            _keyLength = key.Length;
            _cipherType = type;
            GenerateKeys(key);
        }

        private const int SBoxLength = 256;

        private static byte[] SBox()
        {
            return new byte[] { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
        }

        private static byte[] InverseSBox()
        {
            byte[] sbox = SBox();
            byte[] inverse = new byte[SBoxLength];

            for(int i = 0; i < sbox.Length; i++)
                inverse[sbox[i]] = (byte)i;

            return inverse;
        }

        private uint[] BytesToWords(uint[] bytes)
        {
            if (bytes.Length % 4 != 0)
                throw new ArgumentException("Length of bytes must be divisible by one word.");

            uint[] words = new uint[bytes.Length / 4];
            for (int i = 0; i < bytes.Length; i += 4)
                words[i / 4] = (uint)Enumerable.Range(i, 4).Sum(x => bytes[x] << (24 - 8 * (x % 4)));

            return words;
        }

        private uint[] WordsToBytes(uint[] words)
        {
            uint[] bytes = new uint[words.Length * 4];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = (words[i / 4] >> (24 - 8 * (i % 4))) & 0xff;

            return bytes;
        }

        private uint[] Shuffle(uint[] words)
        {
            string inputString = Enumerable.Range(0, words.Length).Select(x => Convert.ToString(words[x], 16).PadLeft(8, '0')).Join("");
            uint[] inputBytes = Enumerable.Range(0, inputString.Length / 2).Select(x => Convert.ToUInt32(inputString.SubstringSafe(2 * x, 2), fromBase: 16)).ToArray();
            uint[] shuffledWords = Enumerable.Range(0, 4).Select(x => Enumerable.Range(0, 4).Select(y => Convert.ToString(inputBytes[_shuffle[4 * x + y]], 16).PadLeft(2, '0')).Join("")).Select(x => Convert.ToUInt32(x, fromBase: 16)).ToArray();

            return shuffledWords;
        }

        private void GenerateKeys(uint[] key)
        {
            for (int i = 0; i < 4 * key.Length + 28; i++)
            {
                if (i < key.Length)
                    _keys.Add(key[i]);
                else if (i % key.Length == 0)
                    _keys.Add(_keys[i - key.Length] ^ SubWord(RotWord(_keys[i - 1])) ^ RoundConstant(i / key.Length - 1));
                else if (key.Length > 6 && i % key.Length == 4)
                    _keys.Add(_keys[i - key.Length] ^ SubWord(_keys[i - 1]));
                else
                    _keys.Add(_keys[i - key.Length] ^ _keys[i - 1]);
            }
        }

        private static uint RoundConstant(int index)
        {
            return new uint[] { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 }[index % 10] << 24;
        }

        private static uint RotWord(uint word, int direction = 0)
        {
            return (word << (8 + 16 * (direction % 2))) | (word >> (24 - 16 * (direction % 2)));
        }

        private static uint SubWord(uint word, bool isDecrypting = false)
        {
            int result = 0;

            for (int i = 0; i < 4; i++)
            {
                if (!isDecrypting)
                    result |= (SBox()[(word >> (8 * i)) & 255]) << (8 * i);
                else
                    result |= (InverseSBox()[(word >> (8 * i)) & 255]) << (8 * i);
            }
            

            return (uint)result;
        }

        private byte PolyMultiply(uint[] a, uint[] b)
        {
            if (a.Length == 0 || b.Length == 0)
                return 0;
            
            uint[] result = new uint[a.Length + b.Length - 1];
            for (int i = 0; i < b.Length; i++)
                for (int j = 0; j < a.Length; j++)
                    result[i + j] += a[j] * b[i];

            return Convert.ToByte(PolyReduce(result, _polynomialModuli).Join(""), 2);
        }

        private static uint[] PolyReduce(uint[] a, uint[] b)
        {
            Stack<uint> bStack = new Stack<uint>();

            for (int i = 0; i < b.Length; i++)
                bStack.Push(b[b.Length - 1 - i]);
            while (bStack.Peek() == 0)
                bStack.Pop();

            if (bStack.Count == 0)
                throw new ArgumentException("B must not be equivalent to 0.");

            List<uint> newBList = new List<uint>();
            
            while (bStack.Count != 0)
                newBList.Add(bStack.Pop());

            List<uint> dataList = Enumerable.Range(0, a.Length).Select(x => a[x]).ToList();

            dataList.Reverse();
            while (dataList.Count < b.Length)
                dataList.Add(0);
            dataList.Reverse();

            uint[] newB = newBList.ToArray();

            bool[] dataBooleans = Enumerable.Range(0, dataList.Count).Select(x => dataList[x] == 1).ToArray();
            bool[] keyBooleans = Enumerable.Range(0, newB.Length).Select(x => newB[x] == 1).ToArray();

            for (int i = 0; i < dataBooleans.Length - keyBooleans.Length + 1; i++)
            {
                if (!dataBooleans[i])
                    continue;
                for (int j = 0; j < keyBooleans.Length; j++)
                    dataBooleans[i + j] ^= keyBooleans[j];
            }

            return Enumerable.Range(0, b.Length - 1)
                .Select(x => (uint)(dataBooleans[dataBooleans.Length - b.Length + 1 + x] ? 1 : 0)).ToArray();
        }

        private static uint[] SubBytes(uint[] state, bool isDecrypting = false)
        {
            return Enumerable.Range(0, state.Length).Select(x => SubWord(state[x], isDecrypting)).ToArray();
        }

        private static uint[] ShiftRows(uint[] state, int direction = 0)
        {
            for (int i = 0; i < state.Length; i++)
                for (int j = 0; j < i; j++)
                    state[i] = RotWord(state[i], direction);

            return state;
        }

        public uint MixColumns(uint[] state)
        {
            List<uint[]> stateBinary = new List<uint[]>();
            for (int i = 0; i < state.Length; i++)
                stateBinary.Add(Convert.ToString(state[i], 2).ToCharArray().Select(x => uint.Parse(x.ToString())).ToArray());

            uint[,] matrix = new uint[,]
            {
                { 2, 3, 1, 1 },
                { 1, 2, 3, 1 },
                { 1, 1, 2, 3 },
                { 3, 1, 1, 2 }
            };

            uint result = 0;

            for (int i = 0; i < state.Length; i++)
            {
                uint t = 0;
                for (int j = 0; j < state.Length; j++)
                    t ^= PolyMultiply(stateBinary[j], Convert.ToString(matrix[i, j], 2).ToCharArray().Select(x => uint.Parse(x.ToString())).ToArray());
                result |= t << (24 - 8 * i);
            }

            return result;
        }

        private uint[] AddRoundKey(uint[] state, uint[] roundKey)
        {
            uint[] shuffledRoundKey = Shuffle(roundKey);

            return Enumerable.Range(0, state.Length).Select(x => state[x] ^ shuffledRoundKey[x]).ToArray();
        }

        private uint[] EncryptSingle(uint[] block)
        {
            Array.Copy(AddRoundKey(block, Enumerable.Range(0, 4).Select(x => _keys[x]).ToArray()), block, block.Length);
            for (int i = 0; i < _keyLength + 5; i++)
            {
                Array.Copy(SubBytes(block), block, block.Length);
                Array.Copy(ShiftRows(block), block, block.Length);
                Array.Copy(Shuffle(block), block, block.Length);
                uint[] result = new uint[block.Length];
                for (int j = 0; j < block.Length; j++)
                {
                    uint[] split = Enumerable.Range(0, 4).Select(x => (block[j] >> (24 - 8 * x)) & 0xff).ToArray();
                    result[j] = MixColumns(split);
                }
                Array.Copy(result, block, block.Length);
                Array.Copy(Shuffle(block), block, block.Length);
                Array.Copy(AddRoundKey(block, Enumerable.Range(4 * i + 4, 4).Select(x => _keys[x]).ToArray()), block, block.Length);
            }
            Array.Copy(SubBytes(block), block, block.Length);
            Array.Copy(ShiftRows(block), block, block.Length);
            Array.Copy(AddRoundKey(block, Enumerable.Range(4 * _keyLength + 24, 4).Select(x => _keys[x]).ToArray()), block, block.Length);
            return Shuffle(block);
        }

        public uint[] Encrypt(uint[] message)
        {
            List<uint> m = message.ToList();
            do
            {
                switch(_paddingType)
                {
                    case PaddingType.ANSIX923:
                        if (m.Count % 16 != 15)
                            m.Add(0);
                        else
                            m.Add((uint)(16 - (message.Length % 8)));
                        break;
                    case PaddingType.ISO10126:
                        if (m.Count % 16 != 15)
                            m.Add((uint)((SBox()[m[m.Count() - 1]] * SBox()[m[m.Count() - 2]]) & 0xff));
                        else
                            m.Add((uint)(16 - (message.Length % 8)));
                        break;
                    case PaddingType.PKCS:
                        m.Add((uint)(16 - (message.Length % 8)));
                        break;
                }
            } while (m.Count % 16 != 0);

            uint[][] blocks = Enumerable.Range(0, m.Count / 16).Select(x => Shuffle(BytesToWords(Enumerable.Range(0, 16).Select(y => m[16 * x + y]).ToArray()))).ToArray();

            uint[] result = new uint[0];
            uint[] initialisationVector = new uint[_initialisationVector.Length];
            Array.Copy(_initialisationVector, initialisationVector, initialisationVector.Length);

            for (int i = 0; i < blocks.Length; i++)
            {
                uint[] blockEncrypt = EncryptSingle(AddRoundKey(blocks[i], initialisationVector));
                result = result.Concat(blockEncrypt);

                if (_cipherType == CipherType.CBC)
                    initialisationVector = blockEncrypt;
            }

            return WordsToBytes(result);
        }

        private uint[] DecryptSingle(uint[] block)
        {
            Array.Copy(AddRoundKey(block, Enumerable.Range(4 * _keyLength + 24, 4).Select(x => _keys[x]).ToArray()), block, block.Length);
            Array.Copy(ShiftRows(block, 1), block, block.Length);
            Array.Copy(SubBytes(block, true), block, block.Length);
            for (int i = _keyLength + 4; i > -1; i--)
            {
                Array.Copy(AddRoundKey(block, Enumerable.Range(4 * i + 4, 4).Select(x => _keys[x]).ToArray()), block, block.Length);
                Array.Copy(Shuffle(block), block, block.Length);
                uint[] result = new uint[block.Length];
                for (int j = 0; j < block.Length; j++)
                {
                    uint[] split = Enumerable.Range(0, 4).Select(x => (block[j] >> (24 - 8 * x)) & 0xff).ToArray();
                    result[j] = MixColumns(WordsToBytes(new uint[] { MixColumns(WordsToBytes(new uint[] { MixColumns(split) })) }));
                }
                Array.Copy(result, block, block.Length);
                Array.Copy(Shuffle(block), block, block.Length);
                Array.Copy(ShiftRows(block, 1), block, block.Length);
                Array.Copy(SubBytes(block, true), block, block.Length);
            }
            Array.Copy(AddRoundKey(block, Enumerable.Range(0, 4).Select(x => _keys[x]).ToArray()), block, block.Length);
            return Shuffle(block);
        }

        public uint[] Decrypt(uint[] encryptedBytes)
        {
            uint[][] blocks = Enumerable.Range(0, encryptedBytes.Length / 16).Select(x => Shuffle(BytesToWords(Enumerable.Range(0, 16).Select(y => encryptedBytes[16 * x + y]).ToArray()))).ToArray();

            uint[] result = new uint[0];
            uint[] initialisationVector = new uint[_initialisationVector.Length];
            Array.Copy(_initialisationVector, initialisationVector, initialisationVector.Length);

            for(int i = 0; i < blocks.Length; i++)
            {
                uint[] blockData = new uint[blocks[i].Length];
                Array.Copy(blocks[i], blockData, blockData.Length);

                uint[] blockDecrypt = AddRoundKey(DecryptSingle(blockData), initialisationVector);
                result = result.Concat(blockDecrypt);

                if (_cipherType == CipherType.CBC)
                    initialisationVector = blocks[i];
            }

            uint[] decryptedBytes = WordsToBytes(result);

            return Enumerable.Range(0, decryptedBytes.Length - (int)decryptedBytes[decryptedBytes.Length - 1]).Select(x => decryptedBytes[x]).ToArray();
        }
    }
}
