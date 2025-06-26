using System;
using System.Collections;
using System.Collections.Generic;
using KModkit;
using KeepCoding;
using UnityEngine;
using Rnd = UnityEngine.Random;
using System.Linq;
using SecureFunctions;

public class RfrfididScript : ModuleScript
{
    private KMBombModule _Module;
    private KMBombInfo _info;
    internal System.Random ModRandom;

    private bool _isModuleSolved, _isSeedSet;
    private byte _crcKey;
    private int _seed;
    private byte[] _goodId;
    private static readonly float[] _strikeMultipliers = new float[] { 1, 1.25f, 1.5f, 1.75f, 2f };

    [SerializeField]
    private AudioClip[] _audioClips;
    [SerializeField]
    private AudioSource _audioSource;

    [SerializeField]
    private Card _card;

    [SerializeField]
    private DataSystem _dataSystem;

    // Use this for initialization
    void Start()
    {
        if (!_isSeedSet)
        {
            _seed = Rnd.Range(int.MinValue, int.MaxValue);
            Log("The seed is: " + _seed.ToString());
            _isSeedSet = true;
        }

        ModRandom = new System.Random(_seed);
        // SET SEED ABOVE IN CASE OF BUGS!!
        // _rnd = new System.Random(loggedSeed);
        _Module = Get<KMBombModule>();
        _info = Get<KMBombInfo>();

        uint[] key = new uint[] { 0x42524541, 0x4B4D4549, 0x46594F55, 0x43414E21 };
        uint[] initialisationVector = new uint[] { 0, 0, 0, 0 };
        AdvancedEncryptionStandard aes = new AdvancedEncryptionStandard(key, initialisationVector);

        uint[] plainText = new uint[] { 50, 67, 246, 168, 136, 90, 48, 141, 49, 49, 152, 162, 224, 55, 0, 52 };
        Log("Plaintext: " + PrettifyArray(plainText) + "; Key: " + PrettifyArray(key, 8));
        Log("After Padding + AES Encrypt: " + PrettifyArray(aes.Encrypt(plainText)));
        Log("After AES Decrypt: " + PrettifyArray(aes.Decrypt(aes.Encrypt(plainText))));
        //Log(aes.AddRoundKey(new uint[] { 0x328831E0, 0x435A3137, 0xF6309807, 0xA88DA234 }, new uint[] { 0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C }));

        _crcKey = GenerateGoodCRCKey();
        CyclicRedundancyCheck cyclicRedundancyCheck = new CyclicRedundancyCheck(_crcKey);

        // _card.Initialise(new byte[] { 0xbc, 0x69, 0x37, 0x42 }, _crcKey, 0, new byte[] { 0x02, 0x61, 0xc8, 0x36 }, false, new byte[][,] { }, new byte[] { }, true);
        // _card.LogCard();

        // _dataSystem.Initialise(false, new byte[] { 0x02, 0x61, 0xc8, 0x36 }, _crcKey);
        // _goodId = _dataSystem.GetInternalId();
        // Log(Enumerable.Range(0, _goodId.Length).Select(x => Convert.ToString(_goodId[x], 16).PadLeft(2, '0')).Join(""));

        Log(Convert.ToString(_crcKey, 16).PadLeft(2, '0'));
        Log(Convert.ToString(cyclicRedundancyCheck.Calculate(new byte[] { 0x10, 0x12, 0x23, 0x66 }), 16).PadLeft(2, '0'));
        // Log("Hidden.");
        // Log(AdvancedEncryptionStandard.InverseSBox(0).Select(x => x.ToString()).Join(", "));
    }

    private byte GenerateGoodCRCKey()
    {
        byte key = 0;
        while (Convert.ToString(key, 2).ToCharArray().Where(x => x == '1').Count() % 2 != 1 || key % 2 == 0)
            key = (byte)ModRandom.Next(3, 256);

        return key;
    }

    void Update()
    {
        /*
        if(!_audioSource.isPlaying)
        {
            if (DateTime.Now.Minute == 59 && DateTime.Now.Second == 59)
                _audioSource.clip = _audioClips[3];
            else if (DateTime.Now.Second == 59)
                _audioSource.clip = _audioClips[2];
            else if (DateTime.Now.Second % 2 == 1)
                _audioSource.clip = _audioClips[0];
            else if (DateTime.Now.Second % 2 == 0)
                _audioSource.clip = _audioClips[1];

            _audioSource.Play();
        }
        */
    }

    private static string PrettifyArray(uint[] numbers, int byteLength = 2)
    {
        return numbers.Select(x => Convert.ToString(x, 16).PadLeft(byteLength, '0')).Join("");
    }

    public static bool[] ParseByte(byte num)
    {
        return Enumerable.Range(0, 8).Select(x => (num >> (7 - x) & 1) == 1).ToArray();
    }

    public static byte CalculateRunningXor(byte[] data)
    {
        byte result = 0;

        foreach (byte b in data)
            result ^= b;

        return result;
    }
}
