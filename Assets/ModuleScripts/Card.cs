using System;
using System.Globalization;
using System.Linq;
using UnityEngine;

public class Card : MonoBehaviour
{
    [SerializeField]
    private RfrfididScript Parent;

    private readonly DateTime _DateTime = DateTime.Now;
    private readonly byte[,] _defaultKeys =
    {
        {0, 0, 0, 0},
        {25, 146, 4, 39},
        {32, 32, 102, 102},
        {39, 24, 40, 24},
        {49, 65, 89, 38},
        {49, 65, 89, 224},
        {73, 87, 65, 68},
        {80, 65, 83, 83},
        {81, 36, 54, 72},
        {84, 65, 80, 69},
        {102, 76, 97, 67},
        {105, 105, 105, 105},
        {113, 111, 105, 102},
        {137, 80, 78, 71},
        {222, 173, 192, 222},
        {241, 234, 94, 237},
        {250, 186, 218, 17},
        {254, 237, 190, 239}
    };
    private readonly byte _defaultIdLength = 4, _defaultManufacturingDataLength = 4, _defaultKeyLength = 4, _defaultBlockKeyCount = 2;
    private byte _type;
    private bool _isBlock0Writable;
    private CyclicRedundancyCheck _cyclicRedundancyCheck;

    private byte[][,] _cardData = new byte[2][,]
    {
        new byte[4, 9],
        new byte[4, 9]
    };

    public void Initialise(byte[] id, byte crcKey, byte type, byte[] manufacturingData, bool isKeyDerivationFunctionUsed, byte[][,] blockKeys, byte[] accessConditions, bool isBlock0Writable)
    {
        _cyclicRedundancyCheck = new CyclicRedundancyCheck(crcKey);
        if (id.Length != _defaultIdLength)
            for (int i = 0; i < _defaultIdLength; i++)
                _cardData[0][0, i] = (byte)Parent.ModRandom.Next(0, 256);
        else
            for (int i = 0; i < _defaultIdLength; i++)
                _cardData[0][0, i] = id[i];

        _cardData[0][0, 4] = crcKey;

        if (manufacturingData.Length != _defaultManufacturingDataLength)
        {
            _type = (byte)Parent.ModRandom.Next(0, 2);
            if (_type == 0) // Fudan
            {
                if (Parent.ModRandom.Next(0, 100) == 0)
                {
                    byte[,] _rare =
                    {
                        { 102, 103, 104, 105 },
                        { 144, 16, 21, 1 }
                    };
                    byte pick = (byte)Parent.ModRandom.Next(0, _rare.Length);

                    for (int i = 0; i < _defaultManufacturingDataLength; i++)
                        _cardData[0][0, i + 5] = _rare[pick, i];
                }
                else
                {
                    _cardData[0][0, 5] = (byte)Parent.ModRandom.Next(1, 5);
                    _cardData[0][0, 6] = (byte)Parent.ModRandom.Next(1, 13);
                    _cardData[0][0, 7] = (byte)((_DateTime.Year - Parent.ModRandom.Next(1, 31)) % 100);

                    if ((_cardData[0][0, 5] - 1) / 2 == 0)
                        _cardData[0][0, 8] = 29;
                    else
                        _cardData[0][0, 8] = 144;
                }
            }
            else // NXP
            {
                Calendar calendar = CultureInfo.InvariantCulture.Calendar;
                _cardData[0][0, 5] = (byte)Parent.ModRandom.Next(0, calendar.GetWeekOfYear(DateTime.Now, CalendarWeekRule.FirstDay, DayOfWeek.Monday));
                _cardData[0][0, 6] = (byte)((_DateTime.Year - Parent.ModRandom.Next(1, 31)) % 100);
                _cardData[0][0, 7] = 200;
                _cardData[0][0, 8] = 54;
            }
        }
        else
        {
            _type = type;
            for (int i = 0; i < manufacturingData.Length; i++)
                _cardData[0][0, i + 5] = manufacturingData[i];
        }

        if (!isKeyDerivationFunctionUsed)
        {
            if (blockKeys.Length != _defaultBlockKeyCount)
            {
                if (Parent.ModRandom.Next(0, 2) == 0)
                    for (int i = 0; i < _cardData.Length; i++)
                        for (int j = 0; j < 2; j++)
                        {
                            byte pick = (byte)Parent.ModRandom.Next(0, _defaultKeys.GetLength(0));
                            for (int k = 0; k < _defaultKeyLength; k++)
                                _cardData[i][3, k + 5 * j] = _defaultKeys[pick, k];
                        }
                else
                    for (int i = 0; i < _cardData.Length; i++)
                        for (int j = 0; j < 2; j++)
                            for (int k = 0; k < _defaultKeyLength; k++)
                                _cardData[i][3, k + 5 * j] = (byte)Parent.ModRandom.Next(0, 256);
            }
            else
                for (int i = 0; i < blockKeys.Length; i++)
                    for (int j = 0; j < blockKeys[i].GetLength(0); j++)
                        for (int k = 0; k < blockKeys[i].GetLength(1); k++)
                            _cardData[i][3, 5 * j + k] = blockKeys[i][j, k];
        }
        else
        {
            // byte[] generatedKeys = KeyDerivation(Enumerable.Range(0, _cardData[0].GetLength(1)).Where(x => x != 4).Select(x => _cardData[0][0, x]).ToArray(), false, 0);
        }

        if (accessConditions.Length != _defaultBlockKeyCount)
            for (int i = 0; i < _cardData.Length; i++)
                _cardData[i][3, 4] = 255;
        else
            for (int i = 0; i < _cardData.Length; i++)
                _cardData[i][3, 4] = accessConditions[i];

        WriteCorrectCRCData();

        _isBlock0Writable = isBlock0Writable;
    }

    public void LogCard()
    {
        for (byte i = 0; i < _cardData.Length; i++)
            for (byte j = 0; j < _cardData[i].GetLength(0); j++)
                Parent.Log(OverrideReadData(new byte[] { i, j }));
    }

    public string ReadData(byte[] sectorBlock, byte[] key, bool keyType)
    {
        if (sectorBlock[0] > 1 || sectorBlock[1] > 3)
            return "10";

        if (!AccessConditionsToBooleans(_cardData[sectorBlock[0]][3, 4])[keyType ? 2 : 0])
            return "10";
        if (sectorBlock[1] == 3)
            if (!AccessConditionsToBooleans(_cardData[sectorBlock[0]][3, 4])[keyType ? 6 : 4])
                return "10";
        for (int i = 0; i < key.Length; i++)
            if (_cardData[sectorBlock[0]][3, 5 * (keyType ? 1 : 0) + i] != key[i])
                return "10";

        if (sectorBlock[1] == 3)
            return Convert.ToString(_cardData[sectorBlock[0]][3, 4], 16).PadLeft(2, '0') + " " + Convert.ToString(_cardData[sectorBlock[0]][3, 4], 16).PadLeft(2, '0');

        byte[] resultData = Enumerable.Range(0, _cardData[sectorBlock[0]].GetLength(1)).Select(x => _cardData[sectorBlock[0]][sectorBlock[1], x]).ToArray();

        byte[] decoyData = new byte[8];
        for (int i = 0; i < decoyData.Length; i++)
            decoyData[i] = resultData[i];

        while (Parent.ModRandom.Next(0, 3) == 0)
            decoyData[Parent.ModRandom.Next(0, decoyData.Length)] ^= (byte)(1 << Parent.ModRandom.Next(0, 8));

        return decoyData.Select(x => Convert.ToString(x, 16).PadLeft(2, '0')).Join(" ") + " " + Convert.ToString(RfrfididScript.CalculateRunningXor(resultData), 16).PadLeft(2, '0');
    }

    internal byte[] ReadInternalBlock(byte[] sectorBlock, byte[] key, bool keyType)
    {
        if (sectorBlock[0] > 1 || sectorBlock[1] > 3)
            return new byte[] { };

        if (!AccessConditionsToBooleans(_cardData[sectorBlock[0]][3, 4])[keyType ? 2 : 0])
            return new byte[] { };
        if (sectorBlock[1] == 3)
            if (!AccessConditionsToBooleans(_cardData[sectorBlock[0]][3, 4])[keyType ? 6 : 4])
                return new byte[] { };
        for (int i = 0; i < key.Length; i++)
            if (_cardData[sectorBlock[0]][3, 5 * (keyType ? 1 : 0) + i] != key[i])
                return new byte[] { };

        if (sectorBlock[1] == 3)
            return new byte[] { _cardData[sectorBlock[0]][3, 4], _cardData[sectorBlock[0]][3, 4] };

        byte[] resultData = Enumerable.Range(0, _cardData[sectorBlock[0]].GetLength(1)).Select(x => _cardData[sectorBlock[0]][sectorBlock[1], x]).ToArray();

        return resultData.Concat(new byte[] { RfrfididScript.CalculateRunningXor(resultData) }).ToArray();
    }

    private string OverrideReadData(byte[] sectorBlock)
    {
        byte[] resultData = Enumerable.Range(0, _cardData[sectorBlock[0]].GetLength(1)).Select(x => _cardData[sectorBlock[0]][sectorBlock[1], x]).ToArray();

        return resultData.Select(x => Convert.ToString(x, 16).PadLeft(2, '0')).Join(" ");
    }

    public string WriteData(byte[] sectorBlockOffset, byte[] key, bool keyType, byte data)
    {
        if (sectorBlockOffset[0] > 1 || sectorBlockOffset[1] > 3 || sectorBlockOffset[2] > 7)
            return "10";

        if (!AccessConditionsToBooleans(_cardData[sectorBlockOffset[0]][3, 4])[keyType ? 3 : 1])
            return "10";
        if (sectorBlockOffset[1] == 3)
            if (!AccessConditionsToBooleans(_cardData[sectorBlockOffset[0]][3, 4])[keyType ? 7 : 5])
                return "10";
        for (int i = 0; i < key.Length; i++)
            if (_cardData[sectorBlockOffset[0]][3, 5 * (keyType ? 1 : 0) + i] != key[i])
                return "10";
        if (sectorBlockOffset[0] == sectorBlockOffset[1] && sectorBlockOffset[0] == 0)
            if (!_isBlock0Writable)
                return "10";

        _cardData[sectorBlockOffset[0]][sectorBlockOffset[1], sectorBlockOffset[2]] = data;
        return "04";
    }

    internal void OverrideWriteData(byte[] sectorBlockOffset, byte data)
    {
        _cardData[sectorBlockOffset[0]][sectorBlockOffset[1], sectorBlockOffset[2]] = data;
    }

    public bool CheckCRCData()
    {
        for (int i = 0; i < _cardData.Length; i++)
        {
            if (i == 0)
                for (int j = 1; j < 3; j++)
                {
                    byte[] data = new byte[0];
                    for (int k = 0; k <= j; k++)
                        data = data.Concat(Enumerable.Range(0, _cardData[i].GetLength(1) - (k == j ? 1 : 0)).Select(x => _cardData[i][k, x])).ToArray();
                    if (_cardData[i][j, 8] != _cyclicRedundancyCheck.Calculate(data))
                        return false;
                }
            else
                for (int j = 0; j < 3; j++)
                {
                    byte[] data = new byte[0];
                    for (int k = 0; k <= j; k++)
                        data = data.Concat(Enumerable.Range(0, _cardData[i].GetLength(1) - (k == j ? 1 : 0)).Select(x => _cardData[i][k, x])).ToArray();
                    if (_cardData[i][j, 8] != _cyclicRedundancyCheck.Calculate(data))
                        return false;
                }
        }
        return true;
    }

    private void WriteCorrectCRCData()
    {
        for (int i = 0; i < _cardData.Length; i++)
        {
            if (i == 0)
                for (int j = 1; j < 3; j++)
                {
                    byte[] data = new byte[0];
                    for (int k = 0; k <= j; k++)
                        data = data.Concat(Enumerable.Range(0, _cardData[i].GetLength(1) - (k == j ? 1 : 0)).Select(x => _cardData[i][k, x])).ToArray();
                    _cardData[i][j, 8] = _cyclicRedundancyCheck.Calculate(data);
                }
            else
                for (int j = 0; j < 3; j++)
                {
                    byte[] data = new byte[0];
                    for (int k = 0; k <= j; k++)
                        data = data.Concat(Enumerable.Range(0, _cardData[i].GetLength(1) - (k == j ? 1 : 0)).Select(x => _cardData[i][k, x])).ToArray();
                    _cardData[i][j, 8] = _cyclicRedundancyCheck.Calculate(data);
                }
        }
    }

    private bool[] AccessConditionsToBooleans(byte accessConditions)
    {
        // 00000000
        // 0           Rb-A    0
        //  0          Wb-A    1
        //   0         Rb-B    2
        //    0        Wb-B    3
        //     0       Rt-A    4
        //      0      Wt-A    5
        //       0     Rt-B    6
        //        0    Wt-B    7

        return RfrfididScript.ParseByte(accessConditions);
    }

    /*
    private byte[] KeyDerivation(byte[] data, bool keyType, byte sector)
    {

    }
    */
}
