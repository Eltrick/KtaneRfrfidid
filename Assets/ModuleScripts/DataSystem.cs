using KeepCoding;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using UnityEngine;

public class DataSystem : MonoBehaviour
{
    [SerializeField]
    private RfrfididScript Parent;

    private readonly byte _defaultIdLength = 4;

    private CyclicRedundancyCheck _cyclicRedundancyCheck;
    private bool _isBlock0Checked;
    private byte _keyIndex;
    private byte[] _internalId, _internalManufacturingData;
    private byte[,] _keys = new byte[4, 4];

    public void Initialise(bool type, byte[] manufacturingData, byte crcKey)
    {
        _isBlock0Checked = !type;

        _cyclicRedundancyCheck = new CyclicRedundancyCheck(crcKey);

        for (int i = 0; i < _keys.GetLength(0); i++)
            for (int j = 0; j < _keys.GetLength(1); j++)
                _keys[i, j] = (byte)Parent.ModRandom.Next(0, 256);

        if (_isBlock0Checked)
        {
            _internalId = Enumerable.Range(0, _defaultIdLength).Select(x => (byte)Parent.ModRandom.Next(0, 256)).ToArray();
            _internalManufacturingData = manufacturingData;
            _keyIndex = (byte)Parent.ModRandom.Next(0, _keys.GetLength(0) - 2);
        }
    }

    public bool CheckData(Card card)
    {
        if (_isBlock0Checked)
        {
            byte[] dataRead = card.ReadInternalBlock(new byte[] { 0, 0 }, Enumerable.Range(0, _keys.GetLength(1)).Select(x => _keys[_keyIndex, x]).ToArray(), _keyIndex % 2 == 1);

            if (dataRead.Length == 0)
                return false;
            if (dataRead[4] != _cyclicRedundancyCheck.GetKey())
                return false;
            if (Enumerable.Range(0, _internalId.Length).Where(x => _internalId[x] == dataRead[x]).Count() != _internalId.Length)
                return false;
            if (Enumerable.Range(0, _internalManufacturingData.Length).Where(x => _internalManufacturingData[x] == dataRead[x + 5]).Count() != _internalManufacturingData.Length)
                return false;
            if (!card.CheckCRCData())
                return false;

            return true;
        }
        else
        {
            return true;
        }
    }

    public byte[] GetInternalId()
    {
        return _internalId;
    }
}
