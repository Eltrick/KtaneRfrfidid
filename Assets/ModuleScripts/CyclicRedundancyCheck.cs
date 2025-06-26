using System;
using System.Linq;

public class CyclicRedundancyCheck
{
    private byte _key;

    public CyclicRedundancyCheck(byte key)
    {
        if (key == 0)
            throw new InvalidOperationException("CRC key cannot be 0.");
        _key = key;
    }

    public byte Calculate(byte[] data)
    {
        bool[] keyBooleans = { true };
        keyBooleans = keyBooleans.Concat(RfrfididScript.ParseByte(_key)).ToArray();

        bool[] dataBooleans = new bool[0];
        foreach (byte b in data)
            dataBooleans = dataBooleans.Concat(RfrfididScript.ParseByte(b)).ToArray();
        dataBooleans = dataBooleans.Concat(new bool[keyBooleans.Length - 1]).ToArray();

        for(int i = 0; i < dataBooleans.Length - keyBooleans.Length + 1; i++)
        {
            if (!dataBooleans[i])
                continue;
            for (int j = 0; j < keyBooleans.Length; j++)
                dataBooleans[i + j] ^= keyBooleans[j];
        }

        return (byte)Enumerable.Range(0, keyBooleans.Length - 1)
            .Sum(x => (dataBooleans[dataBooleans.Length - (keyBooleans.Length - 1) + x] ? 1 : 0) << ((keyBooleans.Length - 2) - x));
    }

    public byte GetKey()
    {
        return _key;
    }
}
