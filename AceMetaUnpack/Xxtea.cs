namespace AceMetaUnpack;

public static class Xxtea
{
	private const uint DELTA = 0x9E3779B9;

	private static byte[] FixKey(byte[] key)
	{
		if (key.Length == 16) return (byte[])key.Clone();

		var fixedKey = new byte[16];
		int copy = Math.Min(16, key.Length);
		Buffer.BlockCopy(key, 0, fixedKey, 0, copy);
		return fixedKey;
	}

	private static uint[] ToUInt32Array(byte[] data, bool includeLength)
	{
		int length = data.Length;
		int n = ((length & 3) == 0) ? (length >> 2) : ((length >> 2) + 1);
		int endLen = includeLength ? (n + 1) : n;

		var result = new uint[endLen];

		if (includeLength)
			result[n] = (uint)length;

		for (int i = 0; i < length; i++)
		{
			result[i >> 2] |= (uint)data[i] << ((i & 3) << 3);
		}

		return result;
	}

	private static byte[]? ToByteArray(uint[] data, bool includeLength)
	{
		int n = data.Length << 2;

		if (includeLength)
		{
			if (data.Length == 0) return Array.Empty<byte>();

			uint last = data[data.Length - 1];
			int m = unchecked((int)last);
			n -= 4;

			int min = Math.Max(0, n - 3);
			if (m < min || m > n) return null;

			n = m;
		}

		var result = new byte[n];
		for (int i = 0; i < n; i++)
		{
			result[i] = (byte)((data[i >> 2] >> ((i & 3) << 3)) & 0xFF);
		}
		return result;
	}

	private static uint Mx(uint sum, uint y, uint z, int p, uint e, uint[] k)
	{
		uint pMask = (uint)p & 3U;
		uint kVal = k[(pMask ^ e) & 3U];

		uint part1 = (z >> 5) ^ (y << 2);
		uint part2 = (y >> 3) ^ (z << 4);
		uint part3 = sum ^ y;
		uint part4 = kVal ^ z;

		unchecked
		{
			return (part1 + part2) ^ (part3 + part4);
		}
	}

	private static void DecryptUInt32(uint[] v, uint[] k)
	{
		int n = v.Length - 1;
		if (n < 1) return;

		uint y = v[0];
		int q = 6 + (52 / (n + 1));

		uint sum = unchecked((uint)q * DELTA);

		while (sum != 0)
		{
			uint e = (sum >> 2) & 3U;

			for (int p = n; p >= 1; p--)
			{
				uint z = v[p - 1];
				uint mxVal = Mx(sum, y, z, p, e, k);
				unchecked { v[p] = v[p] - mxVal; }
				y = v[p];
			}

			{
				int p = 0;
				uint z = v[n];
				uint mxVal = Mx(sum, y, z, p, e, k);
				unchecked { v[0] = v[0] - mxVal; }
				y = v[0];
			}

			unchecked { sum -= DELTA; }
		}
	}

	public static byte[] Decrypt(byte[] data, byte[] key)
	{
		if (data.Length == 0) return Array.Empty<byte>();

		byte[] fixedKey = FixKey(key);
		uint[] v = ToUInt32Array(data, includeLength: false);
		uint[] k = ToUInt32Array(fixedKey, includeLength: false);

		DecryptUInt32(v, k);

		var bytes = ToByteArray(v, includeLength: false);
		if (bytes == null)
			throw new Exception("Invalid XXTEA data or key.");

		return bytes;
	}
}
