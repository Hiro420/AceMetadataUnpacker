namespace AceMetaUnpack;

public sealed class Extractor
{
	private readonly string _dllPath;
	private byte[] _validData = Array.Empty<byte>();

	public Extractor(string dllPath)
	{
		_dllPath = dllPath ?? throw new ArgumentNullException(nameof(dllPath));
	}

	public void Process()
	{
		ExtractDataPattern();
	}

	public byte[] GetValidData()
	{
		var copy = new byte[_validData.Length];
		Buffer.BlockCopy(_validData, 0, copy, 0, _validData.Length);
		return copy;
	}

	private void ExtractDataPattern()
	{
		byte[] dllData;
		try
		{
			dllData = File.ReadAllBytes(_dllPath);
		}
		catch (Exception ex)
		{
			throw new Exception($"File not found: {ex.Message}");
		}

		byte[] headPattern = new byte[]
		{
			(byte)'C', 0,
			(byte)'F', 0,
			(byte)'G', 0,
			0, 0, 0, 0
		};
		byte[] tailPattern = new byte[] { 0, 0, 0, 0 };

		int headPos = IndexOfSequence(dllData, headPattern, 0);
		if (headPos < 0)
			throw new Exception("Head pattern not found");

		int startPos = headPos + headPattern.Length;

		int tailPos = IndexOfSequence(dllData, tailPattern, startPos);
		if (tailPos < 0)
			throw new Exception("Tail pattern not found");

		int len = tailPos - startPos;
		if (len < 0)
			throw new Exception("Tail pattern found before start position (corrupt file?)");

		_validData = new byte[len];
		Buffer.BlockCopy(dllData, startPos, _validData, 0, len);
	}

	private static int IndexOfSequence(byte[] haystack, byte[] needle, int startIndex)
	{
		if (needle.Length == 0) return startIndex;
		if (haystack.Length < needle.Length) return -1;

		int lastStart = haystack.Length - needle.Length;
		for (int i = Math.Max(0, startIndex); i <= lastStart; i++)
		{
			bool match = true;
			for (int j = 0; j < needle.Length; j++)
			{
				if (haystack[i + j] != needle[j])
				{
					match = false;
					break;
				}
			}
			if (match) return i;
		}
		return -1;
	}
}
